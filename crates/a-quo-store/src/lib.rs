//! Non-secret persona metadata and append-only key lifecycle history.
//!
//! This store never accepts private keys or wallet credentials.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a_quo_core::{
    MAX_CONTINUITY_TRANSITIONS, MAX_PROOF_BYTES, PersonaRootProof, PersonaTransitionProof,
    PersonaTransitionStatement, new_routine_transition_statement, public_key_fingerprint,
    verify_persona_continuity_chain, verify_persona_root_proof, verify_persona_transition_proof,
};
use a_quo_display::{
    contains_unsafe_display_characters, escape_untrusted_bytes_for_terminal,
    escape_untrusted_text_for_terminal,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 4;
const MAX_LABEL_BYTES: usize = 256;
const MAX_NOTE_BYTES: usize = 2_048;
const MAX_POLICY_BYTES: usize = 512;
const MAX_ACTOR_BYTES: usize = 256;
const MAX_SIGNING_REFERENCE_BYTES: usize = 4_096;
const MAX_PUBLIC_KEY_BYTES: u64 = 16_384;
const MAX_PERSONA_BACKUP_KEYS: usize = 256;
const MAX_PERSONA_BACKUP_EVENTS: usize = 4_096;

/// One immutable root key plus every transition allowed by the continuity
/// protocol. This live-store bound is deliberately separate from the smaller
/// portable-backup policy.
pub const MAX_STORED_PERSONA_KEYS: usize = MAX_CONTINUITY_TRANSITIONS + 1;

/// A key can have one origin event, one retirement, and one compromise.
pub const MAX_STORED_PERSONA_EVENTS: usize = MAX_STORED_PERSONA_KEYS * 3;

pub const PERSONA_BACKUP_SCHEMA: &str = "urn:a-quo:persona-metadata-backup:v1";
pub const MAX_PERSONA_BACKUP_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("cannot serialize continuity evidence: {0}")]
    Serialization(#[from] serde_json::Error),

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

    #[error("unsafe signing reference {display_path}: {reason}")]
    UnsafeSigningReference {
        path: PathBuf,
        display_path: String,
        reason: String,
    },

    #[error("persona has no active key to rotate: {0}")]
    NoActiveKey(String),

    #[error("invalid key lifecycle transition: {0}")]
    InvalidTransition(String),

    #[error("key lifecycle event references a key outside its persona")]
    CrossPersonaKeyEvent,

    #[error("stored key lifecycle events do not reproduce the recorded key state")]
    InvalidAuditHistory,

    #[error("persona key history cannot exceed the live-store limit of {limit} keys")]
    StoredPersonaKeyLimit { limit: usize },

    #[error("persona lifecycle history cannot exceed the live-store limit of {limit} events")]
    StoredPersonaEventLimit { limit: usize },

    #[error("invalid OpenSSH public key: {0}")]
    InvalidPublicKey(String),

    #[error("persona continuity is not registered: {0}")]
    ContinuityNotFound(String),

    #[error("continuity-managed persona must use the proof-authorized rotation flow: {0}")]
    ContinuityBypass(String),

    #[error(
        "cannot mark the current continuity-head key compromised outside the journaled recovery/compromise flow: {0}"
    )]
    ContinuityCompromiseRequiresJournal(String),

    #[error("continuity journal conflict: {0}")]
    ContinuityConflict(String),

    #[error("invalid continuity evidence: {0}")]
    InvalidContinuity(String),

    #[error("continuity proof exceeds the {MAX_PROOF_BYTES}-byte bound")]
    ContinuityProofTooLarge,

    #[error("system clock is before the Unix epoch")]
    InvalidSystemTime,

    #[error(
        "system clock moved backward relative to stored audit history: observed {observed}, require at least {minimum}"
    )]
    NonMonotonicAuditTime { observed: i64, minimum: i64 },
}

fn serialize_continuity_proof<T: Serialize>(proof: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(proof)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PROOF_BYTES {
        Err(StoreError::ContinuityProofTooLarge)
    } else {
        Ok(bytes)
    }
}

fn deserialize_continuity_proof<T>(bytes: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PROOF_BYTES {
        return Err(StoreError::ContinuityProofTooLarge);
    }
    serde_json::from_slice(bytes).map_err(StoreError::from)
}

fn invalid_continuity(error: impl fmt::Display) -> StoreError {
    StoreError::InvalidContinuity(error.to_string())
}

fn persona_in(connection: &Connection, persona_id: &str) -> Result<Persona> {
    connection
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
        .and_then(persona_from_row)
}

fn require_continuity_unmanaged(connection: &Connection, persona_id: &str) -> Result<()> {
    if continuity_managed_in(connection, persona_id)? {
        Err(StoreError::ContinuityBypass(persona_id.to_owned()))
    } else {
        Ok(())
    }
}

fn continuity_managed_in(connection: &Connection, persona_id: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(
             SELECT 1 FROM persona_continuity_roots WHERE persona_id = ?1
         )",
            [persona_id],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn recorded_persona_root_in(
    connection: &Connection,
    persona_id: &str,
) -> Result<Option<RecordedPersonaRoot>> {
    let raw = connection
        .query_row(
            "SELECT root_statement_sha256, persona_anchor,
                    initial_key_fingerprint, root_proof_json, issued_at, recorded_at
             FROM persona_continuity_roots WHERE persona_id = ?1",
            [persona_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    raw.map(
        |(
            root_statement_sha256,
            persona_anchor,
            initial_key_fingerprint,
            proof_json,
            issued_at,
            recorded_at,
        )| {
            let proof: PersonaRootProof = deserialize_continuity_proof(&proof_json)?;
            let verified = verify_persona_root_proof(&proof).map_err(invalid_continuity)?;
            if verified.root_statement_sha256 != root_statement_sha256
                || verified.statement.persona_anchor != persona_anchor
                || verified.statement.initial_key_fingerprint != initial_key_fingerprint
                || verified.statement.issued_at != issued_at
            {
                return Err(StoreError::InvalidContinuity(
                    "stored root columns do not match the reverified root proof".to_owned(),
                ));
            }
            Ok(RecordedPersonaRoot {
                persona_id: persona_id.to_owned(),
                root_statement_sha256,
                persona_anchor,
                initial_key_fingerprint,
                proof,
                issued_at,
                recorded_at,
            })
        },
    )
    .transpose()
}

fn continuity_head_in(connection: &Connection, persona_id: &str) -> Result<Option<ContinuityHead>> {
    let raw = connection
        .query_row(
            "SELECT revision, transition_sequence, current_key_fingerprint,
                    last_transition_sha256, last_issued_at
             FROM persona_continuity_heads WHERE persona_id = ?1",
            [persona_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    raw.map(
        |(
            revision,
            transition_sequence,
            current_key_fingerprint,
            last_transition_sha256,
            last_issued_at,
        )| {
            let transition_sequence = u32::try_from(transition_sequence).map_err(|_| {
                StoreError::InvalidContinuity(
                    "stored transition sequence does not fit in u32".to_owned(),
                )
            })?;
            Ok(ContinuityHead {
                persona_id: persona_id.to_owned(),
                revision,
                transition_sequence,
                current_key_fingerprint,
                last_transition_sha256,
                last_issued_at,
            })
        },
    )
    .transpose()
}

fn routine_transition_proofs_in(
    connection: &Connection,
    persona_id: &str,
) -> Result<Vec<PersonaTransitionProof>> {
    let mut statement = connection.prepare(
        "SELECT sequence, transition_statement_sha256, root_statement_sha256,
                previous_transition_sha256, previous_key_fingerprint,
                next_key_fingerprint, issued_at, proof_json
         FROM persona_continuity_transitions
         WHERE persona_id = ?1 ORDER BY sequence",
    )?;
    let rows = statement.query_map([persona_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Vec<u8>>(7)?,
        ))
    })?;
    let mut proofs = Vec::new();
    for row in rows {
        let (
            sequence,
            transition_statement_sha256,
            root_statement_sha256,
            previous_transition_sha256,
            previous_key_fingerprint,
            next_key_fingerprint,
            issued_at,
            proof_json,
        ) = row?;
        if proofs.len() >= MAX_CONTINUITY_TRANSITIONS {
            return Err(StoreError::InvalidContinuity(format!(
                "stored chain exceeds {MAX_CONTINUITY_TRANSITIONS} transitions"
            )));
        }
        let proof: PersonaTransitionProof = deserialize_continuity_proof(&proof_json)?;
        let verified = verify_persona_transition_proof(&proof).map_err(invalid_continuity)?;
        let stored_sequence = u32::try_from(sequence).map_err(|_| {
            StoreError::InvalidContinuity(
                "stored transition sequence does not fit in u32".to_owned(),
            )
        })?;
        let stored_matches = verified.statement.sequence == stored_sequence
            && verified.transition_statement_sha256 == transition_statement_sha256
            && verified.statement.root_statement_sha256 == root_statement_sha256
            && verified.statement.previous_transition_sha256 == previous_transition_sha256
            && verified.statement.previous_key_fingerprint == previous_key_fingerprint
            && verified.statement.next_key_fingerprint == next_key_fingerprint
            && verified.statement.issued_at == issued_at;
        if !stored_matches {
            return Err(StoreError::InvalidContinuity(format!(
                "stored transition row {sequence} does not match its reverified proof"
            )));
        }
        proofs.push(proof);
    }
    Ok(proofs)
}

fn routine_continuity_snapshot_in(
    connection: &Connection,
    persona_id: &str,
) -> Result<RoutineContinuitySnapshot> {
    let root = recorded_persona_root_in(connection, persona_id)?
        .ok_or_else(|| StoreError::ContinuityNotFound(persona_id.to_owned()))?;
    let head = continuity_head_in(connection, persona_id)?.ok_or_else(|| {
        StoreError::InvalidContinuity("recorded root has no continuity head".to_owned())
    })?;
    let transitions = routine_transition_proofs_in(connection, persona_id)?;
    let report =
        verify_persona_continuity_chain(&root.proof, &transitions, &root.root_statement_sha256)
            .map_err(invalid_continuity)?;
    let head_matches = report.transition_count == head.transition_sequence
        && report.chain_tip_key_fingerprint == head.current_key_fingerprint
        && report.last_transition_sha256 == head.last_transition_sha256
        && report.last_issued_at == head.last_issued_at;
    if !head_matches {
        return Err(StoreError::InvalidContinuity(
            "stored continuity head does not match the reverified chain".to_owned(),
        ));
    }
    key_history_in(connection, persona_id)?;
    let active_keys = active_key_fingerprints(connection, persona_id)?;
    if active_keys.as_slice() != [head.current_key_fingerprint.as_str()] {
        return Err(StoreError::InvalidContinuity(
            "accepted continuity head is not the persona's unique active key".to_owned(),
        ));
    }
    Ok(RoutineContinuitySnapshot {
        root,
        head,
        transitions,
    })
}

fn validate_persona_authorization_state_in(
    connection: &Connection,
    persona_id: &str,
) -> Result<()> {
    if continuity_managed_in(connection, persona_id)? {
        routine_continuity_snapshot_in(connection, persona_id)?;
    } else {
        key_history_in(connection, persona_id)?;
    }
    Ok(())
}

fn current_snapshot_for_committed_transition(
    connection: &Connection,
    intent: &RoutineTransitionIntent,
    committed: &CommittedRoutineTransition,
) -> Result<RoutineContinuitySnapshot> {
    let snapshot = routine_continuity_snapshot_in(connection, &intent.persona_id)?;
    let exact_current_head = snapshot.head.transition_sequence == intent.sequence
        && snapshot.head.current_key_fingerprint == intent.next_key_fingerprint
        && snapshot.head.last_transition_sha256.as_deref()
            == Some(committed.transition_statement_sha256.as_str())
        && snapshot.transitions.last() == Some(&committed.proof);
    if !exact_current_head {
        return Err(StoreError::ContinuityConflict(format!(
            "persona {} sequence {} is committed but is not the current continuity head",
            intent.persona_id, intent.sequence
        )));
    }
    Ok(snapshot)
}

fn routine_transition_intent(
    persona_id: &str,
    statement: &PersonaTransitionStatement,
) -> RoutineTransitionIntent {
    RoutineTransitionIntent {
        persona_id: persona_id.to_owned(),
        sequence: statement.sequence,
        root_statement_sha256: statement.root_statement_sha256.clone(),
        previous_transition_sha256: statement.previous_transition_sha256.clone(),
        previous_key_fingerprint: statement.previous_key_fingerprint.clone(),
        next_key_fingerprint: statement.next_key_fingerprint.clone(),
        issued_at: statement.issued_at,
    }
}

fn lookup_committed_routine_transition_in(
    connection: &Connection,
    intent: &RoutineTransitionIntent,
) -> Result<Option<CommittedRoutineTransition>> {
    let raw = connection
        .query_row(
            "SELECT transition_statement_sha256, root_statement_sha256,
                    previous_transition_sha256, previous_key_fingerprint,
                    next_key_fingerprint, issued_at, proof_json, committed_at
             FROM persona_continuity_transitions
             WHERE persona_id = ?1 AND sequence = ?2",
            params![intent.persona_id, i64::from(intent.sequence)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        transition_statement_sha256,
        root_statement_sha256,
        previous_transition_sha256,
        previous_key_fingerprint,
        next_key_fingerprint,
        issued_at,
        proof_json,
        committed_at,
    )) = raw
    else {
        return Ok(None);
    };
    let proof: PersonaTransitionProof = deserialize_continuity_proof(&proof_json)?;
    let verified = verify_persona_transition_proof(&proof).map_err(invalid_continuity)?;
    let stored_intent = routine_transition_intent(&intent.persona_id, &verified.statement);
    let columns_match = verified.transition_statement_sha256 == transition_statement_sha256
        && root_statement_sha256 == stored_intent.root_statement_sha256
        && previous_transition_sha256 == stored_intent.previous_transition_sha256
        && previous_key_fingerprint == stored_intent.previous_key_fingerprint
        && next_key_fingerprint == stored_intent.next_key_fingerprint
        && issued_at == stored_intent.issued_at;
    if !columns_match {
        return Err(StoreError::InvalidContinuity(
            "stored committed transition columns do not match its reverified proof".to_owned(),
        ));
    }
    if stored_intent != *intent {
        return Err(StoreError::ContinuityConflict(format!(
            "persona {} sequence {} is already committed with different intent",
            intent.persona_id, intent.sequence
        )));
    }
    Ok(Some(CommittedRoutineTransition {
        intent: stored_intent,
        transition_statement_sha256,
        proof,
        committed_at,
        replayed: true,
    }))
}

fn require_intent_at_head(
    intent: &RoutineTransitionIntent,
    snapshot: &RoutineContinuitySnapshot,
) -> Result<()> {
    let expected_sequence = next_routine_transition_sequence(&snapshot.head)?;
    if intent.persona_id != snapshot.root.persona_id
        || intent.root_statement_sha256 != snapshot.root.root_statement_sha256
        || intent.sequence != expected_sequence
        || intent.previous_transition_sha256 != snapshot.head.last_transition_sha256
        || intent.previous_key_fingerprint != snapshot.head.current_key_fingerprint
        || intent.issued_at < snapshot.head.last_issued_at
    {
        return Err(StoreError::ContinuityConflict(
            "routine transition intent is stale, forked, or bound to a different root".to_owned(),
        ));
    }
    Ok(())
}

fn next_routine_transition_sequence(head: &ContinuityHead) -> Result<u32> {
    if usize::try_from(head.transition_sequence).unwrap_or(usize::MAX) >= MAX_CONTINUITY_TRANSITIONS
    {
        return Err(StoreError::InvalidContinuity(format!(
            "routine continuity journal has reached its {MAX_CONTINUITY_TRANSITIONS}-transition limit"
        )));
    }
    head.transition_sequence
        .checked_add(1)
        .ok_or_else(|| StoreError::InvalidContinuity("transition sequence overflow".to_owned()))
}

fn candidate_key_record(
    persona_id: &str,
    fingerprint: &str,
    public_key: &str,
    provider: KeyProvider,
    added_at: i64,
) -> KeyRecord {
    KeyRecord {
        fingerprint: fingerprint.to_owned(),
        persona_id: persona_id.to_owned(),
        public_key: public_key.to_owned(),
        provider,
        status: KeyStatus::Active,
        added_at,
        retired_at: None,
        compromised_at: None,
    }
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

/// An immutable locally recorded persona root. The proof remains public
/// verification material; it contains no private signing authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordedPersonaRoot {
    pub persona_id: String,
    pub root_statement_sha256: String,
    pub persona_anchor: String,
    pub initial_key_fingerprint: String,
    pub proof: PersonaRootProof,
    pub issued_at: i64,
    pub recorded_at: i64,
}

/// The one locally accepted head of a routine-only continuity journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContinuityHead {
    pub persona_id: String,
    pub revision: i64,
    pub transition_sequence: u32,
    pub current_key_fingerprint: String,
    pub last_transition_sha256: Option<String>,
    pub last_issued_at: i64,
}

/// Exact transition identity used for safe committed-proof retry lookup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutineTransitionIntent {
    pub persona_id: String,
    pub sequence: u32,
    pub root_statement_sha256: String,
    pub previous_transition_sha256: Option<String>,
    pub previous_key_fingerprint: String,
    pub next_key_fingerprint: String,
    pub issued_at: i64,
}

/// A validated, non-persisted candidate signer for the next routine key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutineRotationCandidate {
    pub statement: PersonaTransitionStatement,
    pub intent: RoutineTransitionIntent,
    pub public_key: String,
    pub provider: KeyProvider,
    pub signing_reference: SigningReference,
}

/// A transactionally committed routine handoff, or an exact idempotent retry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedRoutineTransition {
    pub intent: RoutineTransitionIntent,
    pub transition_statement_sha256: String,
    pub proof: PersonaTransitionProof,
    pub committed_at: i64,
    pub replayed: bool,
}

/// Non-secret database metadata for recovering an exact, already-committed
/// transition proof.
///
/// This is deliberately not an [`ActiveSigner`]: the stored locator is
/// returned without opening, canonicalizing, or otherwise claiming that the
/// private signing key still exists or is usable. The metadata is safe only
/// for matching a retry to public evidence that is already in the journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutineContinuityRetryMetadata {
    pub persona_id: String,
    pub current_key_fingerprint: String,
    pub provider: KeyProvider,
    pub signing_locator: PathBuf,
}

/// One consistent, fully verified view of the stored routine-only chain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutineContinuitySnapshot {
    pub root: RecordedPersonaRoot,
    pub head: ContinuityHead,
    pub transitions: Vec<PersonaTransitionProof>,
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
                migrate_v3(&mut connection)?;
                migrate_v4(&mut connection)?;
            }
            1 => {
                migrate_v2(&mut connection)?;
                migrate_v3(&mut connection)?;
                migrate_v4(&mut connection)?;
            }
            2 => {
                migrate_v3(&mut connection)?;
                migrate_v4(&mut connection)?;
            }
            3 => migrate_v4(&mut connection)?,
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
        require_continuity_unmanaged(&transaction, persona_id)?;
        validate_persona_authorization_state_in(&transaction, persona_id)?;
        require_monotonic_audit_time(&transaction, persona_id, now)?;
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
        require_continuity_unmanaged(&transaction, persona_id)?;
        validate_persona_authorization_state_in(&transaction, persona_id)?;
        require_monotonic_audit_time(&transaction, persona_id, now)?;
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
        validate_persona_authorization_state_in(&transaction, &key.persona.id)?;
        require_monotonic_audit_time(&transaction, &key.persona.id, now)?;
        if key.key.status == KeyStatus::Compromised {
            return Err(StoreError::InvalidTransition(format!(
                "key {fingerprint} is already compromised"
            )));
        }
        if recorded_persona_root_in(&transaction, &key.persona.id)?.is_some() {
            let snapshot = routine_continuity_snapshot_in(&transaction, &key.persona.id)?;
            if key.key.status == KeyStatus::Active
                && snapshot.head.current_key_fingerprint == fingerprint
            {
                return Err(StoreError::ContinuityCompromiseRequiresJournal(
                    fingerprint.to_owned(),
                ));
            }
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
        let transaction = self.connection.unchecked_transaction()?;
        validate_persona_authorization_state_in(&transaction, persona_id)?;
        let keys = list_keys_in(&transaction, persona_id)?;
        transaction.commit()?;
        Ok(keys)
    }

    pub fn key_history(&self, persona_id: &str) -> Result<Vec<KeyEvent>> {
        let transaction = self.connection.unchecked_transaction()?;
        let events = key_history_in(&transaction, persona_id)?;
        transaction.commit()?;
        Ok(events)
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
        let transaction = self.connection.unchecked_transaction()?;
        let recognized = validated_lookup_key_in(&transaction, fingerprint)?;
        transaction.commit()?;
        Ok(recognized)
    }

    pub fn bind_signing_reference(
        &mut self,
        fingerprint: &str,
        locator: impl AsRef<Path>,
    ) -> Result<SigningReference> {
        let now = now_unix_seconds()?;
        let transaction = self.connection.transaction()?;
        let recognized = validated_lookup_key_in(&transaction, fingerprint)?
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

    #[cfg(test)]
    fn lookup_signing_reference(&self, fingerprint: &str) -> Result<Option<SigningReference>> {
        lookup_signing_reference_in(&self.connection, fingerprint)
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
        let transaction = self.connection.unchecked_transaction()?;
        require_active_persona(&transaction, persona_id)?;
        validate_persona_authorization_state_in(&transaction, persona_id)?;
        let active_keys = list_keys_in(&transaction, persona_id)?
            .into_iter()
            .filter(|key| key.status == KeyStatus::Active)
            .collect::<Vec<_>>();
        let key = match active_keys.as_slice() {
            [] => return Err(StoreError::NoActiveKey(persona_id.to_owned())),
            [key] => key.clone(),
            _ => return Err(StoreError::AmbiguousActiveKeys(persona_id.to_owned())),
        };
        let recognized = lookup_key_in(&transaction, &key.fingerprint)?
            .ok_or_else(|| StoreError::KeyNotFound(key.fingerprint.clone()))?;
        let signing_reference = lookup_signing_reference_in(&transaction, &key.fingerprint)?
            .ok_or_else(|| StoreError::SigningReferenceNotFound(key.fingerprint.clone()))?;
        let resolved =
            validate_signing_reference_path(&signing_reference.locator, &recognized.key)?;
        if resolved != signing_reference.locator {
            return Err(unsafe_signing_reference(
                &signing_reference.locator,
                "canonical target changed since this reference was bound",
            ));
        }

        let signer = ActiveSigner {
            persona: recognized.persona,
            key: recognized.key,
            signing_reference,
        };
        transaction.commit()?;
        Ok(signer)
    }

    /// Record the immutable root for a new, routine-only local continuity
    /// journal. The independently supplied digest must match the verified root.
    /// Repeating the exact root is idempotent; replacement is never implicit.
    pub fn record_continuity_root(
        &mut self,
        persona_id: &str,
        proof: &PersonaRootProof,
        expected_root_statement_sha256: &str,
    ) -> Result<RecordedPersonaRoot> {
        let verified = verify_persona_root_proof(proof).map_err(invalid_continuity)?;
        if verified.root_statement_sha256 != expected_root_statement_sha256 {
            return Err(StoreError::InvalidContinuity(
                "verified root digest does not match the independently supplied digest".to_owned(),
            ));
        }
        let proof_json = serialize_continuity_proof(proof)?;
        let recorded_at = now_unix_seconds()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_active_persona(&transaction, persona_id)?;
        validate_persona_authorization_state_in(&transaction, persona_id)?;

        if let Some(existing) = recorded_persona_root_in(&transaction, persona_id)? {
            if existing.proof == *proof
                && existing.root_statement_sha256 == verified.root_statement_sha256
            {
                transaction.commit()?;
                return Ok(existing);
            }
            return Err(StoreError::ContinuityConflict(format!(
                "persona {persona_id} already has a different immutable root"
            )));
        }

        require_monotonic_audit_time(&transaction, persona_id, recorded_at)?;

        let persona = persona_in(&transaction, persona_id)?;
        if verified.statement.persona != persona.label {
            return Err(StoreError::InvalidContinuity(
                "root persona label does not match the local persona".to_owned(),
            ));
        }
        let active_keys = active_key_fingerprints(&transaction, persona_id)?;
        let initial_key_fingerprint = match active_keys.as_slice() {
            [] => return Err(StoreError::NoActiveKey(persona_id.to_owned())),
            [initial_key_fingerprint] => initial_key_fingerprint,
            _ => return Err(StoreError::AmbiguousActiveKeys(persona_id.to_owned())),
        };
        if initial_key_fingerprint != &verified.statement.initial_key_fingerprint {
            return Err(StoreError::InvalidContinuity(
                "root initial key is not the persona's unique active key".to_owned(),
            ));
        }
        transaction.execute(
            "INSERT INTO persona_continuity_roots
             (persona_id, root_statement_sha256, persona_anchor,
              initial_key_fingerprint, root_proof_json, issued_at, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                persona_id,
                verified.root_statement_sha256,
                verified.statement.persona_anchor,
                verified.statement.initial_key_fingerprint,
                proof_json,
                verified.statement.issued_at,
                recorded_at
            ],
        )?;
        transaction.execute(
            "INSERT INTO persona_continuity_heads
             (persona_id, revision, transition_sequence, current_key_fingerprint,
              last_transition_sha256, last_issued_at)
             VALUES (?1, 0, 0, ?2, NULL, ?3)",
            params![
                persona_id,
                verified.statement.initial_key_fingerprint,
                verified.statement.issued_at
            ],
        )?;
        let recorded = RecordedPersonaRoot {
            persona_id: persona_id.to_owned(),
            root_statement_sha256: verified.root_statement_sha256,
            persona_anchor: verified.statement.persona_anchor,
            initial_key_fingerprint: verified.statement.initial_key_fingerprint,
            proof: proof.clone(),
            issued_at: verified.statement.issued_at,
            recorded_at,
        };
        transaction.commit()?;
        Ok(recorded)
    }

    pub fn recorded_continuity_root(
        &self,
        persona_id: &str,
    ) -> Result<Option<RecordedPersonaRoot>> {
        recorded_persona_root_in(&self.connection, persona_id)
    }

    pub fn continuity_head(&self, persona_id: &str) -> Result<Option<ContinuityHead>> {
        continuity_head_in(&self.connection, persona_id)
    }

    /// Read and reverify the root, every stored proof, and the resulting head.
    pub fn routine_continuity_snapshot(
        &self,
        persona_id: &str,
    ) -> Result<RoutineContinuitySnapshot> {
        let transaction = self.connection.unchecked_transaction()?;
        let snapshot = routine_continuity_snapshot_in(&transaction, persona_id)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Validate a candidate signing reference without granting it signing
    /// authority or writing the candidate key to the store.
    pub fn validate_routine_rotation_candidate(
        &self,
        persona_id: &str,
        next_public_key: &str,
        provider: KeyProvider,
        locator: impl AsRef<Path>,
    ) -> Result<RoutineRotationCandidate> {
        let snapshot = self.routine_continuity_snapshot(persona_id)?;
        let sequence = next_routine_transition_sequence(&snapshot.head)?;
        let next_public_key = next_public_key.trim().to_owned();
        validate_provider_key(&next_public_key, provider)?;
        let next_key_fingerprint = fingerprint(&next_public_key)?;
        require_unknown_key(&self.connection, &next_key_fingerprint)?;
        let current = lookup_key_in(&self.connection, &snapshot.head.current_key_fingerprint)?
            .ok_or_else(|| {
                StoreError::KeyNotFound(snapshot.head.current_key_fingerprint.clone())
            })?;
        if current.key.status != KeyStatus::Active {
            return Err(StoreError::InactiveSigningKey(
                snapshot.head.current_key_fingerprint,
            ));
        }
        let issued_at = now_unix_seconds()?;
        if issued_at < snapshot.head.last_issued_at {
            return Err(StoreError::InvalidContinuity(
                "system clock precedes the accepted continuity head".to_owned(),
            ));
        }
        let root = verify_persona_root_proof(&snapshot.root.proof).map_err(invalid_continuity)?;
        let statement = new_routine_transition_statement(
            &root,
            sequence,
            snapshot.head.last_transition_sha256.as_deref(),
            &current.key.public_key,
            &next_public_key,
            issued_at,
        )
        .map_err(invalid_continuity)?;
        let candidate_key = candidate_key_record(
            persona_id,
            &next_key_fingerprint,
            &next_public_key,
            provider,
            issued_at,
        );
        let canonical_locator = validate_signing_reference_path(locator.as_ref(), &candidate_key)?;
        Ok(RoutineRotationCandidate {
            intent: routine_transition_intent(persona_id, &statement),
            statement,
            public_key: next_public_key,
            provider,
            signing_reference: SigningReference {
                key_fingerprint: next_key_fingerprint,
                locator: canonical_locator,
                configured_at: issued_at,
            },
        })
    }

    /// Return a committed proof only when every transition-intent field is an
    /// exact match. A row at the same sequence with different intent is a fork,
    /// not an idempotent retry.
    pub fn lookup_committed_routine_transition(
        &self,
        intent: &RoutineTransitionIntent,
    ) -> Result<Option<CommittedRoutineTransition>> {
        lookup_committed_routine_transition_in(&self.connection, intent)
    }

    /// Return non-secret head metadata only for an exact transition that is
    /// already committed as the current, fully reverified journal head.
    ///
    /// The signing locator is database metadata for retry matching. This read
    /// deliberately does not touch its target and makes no claim that a signer
    /// still exists or can be used. It therefore remains usable when a daemon
    /// must return the public committed proof after the candidate key file has
    /// disappeared.
    pub fn committed_routine_transition_retry_metadata(
        &self,
        intent: &RoutineTransitionIntent,
    ) -> Result<Option<RoutineContinuityRetryMetadata>> {
        let transaction = self.connection.unchecked_transaction()?;
        let Some(committed) = lookup_committed_routine_transition_in(&transaction, intent)? else {
            transaction.commit()?;
            return Ok(None);
        };
        require_active_persona(&transaction, &intent.persona_id)?;
        let snapshot = current_snapshot_for_committed_transition(&transaction, intent, &committed)?;
        let current = lookup_key_in(&transaction, &snapshot.head.current_key_fingerprint)?
            .ok_or_else(|| {
                StoreError::KeyNotFound(snapshot.head.current_key_fingerprint.clone())
            })?;
        if current.persona.id != intent.persona_id
            || current.key.persona_id != intent.persona_id
            || current.key.status != KeyStatus::Active
            || current.key.fingerprint != snapshot.head.current_key_fingerprint
        {
            return Err(StoreError::InvalidContinuity(
                "continuity retry key is not the active head key for this persona".to_owned(),
            ));
        }
        let signing_reference =
            lookup_signing_reference_in(&transaction, &current.key.fingerprint)?.ok_or_else(
                || StoreError::SigningReferenceNotFound(current.key.fingerprint.clone()),
            )?;
        if signing_reference.key_fingerprint != current.key.fingerprint {
            return Err(StoreError::InvalidContinuity(
                "continuity retry signing reference is bound to a different key".to_owned(),
            ));
        }
        let metadata = RoutineContinuityRetryMetadata {
            persona_id: intent.persona_id.clone(),
            current_key_fingerprint: current.key.fingerprint,
            provider: current.key.provider,
            signing_locator: signing_reference.locator,
        };
        transaction.commit()?;
        Ok(Some(metadata))
    }

    /// Atomically accept one already-authorized dual-signed routine proof,
    /// retire the previous key, activate and bind the candidate, append audit
    /// history, and advance the compare-and-swap head.
    pub fn commit_routine_transition(
        &mut self,
        persona_id: &str,
        proof: &PersonaTransitionProof,
        next_provider: KeyProvider,
        next_signing_locator: impl AsRef<Path>,
    ) -> Result<CommittedRoutineTransition> {
        self.commit_routine_transition_inner(
            persona_id,
            proof,
            next_provider,
            next_signing_locator,
            || Ok(()),
        )
    }

    fn commit_routine_transition_inner(
        &mut self,
        persona_id: &str,
        proof: &PersonaTransitionProof,
        next_provider: KeyProvider,
        next_signing_locator: impl AsRef<Path>,
        after_previous_key_retired: impl FnOnce() -> Result<()>,
    ) -> Result<CommittedRoutineTransition> {
        let verified = verify_persona_transition_proof(proof).map_err(invalid_continuity)?;
        let intent = routine_transition_intent(persona_id, &verified.statement);
        let proof_json = serialize_continuity_proof(proof)?;

        let retry_transaction = self.connection.unchecked_transaction()?;
        if let Some(committed) =
            lookup_committed_routine_transition_in(&retry_transaction, &intent)?
        {
            if committed.proof == *proof {
                current_snapshot_for_committed_transition(&retry_transaction, &intent, &committed)?;
                retry_transaction.commit()?;
                return Ok(committed);
            }
            return Err(StoreError::ContinuityConflict(
                "retry proof differs from the exact committed proof".to_owned(),
            ));
        }
        retry_transaction.commit()?;

        validate_provider_key(&verified.next_public_key, next_provider)?;
        let now = now_unix_seconds()?;
        let candidate_key = candidate_key_record(
            persona_id,
            &verified.statement.next_key_fingerprint,
            &verified.next_public_key,
            next_provider,
            now,
        );
        let candidate_locator =
            validate_signing_reference_path(next_signing_locator.as_ref(), &candidate_key)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(committed) = lookup_committed_routine_transition_in(&transaction, &intent)? {
            if committed.proof == *proof {
                current_snapshot_for_committed_transition(&transaction, &intent, &committed)?;
                transaction.commit()?;
                return Ok(committed);
            }
            return Err(StoreError::ContinuityConflict(
                "retry proof differs from the exact committed proof".to_owned(),
            ));
        }

        require_active_persona(&transaction, persona_id)?;
        require_unknown_key(&transaction, &verified.statement.next_key_fingerprint)?;
        let snapshot = routine_continuity_snapshot_in(&transaction, persona_id)?;
        require_intent_at_head(&intent, &snapshot)?;
        require_monotonic_audit_time(&transaction, persona_id, now)?;
        let mut resulting_chain = snapshot.transitions.clone();
        resulting_chain.push(proof.clone());
        let report = verify_persona_continuity_chain(
            &snapshot.root.proof,
            &resulting_chain,
            &snapshot.root.root_statement_sha256,
        )
        .map_err(invalid_continuity)?;
        if report.transition_count != intent.sequence
            || report.chain_tip_key_fingerprint != intent.next_key_fingerprint
            || report.last_transition_sha256.as_deref()
                != Some(verified.transition_statement_sha256.as_str())
        {
            return Err(StoreError::InvalidContinuity(
                "verified resulting chain does not equal the proposed new head".to_owned(),
            ));
        }
        let candidate_locator =
            validate_signing_reference_path(&candidate_locator, &candidate_key)?;
        let candidate_locator_text = candidate_locator
            .to_str()
            .expect("validated signing references are UTF-8");

        let retired = transaction.execute(
            "UPDATE key_records
             SET status = 'retired', retired_at = ?1
             WHERE fingerprint = ?2 AND persona_id = ?3 AND status = 'active'",
            params![now, intent.previous_key_fingerprint, persona_id],
        )?;
        if retired != 1 {
            return Err(StoreError::ContinuityConflict(
                "accepted head no longer has exactly one active previous key".to_owned(),
            ));
        }
        append_event(
            &transaction,
            persona_id,
            &intent.previous_key_fingerprint,
            "retired",
            now,
            "local-user",
            rotation_policy(RotationReason::Routine),
            None,
        )?;
        after_previous_key_retired()?;
        insert_key(
            &transaction,
            persona_id,
            &intent.next_key_fingerprint,
            &verified.next_public_key,
            next_provider,
            now,
        )?;
        append_event(
            &transaction,
            persona_id,
            &intent.next_key_fingerprint,
            "rotated_in",
            now,
            "local-user",
            rotation_policy(RotationReason::Routine),
            None,
        )?;
        transaction.execute(
            "INSERT INTO signing_references
             (key_fingerprint, locator, configured_at) VALUES (?1, ?2, ?3)",
            params![intent.next_key_fingerprint, candidate_locator_text, now],
        )?;
        append_signing_reference_event(&transaction, &intent.next_key_fingerprint, "bound", now)?;
        transaction.execute(
            "INSERT INTO persona_continuity_transitions
             (persona_id, sequence, transition_statement_sha256,
              root_statement_sha256, previous_transition_sha256,
              previous_key_fingerprint, next_key_fingerprint, issued_at,
              proof_json, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                persona_id,
                i64::from(intent.sequence),
                verified.transition_statement_sha256,
                intent.root_statement_sha256,
                intent.previous_transition_sha256,
                intent.previous_key_fingerprint,
                intent.next_key_fingerprint,
                intent.issued_at,
                proof_json,
                now
            ],
        )?;
        let updated = transaction.execute(
            "UPDATE persona_continuity_heads
             SET revision = revision + 1,
                 transition_sequence = ?1,
                 current_key_fingerprint = ?2,
                 last_transition_sha256 = ?3,
                 last_issued_at = ?4
             WHERE persona_id = ?5 AND revision = ?6
               AND transition_sequence = ?7
               AND current_key_fingerprint = ?8
               AND last_transition_sha256 IS ?9",
            params![
                i64::from(intent.sequence),
                intent.next_key_fingerprint,
                verified.transition_statement_sha256,
                intent.issued_at,
                persona_id,
                snapshot.head.revision,
                i64::from(snapshot.head.transition_sequence),
                intent.previous_key_fingerprint,
                intent.previous_transition_sha256
            ],
        )?;
        if updated != 1 {
            return Err(StoreError::ContinuityConflict(
                "continuity head changed before commit".to_owned(),
            ));
        }
        transaction.commit()?;

        Ok(CommittedRoutineTransition {
            intent,
            transition_statement_sha256: verified.transition_statement_sha256,
            proof: proof.clone(),
            committed_at: now,
            replayed: false,
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

type RawKeyEventRow = (
    i64,
    String,
    String,
    String,
    i64,
    String,
    String,
    Option<String>,
    i64,
);

fn list_keys_in(connection: &Connection, persona_id: &str) -> Result<Vec<KeyRecord>> {
    require_stored_key_count(connection, persona_id, false)?;
    let mut statement = connection.prepare(
        "SELECT fingerprint, persona_id, public_key, provider, status,
                added_at, retired_at, compromised_at
         FROM key_records WHERE persona_id = ?1 ORDER BY added_at, fingerprint",
    )?;
    let rows = statement.query_map([persona_id], raw_key_row)?;
    rows.map(|row| key_from_row(row?)).collect()
}

fn key_history_in(connection: &Connection, persona_id: &str) -> Result<Vec<KeyEvent>> {
    require_stored_event_count(connection, persona_id, false)?;
    let mut statement = connection.prepare(
        "SELECT sequence, persona_id, key_fingerprint, event_type,
                occurred_at, actor, policy, note,
                EXISTS(
                    SELECT 1 FROM key_records
                    WHERE key_records.fingerprint = key_events.key_fingerprint
                      AND key_records.persona_id = key_events.persona_id
                )
         FROM key_events WHERE persona_id = ?1 ORDER BY sequence",
    )?;
    let rows = statement.query_map([persona_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, i64>(8)?,
        ))
    })?;
    let events = rows
        .map(|row| key_event_from_row(row?))
        .collect::<Result<Vec<_>>>()?;
    drop(statement);
    validate_stored_key_history(connection, persona_id, &events)?;
    Ok(events)
}

fn stored_persona_key_count(connection: &Connection, persona_id: &str) -> Result<usize> {
    let count = connection.query_row(
        "SELECT count(*) FROM key_records WHERE persona_id = ?1",
        [persona_id],
        |row| row.get::<_, i64>(0),
    )?;
    usize::try_from(count).map_err(|_| StoreError::StoredPersonaKeyLimit {
        limit: MAX_STORED_PERSONA_KEYS,
    })
}

fn stored_persona_event_count(connection: &Connection, persona_id: &str) -> Result<usize> {
    let count = connection.query_row(
        "SELECT count(*) FROM key_events WHERE persona_id = ?1",
        [persona_id],
        |row| row.get::<_, i64>(0),
    )?;
    usize::try_from(count).map_err(|_| StoreError::StoredPersonaEventLimit {
        limit: MAX_STORED_PERSONA_EVENTS,
    })
}

fn require_stored_key_count(
    connection: &Connection,
    persona_id: &str,
    reserving_one: bool,
) -> Result<usize> {
    let count = stored_persona_key_count(connection, persona_id)?;
    let allowed = if reserving_one {
        count < MAX_STORED_PERSONA_KEYS
    } else {
        count <= MAX_STORED_PERSONA_KEYS
    };
    if !allowed {
        return Err(StoreError::StoredPersonaKeyLimit {
            limit: MAX_STORED_PERSONA_KEYS,
        });
    }
    Ok(count)
}

fn require_stored_event_count(
    connection: &Connection,
    persona_id: &str,
    reserving_one: bool,
) -> Result<usize> {
    let count = stored_persona_event_count(connection, persona_id)?;
    let allowed = if reserving_one {
        count < MAX_STORED_PERSONA_EVENTS
    } else {
        count <= MAX_STORED_PERSONA_EVENTS
    };
    if !allowed {
        return Err(StoreError::StoredPersonaEventLimit {
            limit: MAX_STORED_PERSONA_EVENTS,
        });
    }
    Ok(count)
}

fn require_monotonic_audit_time(
    connection: &Connection,
    persona_id: &str,
    observed: i64,
) -> Result<()> {
    let latest = connection
        .query_row(
            "SELECT max(value) FROM (
                 SELECT created_at AS value FROM personas WHERE id = ?1
                 UNION ALL SELECT archived_at FROM personas
                     WHERE id = ?1 AND archived_at IS NOT NULL
                 UNION ALL SELECT added_at FROM key_records WHERE persona_id = ?1
                 UNION ALL SELECT retired_at FROM key_records
                     WHERE persona_id = ?1 AND retired_at IS NOT NULL
                 UNION ALL SELECT compromised_at FROM key_records
                     WHERE persona_id = ?1 AND compromised_at IS NOT NULL
                 UNION ALL SELECT occurred_at FROM key_events WHERE persona_id = ?1
                 UNION ALL SELECT recorded_at FROM persona_continuity_roots WHERE persona_id = ?1
                 UNION ALL SELECT committed_at FROM persona_continuity_transitions
                     WHERE persona_id = ?1
             )",
            [persona_id],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .ok_or_else(|| StoreError::PersonaNotFound(persona_id.to_owned()))?;
    if observed < latest {
        return Err(StoreError::NonMonotonicAuditTime {
            observed,
            minimum: latest,
        });
    }
    Ok(())
}

fn validate_stored_key_history(
    connection: &Connection,
    persona_id: &str,
    events: &[KeyEvent],
) -> Result<()> {
    let persona = persona_in(connection, persona_id)?;
    let keys = list_keys_in(connection, persona_id)?;
    let exported_at = std::iter::once(persona.created_at)
        .chain(persona.archived_at)
        .chain(keys.iter().flat_map(|key| {
            std::iter::once(key.added_at)
                .chain(key.retired_at)
                .chain(key.compromised_at)
        }))
        .chain(events.iter().map(|event| event.occurred_at))
        .max()
        .expect("persona creation time always supplies one timestamp");
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
            .iter()
            .enumerate()
            .map(|(index, event)| BackupKeyEvent {
                ordinal: u32::try_from(index + 1)
                    .expect("stored event bound fits in a u32 ordinal"),
                key_fingerprint: event.key_fingerprint.clone(),
                event_type: event.event_type.clone(),
                occurred_at: event.occurred_at,
                actor: event.actor.clone(),
                policy: event.policy.clone(),
                note: event.note.clone(),
            })
            .collect(),
    };
    validate_persona_history(&backup, HistoryValidationScope::LiveStore)
        .map_err(|_| StoreError::InvalidAuditHistory)
}

fn key_event_from_row(row: RawKeyEventRow) -> Result<KeyEvent> {
    if row.8 != 1 {
        return Err(StoreError::CrossPersonaKeyEvent);
    }
    let actor = validate_canonical_text("stored key event actor", &row.5, MAX_ACTOR_BYTES)?;
    let policy = validate_canonical_text("stored key event policy", &row.6, MAX_POLICY_BYTES)?;
    let note = row
        .7
        .as_deref()
        .map(|note| validate_canonical_text("stored key event note", note, MAX_NOTE_BYTES))
        .transpose()?;
    Ok(KeyEvent {
        sequence: row.0,
        persona_id: row.1,
        key_fingerprint: row.2,
        event_type: row.3,
        occurred_at: row.4,
        actor,
        policy,
        note,
    })
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

fn migrate_v3(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE persona_continuity_roots (
             persona_id TEXT PRIMARY KEY NOT NULL REFERENCES personas(id),
             root_statement_sha256 TEXT NOT NULL UNIQUE CHECK(
                 length(root_statement_sha256) = 64 AND
                 root_statement_sha256 NOT GLOB '*[^0-9a-f]*'
             ),
             persona_anchor TEXT NOT NULL UNIQUE CHECK(length(persona_anchor) = 43),
             initial_key_fingerprint TEXT NOT NULL REFERENCES key_records(fingerprint),
             root_proof_json BLOB NOT NULL
                 CHECK(length(root_proof_json) BETWEEN 1 AND 1048576),
             issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
             recorded_at INTEGER NOT NULL CHECK(recorded_at >= 0)
         ) STRICT;

         CREATE TRIGGER persona_continuity_roots_no_update
         BEFORE UPDATE ON persona_continuity_roots BEGIN
             SELECT RAISE(ABORT, 'persona continuity roots are immutable');
         END;

         CREATE TRIGGER persona_continuity_roots_no_delete
         BEFORE DELETE ON persona_continuity_roots BEGIN
             SELECT RAISE(ABORT, 'persona continuity roots are immutable');
         END;

         CREATE TABLE persona_continuity_heads (
             persona_id TEXT PRIMARY KEY NOT NULL
                 REFERENCES persona_continuity_roots(persona_id),
             revision INTEGER NOT NULL CHECK(revision >= 0),
             transition_sequence INTEGER NOT NULL
                 CHECK(transition_sequence BETWEEN 0 AND 4096),
             current_key_fingerprint TEXT NOT NULL REFERENCES key_records(fingerprint),
             last_transition_sha256 TEXT CHECK(
                 last_transition_sha256 IS NULL OR
                 (length(last_transition_sha256) = 64 AND
                  last_transition_sha256 NOT GLOB '*[^0-9a-f]*')
             ),
             last_issued_at INTEGER NOT NULL CHECK(last_issued_at >= 0),
             CHECK(
                 (transition_sequence = 0 AND last_transition_sha256 IS NULL) OR
                 (transition_sequence > 0 AND last_transition_sha256 IS NOT NULL)
             )
         ) STRICT;

         CREATE TRIGGER persona_continuity_heads_no_delete
         BEFORE DELETE ON persona_continuity_heads BEGIN
             SELECT RAISE(ABORT, 'persona continuity heads cannot be deleted');
         END;

         CREATE TABLE persona_continuity_transitions (
             persona_id TEXT NOT NULL REFERENCES persona_continuity_roots(persona_id),
             sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 4096),
             transition_statement_sha256 TEXT NOT NULL UNIQUE CHECK(
                 length(transition_statement_sha256) = 64 AND
                 transition_statement_sha256 NOT GLOB '*[^0-9a-f]*'
             ),
             root_statement_sha256 TEXT NOT NULL CHECK(
                 length(root_statement_sha256) = 64 AND
                 root_statement_sha256 NOT GLOB '*[^0-9a-f]*'
             ),
             previous_transition_sha256 TEXT CHECK(
                 previous_transition_sha256 IS NULL OR
                 (length(previous_transition_sha256) = 64 AND
                  previous_transition_sha256 NOT GLOB '*[^0-9a-f]*')
             ),
             previous_key_fingerprint TEXT NOT NULL REFERENCES key_records(fingerprint),
             next_key_fingerprint TEXT NOT NULL REFERENCES key_records(fingerprint),
             issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
             proof_json BLOB NOT NULL CHECK(length(proof_json) BETWEEN 1 AND 1048576),
             committed_at INTEGER NOT NULL CHECK(committed_at >= 0),
             PRIMARY KEY(persona_id, sequence)
         ) STRICT;

         CREATE INDEX persona_continuity_transitions_persona_idx
             ON persona_continuity_transitions(persona_id, sequence);

         CREATE TRIGGER persona_continuity_transitions_no_update
         BEFORE UPDATE ON persona_continuity_transitions BEGIN
             SELECT RAISE(ABORT, 'persona continuity transitions are append-only');
         END;

         CREATE TRIGGER persona_continuity_transitions_no_delete
         BEFORE DELETE ON persona_continuity_transitions BEGIN
             SELECT RAISE(ABORT, 'persona continuity transitions are append-only');
         END;

         PRAGMA user_version = 3;",
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v4(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction()?;
    let has_cross_persona_event: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM key_events
             WHERE NOT EXISTS (
                 SELECT 1 FROM key_records
                 WHERE key_records.fingerprint = key_events.key_fingerprint
                   AND key_records.persona_id = key_events.persona_id
             )
         )",
        [],
        |row| row.get(0),
    )?;
    if has_cross_persona_event {
        return Err(StoreError::CrossPersonaKeyEvent);
    }
    let persona_ids = {
        let mut statement = transaction.prepare("SELECT id FROM personas ORDER BY id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for persona_id in persona_ids {
        key_history_in(&transaction, &persona_id)?;
    }
    transaction.execute_batch(
        "CREATE UNIQUE INDEX key_events_one_origin_per_key
             ON key_events(key_fingerprint)
             WHERE event_type IN ('enrolled', 'rotated_in');

         CREATE UNIQUE INDEX key_events_one_retirement_per_key
             ON key_events(key_fingerprint)
             WHERE event_type = 'retired';

         CREATE UNIQUE INDEX key_events_one_compromise_per_key
             ON key_events(key_fingerprint)
             WHERE event_type = 'compromised';

         CREATE TRIGGER key_events_same_persona_insert
         BEFORE INSERT ON key_events
         WHEN NOT EXISTS (
             SELECT 1 FROM key_records
             WHERE key_records.fingerprint = NEW.key_fingerprint
               AND key_records.persona_id = NEW.persona_id
         ) BEGIN
             SELECT RAISE(ABORT, 'key lifecycle event key must belong to its persona');
         END;

         PRAGMA user_version = 4;",
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
    require_stored_key_count(transaction, persona_id, true)?;
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
    require_stored_event_count(transaction, persona_id, true)?;
    let key_belongs_to_persona: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM key_records
             WHERE fingerprint = ?1 AND persona_id = ?2
         )",
        params![fingerprint, persona_id],
        |row| row.get(0),
    )?;
    if !key_belongs_to_persona {
        return Err(StoreError::CrossPersonaKeyEvent);
    }
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

fn active_key_fingerprints(connection: &Connection, persona_id: &str) -> Result<Vec<String>> {
    let mut statement = connection.prepare(
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
            persona: persona_from_row((id, label, purpose, created_at, archived_at))?,
            key: key_from_row(key)?,
        })
    })
    .transpose()
}

fn validated_lookup_key_in(
    connection: &Connection,
    fingerprint: &str,
) -> Result<Option<RecognizedKey>> {
    let recognized = lookup_key_in(connection, fingerprint)?;
    if let Some(recognized) = &recognized {
        validate_persona_authorization_state_in(connection, &recognized.persona.id)?;
    }
    Ok(recognized)
}

fn lookup_signing_reference_in(
    connection: &Connection,
    fingerprint: &str,
) -> Result<Option<SigningReference>> {
    connection
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
        label: validate_canonical_text("stored persona label", &row.1, MAX_LABEL_BYTES)?,
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
    validate_persona_history(backup, HistoryValidationScope::PortableBackup)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HistoryValidationScope {
    LiveStore,
    PortableBackup,
}

fn validate_persona_history(backup: &PersonaBackup, scope: HistoryValidationScope) -> Result<()> {
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
    if scope == HistoryValidationScope::PortableBackup {
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
    if contains_unsafe_display_characters(&key.public_key) {
        return Err(invalid_backup(format!(
            "public key {} contains a control, line/paragraph separator, or default-ignorable Unicode character",
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
    validate_canonical_text(field, value, maximum).map(drop)
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

fn invalid_backup(reason: impl AsRef<str>) -> StoreError {
    StoreError::InvalidField {
        field: "persona backup",
        reason: escape_untrusted_text_for_terminal(reason.as_ref()),
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
    if contains_unsafe_display_characters(text) {
        return Err(unsafe_signing_reference(
            path,
            "control, line/paragraph separator, or default-ignorable Unicode characters are not allowed",
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
        display_path: escape_untrusted_bytes_for_terminal(path.as_os_str().as_encoded_bytes()),
        reason: reason.to_owned(),
    }
}

fn validate_canonical_text(field: &'static str, value: &str, maximum: usize) -> Result<String> {
    let canonical = validate_required_text(field, value, maximum)?;
    if canonical != value {
        Err(StoreError::InvalidField {
            field,
            reason: "surrounding whitespace is not canonical".to_owned(),
        })
    } else {
        Ok(canonical)
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
    if contains_unsafe_display_characters(value) {
        return Err(StoreError::InvalidField {
            field,
            reason: "control, line/paragraph separator, or default-ignorable Unicode characters are not allowed".to_owned(),
        });
    }
    Ok(value.to_owned())
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
    use std::process::Command;

    use super::*;
    use a_quo_core::{
        create_persona_root_proof, create_routine_transition_proof, new_persona_root_statement,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    const KEY_ONE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";
    const KEY_TWO: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfX7hAdqGfF0mYz2oD88dL84M2yr2KoXqhh7sSRvqHQ";
    const ABORT_TEST_DATABASE: &str = "A_QUO_TEST_ABORT_CONTINUITY_DATABASE";
    const ABORT_TEST_PERSONA: &str = "A_QUO_TEST_ABORT_CONTINUITY_PERSONA";
    const ABORT_TEST_PROOF: &str = "A_QUO_TEST_ABORT_CONTINUITY_PROOF";
    const ABORT_TEST_LOCATOR: &str = "A_QUO_TEST_ABORT_CONTINUITY_LOCATOR";

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

    fn generate_key(directory: &Path, name: &str) -> (PathBuf, String) {
        let path = directory.join(name);
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&path)
            .status()
            .expect("OpenSSH ssh-keygen must be installed for continuity tests");
        assert!(status.success());
        let public_key = fs::read_to_string(path.with_extension("pub"))
            .unwrap()
            .trim()
            .to_owned();
        (path, public_key)
    }

    fn synthetic_ed25519_public_key(index: u32) -> String {
        let algorithm = b"ssh-ed25519";
        let mut blob = Vec::with_capacity(4 + algorithm.len() + 4 + 32);
        blob.extend_from_slice(&u32::try_from(algorithm.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(algorithm);
        blob.extend_from_slice(&32_u32.to_be_bytes());
        let mut key_bytes = [0_u8; 32];
        key_bytes[..4].copy_from_slice(&index.to_be_bytes());
        key_bytes[4..8].copy_from_slice(&index.wrapping_mul(0x9e37_79b9).to_be_bytes());
        blob.extend_from_slice(&key_bytes);
        format!("ssh-ed25519 {}", STANDARD.encode(blob))
    }

    struct RoutineTransitionFixture {
        persona: Persona,
        previous_key: KeyRecord,
        next_path: PathBuf,
        candidate: RoutineRotationCandidate,
        proof: PersonaTransitionProof,
    }

    fn prepare_routine_transition(
        store: &mut PersonaStore,
        directory: &Path,
    ) -> RoutineTransitionFixture {
        let (previous_path, previous_public_key) = generate_key(directory, "previous-key");
        let (next_path, next_public_key) = generate_key(directory, "candidate-key");
        let persona = store
            .create_persona("Transactional publisher", PersonaPurpose::Project)
            .unwrap();
        let previous_key = store
            .enroll_key(&persona.id, &previous_public_key, KeyProvider::OpensshFile)
            .unwrap();
        store
            .bind_signing_reference(&previous_key.fingerprint, &previous_path)
            .unwrap();
        let root_statement =
            new_persona_root_statement(&persona.label, 100, &previous_public_key).unwrap();
        let root_proof =
            create_persona_root_proof(root_statement, &previous_path, &previous_public_key)
                .unwrap();
        let root = verify_persona_root_proof(&root_proof).unwrap();
        store
            .record_continuity_root(&persona.id, &root_proof, &root.root_statement_sha256)
            .unwrap();
        let candidate = store
            .validate_routine_rotation_candidate(
                &persona.id,
                &next_public_key,
                KeyProvider::OpensshFile,
                &next_path,
            )
            .unwrap();
        let proof = create_routine_transition_proof(
            candidate.statement.clone(),
            &previous_path,
            &previous_public_key,
            &next_path,
            &next_public_key,
        )
        .unwrap();
        RoutineTransitionFixture {
            persona,
            previous_key,
            next_path,
            candidate,
            proof,
        }
    }

    fn commit_second_routine_transition(
        store: &mut PersonaStore,
        directory: &Path,
        first: &RoutineTransitionFixture,
    ) -> PersonaTransitionProof {
        store
            .commit_routine_transition(
                &first.persona.id,
                &first.proof,
                KeyProvider::OpensshFile,
                &first.next_path,
            )
            .unwrap();
        let previous = store
            .lookup_key(&first.candidate.intent.next_key_fingerprint)
            .unwrap()
            .unwrap()
            .key;
        let (next_path, next_public_key) = generate_key(directory, "third-key");
        let candidate = store
            .validate_routine_rotation_candidate(
                &first.persona.id,
                &next_public_key,
                KeyProvider::OpensshFile,
                &next_path,
            )
            .unwrap();
        let proof = create_routine_transition_proof(
            candidate.statement,
            &first.next_path,
            &previous.public_key,
            &next_path,
            &next_public_key,
        )
        .unwrap();
        store
            .commit_routine_transition(
                &first.persona.id,
                &proof,
                KeyProvider::OpensshFile,
                &next_path,
            )
            .unwrap();
        proof
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

    fn rotated_history_store() -> (PersonaStore, Persona, KeyRecord, KeyRecord) {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Audit history", PersonaPurpose::Project)
            .unwrap();
        let first = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
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
        (store, persona, first, second)
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
    fn backup_history_rejects_bounded_omission_duplicate_reorder_and_substitution_matrix() {
        fn renumber(backup: &mut PersonaBackup) {
            for (index, event) in backup.events.iter_mut().enumerate() {
                event.ordinal = u32::try_from(index + 1).unwrap();
            }
        }

        let (mut store, persona, _, _) = rotated_history_store();
        let backup = store.export_persona_backup(&persona.id).unwrap();
        assert_eq!(backup.events.len(), 3);

        for omitted in 0..backup.events.len() {
            let mut candidate = backup.clone();
            candidate.events.remove(omitted);
            renumber(&mut candidate);
            assert!(validate_persona_backup(&candidate).is_err());
        }

        for duplicated in 0..backup.events.len() {
            for insertion in 0..=backup.events.len() {
                let mut candidate = backup.clone();
                candidate
                    .events
                    .insert(insertion, backup.events[duplicated].clone());
                renumber(&mut candidate);
                assert!(validate_persona_backup(&candidate).is_err());
            }
        }

        let mut reordered = backup.clone();
        reordered.events.swap(0, 1);
        renumber(&mut reordered);
        assert!(validate_persona_backup(&reordered).is_err());

        let mut substituted = backup;
        substituted.events[0].key_fingerprint = substituted.keys[1].fingerprint.clone();
        assert!(validate_persona_backup(&substituted).is_err());
    }

    #[test]
    fn backup_round_trip_preserves_recovery_and_compromise_audit_details() {
        let mut source = PersonaStore::open_in_memory().unwrap();
        let persona = source
            .create_persona("Recovered project", PersonaPurpose::Project)
            .unwrap();
        source
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        let recovered = source
            .rotate_key(
                &persona.id,
                KEY_TWO,
                KeyProvider::OpensshFile,
                RotationReason::Recovery,
                Some("two custodians approved replacement hardware"),
            )
            .unwrap();
        source
            .mark_key_compromised(
                &recovered.fingerprint,
                "Project custodians",
                "example.invalid/key-compromise-v1",
                Some("device reported lost"),
            )
            .unwrap();

        let backup = source.export_persona_backup(&persona.id).unwrap();
        let mut destination = PersonaStore::open_in_memory().unwrap();
        destination.import_persona_backup(&backup).unwrap();
        let restored = destination.export_persona_backup(&persona.id).unwrap();

        assert_eq!(restored.persona, backup.persona);
        assert_eq!(restored.keys, backup.keys);
        assert_eq!(restored.events, backup.events);
        let compromise = restored.events.last().unwrap();
        assert_eq!(compromise.event_type, "compromised");
        assert_eq!(compromise.actor, "Project custodians");
        assert_eq!(compromise.policy, "example.invalid/key-compromise-v1");
        assert_eq!(compromise.note.as_deref(), Some("device reported lost"));
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
    fn malformed_backup_diagnostics_are_bounded_ascii() {
        fn assert_safe(error: StoreError) {
            let rendered = error.to_string();
            assert!(rendered.is_ascii(), "unsafe diagnostic: {rendered:?}");
            assert!(!contains_unsafe_display_characters(&rendered));
            assert!(rendered.len() <= a_quo_display::MAX_ESCAPED_DIAGNOSTIC_INPUT_BYTES * 4 + 64);
        }

        let mut backup = active_backup();
        backup.schema = format!("bad\n\u{2028}\u{202e}\u{200b}{}", "x".repeat(512));
        assert_safe(validate_persona_backup(&backup).unwrap_err());

        let mut backup = active_backup();
        backup.keys[0].public_key.clear();
        backup.keys[0].fingerprint = "hostile\u{1b}\n\u{202e}".to_owned();
        assert_safe(validate_persona_backup(&backup).unwrap_err());

        let mut backup = active_backup();
        backup.events[0].key_fingerprint = "unknown\u{1b}\n\u{2028}".to_owned();
        assert_safe(validate_persona_backup(&backup).unwrap_err());

        let mut backup = active_backup();
        backup.events[0].event_type = "unknown\u{1b}\n\u{200b}".to_owned();
        assert_safe(validate_persona_backup(&backup).unwrap_err());
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
    fn clock_rollback_refuses_lifecycle_mutation_without_partial_state() {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Clock-sensitive publisher", PersonaPurpose::Project)
            .unwrap();
        let first = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        let future = now_unix_seconds().unwrap() + 3_600;
        store
            .connection
            .execute_batch("DROP TRIGGER key_events_no_update;")
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE personas SET created_at = ?1 WHERE id = ?2",
                params![future, persona.id],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE key_records SET added_at = ?1 WHERE fingerprint = ?2",
                params![future, first.fingerprint],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE key_events SET occurred_at = ?1 WHERE persona_id = ?2",
                params![future, persona.id],
            )
            .unwrap();

        let error = store
            .rotate_key(
                &persona.id,
                KEY_TWO,
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                None,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            StoreError::NonMonotonicAuditTime {
                minimum,
                observed
            } if minimum == future && observed < minimum
        ));
        assert_eq!(store.list_keys(&persona.id).unwrap().len(), 1);
        assert_eq!(store.key_history(&persona.id).unwrap().len(), 1);
        assert!(
            store
                .lookup_key(&fingerprint(KEY_TWO).unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn clock_rollback_refuses_journal_commit_before_retirement() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = PersonaStore::open_in_memory().unwrap();
        let fixture = prepare_routine_transition(&mut store, directory.path());
        let future = now_unix_seconds().unwrap() + 3_600;
        store
            .connection
            .execute_batch("DROP TRIGGER key_events_no_update;")
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE personas SET created_at = ?1 WHERE id = ?2",
                params![future, fixture.persona.id],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE key_records SET added_at = ?1 WHERE persona_id = ?2",
                params![future, fixture.persona.id],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE key_events SET occurred_at = ?1 WHERE persona_id = ?2",
                params![future, fixture.persona.id],
            )
            .unwrap();

        let error = store
            .commit_routine_transition(
                &fixture.persona.id,
                &fixture.proof,
                KeyProvider::OpensshFile,
                &fixture.next_path,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            StoreError::NonMonotonicAuditTime {
                minimum,
                observed
            } if minimum == future && observed < minimum
        ));
        let snapshot = store
            .routine_continuity_snapshot(&fixture.persona.id)
            .unwrap();
        assert_eq!(snapshot.head.transition_sequence, 0);
        assert!(snapshot.transitions.is_empty());
        assert!(
            store
                .lookup_key(&fixture.candidate.intent.next_key_fingerprint)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn future_signed_times_do_not_poison_the_local_audit_clock() {
        let directory = tempfile::tempdir().unwrap();
        let (first_path, first_public) = generate_key(directory.path(), "future-root-key");
        let (next_path, next_public) = generate_key(directory.path(), "future-next-key");
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Clock-skew publisher", PersonaPurpose::Project)
            .unwrap();
        let first = store
            .enroll_key(&persona.id, &first_public, KeyProvider::OpensshFile)
            .unwrap();
        store
            .bind_signing_reference(&first.fingerprint, &first_path)
            .unwrap();
        let future_issued_at = now_unix_seconds().unwrap() + 60;
        let root_statement =
            new_persona_root_statement(&persona.label, future_issued_at, &first_public).unwrap();
        let root_proof =
            create_persona_root_proof(root_statement, &first_path, &first_public).unwrap();
        let root = verify_persona_root_proof(&root_proof).unwrap();
        store
            .record_continuity_root(&persona.id, &root_proof, &root.root_statement_sha256)
            .unwrap();
        let transition_statement = new_routine_transition_statement(
            &root,
            1,
            None,
            &first_public,
            &next_public,
            future_issued_at + 1,
        )
        .unwrap();
        let transition_proof = create_routine_transition_proof(
            transition_statement,
            &first_path,
            &first_public,
            &next_path,
            &next_public,
        )
        .unwrap();

        store
            .commit_routine_transition(
                &persona.id,
                &transition_proof,
                KeyProvider::OpensshFile,
                &next_path,
            )
            .unwrap();

        let snapshot = store.routine_continuity_snapshot(&persona.id).unwrap();
        assert_eq!(snapshot.head.transition_sequence, 1);
        assert_eq!(snapshot.head.last_issued_at, future_issued_at + 1);
    }

    #[test]
    fn audit_history_rejects_cross_persona_event_inserts_and_legacy_rows() {
        let (mut store, first, _, key) = rotated_history_store();
        let second = store
            .create_persona("Other persona", PersonaPurpose::Pseudonymous)
            .unwrap();
        let event_count = store.key_history(&second.id).unwrap().len();

        let rejected = store.connection.execute(
            "INSERT INTO key_events
             (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
             VALUES (?1, ?2, 'compromised', ?3, 'attacker', 'cross-persona')",
            params![second.id, key.fingerprint, key.added_at],
        );
        assert!(rejected.is_err());
        assert_eq!(store.key_history(&second.id).unwrap().len(), event_count);

        store
            .connection
            .execute_batch("DROP TRIGGER key_events_same_persona_insert;")
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO key_events
                 (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
                 VALUES (?1, ?2, 'compromised', ?3, 'legacy', 'legacy')",
                params![second.id, key.fingerprint, key.added_at],
            )
            .unwrap();
        assert!(matches!(
            store.key_history(&second.id),
            Err(StoreError::CrossPersonaKeyEvent)
        ));
        assert!(matches!(
            store.export_persona_backup(&second.id),
            Err(StoreError::CrossPersonaKeyEvent)
        ));
        assert_eq!(store.key_history(&first.id).unwrap().len(), 3);
    }

    #[test]
    fn audit_history_rejects_duplicate_truncated_and_reordered_rows() {
        let (duplicate_store, persona, _, key) = rotated_history_store();
        let duplicate_insert = duplicate_store.connection.execute(
            "INSERT INTO key_events
             (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
             VALUES (?1, ?2, 'rotated_in', ?3, 'attacker', 'duplicate')",
            params![persona.id, key.fingerprint, key.added_at],
        );
        assert!(duplicate_insert.is_err());
        duplicate_store
            .connection
            .execute_batch("DROP INDEX key_events_one_origin_per_key;")
            .unwrap();
        duplicate_store
            .connection
            .execute(
                "INSERT INTO key_events
                 (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
                 VALUES (?1, ?2, 'rotated_in', ?3, 'legacy', 'legacy')",
                params![persona.id, key.fingerprint, key.added_at],
            )
            .unwrap();
        assert!(matches!(
            duplicate_store.key_history(&persona.id),
            Err(StoreError::InvalidAuditHistory)
        ));

        let (truncated_store, persona, _, _) = rotated_history_store();
        truncated_store
            .connection
            .execute_batch("DROP TRIGGER key_events_no_delete;")
            .unwrap();
        truncated_store
            .connection
            .execute(
                "DELETE FROM key_events
                 WHERE sequence = (SELECT max(sequence) FROM key_events WHERE persona_id = ?1)",
                [&persona.id],
            )
            .unwrap();
        assert!(matches!(
            truncated_store.key_history(&persona.id),
            Err(StoreError::InvalidAuditHistory)
        ));

        let (reordered_store, persona, _, _) = rotated_history_store();
        let sequences = {
            let mut statement = reordered_store
                .connection
                .prepare("SELECT sequence FROM key_events WHERE persona_id = ?1 ORDER BY sequence")
                .unwrap();
            statement
                .query_map([&persona.id], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };
        reordered_store
            .connection
            .execute_batch("DROP TRIGGER key_events_no_update;")
            .unwrap();
        reordered_store
            .connection
            .execute(
                "UPDATE key_events SET sequence = -1 WHERE sequence = ?1",
                [sequences[0]],
            )
            .unwrap();
        reordered_store
            .connection
            .execute(
                "UPDATE key_events SET sequence = ?1 WHERE sequence = ?2",
                params![sequences[0], sequences[1]],
            )
            .unwrap();
        reordered_store
            .connection
            .execute(
                "UPDATE key_events SET sequence = ?1 WHERE sequence = -1",
                [sequences[1]],
            )
            .unwrap();
        assert!(matches!(
            reordered_store.key_history(&persona.id),
            Err(StoreError::InvalidAuditHistory)
        ));
    }

    #[test]
    fn lifecycle_mutations_do_not_extend_a_tampered_history() {
        let (mut store, persona, _, active) = rotated_history_store();
        store
            .connection
            .execute_batch("DROP TRIGGER key_events_no_delete;")
            .unwrap();
        store
            .connection
            .execute(
                "DELETE FROM key_events
                 WHERE sequence = (SELECT max(sequence) FROM key_events WHERE persona_id = ?1)",
                [&persona.id],
            )
            .unwrap();
        let key_count = stored_persona_key_count(&store.connection, &persona.id).unwrap();
        let event_count = stored_persona_event_count(&store.connection, &persona.id).unwrap();
        let candidate = synthetic_ed25519_public_key(42_000);

        assert!(matches!(
            store.rotate_key(
                &persona.id,
                &candidate,
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                None,
            ),
            Err(StoreError::InvalidAuditHistory)
        ));
        assert!(matches!(
            store.mark_key_compromised(
                &active.fingerprint,
                "local-user",
                "test-compromise-policy",
                None,
            ),
            Err(StoreError::InvalidAuditHistory)
        ));
        assert_eq!(
            stored_persona_key_count(&store.connection, &persona.id).unwrap(),
            key_count
        );
        assert_eq!(
            stored_persona_event_count(&store.connection, &persona.id).unwrap(),
            event_count
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
    fn legacy_unsafe_display_text_fails_closed_at_read_boundaries() {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Legacy publisher", PersonaPurpose::Project)
            .unwrap();
        let key = store
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();

        store
            .connection
            .execute(
                "UPDATE personas SET label = ?1 WHERE id = ?2",
                params!["legacy\u{200b}publisher", &persona.id],
            )
            .unwrap();
        for error in [
            store.list_personas().unwrap_err(),
            store.lookup_key(&key.fingerprint).unwrap_err(),
        ] {
            assert!(matches!(
                error,
                StoreError::InvalidField {
                    field: "stored persona label",
                    ..
                }
            ));
        }

        store
            .connection
            .execute(
                "UPDATE personas SET label = 'Legacy publisher' WHERE id = ?1",
                [&persona.id],
            )
            .unwrap();
        // Seed rows that an older validator could have written. Current stores
        // remain append-only; dropping the update trigger is test setup only.
        store
            .connection
            .execute_batch("DROP TRIGGER key_events_no_update;")
            .unwrap();
        for (column, value, expected_field) in [
            ("actor", "legacy\u{2028}actor", "stored key event actor"),
            ("policy", "legacy\u{200b}policy", "stored key event policy"),
            ("note", "legacy\u{2029}note", "stored key event note"),
        ] {
            store
                .connection
                .execute(
                    "UPDATE key_events SET actor = 'safe', policy = 'safe', note = 'safe'",
                    [],
                )
                .unwrap();
            let statement = format!("UPDATE key_events SET {column} = ?1");
            store.connection.execute(&statement, [value]).unwrap();
            assert!(matches!(
                store.key_history(&persona.id),
                Err(StoreError::InvalidField { field, .. }) if field == expected_field
            ));
        }
    }

    #[test]
    fn unsafe_signing_reference_diagnostics_escape_but_retain_the_path() {
        let path = Path::new("relative\n\u{202e}\u{200b}/key");
        let error = unsafe_signing_reference(path, "test rejection");
        let rendered = error.to_string();

        assert!(rendered.is_ascii());
        assert!(!contains_unsafe_display_characters(&rendered));
        assert!(rendered.contains("\\x0a"));
        assert!(rendered.contains("\\xe2\\x80\\xae"));
        assert!(rendered.contains("\\xe2\\x80\\x8b"));
        assert!(matches!(
            error,
            StoreError::UnsafeSigningReference {
                path: ref stored, ..
            } if stored == path
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
    fn migrates_v2_stores_to_the_bounded_continuity_journal() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate_v1(&mut connection).unwrap();
        migrate_v2(&mut connection).unwrap();
        let before: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(before, 2);

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
                     ('persona_continuity_roots', 'persona_continuity_heads',
                      'persona_continuity_transitions')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 3);
        let v4_guards: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE (type = 'trigger' AND name = 'key_events_same_persona_insert')
                    OR (type = 'index' AND name IN
                        ('key_events_one_origin_per_key',
                         'key_events_one_retirement_per_key',
                         'key_events_one_compromise_per_key'))",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v4_guards, 4);
    }

    #[test]
    fn schema_v4_refuses_legacy_cross_persona_audit_history() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate_v1(&mut connection).unwrap();
        migrate_v2(&mut connection).unwrap();
        migrate_v3(&mut connection).unwrap();
        let first_persona = Uuid::new_v4().to_string();
        let second_persona = Uuid::new_v4().to_string();
        let first_fingerprint = fingerprint(KEY_ONE).unwrap();
        let second_fingerprint = fingerprint(KEY_TWO).unwrap();
        connection
            .execute(
                "INSERT INTO personas (id, label, purpose, created_at)
                 VALUES (?1, 'First', 'project', 1), (?2, 'Second', 'project', 1)",
                params![first_persona, second_persona],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO key_records
                 (fingerprint, persona_id, public_key, provider, status, added_at)
                 VALUES (?1, ?2, ?3, 'openssh-file', 'active', 1),
                        (?4, ?5, ?6, 'openssh-file', 'active', 1)",
                params![
                    first_fingerprint,
                    first_persona,
                    KEY_ONE,
                    second_fingerprint,
                    second_persona,
                    KEY_TWO
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO key_events
                 (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
                 VALUES (?1, ?2, 'enrolled', 1, 'legacy', 'legacy')",
                params![first_persona, second_fingerprint],
            )
            .unwrap();

        assert!(matches!(
            migrate_v4(&mut connection),
            Err(StoreError::CrossPersonaKeyEvent)
        ));
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn schema_v4_accepts_populated_valid_legacy_history() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate_v1(&mut connection).unwrap();
        migrate_v2(&mut connection).unwrap();
        migrate_v3(&mut connection).unwrap();
        let persona_id = Uuid::new_v4().to_string();
        let key_fingerprint = fingerprint(KEY_ONE).unwrap();
        connection
            .execute(
                "INSERT INTO personas (id, label, purpose, created_at)
                 VALUES (?1, 'Legacy publisher', 'project', 1)",
                [&persona_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO key_records
                 (fingerprint, persona_id, public_key, provider, status, added_at)
                 VALUES (?1, ?2, ?3, 'openssh-file', 'active', 1)",
                params![key_fingerprint, persona_id, KEY_ONE],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO key_events
                 (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
                 VALUES (?1, ?2, 'enrolled', 1, 'legacy-user', 'legacy-enrollment')",
                params![persona_id, key_fingerprint],
            )
            .unwrap();

        migrate_v4(&mut connection).unwrap();

        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(key_history_in(&connection, &persona_id).unwrap().len(), 1);
    }

    #[test]
    fn schema_v4_keeps_valid_live_history_beyond_portable_backup_cap() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate_v1(&mut connection).unwrap();
        migrate_v2(&mut connection).unwrap();
        migrate_v3(&mut connection).unwrap();
        let persona_id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO personas (id, label, purpose, created_at)
                 VALUES (?1, 'Large legacy publisher', 'project', 1)",
                [&persona_id],
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        for index in 0..=u32::try_from(MAX_PERSONA_BACKUP_KEYS).unwrap() {
            let public_key = synthetic_ed25519_public_key(index);
            let key_fingerprint = fingerprint(&public_key).unwrap();
            transaction
                .execute(
                    "INSERT INTO key_records
                     (fingerprint, persona_id, public_key, provider, status, added_at)
                     VALUES (?1, ?2, ?3, 'openssh-file', 'active', 1)",
                    params![key_fingerprint, persona_id, public_key],
                )
                .unwrap();
            transaction
                .execute(
                    "INSERT INTO key_events
                     (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
                     VALUES (?1, ?2, 'enrolled', 1, 'legacy-user', 'legacy-enrollment')",
                    params![persona_id, key_fingerprint],
                )
                .unwrap();
        }
        transaction.commit().unwrap();

        migrate_v4(&mut connection).unwrap();

        let mut store = PersonaStore::initialize(connection).unwrap();
        assert_eq!(
            store.key_history(&persona_id).unwrap().len(),
            MAX_PERSONA_BACKUP_KEYS + 1
        );
        assert!(matches!(
            store.export_persona_backup(&persona_id),
            Err(StoreError::InvalidField {
                field: "persona backup",
                ..
            })
        ));
    }

    #[test]
    fn live_key_bound_accepts_protocol_maximum_and_migration_rejects_one_more() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate_v1(&mut connection).unwrap();
        migrate_v2(&mut connection).unwrap();
        migrate_v3(&mut connection).unwrap();
        let persona_id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO personas (id, label, purpose, created_at)
                 VALUES (?1, 'Oversized legacy publisher', 'project', 1)",
                [&persona_id],
            )
            .unwrap();
        connection
            .execute(
                "WITH RECURSIVE numbers(value) AS (
                     SELECT 1
                     UNION ALL
                     SELECT value + 1 FROM numbers WHERE value < ?2
                 )
                 INSERT INTO key_records
                     (fingerprint, persona_id, public_key, provider, status, added_at)
                 SELECT printf('legacy-fingerprint-%d', value), ?1,
                        printf('invalid-but-not-read-%d', value),
                        'openssh-file', 'active', 1
                 FROM numbers",
                params![persona_id, i64::try_from(MAX_STORED_PERSONA_KEYS).unwrap()],
            )
            .unwrap();

        assert_eq!(
            require_stored_key_count(&connection, &persona_id, false).unwrap(),
            MAX_STORED_PERSONA_KEYS
        );
        assert!(matches!(
            require_stored_key_count(&connection, &persona_id, true),
            Err(StoreError::StoredPersonaKeyLimit { .. })
        ));
        connection
            .execute(
                "INSERT INTO key_records
                 (fingerprint, persona_id, public_key, provider, status, added_at)
                 VALUES ('one-too-many', ?1, 'not-read', 'openssh-file', 'active', 1)",
                [&persona_id],
            )
            .unwrap();

        assert!(matches!(
            migrate_v4(&mut connection),
            Err(StoreError::StoredPersonaKeyLimit { .. })
        ));
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn live_event_bound_is_checked_before_history_materialization() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate_v1(&mut connection).unwrap();
        let persona_id = Uuid::new_v4().to_string();
        let key_fingerprint = fingerprint(KEY_ONE).unwrap();
        connection
            .execute(
                "INSERT INTO personas (id, label, purpose, created_at)
                 VALUES (?1, 'Hostile legacy publisher', 'project', 1)",
                [&persona_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO key_records
                 (fingerprint, persona_id, public_key, provider, status, added_at)
                 VALUES (?1, ?2, ?3, 'openssh-file', 'active', 1)",
                params![key_fingerprint, persona_id, KEY_ONE],
            )
            .unwrap();
        connection
            .execute(
                "WITH RECURSIVE numbers(value) AS (
                     SELECT 1
                     UNION ALL
                     SELECT value + 1 FROM numbers WHERE value < ?3
                 )
                 INSERT INTO key_events
                     (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
                 SELECT ?1, ?2, 'enrolled', 1, 'legacy-user', 'legacy-enrollment'
                 FROM numbers",
                params![
                    persona_id,
                    key_fingerprint,
                    i64::try_from(MAX_STORED_PERSONA_EVENTS).unwrap()
                ],
            )
            .unwrap();

        assert_eq!(
            require_stored_event_count(&connection, &persona_id, false).unwrap(),
            MAX_STORED_PERSONA_EVENTS
        );
        assert!(matches!(
            require_stored_event_count(&connection, &persona_id, true),
            Err(StoreError::StoredPersonaEventLimit { .. })
        ));
        connection
            .execute(
                "INSERT INTO key_events
                 (persona_id, key_fingerprint, event_type, occurred_at, actor, policy)
                 VALUES (?1, ?2, 'enrolled', 1, 'legacy-user', 'legacy-enrollment')",
                params![persona_id, key_fingerprint],
            )
            .unwrap();

        assert!(matches!(
            key_history_in(&connection, &persona_id),
            Err(StoreError::StoredPersonaEventLimit { .. })
        ));
    }

    #[test]
    fn records_one_immutable_root_and_blocks_legacy_key_bypasses() {
        let directory = tempfile::tempdir().unwrap();
        let (first_path, first_public) = generate_key(directory.path(), "root-key");
        let (_, next_public) = generate_key(directory.path(), "next-key");
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Journaled publisher", PersonaPurpose::Project)
            .unwrap();
        let initial = store
            .enroll_key(&persona.id, &first_public, KeyProvider::OpensshFile)
            .unwrap();
        store
            .bind_signing_reference(&initial.fingerprint, &first_path)
            .unwrap();
        let root_statement =
            new_persona_root_statement(&persona.label, 100, &first_public).unwrap();
        let root_proof =
            create_persona_root_proof(root_statement, &first_path, &first_public).unwrap();
        let verified_root = verify_persona_root_proof(&root_proof).unwrap();

        let first_record = store
            .record_continuity_root(
                &persona.id,
                &root_proof,
                &verified_root.root_statement_sha256,
            )
            .unwrap();
        let retry_record = store
            .record_continuity_root(
                &persona.id,
                &root_proof,
                &verified_root.root_statement_sha256,
            )
            .unwrap();
        assert_eq!(retry_record, first_record);

        let replacement_statement =
            new_persona_root_statement(&persona.label, 101, &first_public).unwrap();
        let replacement =
            create_persona_root_proof(replacement_statement, &first_path, &first_public).unwrap();
        let replacement_digest = verify_persona_root_proof(&replacement)
            .unwrap()
            .root_statement_sha256;
        assert!(matches!(
            store.record_continuity_root(&persona.id, &replacement, &replacement_digest),
            Err(StoreError::ContinuityConflict(_))
        ));
        assert!(matches!(
            store.enroll_key(&persona.id, &next_public, KeyProvider::OpensshFile),
            Err(StoreError::ContinuityBypass(id)) if id == persona.id
        ));
        assert!(matches!(
            store.rotate_key(
                &persona.id,
                &next_public,
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                None,
            ),
            Err(StoreError::ContinuityBypass(id)) if id == persona.id
        ));
    }

    #[test]
    fn current_continuity_head_cannot_be_marked_compromised_out_of_band() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = PersonaStore::open_in_memory().unwrap();
        let fixture = prepare_routine_transition(&mut store, directory.path());
        let history_before = store.key_history(&fixture.persona.id).unwrap();

        let error = store
            .mark_key_compromised(
                &fixture.previous_key.fingerprint,
                "Project owner",
                "example.invalid/compromise-policy",
                Some("suspected compromise"),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            StoreError::ContinuityCompromiseRequiresJournal(fingerprint)
                if fingerprint == fixture.previous_key.fingerprint
        ));
        assert_eq!(
            store
                .lookup_key(&fixture.previous_key.fingerprint)
                .unwrap()
                .unwrap()
                .key
                .status,
            KeyStatus::Active
        );
        assert_eq!(
            store.key_history(&fixture.persona.id).unwrap(),
            history_before
        );
        assert_eq!(
            store
                .routine_continuity_snapshot(&fixture.persona.id)
                .unwrap()
                .head
                .transition_sequence,
            0
        );

        store
            .commit_routine_transition(
                &fixture.persona.id,
                &fixture.proof,
                KeyProvider::OpensshFile,
                &fixture.next_path,
            )
            .unwrap();
        store
            .mark_key_compromised(
                &fixture.previous_key.fingerprint,
                "Project owner",
                "example.invalid/compromise-policy",
                None,
            )
            .unwrap();
        assert_eq!(
            store
                .lookup_key(&fixture.previous_key.fingerprint)
                .unwrap()
                .unwrap()
                .key
                .status,
            KeyStatus::Compromised
        );
        assert_eq!(
            store
                .routine_continuity_snapshot(&fixture.persona.id)
                .unwrap()
                .head
                .current_key_fingerprint,
            fixture.candidate.intent.next_key_fingerprint
        );
    }

    #[test]
    fn routine_transition_sequence_stops_at_the_configured_boundary() {
        let mut head = ContinuityHead {
            persona_id: "boundary-persona".to_owned(),
            revision: i64::try_from(MAX_CONTINUITY_TRANSITIONS - 1).unwrap(),
            transition_sequence: u32::try_from(MAX_CONTINUITY_TRANSITIONS - 1).unwrap(),
            current_key_fingerprint: "SHA256:boundary".to_owned(),
            last_transition_sha256: Some("0".repeat(64)),
            last_issued_at: 1,
        };
        assert_eq!(
            next_routine_transition_sequence(&head).unwrap(),
            u32::try_from(MAX_CONTINUITY_TRANSITIONS).unwrap()
        );

        head.revision = i64::try_from(MAX_CONTINUITY_TRANSITIONS).unwrap();
        head.transition_sequence = u32::try_from(MAX_CONTINUITY_TRANSITIONS).unwrap();
        let error = next_routine_transition_sequence(&head).unwrap_err();
        assert!(matches!(error, StoreError::InvalidContinuity(message)
            if message.contains("transition limit")));
    }

    #[test]
    fn commits_one_routine_proof_atomically_and_retries_without_the_candidate_path() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (first_path, first_public) = generate_key(directory.path(), "first-key");
        let (next_path, next_public) = generate_key(directory.path(), "next-key");
        let (fork_path, fork_public) = generate_key(directory.path(), "fork-key");
        let store_path = directory.path().join("personas.sqlite3");
        let mut store = PersonaStore::open(&store_path).unwrap();
        let persona = store
            .create_persona("Continuous publisher", PersonaPurpose::Project)
            .unwrap();
        let first = store
            .enroll_key(&persona.id, &first_public, KeyProvider::OpensshFile)
            .unwrap();
        store
            .bind_signing_reference(&first.fingerprint, &first_path)
            .unwrap();
        let root_statement =
            new_persona_root_statement(&persona.label, 100, &first_public).unwrap();
        let root_proof =
            create_persona_root_proof(root_statement, &first_path, &first_public).unwrap();
        let root = verify_persona_root_proof(&root_proof).unwrap();
        store
            .record_continuity_root(&persona.id, &root_proof, &root.root_statement_sha256)
            .unwrap();

        let candidate = store
            .validate_routine_rotation_candidate(
                &persona.id,
                &next_public,
                KeyProvider::OpensshFile,
                &next_path,
            )
            .unwrap();
        let statement = new_routine_transition_statement(
            &root,
            candidate.intent.sequence,
            candidate.intent.previous_transition_sha256.as_deref(),
            &first_public,
            &next_public,
            candidate.intent.issued_at,
        )
        .unwrap();
        assert_eq!(
            routine_transition_intent(&persona.id, &statement),
            candidate.intent
        );
        let proof = create_routine_transition_proof(
            statement,
            &first_path,
            &first_public,
            &next_path,
            &next_public,
        )
        .unwrap();

        let committed = store
            .commit_routine_transition(&persona.id, &proof, KeyProvider::OpensshFile, &next_path)
            .unwrap();
        assert!(!committed.replayed);
        let snapshot = store.routine_continuity_snapshot(&persona.id).unwrap();
        assert_eq!(snapshot.head.revision, 1);
        assert_eq!(snapshot.head.transition_sequence, 1);
        assert_eq!(
            snapshot.head.current_key_fingerprint,
            committed.intent.next_key_fingerprint
        );
        assert_eq!(
            snapshot.transitions.as_slice(),
            std::slice::from_ref(&proof)
        );
        assert_eq!(
            store
                .lookup_key(&first.fingerprint)
                .unwrap()
                .unwrap()
                .key
                .status,
            KeyStatus::Retired
        );

        drop(store);
        fs::remove_file(&next_path).unwrap();
        let mut store = PersonaStore::open(&store_path).unwrap();
        assert!(store.active_signer_for_persona(&persona.id).is_err());
        let retry_metadata = store
            .committed_routine_transition_retry_metadata(&committed.intent)
            .unwrap()
            .unwrap();
        assert_eq!(retry_metadata.persona_id, persona.id);
        assert_eq!(
            retry_metadata.current_key_fingerprint,
            committed.intent.next_key_fingerprint
        );
        assert_eq!(retry_metadata.provider, KeyProvider::OpensshFile);
        assert_eq!(
            retry_metadata.signing_locator,
            candidate.signing_reference.locator
        );
        let retry = store
            .commit_routine_transition(
                &persona.id,
                &proof,
                KeyProvider::OpensshFile,
                directory.path().join("missing-candidate-key"),
            )
            .unwrap();
        assert!(retry.replayed);
        assert_eq!(retry.proof, proof);
        assert_eq!(store.key_history(&persona.id).unwrap().len(), 3);

        let fork_statement = new_routine_transition_statement(
            &root,
            1,
            None,
            &first_public,
            &fork_public,
            committed.intent.issued_at,
        )
        .unwrap();
        let fork = create_routine_transition_proof(
            fork_statement,
            &first_path,
            &first_public,
            &fork_path,
            &fork_public,
        )
        .unwrap();
        assert!(matches!(
            store.commit_routine_transition(
                &persona.id,
                &fork,
                KeyProvider::OpensshFile,
                &fork_path,
            ),
            Err(StoreError::ContinuityConflict(_))
        ));
        assert_eq!(
            store
                .routine_continuity_snapshot(&persona.id)
                .unwrap()
                .head
                .transition_sequence,
            1
        );

        store
            .connection
            .execute(
                "UPDATE persona_continuity_heads
                 SET last_issued_at = last_issued_at + 1 WHERE persona_id = ?1",
                [&persona.id],
            )
            .unwrap();
        assert!(matches!(
            store.committed_routine_transition_retry_metadata(&committed.intent),
            Err(StoreError::InvalidContinuity(_))
        ));
    }

    #[test]
    fn persisted_continuity_journal_rejects_partial_history_attack_matrix() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let primary_directory = directory.path().join("primary");
        let other_directory = directory.path().join("other");
        fs::create_dir(&primary_directory).unwrap();
        fs::create_dir(&other_directory).unwrap();
        let base_path = directory.path().join("base.sqlite3");
        let mut base = PersonaStore::open(&base_path).unwrap();
        let primary = prepare_routine_transition(&mut base, &primary_directory);
        let first_proof = primary.proof.clone();
        let second_proof =
            commit_second_routine_transition(&mut base, &primary_directory, &primary);
        let other = prepare_routine_transition(&mut base, &other_directory);
        base.commit_routine_transition(
            &other.persona.id,
            &other.proof,
            KeyProvider::OpensshFile,
            &other.next_path,
        )
        .unwrap();
        let first = verify_persona_transition_proof(&first_proof).unwrap();
        let first_proof_json = serialize_continuity_proof(&first_proof).unwrap();
        let second_proof_json = serialize_continuity_proof(&second_proof).unwrap();
        drop(base);

        let open_case = |name: &str| {
            let path = directory.path().join(format!("{name}.sqlite3"));
            fs::copy(&base_path, &path).unwrap();
            PersonaStore::open(path).unwrap()
        };

        let rolled_back_head = open_case("rolled-back-head");
        rolled_back_head
            .connection
            .execute(
                "UPDATE persona_continuity_heads
                 SET revision = 1, transition_sequence = 1,
                     current_key_fingerprint = ?1,
                     last_transition_sha256 = ?2, last_issued_at = ?3
                 WHERE persona_id = ?4",
                params![
                    first.statement.next_key_fingerprint,
                    first.transition_statement_sha256,
                    first.statement.issued_at,
                    primary.persona.id
                ],
            )
            .unwrap();
        assert!(matches!(
            rolled_back_head.routine_continuity_snapshot(&primary.persona.id),
            Err(StoreError::InvalidContinuity(_))
        ));

        let truncated = open_case("truncated-tail");
        assert!(
            truncated
                .connection
                .execute(
                    "DELETE FROM persona_continuity_transitions
                     WHERE persona_id = ?1 AND sequence = 2",
                    [&primary.persona.id],
                )
                .is_err()
        );
        truncated
            .connection
            .execute_batch("DROP TRIGGER persona_continuity_transitions_no_delete;")
            .unwrap();
        truncated
            .connection
            .execute(
                "DELETE FROM persona_continuity_transitions
                 WHERE persona_id = ?1 AND sequence = 2",
                [&primary.persona.id],
            )
            .unwrap();
        assert!(matches!(
            truncated.routine_continuity_snapshot(&primary.persona.id),
            Err(StoreError::InvalidContinuity(_))
        ));

        let reordered = open_case("reordered-proofs");
        reordered
            .connection
            .execute_batch("DROP TRIGGER persona_continuity_transitions_no_update;")
            .unwrap();
        reordered
            .connection
            .execute(
                "UPDATE persona_continuity_transitions SET proof_json = ?1
                 WHERE persona_id = ?2 AND sequence = 1",
                params![second_proof_json, primary.persona.id],
            )
            .unwrap();
        reordered
            .connection
            .execute(
                "UPDATE persona_continuity_transitions SET proof_json = ?1
                 WHERE persona_id = ?2 AND sequence = 2",
                params![first_proof_json, primary.persona.id],
            )
            .unwrap();
        assert!(matches!(
            reordered.routine_continuity_snapshot(&primary.persona.id),
            Err(StoreError::InvalidContinuity(_))
        ));

        let duplicated = open_case("duplicated-proof");
        assert!(
            duplicated
                .connection
                .execute(
                    "INSERT INTO persona_continuity_transitions
                     SELECT * FROM persona_continuity_transitions
                     WHERE persona_id = ?1 AND sequence = 2",
                    [&primary.persona.id],
                )
                .is_err()
        );
        duplicated
            .connection
            .execute(
                "INSERT INTO persona_continuity_transitions
                 (persona_id, sequence, transition_statement_sha256,
                  root_statement_sha256, previous_transition_sha256,
                  previous_key_fingerprint, next_key_fingerprint, issued_at,
                  proof_json, committed_at)
                 SELECT persona_id, 3, ?1, root_statement_sha256,
                        previous_transition_sha256, previous_key_fingerprint,
                        next_key_fingerprint, issued_at, proof_json, committed_at
                 FROM persona_continuity_transitions
                 WHERE persona_id = ?2 AND sequence = 2",
                params!["0".repeat(64), primary.persona.id],
            )
            .unwrap();
        assert!(matches!(
            duplicated.routine_continuity_snapshot(&primary.persona.id),
            Err(StoreError::InvalidContinuity(_))
        ));

        let cross_persona = open_case("cross-persona-row");
        cross_persona
            .connection
            .execute_batch("DROP TRIGGER persona_continuity_transitions_no_update;")
            .unwrap();
        cross_persona
            .connection
            .execute(
                "UPDATE persona_continuity_transitions SET persona_id = ?1
                 WHERE persona_id = ?2 AND sequence = 2",
                params![other.persona.id, primary.persona.id],
            )
            .unwrap();
        for persona_id in [&primary.persona.id, &other.persona.id] {
            assert!(matches!(
                cross_persona.routine_continuity_snapshot(persona_id),
                Err(StoreError::InvalidContinuity(_))
            ));
        }
    }

    #[test]
    fn authorization_reads_reject_partial_key_status_rewrite() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = PersonaStore::open_in_memory().unwrap();
        let fixture = prepare_routine_transition(&mut store, directory.path());
        store
            .commit_routine_transition(
                &fixture.persona.id,
                &fixture.proof,
                KeyProvider::OpensshFile,
                &fixture.next_path,
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE key_records
                 SET status = 'active', retired_at = NULL
                 WHERE fingerprint = ?1",
                [&fixture.previous_key.fingerprint],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE key_records
                 SET status = 'retired', retired_at = added_at
                 WHERE fingerprint = ?1",
                [&fixture.candidate.intent.next_key_fingerprint],
            )
            .unwrap();

        assert!(matches!(
            store.lookup_key(&fixture.previous_key.fingerprint),
            Err(StoreError::InvalidAuditHistory)
        ));
        assert!(matches!(
            store.list_keys(&fixture.persona.id),
            Err(StoreError::InvalidAuditHistory)
        ));
        assert!(matches!(
            store.active_signer_for_persona(&fixture.persona.id),
            Err(StoreError::InvalidAuditHistory)
        ));
        assert!(matches!(
            store.commit_routine_transition(
                &fixture.persona.id,
                &fixture.proof,
                KeyProvider::OpensshFile,
                &fixture.next_path,
            ),
            Err(StoreError::InvalidAuditHistory)
        ));
        assert!(matches!(
            store.bind_signing_reference(
                &fixture.previous_key.fingerprint,
                &fixture.previous_key.public_key
            ),
            Err(StoreError::InvalidAuditHistory)
        ));
    }

    #[test]
    fn transaction_error_after_retirement_rolls_back_every_continuity_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = PersonaStore::open_in_memory().unwrap();
        let fixture = prepare_routine_transition(&mut store, directory.path());

        let error = store
            .commit_routine_transition_inner(
                &fixture.persona.id,
                &fixture.proof,
                KeyProvider::OpensshFile,
                &fixture.next_path,
                || {
                    Err(StoreError::ContinuityConflict(
                        "test interruption after previous-key retirement".to_owned(),
                    ))
                },
            )
            .unwrap_err();
        assert!(matches!(error, StoreError::ContinuityConflict(message)
            if message.contains("test interruption")));

        let snapshot = store
            .routine_continuity_snapshot(&fixture.persona.id)
            .unwrap();
        assert_eq!(snapshot.head.revision, 0);
        assert_eq!(snapshot.head.transition_sequence, 0);
        assert_eq!(
            snapshot.head.current_key_fingerprint,
            fixture.previous_key.fingerprint
        );
        assert!(snapshot.transitions.is_empty());
        assert_eq!(store.list_keys(&fixture.persona.id).unwrap().len(), 1);
        assert_eq!(
            store
                .lookup_key(&fixture.previous_key.fingerprint)
                .unwrap()
                .unwrap()
                .key
                .status,
            KeyStatus::Active
        );
        assert!(
            store
                .lookup_key(&fixture.candidate.intent.next_key_fingerprint)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.key_history(&fixture.persona.id).unwrap().len(), 1);
        assert!(
            store
                .lookup_signing_reference(&fixture.candidate.intent.next_key_fingerprint)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .signing_reference_history(&fixture.candidate.intent.next_key_fingerprint)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .lookup_committed_routine_transition(&fixture.candidate.intent)
                .unwrap()
                .is_none()
        );

        let committed = store
            .commit_routine_transition(
                &fixture.persona.id,
                &fixture.proof,
                KeyProvider::OpensshFile,
                &fixture.next_path,
            )
            .unwrap();
        assert!(!committed.replayed);
        assert_eq!(
            store
                .routine_continuity_snapshot(&fixture.persona.id)
                .unwrap()
                .head
                .transition_sequence,
            1
        );
    }

    #[test]
    fn abrupt_exit_mid_routine_transition_child() {
        let Some(database_path) = std::env::var_os(ABORT_TEST_DATABASE) else {
            return;
        };
        let persona_id = std::env::var(ABORT_TEST_PERSONA).unwrap();
        let proof_path = PathBuf::from(std::env::var_os(ABORT_TEST_PROOF).unwrap());
        let locator = PathBuf::from(std::env::var_os(ABORT_TEST_LOCATOR).unwrap());
        let proof: PersonaTransitionProof =
            serde_json::from_slice(&fs::read(proof_path).unwrap()).unwrap();
        let mut store = PersonaStore::open(database_path).unwrap();

        let _ = store.commit_routine_transition_inner(
            &persona_id,
            &proof,
            KeyProvider::OpensshFile,
            locator,
            || std::process::abort(),
        );
        unreachable!("the mid-transaction abort hook must terminate this child")
    }

    #[test]
    fn abrupt_exit_after_routine_transition_commit_child() {
        let Some(database_path) = std::env::var_os(ABORT_TEST_DATABASE) else {
            return;
        };
        let persona_id = std::env::var(ABORT_TEST_PERSONA).unwrap();
        let proof_path = PathBuf::from(std::env::var_os(ABORT_TEST_PROOF).unwrap());
        let locator = PathBuf::from(std::env::var_os(ABORT_TEST_LOCATOR).unwrap());
        let proof: PersonaTransitionProof =
            serde_json::from_slice(&fs::read(proof_path).unwrap()).unwrap();
        let mut store = PersonaStore::open(database_path).unwrap();

        store
            .commit_routine_transition(&persona_id, &proof, KeyProvider::OpensshFile, locator)
            .unwrap();
        std::process::abort();
    }

    #[test]
    fn hot_journal_recovery_after_abrupt_mid_transaction_exit_is_unambiguous() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store_path = directory.path().join("personas.sqlite3");
        let proof_path = directory.path().join("candidate-transition-proof.json");
        let mut store = PersonaStore::open(&store_path).unwrap();
        let fixture = prepare_routine_transition(&mut store, directory.path());
        let journal_mode: String = store
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode, "delete");
        fs::write(&proof_path, serde_json::to_vec(&fixture.proof).unwrap()).unwrap();
        drop(store);

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::abrupt_exit_mid_routine_transition_child",
                "--nocapture",
            ])
            .env(ABORT_TEST_DATABASE, &store_path)
            .env(ABORT_TEST_PERSONA, &fixture.persona.id)
            .env(ABORT_TEST_PROOF, &proof_path)
            .env(ABORT_TEST_LOCATOR, &fixture.next_path)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "child unexpectedly survived the mid-transaction abort"
        );

        let mut journal_name = store_path.as_os_str().to_os_string();
        journal_name.push("-journal");
        let journal_path = PathBuf::from(journal_name);
        assert!(journal_path.is_file(), "abrupt exit left no hot journal");
        assert!(fs::metadata(&journal_path).unwrap().len() > 0);

        let mut reopened = PersonaStore::open(&store_path).unwrap();
        let integrity: String = reopened
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let snapshot = reopened
            .routine_continuity_snapshot(&fixture.persona.id)
            .unwrap();
        assert_eq!(snapshot.head.revision, 0);
        assert_eq!(snapshot.head.transition_sequence, 0);
        assert_eq!(
            snapshot.head.current_key_fingerprint,
            fixture.previous_key.fingerprint
        );
        assert!(snapshot.transitions.is_empty());
        assert_eq!(reopened.list_keys(&fixture.persona.id).unwrap().len(), 1);
        assert_eq!(reopened.key_history(&fixture.persona.id).unwrap().len(), 1);
        assert!(
            reopened
                .lookup_key(&fixture.candidate.intent.next_key_fingerprint)
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .lookup_signing_reference(&fixture.candidate.intent.next_key_fingerprint)
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .lookup_committed_routine_transition(&fixture.candidate.intent)
                .unwrap()
                .is_none()
        );

        let committed = reopened
            .commit_routine_transition(
                &fixture.persona.id,
                &fixture.proof,
                KeyProvider::OpensshFile,
                &fixture.next_path,
            )
            .unwrap();
        assert!(!committed.replayed);
        assert_eq!(
            reopened
                .routine_continuity_snapshot(&fixture.persona.id)
                .unwrap()
                .head
                .transition_sequence,
            1
        );
    }

    #[test]
    fn abrupt_exit_after_commit_recovers_exact_proof_without_duplicate_audit() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store_path = directory.path().join("personas.sqlite3");
        let proof_path = directory.path().join("candidate-transition-proof.json");
        let mut store = PersonaStore::open(&store_path).unwrap();
        let fixture = prepare_routine_transition(&mut store, directory.path());
        fs::write(&proof_path, serde_json::to_vec(&fixture.proof).unwrap()).unwrap();
        drop(store);

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::abrupt_exit_after_routine_transition_commit_child",
                "--nocapture",
            ])
            .env(ABORT_TEST_DATABASE, &store_path)
            .env(ABORT_TEST_PERSONA, &fixture.persona.id)
            .env(ABORT_TEST_PROOF, &proof_path)
            .env(ABORT_TEST_LOCATOR, &fixture.next_path)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "child unexpectedly survived the post-commit abort"
        );

        let mut reopened = PersonaStore::open(&store_path).unwrap();
        let integrity: String = reopened
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let snapshot = reopened
            .routine_continuity_snapshot(&fixture.persona.id)
            .unwrap();
        assert_eq!(snapshot.head.revision, 1);
        assert_eq!(snapshot.head.transition_sequence, 1);
        assert_eq!(
            snapshot.transitions.as_slice(),
            std::slice::from_ref(&fixture.proof)
        );
        assert_eq!(reopened.list_keys(&fixture.persona.id).unwrap().len(), 2);
        assert_eq!(reopened.key_history(&fixture.persona.id).unwrap().len(), 3);

        fs::remove_file(&fixture.next_path).unwrap();
        let replayed = reopened
            .commit_routine_transition(
                &fixture.persona.id,
                &fixture.proof,
                KeyProvider::OpensshFile,
                directory.path().join("missing-after-commit-key"),
            )
            .unwrap();
        assert!(replayed.replayed);
        assert_eq!(replayed.proof, fixture.proof);
        assert_eq!(reopened.key_history(&fixture.persona.id).unwrap().len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn rejected_or_incomplete_proofs_leave_the_continuity_head_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let (first_path, first_public) = generate_key(directory.path(), "first-key");
        let (next_path, next_public) = generate_key(directory.path(), "next-key");
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Fail-closed publisher", PersonaPurpose::Project)
            .unwrap();
        store
            .enroll_key(&persona.id, &first_public, KeyProvider::OpensshFile)
            .unwrap();
        let root_statement =
            new_persona_root_statement(&persona.label, 100, &first_public).unwrap();
        let root_proof =
            create_persona_root_proof(root_statement, &first_path, &first_public).unwrap();
        let root = verify_persona_root_proof(&root_proof).unwrap();
        store
            .record_continuity_root(&persona.id, &root_proof, &root.root_statement_sha256)
            .unwrap();
        let statement =
            new_routine_transition_statement(&root, 1, None, &first_public, &next_public, 101)
                .unwrap();
        let proof = create_routine_transition_proof(
            statement,
            &first_path,
            &first_public,
            &next_path,
            &next_public,
        )
        .unwrap();

        let mut incomplete = proof.clone();
        incomplete.signatures.pop();
        assert!(matches!(
            store.commit_routine_transition(
                &persona.id,
                &incomplete,
                KeyProvider::OpensshFile,
                &next_path,
            ),
            Err(StoreError::InvalidContinuity(_))
        ));
        fs::set_permissions(&next_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            store.commit_routine_transition(
                &persona.id,
                &proof,
                KeyProvider::OpensshFile,
                &next_path,
            ),
            Err(StoreError::UnsafeSigningReference { .. })
        ));

        let snapshot = store.routine_continuity_snapshot(&persona.id).unwrap();
        assert_eq!(snapshot.head.transition_sequence, 0);
        assert_eq!(
            snapshot.head.current_key_fingerprint,
            root.statement.initial_key_fingerprint
        );
        assert!(snapshot.transitions.is_empty());
        assert_eq!(store.list_keys(&persona.id).unwrap().len(), 1);
        assert_eq!(store.key_history(&persona.id).unwrap().len(), 1);
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
