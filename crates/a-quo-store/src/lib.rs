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
    MAX_CONTINUITY_TRANSITIONS, MAX_PROOF_BYTES, PersonaContinuityTransitionProof,
    PersonaRootProof, PersonaTransitionProof, PersonaTransitionStatement,
    RecoveryPolicyAuthorization, RecoveryPolicyProof, RecoveryPolicyTimeStatus,
    RecoveryTransitionProof, inspect_recovery_transition_proof, new_routine_transition_statement,
    parse_persona_continuity_transition_proof_bytes, parse_persona_root_proof_bytes,
    parse_persona_transition_proof_bytes, parse_recovery_policy_proof_bytes,
    public_key_fingerprint, verify_persona_continuity_chain,
    verify_persona_continuity_chain_with_recovery, verify_persona_root_proof,
    verify_persona_transition_proof, verify_recovery_policy_proof_sequence,
};
use a_quo_display::{
    contains_unsafe_display_characters, escape_untrusted_bytes_for_terminal,
    escape_untrusted_text_for_terminal,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 5;
const MAX_LABEL_BYTES: usize = 256;
const MAX_NOTE_BYTES: usize = 2_048;
const MAX_POLICY_BYTES: usize = 512;
const MAX_ACTOR_BYTES: usize = 256;
const MAX_SIGNING_REFERENCE_BYTES: usize = 4_096;
const MAX_PUBLIC_KEY_BYTES: u64 = 16_384;
const MAX_PORTABLE_JSON_INTEGER: i64 = 9_007_199_254_740_991;
pub const MAX_PERSONA_BACKUP_KEYS: usize = 256;
pub const MAX_PERSONA_BACKUP_EVENTS: usize = 4_096;
pub const MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS: usize = 256;
pub const MAX_PERSONA_BACKUP_RECOVERY_POLICIES: usize = 256;
pub const MAX_PERSONA_BACKUP_SIGNATURES: usize = 2_048;

/// One immutable root key plus every transition allowed by the continuity
/// protocol. This live-store bound is deliberately separate from the smaller
/// portable-backup policy.
pub const MAX_STORED_PERSONA_KEYS: usize = MAX_CONTINUITY_TRANSITIONS + 1;

/// A key can have one origin event, one retirement, and one compromise.
pub const MAX_STORED_PERSONA_EVENTS: usize = MAX_STORED_PERSONA_KEYS * 3;

pub const PERSONA_BACKUP_V1_SCHEMA: &str = "urn:a-quo:persona-metadata-backup:v1";
pub const PERSONA_BACKUP_SCHEMA: &str = "urn:a-quo:persona-metadata-backup:v2";
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

    #[error("signed persona label does not match the selected key's registered persona: {0}")]
    PersonaLabelMismatch(String),

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

    #[error("persona has imported continuity evidence but no local signing authority: {0}")]
    ContinuityEvidenceOnly(String),

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
    require_no_evidence_archive(connection, persona_id)?;
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
             UNION ALL
             SELECT 1 FROM persona_continuity_archives WHERE persona_id = ?1
         )",
            [persona_id],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn continuity_archive_exists_in(connection: &Connection, persona_id: &str) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM persona_continuity_archives WHERE persona_id = ?1
             )",
            [persona_id],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn require_no_evidence_archive(connection: &Connection, persona_id: &str) -> Result<()> {
    if continuity_archive_exists_in(connection, persona_id)? {
        Err(StoreError::ContinuityEvidenceOnly(persona_id.to_owned()))
    } else {
        Ok(())
    }
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
            let proof = parse_persona_root_proof_bytes(&proof_json).map_err(invalid_continuity)?;
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
        let proof =
            parse_persona_transition_proof_bytes(&proof_json).map_err(invalid_continuity)?;
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
    require_no_evidence_archive(connection, persona_id)?;
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
    let has_live_root = recorded_persona_root_in(connection, persona_id)?.is_some();
    let archived = archived_backup_in(connection, persona_id)?;
    match (has_live_root, archived) {
        (true, Some(_)) => {
            return Err(StoreError::InvalidContinuity(
                "persona has both a live continuity root and imported evidence archive".to_owned(),
            ));
        }
        (true, None) => {
            routine_continuity_snapshot_in(connection, persona_id)?;
        }
        (false, Some(backup)) => {
            verify_persona_backup_continuity(&backup)?.ok_or_else(|| {
                StoreError::InvalidContinuity(
                    "stored evidence archive did not produce a verification report".to_owned(),
                )
            })?;
        }
        (false, None) => {
            key_history_in(connection, persona_id)?;
        }
    }
    Ok(())
}

fn persona_authority_disposition_in(
    connection: &Connection,
    persona_id: &str,
) -> Result<PersonaAuthorityDisposition> {
    let persona = persona_in(connection, persona_id)?;
    validate_persona_authorization_state_in(connection, persona_id)?;
    if continuity_archive_exists_in(connection, persona_id)? {
        Ok(PersonaAuthorityDisposition::EvidenceOnly)
    } else if persona.archived_at.is_some() {
        Ok(PersonaAuthorityDisposition::Archived)
    } else {
        Ok(PersonaAuthorityDisposition::Operational)
    }
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
    let proof = parse_persona_transition_proof_bytes(&proof_json).map_err(invalid_continuity)?;
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaBackup {
    pub schema: String,
    pub exported_at: i64,
    pub persona: BackupPersona,
    pub keys: Vec<BackupKey>,
    pub events: Vec<BackupKeyEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity: Option<BackupContinuity>,
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

/// Schema-v2 continuity state. The explicit unmanaged variant prevents a
/// missing archive from silently downgrading a continuity-managed persona.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
// This is a bounded, short-lived wire/API value. Keeping the archive inline
// avoids a heap-specific public constructor while its serialization remains
// explicit and portable.
#[allow(clippy::large_enum_variant)]
#[serde(
    tag = "kind",
    content = "archive",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum BackupContinuity {
    Unmanaged,
    EvidenceArchive(BackupContinuityArchive),
}

/// Portable public continuity evidence. It contains signed public proofs and
/// optional local observation times, never a signer locator or private key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupContinuityArchive {
    pub root: BackupPersonaRootEvidence,
    pub recovery_policies: Vec<BackupRecoveryPolicyEvidence>,
    pub transitions: Vec<BackupTransitionEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupPersonaRootEvidence {
    pub proof: PersonaRootProof,
    pub observed_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRecoveryPolicyEvidence {
    pub proof: RecoveryPolicyProof,
    pub observed_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupTransitionEvidence {
    #[serde(with = "tagged_transition_proof")]
    pub proof: PersonaContinuityTransitionProof,
    pub observed_at: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonaBackupWire {
    schema: String,
    exported_at: i64,
    persona: BackupPersona,
    keys: Vec<BackupKey>,
    events: Vec<BackupKeyEvent>,
    #[serde(default)]
    continuity: ContinuityFieldPresence,
}

#[derive(Default)]
enum ContinuityFieldPresence {
    #[default]
    Missing,
    Null,
    Value(Box<BackupContinuity>),
}

impl<'de> Deserialize<'de> for ContinuityFieldPresence {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match Option::<BackupContinuity>::deserialize(deserializer)? {
                Some(value) => Self::Value(Box::new(value)),
                None => Self::Null,
            },
        )
    }
}

impl<'de> Deserialize<'de> for PersonaBackup {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PersonaBackupWire::deserialize(deserializer)?;
        let continuity = match (wire.schema.as_str(), wire.continuity) {
            (PERSONA_BACKUP_V1_SCHEMA, ContinuityFieldPresence::Missing) => None,
            (PERSONA_BACKUP_V1_SCHEMA, _) => {
                return Err(<D::Error as serde::de::Error>::custom(
                    "schema v1 must omit the continuity field",
                ));
            }
            (PERSONA_BACKUP_SCHEMA, ContinuityFieldPresence::Value(value)) => Some(*value),
            (PERSONA_BACKUP_SCHEMA, _) => {
                return Err(<D::Error as serde::de::Error>::custom(
                    "schema v2 requires a non-null continuity field",
                ));
            }
            (_, ContinuityFieldPresence::Value(value)) => Some(*value),
            (_, ContinuityFieldPresence::Missing | ContinuityFieldPresence::Null) => None,
        };
        Ok(Self {
            schema: wire.schema,
            exported_at: wire.exported_at,
            persona: wire.persona,
            keys: wire.keys,
            events: wire.events,
            continuity,
        })
    }
}

mod tagged_transition_proof {
    use super::*;

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "proof", rename_all = "snake_case")]
    enum BorrowedTransitionProof<'a> {
        Routine(&'a PersonaTransitionProof),
        Recovery(&'a RecoveryTransitionProof),
    }

    #[derive(Deserialize)]
    #[serde(
        tag = "kind",
        content = "proof",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    enum OwnedTransitionProof {
        Routine(PersonaTransitionProof),
        Recovery(RecoveryTransitionProof),
    }

    pub fn serialize<S>(
        proof: &PersonaContinuityTransitionProof,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match proof {
            PersonaContinuityTransitionProof::Routine(proof) => {
                BorrowedTransitionProof::Routine(proof).serialize(serializer)
            }
            PersonaContinuityTransitionProof::Recovery(proof) => {
                BorrowedTransitionProof::Recovery(proof).serialize(serializer)
            }
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<PersonaContinuityTransitionProof, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match OwnedTransitionProof::deserialize(deserializer)? {
            OwnedTransitionProof::Routine(proof) => {
                PersonaContinuityTransitionProof::Routine(proof)
            }
            OwnedTransitionProof::Recovery(proof) => {
                PersonaContinuityTransitionProof::Recovery(proof)
            }
        })
    }
}

/// Cryptographic facts established from an evidence archive. The three pin
/// fields remain false because an archive cannot independently authenticate
/// expectations that it carries itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupContinuityVerificationReport {
    pub lifecycle_metadata_consistent: bool,
    pub persona_label_binding_verified: bool,
    pub root_signature_verified: bool,
    pub transition_chain_verified: bool,
    pub recovery_policy_chain_verified: Option<bool>,
    pub policy_transition_checkpoints_verified: Option<bool>,
    pub cryptographic_continuity: bool,
    pub signing_authority: bool,
    pub root_statement_sha256: String,
    pub chain_tip_key_fingerprint: String,
    pub transition_count: u32,
    pub routine_transition_count: u32,
    pub recovery_transition_count: u32,
    pub latest_policy_sha256: Option<String>,
    pub latest_policy_version: Option<u32>,
    pub latest_policy_time_status: Option<RecoveryPolicyTimeStatus>,
    pub checked_at: i64,
    pub external_root_pin_checked: bool,
    pub external_head_pin_checked: bool,
    pub external_policy_pin_checked: bool,
    pub not_established: Vec<String>,
}

/// Opaque proof that this exact immutably borrowed backup passed every
/// structural, portable-size, and cryptographic import check. Only
/// [`verify_persona_backup_for_import`] can construct it.
pub struct VerifiedPersonaBackup<'a> {
    backup: &'a PersonaBackup,
    archive_json: Option<Vec<u8>>,
    continuity_report: Option<BackupContinuityVerificationReport>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecognizedKey {
    pub persona: Persona,
    pub key: KeyRecord,
    pub authority_disposition: PersonaAuthorityDisposition,
}

/// A non-cryptographic, fail-closed persona-listing row. `NotChecked` is
/// deliberately distinct from operational authority; callers must use
/// [`PersonaStore::persona_authority_disposition`] before an authorization
/// decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PersonaListing {
    pub persona: Persona,
    pub authority_disposition: PersonaListingAuthorityDisposition,
}

/// Authority presentation available without launching proof verification for
/// every persona in an unbounded bulk listing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaListingAuthorityDisposition {
    NotChecked,
    Archived,
    EvidenceOnly,
}

/// Whether a recognized public key is locally authorized for operational use,
/// retained under archived persona metadata, or present only to inspect an
/// imported continuity evidence archive.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaAuthorityDisposition {
    Operational,
    Archived,
    EvidenceOnly,
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
                migrate_v5(&mut connection)?;
            }
            1 => {
                migrate_v2(&mut connection)?;
                migrate_v3(&mut connection)?;
                migrate_v4(&mut connection)?;
                migrate_v5(&mut connection)?;
            }
            2 => {
                migrate_v3(&mut connection)?;
                migrate_v4(&mut connection)?;
                migrate_v5(&mut connection)?;
            }
            3 => {
                migrate_v4(&mut connection)?;
                migrate_v5(&mut connection)?;
            }
            4 => migrate_v5(&mut connection)?,
            SCHEMA_VERSION => {}
            newer if newer > SCHEMA_VERSION => {
                return Err(StoreError::UnsupportedSchema(newer));
            }
            older => return Err(StoreError::UnsupportedSchema(older)),
        }

        let store = Self { connection };
        store.validate_continuity_archive_exclusivity()?;
        Ok(store)
    }

    /// Enforce the cross-table invariant with one non-cryptographic query at open without launching an
    /// unbounded number of signature processes for unrelated archives.
    /// Selected authorization and evidence reads reparse and cryptographically
    /// verify their exact archive before returning security-relevant state.
    fn validate_continuity_archive_exclusivity(&self) -> Result<()> {
        let coexistence: bool = self.connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM persona_continuity_archives archive
                 JOIN persona_continuity_roots root
                   ON root.persona_id = archive.persona_id
             )",
            [],
            |row| row.get(0),
        )?;
        if coexistence {
            return Err(StoreError::InvalidContinuity(
                "persona has both a live continuity root and imported evidence archive".to_owned(),
            ));
        }
        Ok(())
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

    /// List persona lifecycle metadata. `archived_at == None` does not by
    /// itself establish operational authority; use
    /// [`Self::persona_authority_disposition`] when making that distinction.
    pub fn list_personas(&self) -> Result<Vec<Persona>> {
        self.list_personas_with_listing_authority()
            .map(|rows| rows.into_iter().map(|row| row.persona).collect())
    }

    /// List every persona and only the authority facts that are safe to derive
    /// without an unbounded store-wide cryptographic sweep. Archive presence
    /// fails closed as evidence-only and takes precedence over archived
    /// lifecycle state; every other unarchived row remains explicitly
    /// `NotChecked` rather than being presented as operational.
    pub fn list_personas_with_listing_authority(&self) -> Result<Vec<PersonaListing>> {
        let mut statement = self.connection.prepare(
            "SELECT p.id, p.label, p.purpose, p.created_at, p.archived_at,
                    EXISTS(
                        SELECT 1 FROM persona_continuity_archives archive
                        WHERE archive.persona_id = p.id
                    )
             FROM personas p ORDER BY p.created_at, p.id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, bool>(5)?,
            ))
        })?;

        rows.map(|row| {
            let (id, label, purpose, created_at, archived_at, has_archive) = row?;
            let persona = persona_from_row((id, label, purpose, created_at, archived_at))?;
            let authority_disposition = if has_archive {
                PersonaListingAuthorityDisposition::EvidenceOnly
            } else if persona.archived_at.is_some() {
                PersonaListingAuthorityDisposition::Archived
            } else {
                PersonaListingAuthorityDisposition::NotChecked
            };
            Ok(PersonaListing {
                persona,
                authority_disposition,
            })
        })
        .collect()
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
        require_continuity_unmanaged(&transaction, persona_id)?;
        require_active_persona(&transaction, persona_id)?;
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
        require_continuity_unmanaged(&transaction, persona_id)?;
        require_active_persona(&transaction, persona_id)?;
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
        let has_evidence_archive = continuity_archive_exists_in(&transaction, &key.persona.id)?;
        if has_evidence_archive && key.key.status == KeyStatus::Active {
            return Err(StoreError::ContinuityEvidenceOnly(key.persona.id.clone()));
        }
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

    /// List key lifecycle metadata. `KeyStatus::Active` does not by itself
    /// establish operational authority for evidence-only personas; use
    /// [`Self::persona_authority_disposition`] alongside this read.
    pub fn list_keys(&self, persona_id: &str) -> Result<Vec<KeyRecord>> {
        let transaction = self.connection.unchecked_transaction()?;
        validate_persona_authorization_state_in(&transaction, persona_id)?;
        let keys = list_keys_in(&transaction, persona_id)?;
        transaction.commit()?;
        Ok(keys)
    }

    /// Reverify the persona's complete authorization state and distinguish
    /// locally operational metadata from an imported evidence-only archive.
    pub fn persona_authority_disposition(
        &self,
        persona_id: &str,
    ) -> Result<PersonaAuthorityDisposition> {
        let transaction = self.connection.unchecked_transaction()?;
        let disposition = persona_authority_disposition_in(&transaction, persona_id)?;
        transaction.commit()?;
        Ok(disposition)
    }

    pub fn key_history(&self, persona_id: &str) -> Result<Vec<KeyEvent>> {
        let transaction = self.connection.unchecked_transaction()?;
        validate_persona_authorization_state_in(&transaction, persona_id)?;
        let events = key_history_in(&transaction, persona_id)?;
        transaction.commit()?;
        Ok(events)
    }

    /// Export one persona's non-secret metadata and lifecycle history.
    ///
    /// Signer references are deliberately excluded: this backup cannot grant
    /// signing or recovery authority on another installation.
    pub fn export_persona_backup(&mut self, persona_id: &str) -> Result<PersonaBackup> {
        self.export_persona_backup_with_archive(persona_id, None)
    }

    /// Export current store state, optionally attaching caller-supplied public
    /// evidence to a persona that is not already continuity-managed.
    /// Existing live or imported continuity can never be replaced this way.
    pub fn export_persona_backup_with_archive(
        &mut self,
        persona_id: &str,
        supplied_archive: Option<BackupContinuityArchive>,
    ) -> Result<PersonaBackup> {
        self.export_persona_backup_with_archive_and_report(persona_id, supplied_archive)
            .map(|(backup, _)| backup)
    }

    /// Export and return the archive verification report from the same bounded
    /// cryptographic pass. This lets CLI/reporting callers avoid reverifying
    /// every archive signature after export.
    pub fn export_persona_backup_with_archive_and_report(
        &mut self,
        persona_id: &str,
        supplied_archive: Option<BackupContinuityArchive>,
    ) -> Result<(PersonaBackup, Option<BackupContinuityVerificationReport>)> {
        let transaction = self.connection.transaction()?;
        let has_live_root = recorded_persona_root_in(&transaction, persona_id)?.is_some();
        let imported_archive = continuity_archive_in(&transaction, persona_id)?;
        if has_live_root && imported_archive.is_some() {
            return Err(StoreError::InvalidContinuity(
                "persona has both a live continuity root and imported evidence archive".to_owned(),
            ));
        }
        if supplied_archive.is_some() && (has_live_root || imported_archive.is_some()) {
            return Err(StoreError::ContinuityConflict(format!(
                "persona {persona_id} already has continuity that cannot be replaced during export"
            )));
        }
        let continuity = if has_live_root {
            BackupContinuity::EvidenceArchive(routine_backup_archive_in(&transaction, persona_id)?)
        } else if let Some(archive) = imported_archive {
            BackupContinuity::EvidenceArchive(archive)
        } else if let Some(archive) = supplied_archive {
            BackupContinuity::EvidenceArchive(archive)
        } else {
            BackupContinuity::Unmanaged
        };
        // `exported_at` is unsigned metadata, but it is also the portable
        // upper bound for every preserved lifecycle/observation timestamp.
        // A destination clock behind an imported archive must not make an
        // otherwise valid re-export impossible.
        let exported_at = now_unix_seconds()?
            .max(latest_persona_backup_time_in(&transaction, persona_id)?)
            .max(continuity_observed_at_max(&continuity).unwrap_or(0));
        let backup = persona_backup_in(&transaction, persona_id, exported_at, continuity)?;
        validate_persona_backup(&backup)?;
        require_serialized_backup_bound(&backup)?;
        let continuity_report = if matches!(
            backup.continuity,
            Some(BackupContinuity::EvidenceArchive(_))
        ) {
            Some(verify_persona_backup_continuity(&backup)?.ok_or_else(|| {
                StoreError::InvalidContinuity(
                    "evidence archive did not produce a verification report".to_owned(),
                )
            })?)
        } else {
            None
        };
        transaction.commit()?;
        Ok((backup, continuity_report))
    }

    /// Restore a fully validated metadata backup in one transaction.
    ///
    /// Existing persona IDs and public-key fingerprints are never merged.
    /// Signer references remain absent. Schema-v1/unmanaged imports may be
    /// rebound explicitly; evidence archives remain non-authoritative unless a
    /// separate, explicit adoption workflow is implemented and invoked.
    pub fn import_persona_backup(&mut self, backup: &PersonaBackup) -> Result<Persona> {
        self.import_verified_persona_backup(verify_persona_backup_for_import(backup)?)
            .map(|(persona, _)| persona)
    }

    /// Import with the same single cryptographic pass while also returning its
    /// evidence report. This lets inspection-oriented callers avoid verifying
    /// hostile archive signatures once for display and again for persistence.
    pub fn import_persona_backup_with_report(
        &mut self,
        backup: &PersonaBackup,
    ) -> Result<(Persona, Option<BackupContinuityVerificationReport>)> {
        self.import_verified_persona_backup(verify_persona_backup_for_import(backup)?)
    }

    /// Consume an opaque token created before destination-store open and write
    /// the already-verified exact backup in one IMMEDIATE transaction, without
    /// launching a second cryptographic pass.
    pub fn import_verified_persona_backup(
        &mut self,
        verified: VerifiedPersonaBackup<'_>,
    ) -> Result<(Persona, Option<BackupContinuityVerificationReport>)> {
        let VerifiedPersonaBackup {
            backup,
            archive_json,
            continuity_report,
        } = verified;
        let persona = Persona {
            id: backup.persona.id.clone(),
            label: backup.persona.label.clone(),
            purpose: backup.persona.purpose,
            created_at: backup.persona.created_at,
            archived_at: backup.persona.archived_at,
        };
        let imported_at = now_unix_seconds()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        if let Some(archive_json) = archive_json {
            transaction.execute(
                "INSERT INTO persona_continuity_archives
                 (persona_id, archive_json, imported_at) VALUES (?1, ?2, ?3)",
                params![persona.id, archive_json, imported_at],
            )?;
        }
        transaction.commit()?;
        Ok((persona, continuity_report))
    }

    pub fn lookup_key(&self, fingerprint: &str) -> Result<Option<RecognizedKey>> {
        let transaction = self.connection.unchecked_transaction()?;
        let recognized = validated_lookup_key_in(&transaction, fingerprint)?;
        transaction.commit()?;
        Ok(recognized)
    }

    /// Return one recognized key and its lifecycle events from the same SQLite
    /// snapshot. Authorization state, including any evidence archive, is fully
    /// validated exactly once before the raw history read.
    pub fn lookup_key_with_history(
        &self,
        fingerprint: &str,
    ) -> Result<Option<(RecognizedKey, Vec<KeyEvent>)>> {
        let transaction = self.connection.unchecked_transaction()?;
        let Some(recognized) = validated_lookup_key_in(&transaction, fingerprint)? else {
            transaction.commit()?;
            return Ok(None);
        };
        let events = key_history_in(&transaction, &recognized.persona.id)?;
        transaction.commit()?;
        Ok(Some((recognized, events)))
    }

    /// Hold an IMMEDIATE database transaction across one final external
    /// operation after freshly revalidating every local authorization fact.
    /// The closure is never invoked for evidence-only, archived, inactive, or
    /// signed-label-mismatched keys.
    pub fn with_active_key_authorization<T, E>(
        &mut self,
        fingerprint: &str,
        expected_persona_label: &str,
        operation: impl FnOnce(&RecognizedKey) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<StoreError>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)
            .map_err(E::from)?;
        let recognized = validated_lookup_key_in(&transaction, fingerprint)
            .map_err(E::from)?
            .ok_or_else(|| E::from(StoreError::KeyNotFound(fingerprint.to_owned())))?;
        match recognized.authority_disposition {
            PersonaAuthorityDisposition::Operational => {}
            PersonaAuthorityDisposition::Archived => {
                return Err(E::from(StoreError::PersonaArchived(
                    recognized.persona.id.clone(),
                )));
            }
            PersonaAuthorityDisposition::EvidenceOnly => {
                return Err(E::from(StoreError::ContinuityEvidenceOnly(
                    recognized.persona.id.clone(),
                )));
            }
        }
        require_active_persona(&transaction, &recognized.persona.id).map_err(E::from)?;
        if recognized.key.status != KeyStatus::Active {
            return Err(E::from(StoreError::InactiveSigningKey(
                fingerprint.to_owned(),
            )));
        }
        if recognized.persona.label != expected_persona_label {
            return Err(E::from(StoreError::PersonaLabelMismatch(
                fingerprint.to_owned(),
            )));
        }
        let result = operation(&recognized)?;
        transaction
            .commit()
            .map_err(StoreError::from)
            .map_err(E::from)?;
        Ok(result)
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
        require_no_evidence_archive(&transaction, &recognized.persona.id)?;
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
        let persona_id = lookup_key_in(&transaction, fingerprint)?
            .expect("key existence checked above")
            .persona
            .id;
        require_no_evidence_archive(&transaction, &persona_id)?;
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
        require_no_evidence_archive(&transaction, persona_id)?;
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
        require_no_evidence_archive(&self.connection, persona_id)?;
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
        require_no_evidence_archive(&transaction, persona_id)?;
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
        require_no_evidence_archive(&self.connection, persona_id)?;
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

fn persona_backup_in(
    connection: &Connection,
    persona_id: &str,
    exported_at: i64,
    continuity: BackupContinuity,
) -> Result<PersonaBackup> {
    let persona = persona_in(connection, persona_id)?;
    let keys = list_keys_in(connection, persona_id)?;
    let events = key_history_in(connection, persona_id)?;
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
    Ok(PersonaBackup {
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
        continuity: Some(continuity),
    })
}

fn routine_backup_archive_in(
    connection: &Connection,
    persona_id: &str,
) -> Result<BackupContinuityArchive> {
    require_no_evidence_archive(connection, persona_id)?;
    let transition_count: i64 = connection.query_row(
        "SELECT count(*) FROM persona_continuity_transitions WHERE persona_id = ?1",
        [persona_id],
        |row| row.get(0),
    )?;
    if usize::try_from(transition_count).unwrap_or(usize::MAX)
        > MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS
    {
        return Err(invalid_backup(format!(
            "continuity archive cannot contain more than {MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS} transitions"
        )));
    }
    let snapshot = routine_continuity_snapshot_in(connection, persona_id)?;
    let mut statement = connection.prepare(
        "SELECT committed_at FROM persona_continuity_transitions
         WHERE persona_id = ?1 ORDER BY sequence",
    )?;
    let observed_at = statement
        .query_map([persona_id], |row| row.get::<_, i64>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if observed_at.len() != snapshot.transitions.len() {
        return Err(StoreError::InvalidContinuity(
            "transition proof and observation-time counts differ".to_owned(),
        ));
    }
    Ok(BackupContinuityArchive {
        root: BackupPersonaRootEvidence {
            proof: snapshot.root.proof,
            observed_at: Some(snapshot.root.recorded_at),
        },
        recovery_policies: Vec::new(),
        transitions: snapshot
            .transitions
            .into_iter()
            .zip(observed_at)
            .map(|(proof, observed_at)| BackupTransitionEvidence {
                proof: PersonaContinuityTransitionProof::Routine(proof),
                observed_at: Some(observed_at),
            })
            .collect(),
    })
}

fn continuity_archive_in(
    connection: &Connection,
    persona_id: &str,
) -> Result<Option<BackupContinuityArchive>> {
    let bytes = connection
        .query_row(
            "SELECT archive_json FROM persona_continuity_archives WHERE persona_id = ?1",
            [persona_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PERSONA_BACKUP_BYTES {
        return Err(StoreError::InvalidContinuity(
            "stored continuity archive exceeds the portable byte bound".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes).map(Some).map_err(|_| {
        StoreError::InvalidContinuity("stored continuity archive is invalid JSON".to_owned())
    })
}

fn latest_persona_backup_time_in(connection: &Connection, persona_id: &str) -> Result<i64> {
    connection
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
             )",
            [persona_id],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .ok_or_else(|| StoreError::PersonaNotFound(persona_id.to_owned()))
}

fn archived_backup_in(connection: &Connection, persona_id: &str) -> Result<Option<PersonaBackup>> {
    let Some(archive) = continuity_archive_in(connection, persona_id)? else {
        return Ok(None);
    };
    let observed_max = archive_observed_at_max(&archive).unwrap_or(0);
    let exported_at = latest_persona_backup_time_in(connection, persona_id)?.max(observed_max);
    persona_backup_in(
        connection,
        persona_id,
        exported_at,
        BackupContinuity::EvidenceArchive(archive),
    )
    .map(Some)
}

fn continuity_observed_at_max(continuity: &BackupContinuity) -> Option<i64> {
    match continuity {
        BackupContinuity::Unmanaged => None,
        BackupContinuity::EvidenceArchive(archive) => archive_observed_at_max(archive),
    }
}

fn archive_observed_at_max(archive: &BackupContinuityArchive) -> Option<i64> {
    std::iter::once(archive.root.observed_at)
        .chain(
            archive
                .recovery_policies
                .iter()
                .map(|entry| entry.observed_at),
        )
        .chain(archive.transitions.iter().map(|entry| entry.observed_at))
        .flatten()
        .max()
}

fn require_serialized_backup_bound(backup: &PersonaBackup) -> Result<()> {
    let compact = serde_json::to_vec(backup)?;
    if u64::try_from(compact.len()).unwrap_or(u64::MAX) > MAX_PERSONA_BACKUP_BYTES {
        return Err(invalid_backup(format!(
            "serialized compact backup exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
        )));
    }
    let pretty_len = serde_json::to_vec_pretty(backup)?.len().saturating_add(1);
    if u64::try_from(pretty_len).unwrap_or(u64::MAX) > MAX_PERSONA_BACKUP_BYTES {
        return Err(invalid_backup(format!(
            "serialized backup exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
        )));
    }
    Ok(())
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
        schema: PERSONA_BACKUP_V1_SCHEMA.to_owned(),
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
        continuity: None,
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

fn migrate_v5(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE persona_continuity_archives (
             persona_id TEXT PRIMARY KEY NOT NULL REFERENCES personas(id),
             archive_json BLOB NOT NULL
                 CHECK(length(archive_json) BETWEEN 1 AND 4194304),
             imported_at INTEGER NOT NULL CHECK(imported_at >= 0)
         ) STRICT;

         CREATE TRIGGER persona_continuity_archives_no_update
         BEFORE UPDATE ON persona_continuity_archives BEGIN
             SELECT RAISE(ABORT, 'imported continuity evidence is immutable');
         END;

         CREATE TRIGGER persona_continuity_archives_no_delete
         BEFORE DELETE ON persona_continuity_archives BEGIN
             SELECT RAISE(ABORT, 'imported continuity evidence is immutable');
         END;

         CREATE TRIGGER persona_continuity_archives_no_replace
         BEFORE INSERT ON persona_continuity_archives
         WHEN EXISTS (
             SELECT 1 FROM persona_continuity_archives
             WHERE persona_id = NEW.persona_id
         ) BEGIN
             SELECT RAISE(ABORT, 'imported continuity evidence is immutable');
         END;

         CREATE TRIGGER persona_continuity_archives_no_live_root
         BEFORE INSERT ON persona_continuity_archives
         WHEN EXISTS (
             SELECT 1 FROM persona_continuity_roots WHERE persona_id = NEW.persona_id
         ) BEGIN
             SELECT RAISE(ABORT, 'continuity archive cannot coexist with a live root');
         END;

         CREATE TRIGGER persona_continuity_roots_no_evidence_archive
         BEFORE INSERT ON persona_continuity_roots
         WHEN EXISTS (
             SELECT 1 FROM persona_continuity_archives WHERE persona_id = NEW.persona_id
         ) BEGIN
             SELECT RAISE(ABORT, 'live root cannot coexist with a continuity archive');
         END;

         PRAGMA user_version = 5;",
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

struct StoredRecognizedKey {
    persona: Persona,
    key: KeyRecord,
}

fn lookup_key_in(
    connection: &Connection,
    fingerprint: &str,
) -> Result<Option<StoredRecognizedKey>> {
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
        Ok(StoredRecognizedKey {
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
    let Some(stored) = lookup_key_in(connection, fingerprint)? else {
        return Ok(None);
    };
    let authority_disposition = persona_authority_disposition_in(connection, &stored.persona.id)?;
    Ok(Some(RecognizedKey {
        persona: stored.persona,
        key: stored.key,
        authority_disposition,
    }))
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

/// Parse and validate one hostile portable backup after enforcing its hard
/// byte bound. Diagnostics never echo raw attacker-controlled JSON text.
pub fn parse_persona_backup_bytes(bytes: &[u8]) -> Result<PersonaBackup> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PERSONA_BACKUP_BYTES {
        return Err(invalid_backup(format!(
            "backup exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
        )));
    }
    let backup: PersonaBackup = serde_json::from_slice(bytes).map_err(|error| {
        let category = match error.classify() {
            serde_json::error::Category::Io => "I/O",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "end-of-input",
        };
        invalid_backup(format!(
            "invalid JSON ({category}) at line {}, column {}",
            error.line(),
            error.column()
        ))
    })?;
    validate_persona_backup(&backup)?;
    Ok(backup)
}

/// Fully verify an exact backup before opening or creating its destination
/// store. The returned token borrows the backup immutably, so callers cannot
/// alter any verified byte-bearing field before consuming it during import.
pub fn verify_persona_backup_for_import(
    backup: &PersonaBackup,
) -> Result<VerifiedPersonaBackup<'_>> {
    validate_persona_backup(backup)?;
    require_serialized_backup_bound(backup)?;
    let (archive_json, continuity_report) = match &backup.continuity {
        Some(BackupContinuity::EvidenceArchive(archive)) => {
            let report = verify_persona_backup_continuity(backup)?.ok_or_else(|| {
                StoreError::InvalidContinuity(
                    "evidence archive did not produce a verification report".to_owned(),
                )
            })?;
            (Some(serde_json::to_vec(archive)?), Some(report))
        }
        _ => (None, None),
    };
    Ok(VerifiedPersonaBackup {
        backup,
        archive_json,
        continuity_report,
    })
}

/// Verify every signature and ordered link in a schema-v2 evidence archive,
/// then bind the derived online keys and chain tip to the backup metadata.
///
/// Archive-contained digests are deliberately not treated as independently
/// obtained pins, and this function never returns signing authority.
pub fn verify_persona_backup_continuity(
    backup: &PersonaBackup,
) -> Result<Option<BackupContinuityVerificationReport>> {
    verify_persona_backup_continuity_at(backup, now_unix_seconds()?)
}

/// Verify an archive at an explicit verifier-observed time. This keeps the
/// unsigned backup export time separate from recovery-policy time reporting.
pub fn verify_persona_backup_continuity_at(
    backup: &PersonaBackup,
    checked_at: i64,
) -> Result<Option<BackupContinuityVerificationReport>> {
    validate_persona_backup(backup)?;
    require_serialized_backup_bound(backup)?;
    if !(0..=MAX_PORTABLE_JSON_INTEGER).contains(&checked_at) {
        return Err(invalid_backup(
            "continuity verification time is outside the portable JSON integer range",
        ));
    }
    let Some(BackupContinuity::EvidenceArchive(archive)) = &backup.continuity else {
        return Ok(None);
    };

    let keys = backup
        .keys
        .iter()
        .map(|key| (key.fingerprint.as_str(), key))
        .collect::<HashMap<_, _>>();
    let verified_root =
        verify_persona_root_proof(&archive.root.proof).map_err(invalid_continuity)?;
    if verified_root.statement.persona != backup.persona.label {
        return Err(StoreError::InvalidContinuity(
            "continuity root persona does not match backup persona metadata".to_owned(),
        ));
    }
    require_backup_proof_key(
        &keys,
        &verified_root.statement.initial_key_fingerprint,
        &verified_root.initial_public_key,
    )?;

    let transitions = archive
        .transitions
        .iter()
        .map(|entry| entry.proof.clone())
        .collect::<Vec<_>>();
    let policies = archive
        .recovery_policies
        .iter()
        .map(|entry| entry.proof.clone())
        .collect::<Vec<_>>();
    let verified_policies = if policies.is_empty() {
        Vec::new()
    } else {
        verify_recovery_policy_proof_sequence(&verified_root, &policies)
            .map_err(invalid_continuity)?
    };

    let (
        chain_tip_key_fingerprint,
        transition_count,
        routine_transition_count,
        recovery_transition_count,
        latest_policy_sha256,
        latest_policy_version,
        latest_policy_time_status,
    ) = if policies.is_empty() {
        let routine = transitions
            .iter()
            .map(|proof| match proof {
                PersonaContinuityTransitionProof::Routine(proof) => Ok(proof.clone()),
                PersonaContinuityTransitionProof::Recovery(_) => Err(invalid_backup(
                    "a recovery transition requires a recovery policy chain",
                )),
            })
            .collect::<Result<Vec<_>>>()?;
        let report = verify_persona_continuity_chain(
            &archive.root.proof,
            &routine,
            &verified_root.root_statement_sha256,
        )
        .map_err(invalid_continuity)?;
        (
            report.chain_tip_key_fingerprint,
            report.transition_count,
            report.transition_count,
            0,
            None,
            None,
            None,
        )
    } else {
        let latest = verified_policies
            .last()
            .expect("a non-empty policy input produces a non-empty verified chain");
        let report = verify_persona_continuity_chain_with_recovery(
            &archive.root.proof,
            &transitions,
            &policies,
            &verified_root.root_statement_sha256,
            &latest.policy_statement_sha256,
            checked_at,
        )
        .map_err(invalid_continuity)?;
        (
            report.chain_tip_key_fingerprint,
            report.transition_count,
            report.routine_transition_count,
            report.recovery_transition_count,
            Some(report.latest_policy_sha256),
            Some(report.latest_policy_version),
            Some(report.latest_policy_time_status),
        )
    };

    for entry in &archive.transitions {
        match &entry.proof {
            PersonaContinuityTransitionProof::Routine(proof) => {
                for signature in &proof.signatures {
                    let fingerprint = public_key_fingerprint(&signature.public_key)
                        .map_err(invalid_continuity)?;
                    require_backup_proof_key(&keys, &fingerprint, &signature.public_key)?;
                }
            }
            PersonaContinuityTransitionProof::Recovery(proof) => {
                let statement =
                    inspect_recovery_transition_proof(proof).map_err(invalid_continuity)?;
                if !keys.contains_key(statement.previous_key_fingerprint.as_str()) {
                    return Err(StoreError::InvalidContinuity(
                        "recovery transition previous key is absent from backup metadata"
                            .to_owned(),
                    ));
                }
                verified_policies
                    .iter()
                    .find(|policy| {
                        policy.policy_statement_sha256 == statement.recovery_policy_sha256
                            && policy.statement.policy_version == statement.recovery_policy_version
                    })
                    .ok_or_else(|| {
                        StoreError::InvalidContinuity(
                            "recovery transition references a policy outside the archive"
                                .to_owned(),
                        )
                    })?;
                let next_fingerprint = public_key_fingerprint(&proof.next_signature.public_key)
                    .map_err(invalid_continuity)?;
                require_backup_proof_key(
                    &keys,
                    &next_fingerprint,
                    &proof.next_signature.public_key,
                )?;
            }
        }
    }
    let active = backup
        .keys
        .iter()
        .filter(|key| key.status == KeyStatus::Active)
        .map(|key| key.fingerprint.as_str())
        .collect::<Vec<_>>();
    if active.as_slice() != [chain_tip_key_fingerprint.as_str()] {
        return Err(StoreError::InvalidContinuity(
            "derived continuity tip is not the backup's unique active key".to_owned(),
        ));
    }

    let has_policies = !policies.is_empty();
    let mut not_established = vec![
        "when_or_how_the_root_was_pinned".to_owned(),
        "whether_a_newer_or_competing_transition_was_withheld".to_owned(),
        "independent_head_checkpoint_not_checked".to_owned(),
        "current_online_key_non_revocation".to_owned(),
        "signing_or_recovery_authority".to_owned(),
        "trusted_time_for_signed_issuance_or_archive_export".to_owned(),
        "archive_freshness_completeness_or_authorship_as_a_whole".to_owned(),
        "exact_correspondence_between_unsigned_lifecycle_events_and_signed_transitions".to_owned(),
        "cryptographic_binding_of_persona_id_purpose_or_lifecycle_timestamps".to_owned(),
        "legal_or_government_identity".to_owned(),
        "current_signer_custody".to_owned(),
        "artifact_or_software_safety".to_owned(),
    ];
    if has_policies {
        not_established.extend([
            "when_or_how_the_latest_recovery_policy_was_pinned".to_owned(),
            "whether_a_newer_or_competing_recovery_policy_was_withheld".to_owned(),
        ]);
    }
    Ok(Some(BackupContinuityVerificationReport {
        lifecycle_metadata_consistent: true,
        persona_label_binding_verified: true,
        root_signature_verified: true,
        transition_chain_verified: true,
        recovery_policy_chain_verified: has_policies.then_some(true),
        policy_transition_checkpoints_verified: has_policies.then_some(true),
        cryptographic_continuity: true,
        signing_authority: false,
        root_statement_sha256: verified_root.root_statement_sha256,
        chain_tip_key_fingerprint,
        transition_count,
        routine_transition_count,
        recovery_transition_count,
        latest_policy_sha256,
        latest_policy_version,
        latest_policy_time_status,
        checked_at,
        external_root_pin_checked: false,
        external_head_pin_checked: false,
        external_policy_pin_checked: false,
        not_established,
    }))
}

fn require_backup_proof_key(
    keys: &HashMap<&str, &BackupKey>,
    expected_fingerprint: &str,
    proof_public_key: &str,
) -> Result<()> {
    let key = keys.get(expected_fingerprint).ok_or_else(|| {
        StoreError::InvalidContinuity(format!(
            "continuity proof key {expected_fingerprint} is absent from backup metadata"
        ))
    })?;
    let proof_fingerprint = public_key_fingerprint(proof_public_key).map_err(invalid_continuity)?;
    if proof_fingerprint != expected_fingerprint || key.fingerprint != proof_fingerprint {
        return Err(StoreError::InvalidContinuity(
            "continuity proof public key does not match backup key metadata".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HistoryValidationScope {
    LiveStore,
    PortableBackup,
}

fn validate_persona_history(backup: &PersonaBackup, scope: HistoryValidationScope) -> Result<()> {
    let is_v2 = match backup.schema.as_str() {
        PERSONA_BACKUP_V1_SCHEMA => {
            if backup.continuity.is_some() {
                return Err(invalid_backup("schema v1 must omit the continuity field"));
            }
            false
        }
        PERSONA_BACKUP_SCHEMA => {
            if backup.continuity.is_none() {
                return Err(invalid_backup(
                    "schema v2 must include an explicit continuity field",
                ));
            }
            true
        }
        _ => {
            return Err(invalid_backup(format!(
                "unsupported schema {}; expected {PERSONA_BACKUP_V1_SCHEMA} or {PERSONA_BACKUP_SCHEMA}",
                backup.schema
            )));
        }
    };
    if backup.exported_at < 0 {
        return Err(invalid_backup("exported_at cannot be negative"));
    }
    if is_v2 && backup.exported_at > MAX_PORTABLE_JSON_INTEGER {
        return Err(invalid_backup(
            "schema-v2 exported_at is outside the portable JSON integer range",
        ));
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
        if let Some(archived_at) = backup.persona.archived_at
            && key.added_at > archived_at
        {
            return Err(invalid_backup(
                "key.added_at cannot occur after persona.archived_at",
            ));
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
    let mut last_persona_event_time = None;
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
        if matches!(event.event_type.as_str(), "enrolled" | "rotated_in")
            && backup
                .persona
                .archived_at
                .is_some_and(|archived_at| event.occurred_at > archived_at)
        {
            return Err(invalid_backup(
                "authority-granting event cannot occur after persona.archived_at",
            ));
        }
        if is_v2
            && let Some(previous_time) = last_persona_event_time
            && event.occurred_at < previous_time
        {
            return Err(invalid_backup(
                "schema-v2 lifecycle events move backward in persona-wide ordinal order",
            ));
        }
        last_persona_event_time = Some(event.occurred_at);
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
    if let Some(continuity) = &backup.continuity {
        validate_backup_continuity_structure(backup, continuity)?;
    }
    Ok(())
}

fn validate_backup_continuity_structure(
    backup: &PersonaBackup,
    continuity: &BackupContinuity,
) -> Result<()> {
    let BackupContinuity::EvidenceArchive(archive) = continuity else {
        return Ok(());
    };
    if archive.recovery_policies.len() > MAX_PERSONA_BACKUP_RECOVERY_POLICIES {
        return Err(invalid_backup(format!(
            "continuity archive cannot contain more than {MAX_PERSONA_BACKUP_RECOVERY_POLICIES} recovery policies"
        )));
    }
    if archive.transitions.len() > MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS {
        return Err(invalid_backup(format!(
            "continuity archive cannot contain more than {MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS} transitions"
        )));
    }

    validate_observed_time(
        "continuity root observed_at",
        archive.root.observed_at,
        backup,
    )?;
    let root_bytes = serde_json::to_vec(&archive.root.proof)?;
    parse_persona_root_proof_bytes(&root_bytes).map_err(invalid_continuity)?;

    // The current core chain APIs require a first root/policy pass to derive
    // digests and a second pass to verify the complete chain against them.
    let mut signature_count = 2_usize;
    let mut previous_policy_observed_at = archive.root.observed_at;
    for policy in &archive.recovery_policies {
        validate_observed_time("recovery policy observed_at", policy.observed_at, backup)?;
        require_nondecreasing_observation(
            "recovery policy",
            previous_policy_observed_at,
            policy.observed_at,
        )?;
        if policy.observed_at.is_some() {
            previous_policy_observed_at = policy.observed_at;
        }
        let policy_bytes = serde_json::to_vec(&policy.proof)?;
        parse_recovery_policy_proof_bytes(&policy_bytes).map_err(invalid_continuity)?;
        let policy_signatures = match &policy.proof.authorization {
            RecoveryPolicyAuthorization::Enrollment { signatures } => signatures.len(),
            RecoveryPolicyAuthorization::Update {
                previous_policy_signatures,
                current_policy_signatures,
            } => previous_policy_signatures
                .len()
                .checked_add(current_policy_signatures.len())
                .ok_or_else(|| invalid_backup("continuity signature count overflow"))?,
        };
        signature_count = signature_count
            .checked_add(policy_signatures.checked_mul(2).ok_or_else(|| {
                invalid_backup("continuity signature verification count overflow")
            })?)
            .ok_or_else(|| invalid_backup("continuity signature count overflow"))?;
    }

    let mut previous_transition_observed_at = archive.root.observed_at;
    for transition in &archive.transitions {
        validate_observed_time(
            "continuity transition observed_at",
            transition.observed_at,
            backup,
        )?;
        require_nondecreasing_observation(
            "continuity transition",
            previous_transition_observed_at,
            transition.observed_at,
        )?;
        if transition.observed_at.is_some() {
            previous_transition_observed_at = transition.observed_at;
        }
        let proof_bytes = serde_json::to_vec(&transition.proof)?;
        parse_persona_continuity_transition_proof_bytes(&proof_bytes)
            .map_err(invalid_continuity)?;
        let transition_signatures = match &transition.proof {
            PersonaContinuityTransitionProof::Routine(proof) => proof.signatures.len(),
            PersonaContinuityTransitionProof::Recovery(proof) => proof
                .recovery_signatures
                .len()
                .checked_add(1)
                .ok_or_else(|| invalid_backup("continuity signature count overflow"))?,
        };
        signature_count = signature_count
            .checked_add(transition_signatures)
            .ok_or_else(|| invalid_backup("continuity signature count overflow"))?;
    }
    if archive.recovery_policies.is_empty()
        && archive.transitions.iter().any(|transition| {
            matches!(
                transition.proof,
                PersonaContinuityTransitionProof::Recovery(_)
            )
        })
    {
        return Err(invalid_backup(
            "a recovery transition requires a recovery policy chain",
        ));
    }
    if signature_count > MAX_PERSONA_BACKUP_SIGNATURES {
        return Err(invalid_backup(format!(
            "continuity archive cannot require more than {MAX_PERSONA_BACKUP_SIGNATURES} signature verifications"
        )));
    }
    Ok(())
}

fn validate_observed_time(
    field: &str,
    observed_at: Option<i64>,
    backup: &PersonaBackup,
) -> Result<()> {
    if let Some(observed_at) = observed_at {
        validate_backup_time(
            field,
            observed_at,
            backup.persona.created_at,
            backup.exported_at,
        )?;
    }
    Ok(())
}

fn require_nondecreasing_observation(
    evidence: &str,
    previous: Option<i64>,
    current: Option<i64>,
) -> Result<()> {
    if let (Some(previous), Some(current)) = (previous, current)
        && current < previous
    {
        return Err(invalid_backup(format!(
            "{evidence} observation times move backward"
        )));
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
    use std::cell::Cell;
    use std::path::Path;
    use std::process::Command;

    use super::*;
    use a_quo_core::{
        RECOVERY_POLICY_ENROLLMENT_NAMESPACE, RECOVERY_POLICY_PROOF_SCHEMA,
        RecoveryContinuityCheckpoint, RecoverySignature, RecoverySigner,
        canonical_recovery_policy_statement_bytes, create_initial_recovery_policy_proof,
        create_persona_root_proof, create_routine_transition_proof,
        new_initial_recovery_policy_statement, new_persona_root_statement,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

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

    fn routine_archive_backup() -> (PersonaStore, PersonaBackup) {
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
        let backup = store.export_persona_backup(&fixture.persona.id).unwrap();
        (store, backup)
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
    fn v1_remains_compatible_while_v2_requires_explicit_continuity() {
        let v2 = active_backup();
        assert_eq!(v2.schema, PERSONA_BACKUP_SCHEMA);
        assert_eq!(v2.continuity, Some(BackupContinuity::Unmanaged));
        let wire = serde_json::to_value(&v2).unwrap();
        assert_eq!(wire["continuity"]["kind"], "unmanaged");

        let mut v1 = v2.clone();
        v1.schema = PERSONA_BACKUP_V1_SCHEMA.to_owned();
        v1.continuity = None;
        let v1_wire = serde_json::to_vec(&v1).unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&v1_wire)
                .unwrap()
                .get("continuity")
                .is_none()
        );
        assert_eq!(parse_persona_backup_bytes(&v1_wire).unwrap(), v1);
        let mut v1_null = serde_json::to_value(&v1).unwrap();
        v1_null
            .as_object_mut()
            .unwrap()
            .insert("continuity".to_owned(), serde_json::Value::Null);
        assert!(parse_persona_backup_bytes(&serde_json::to_vec(&v1_null).unwrap()).is_err());
        let mut v2_null = wire.clone();
        v2_null
            .as_object_mut()
            .unwrap()
            .insert("continuity".to_owned(), serde_json::Value::Null);
        assert!(parse_persona_backup_bytes(&serde_json::to_vec(&v2_null).unwrap()).is_err());
        let mut v2_missing = wire.clone();
        v2_missing.as_object_mut().unwrap().remove("continuity");
        assert!(parse_persona_backup_bytes(&serde_json::to_vec(&v2_missing).unwrap()).is_err());
        let mut legacy_store = PersonaStore::open_in_memory().unwrap();
        legacy_store.import_persona_backup(&v1).unwrap();
        assert_eq!(
            legacy_store
                .lookup_key(&v1.keys[0].fingerprint)
                .unwrap()
                .unwrap()
                .authority_disposition,
            PersonaAuthorityDisposition::Operational
        );
        assert_eq!(
            legacy_store
                .persona_authority_disposition(&v1.persona.id)
                .unwrap(),
            PersonaAuthorityDisposition::Operational
        );

        let mut missing = v2.clone();
        missing.continuity = None;
        assert!(validate_persona_backup(&missing).is_err());
        let mut nonportable_time = v2.clone();
        nonportable_time.exported_at = MAX_PORTABLE_JSON_INTEGER + 1;
        assert!(validate_persona_backup(&nonportable_time).is_err());
        nonportable_time.schema = PERSONA_BACKUP_V1_SCHEMA.to_owned();
        nonportable_time.continuity = None;
        validate_persona_backup(&nonportable_time).unwrap();
        let mut archived_v1 = v1.clone();
        archived_v1.persona.archived_at = Some(archived_v1.exported_at);
        let mut archived_store = PersonaStore::open_in_memory().unwrap();
        archived_store.import_persona_backup(&archived_v1).unwrap();
        assert_eq!(
            archived_store
                .persona_authority_disposition(&archived_v1.persona.id)
                .unwrap(),
            PersonaAuthorityDisposition::Archived
        );
        assert_eq!(
            archived_store
                .lookup_key(&archived_v1.keys[0].fingerprint)
                .unwrap()
                .unwrap()
                .authority_disposition,
            PersonaAuthorityDisposition::Archived
        );
        archived_store
            .mark_key_compromised(
                &archived_v1.keys[0].fingerprint,
                "archive-reviewer",
                "example.invalid/compromise",
                None,
            )
            .unwrap();
        let archived_key = archived_store
            .lookup_key(&archived_v1.keys[0].fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(archived_key.key.status, KeyStatus::Compromised);
        assert_eq!(
            archived_key.authority_disposition,
            PersonaAuthorityDisposition::Archived
        );
        let mut forbidden = v1;
        forbidden.continuity = Some(BackupContinuity::Unmanaged);
        assert!(validate_persona_backup(&forbidden).is_err());
    }

    #[test]
    fn v2_enforces_persona_wide_event_time_order_without_breaking_v1() {
        let (mut store, persona, _, _) = rotated_history_store();
        let mut backup = store.export_persona_backup(&persona.id).unwrap();
        let base = backup.persona.created_at;
        let first_fingerprint = backup.events[0].key_fingerprint.clone();
        let second_fingerprint = backup.events[2].key_fingerprint.clone();
        backup.exported_at = base + 30;
        let first = backup
            .keys
            .iter_mut()
            .find(|key| key.fingerprint == first_fingerprint)
            .unwrap();
        first.added_at = base;
        first.retired_at = Some(base + 30);
        let second = backup
            .keys
            .iter_mut()
            .find(|key| key.fingerprint == second_fingerprint)
            .unwrap();
        second.added_at = base + 20;
        backup.events[0].occurred_at = base;
        backup.events[1].occurred_at = base + 30;
        backup.events[2].occurred_at = base + 20;

        assert!(validate_persona_backup(&backup).is_err());
        backup.schema = PERSONA_BACKUP_V1_SCHEMA.to_owned();
        backup.continuity = None;
        validate_persona_backup(&backup).unwrap();
    }

    #[test]
    fn archived_at_blocks_later_authority_origins_but_allows_deauthorization() {
        let mut boundary = active_backup();
        boundary.persona.archived_at = Some(boundary.exported_at);
        validate_persona_backup(&boundary).unwrap();
        let mut v1_boundary = boundary.clone();
        v1_boundary.schema = PERSONA_BACKUP_V1_SCHEMA.to_owned();
        v1_boundary.continuity = None;
        validate_persona_backup(&v1_boundary).unwrap();

        let archived_at = boundary.persona.archived_at.unwrap();
        let mut added_after = boundary.clone();
        added_after.exported_at = archived_at + 1;
        added_after.keys[0].added_at = archived_at + 1;
        assert!(
            validate_persona_backup(&added_after)
                .unwrap_err()
                .to_string()
                .contains("key.added_at cannot occur after persona.archived_at")
        );
        let mut retired_after = boundary.clone();
        retired_after.exported_at = archived_at + 1;
        retired_after.keys[0].status = KeyStatus::Retired;
        retired_after.keys[0].retired_at = Some(archived_at + 1);
        retired_after.events.push(BackupKeyEvent {
            ordinal: 2,
            key_fingerprint: retired_after.keys[0].fingerprint.clone(),
            event_type: "retired".to_owned(),
            occurred_at: archived_at + 1,
            actor: "archive-reviewer".to_owned(),
            policy: "example.invalid/retirement".to_owned(),
            note: None,
        });
        validate_persona_backup(&retired_after).unwrap();
        let mut compromised_after = boundary.clone();
        compromised_after.exported_at = archived_at + 1;
        compromised_after.keys[0].status = KeyStatus::Compromised;
        compromised_after.keys[0].compromised_at = Some(archived_at + 1);
        compromised_after.events.push(BackupKeyEvent {
            ordinal: 2,
            key_fingerprint: compromised_after.keys[0].fingerprint.clone(),
            event_type: "compromised".to_owned(),
            occurred_at: archived_at + 1,
            actor: "archive-reviewer".to_owned(),
            policy: "example.invalid/compromise".to_owned(),
            note: None,
        });
        validate_persona_backup(&compromised_after).unwrap();
        let mut event_after = v1_boundary;
        event_after.exported_at = archived_at + 1;
        event_after.events[0].occurred_at = archived_at + 1;
        assert!(
            validate_persona_backup(&event_after)
                .unwrap_err()
                .to_string()
                .contains("authority-granting event cannot occur after persona.archived_at")
        );

        let mut live = PersonaStore::open_in_memory().unwrap();
        let persona = live
            .create_persona("Terminal archive boundary", PersonaPurpose::Project)
            .unwrap();
        live.enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        live.connection
            .execute(
                "UPDATE personas SET archived_at = ?2 WHERE id = ?1",
                params![persona.id, persona.created_at],
            )
            .unwrap();
        live.connection
            .execute(
                "UPDATE key_records SET added_at = ?2 WHERE persona_id = ?1",
                params![persona.id, persona.created_at + 1],
            )
            .unwrap();
        live.connection
            .execute_batch("DROP TRIGGER key_events_no_update")
            .unwrap();
        live.connection
            .execute(
                "UPDATE key_events SET occurred_at = ?2 WHERE persona_id = ?1",
                params![persona.id, persona.created_at + 1],
            )
            .unwrap();
        assert!(matches!(
            live.list_keys(&persona.id),
            Err(StoreError::InvalidAuditHistory)
        ));
    }

    #[test]
    fn v2_archive_round_trips_as_verified_evidence_without_signing_authority() {
        let (mut live_source, live_backup) = routine_archive_backup();
        let archive = match &live_backup.continuity {
            Some(BackupContinuity::EvidenceArchive(archive)) => archive.clone(),
            other => panic!("expected evidence archive, got {other:?}"),
        };
        assert!(archive.recovery_policies.is_empty());
        assert_eq!(archive.transitions.len(), 1);
        let report = verify_persona_backup_continuity_at(&live_backup, live_backup.exported_at)
            .unwrap()
            .unwrap();
        assert!(report.lifecycle_metadata_consistent);
        assert!(report.persona_label_binding_verified);
        assert!(report.root_signature_verified);
        assert!(report.transition_chain_verified);
        assert_eq!(report.recovery_policy_chain_verified, None);
        assert_eq!(report.policy_transition_checkpoints_verified, None);
        assert_eq!(report.latest_policy_time_status, None);
        assert!(report.cryptographic_continuity);
        assert!(!report.signing_authority);
        assert!(!report.external_root_pin_checked);
        assert!(!report.external_head_pin_checked);
        assert!(!report.external_policy_pin_checked);
        assert!(report.not_established.iter().any(|claim| {
            claim == "cryptographic_binding_of_persona_id_purpose_or_lifecycle_timestamps"
        }));
        let mut changed_purpose = live_backup.clone();
        changed_purpose.persona.purpose = PersonaPurpose::Personal;
        assert!(
            verify_persona_backup_continuity(&changed_purpose)
                .unwrap()
                .unwrap()
                .persona_label_binding_verified
        );
        let mut changed_id = live_backup.clone();
        changed_id.persona.id = Uuid::new_v4().to_string();
        let changed_id_report = verify_persona_backup_continuity(&changed_id)
            .unwrap()
            .unwrap();
        assert!(changed_id_report.persona_label_binding_verified);
        assert!(changed_id_report.not_established.iter().any(|claim| {
            claim == "cryptographic_binding_of_persona_id_purpose_or_lifecycle_timestamps"
        }));
        assert_eq!(
            live_source
                .lookup_key(&report.chain_tip_key_fingerprint)
                .unwrap()
                .unwrap()
                .authority_disposition,
            PersonaAuthorityDisposition::Operational
        );
        assert_eq!(
            live_source
                .persona_authority_disposition(&live_backup.persona.id)
                .unwrap(),
            PersonaAuthorityDisposition::Operational
        );

        let wire = serde_json::to_value(&live_backup).unwrap();
        assert_eq!(wire["continuity"]["kind"], "evidence_archive");
        assert_eq!(
            wire["continuity"]["archive"]["transitions"][0]["proof"]["kind"],
            "routine"
        );
        let wire_text = serde_json::to_string(&wire).unwrap();
        assert!(!wire_text.contains("signing_reference"));
        assert!(!wire_text.contains("revision"));

        assert!(matches!(
            live_source
                .export_persona_backup_with_archive(&live_backup.persona.id, Some(archive.clone())),
            Err(StoreError::ContinuityConflict(_))
        ));

        // Simulate the CLI attaching separately supplied public evidence to
        // matching legacy metadata. Supplying evidence changes only the
        // returned backup; it does not silently adopt authority into the store.
        let mut legacy = live_backup.clone();
        legacy.schema = PERSONA_BACKUP_V1_SCHEMA.to_owned();
        legacy.continuity = None;
        let mut unmanaged = PersonaStore::open_in_memory().unwrap();
        unmanaged.import_persona_backup(&legacy).unwrap();
        let attached = unmanaged
            .export_persona_backup_with_archive(&legacy.persona.id, Some(archive.clone()))
            .unwrap();
        assert_eq!(
            attached.continuity,
            Some(BackupContinuity::EvidenceArchive(archive.clone()))
        );
        assert_eq!(
            unmanaged
                .export_persona_backup(&legacy.persona.id)
                .unwrap()
                .continuity,
            Some(BackupContinuity::Unmanaged)
        );

        let mut archived_attached = attached.clone();
        archived_attached.persona.archived_at = Some(archived_attached.exported_at);
        let mut archived_evidence = PersonaStore::open_in_memory().unwrap();
        archived_evidence
            .import_persona_backup(&archived_attached)
            .unwrap();
        assert_eq!(
            archived_evidence
                .persona_authority_disposition(&archived_attached.persona.id)
                .unwrap(),
            PersonaAuthorityDisposition::EvidenceOnly
        );
        let recognized = archived_evidence
            .lookup_key(&report.chain_tip_key_fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(
            recognized.authority_disposition,
            PersonaAuthorityDisposition::EvidenceOnly
        );
        assert_eq!(
            recognized.persona.archived_at,
            Some(archived_attached.exported_at)
        );
        assert!(matches!(
            archived_evidence.enroll_key(
                &archived_attached.persona.id,
                &synthetic_ed25519_public_key(902),
                KeyProvider::OpensshFile
            ),
            Err(StoreError::ContinuityEvidenceOnly(id))
                if id == archived_attached.persona.id
        ));
        assert!(matches!(
            archived_evidence.rotate_key(
                &archived_attached.persona.id,
                &synthetic_ed25519_public_key(903),
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                None
            ),
            Err(StoreError::ContinuityEvidenceOnly(id))
                if id == archived_attached.persona.id
        ));
        let archived_historical = archived_attached
            .keys
            .iter()
            .find(|key| key.status == KeyStatus::Retired)
            .unwrap()
            .fingerprint
            .clone();
        archived_evidence
            .mark_key_compromised(
                &archived_historical,
                "archive-reviewer",
                "example.invalid/historical-compromise",
                None,
            )
            .unwrap();
        assert_eq!(
            archived_evidence
                .persona_authority_disposition(&archived_attached.persona.id)
                .unwrap(),
            PersonaAuthorityDisposition::EvidenceOnly
        );

        let verified_import = verify_persona_backup_for_import(&attached).unwrap();
        let mut restored = PersonaStore::open_in_memory().unwrap();
        let (_, imported_report) = restored
            .import_verified_persona_backup(verified_import)
            .unwrap();
        assert_eq!(
            imported_report.unwrap().chain_tip_key_fingerprint,
            report.chain_tip_key_fingerprint
        );
        let persona_id = attached.persona.id.as_str();
        assert_eq!(
            restored
                .lookup_key(&report.chain_tip_key_fingerprint)
                .unwrap()
                .unwrap()
                .authority_disposition,
            PersonaAuthorityDisposition::EvidenceOnly
        );
        assert_eq!(
            restored.persona_authority_disposition(persona_id).unwrap(),
            PersonaAuthorityDisposition::EvidenceOnly
        );
        assert!(matches!(
            restored.export_persona_backup_with_archive(persona_id, Some(archive.clone())),
            Err(StoreError::ContinuityConflict(_))
        ));
        assert!(matches!(
            restored.enroll_key(
                persona_id,
                &synthetic_ed25519_public_key(900),
                KeyProvider::OpensshFile
            ),
            Err(StoreError::ContinuityEvidenceOnly(id)) if id == persona_id
        ));
        assert!(matches!(
            restored.rotate_key(
                persona_id,
                &synthetic_ed25519_public_key(901),
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                None
            ),
            Err(StoreError::ContinuityEvidenceOnly(id)) if id == persona_id
        ));
        assert!(matches!(
            restored.bind_signing_reference(
                &report.chain_tip_key_fingerprint,
                Path::new("/does/not/need/to/exist")
            ),
            Err(StoreError::ContinuityEvidenceOnly(id)) if id == persona_id
        ));
        assert!(matches!(
            restored.active_signer_for_persona(persona_id),
            Err(StoreError::ContinuityEvidenceOnly(id)) if id == persona_id
        ));
        let verified_root = verify_persona_root_proof(&archive.root.proof).unwrap();
        assert!(matches!(
            restored.record_continuity_root(
                persona_id,
                &archive.root.proof,
                &verified_root.root_statement_sha256
            ),
            Err(StoreError::ContinuityEvidenceOnly(id)) if id == persona_id
        ));
        assert!(matches!(
            restored.mark_key_compromised(
                &report.chain_tip_key_fingerprint,
                "archive-reviewer",
                "example.invalid/compromise",
                None
            ),
            Err(StoreError::ContinuityEvidenceOnly(id)) if id == persona_id
        ));

        let historical = attached
            .keys
            .iter()
            .find(|key| key.status == KeyStatus::Retired)
            .unwrap()
            .fingerprint
            .clone();
        restored
            .mark_key_compromised(
                &historical,
                "archive-reviewer",
                "example.invalid/historical-compromise",
                None,
            )
            .unwrap();
        let reexported = restored.export_persona_backup(persona_id).unwrap();
        assert_eq!(
            reexported.continuity,
            Some(BackupContinuity::EvidenceArchive(archive))
        );
        assert!(
            verify_persona_backup_continuity(&reexported)
                .unwrap()
                .is_some()
        );
        let signer_count: i64 = restored
            .connection
            .query_row("SELECT count(*) FROM signing_references", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(signer_count, 0);
    }

    #[test]
    fn active_key_authorization_guard_invokes_only_for_fresh_operational_state() {
        let mut operational = PersonaStore::open_in_memory().unwrap();
        let persona = operational
            .create_persona("Atomic publisher", PersonaPurpose::Project)
            .unwrap();
        let key = operational
            .enroll_key(&persona.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        let invoked = Cell::new(false);
        let authorized = operational
            .with_active_key_authorization::<_, StoreError>(
                &key.fingerprint,
                &persona.label,
                |recognized| {
                    invoked.set(true);
                    Ok(recognized.persona.id.clone())
                },
            )
            .unwrap();
        assert!(invoked.get());
        assert_eq!(authorized, persona.id);

        invoked.set(false);
        assert!(matches!(
            operational.with_active_key_authorization::<(), StoreError>(
                &key.fingerprint,
                "Different signed label",
                |_| {
                    invoked.set(true);
                    Ok(())
                }
            ),
            Err(StoreError::PersonaLabelMismatch(fingerprint))
                if fingerprint == key.fingerprint
        ));
        assert!(!invoked.get());

        let mut archived_backup = active_backup();
        archived_backup.persona.archived_at = Some(archived_backup.exported_at);
        let mut archived = PersonaStore::open_in_memory().unwrap();
        archived.import_persona_backup(&archived_backup).unwrap();
        invoked.set(false);
        assert!(matches!(
            archived.with_active_key_authorization::<(), StoreError>(
                &archived_backup.keys[0].fingerprint,
                &archived_backup.persona.label,
                |_| {
                    invoked.set(true);
                    Ok(())
                }
            ),
            Err(StoreError::PersonaArchived(id)) if id == archived_backup.persona.id
        ));
        assert!(!invoked.get());

        let (_, evidence_backup) = routine_archive_backup();
        let evidence_tip = verify_persona_backup_continuity(&evidence_backup)
            .unwrap()
            .unwrap()
            .chain_tip_key_fingerprint;
        let mut evidence = PersonaStore::open_in_memory().unwrap();
        evidence.import_persona_backup(&evidence_backup).unwrap();
        invoked.set(false);
        assert!(matches!(
            evidence.with_active_key_authorization::<(), StoreError>(
                &evidence_tip,
                &evidence_backup.persona.label,
                |_| {
                    invoked.set(true);
                    Ok(())
                }
            ),
            Err(StoreError::ContinuityEvidenceOnly(id)) if id == evidence_backup.persona.id
        ));
        assert!(!invoked.get());

        let (mut retired_store, retired_persona, retired, _) = rotated_history_store();
        invoked.set(false);
        assert!(matches!(
            retired_store.with_active_key_authorization::<(), StoreError>(
                &retired.fingerprint,
                &retired_persona.label,
                |_| {
                    invoked.set(true);
                    Ok(())
                }
            ),
            Err(StoreError::InactiveSigningKey(fingerprint))
                if fingerprint == retired.fingerprint
        ));
        assert!(!invoked.get());
    }

    #[test]
    fn bulk_persona_listing_is_noncryptographic_and_never_claims_operational() {
        let mut ordinary = PersonaStore::open_in_memory().unwrap();
        let ordinary_persona = ordinary
            .create_persona("Ordinary listing", PersonaPurpose::Project)
            .unwrap();
        let ordinary_rows = ordinary.list_personas_with_listing_authority().unwrap();
        assert_eq!(ordinary_rows.len(), 1);
        assert_eq!(ordinary_rows[0].persona, ordinary_persona);
        assert_eq!(
            ordinary_rows[0].authority_disposition,
            PersonaListingAuthorityDisposition::NotChecked
        );

        let mut archived_backup = active_backup();
        archived_backup.schema = PERSONA_BACKUP_V1_SCHEMA.to_owned();
        archived_backup.continuity = None;
        archived_backup.persona.archived_at = Some(archived_backup.exported_at);
        let mut archived = PersonaStore::open_in_memory().unwrap();
        archived.import_persona_backup(&archived_backup).unwrap();
        assert_eq!(
            archived.list_personas_with_listing_authority().unwrap()[0].authority_disposition,
            PersonaListingAuthorityDisposition::Archived
        );

        let (_, mut evidence_backup) = routine_archive_backup();
        evidence_backup.persona.archived_at = Some(evidence_backup.exported_at);
        let mut evidence = PersonaStore::open_in_memory().unwrap();
        evidence.import_persona_backup(&evidence_backup).unwrap();
        let evidence_rows = evidence.list_personas_with_listing_authority().unwrap();
        assert_eq!(evidence_rows.len(), 1);
        assert!(evidence_rows[0].persona.archived_at.is_some());
        assert_eq!(
            evidence_rows[0].authority_disposition,
            PersonaListingAuthorityDisposition::EvidenceOnly
        );

        let Some(BackupContinuity::EvidenceArchive(mut archive)) = evidence_backup.continuity
        else {
            panic!("expected evidence archive");
        };
        archive.root.proof.signature.value.replace_range(0..1, "X");
        evidence
            .connection
            .execute_batch("DROP TRIGGER persona_continuity_archives_no_update")
            .unwrap();
        evidence
            .connection
            .execute(
                "UPDATE persona_continuity_archives SET archive_json = ?2
                 WHERE persona_id = ?1",
                params![
                    evidence_backup.persona.id,
                    serde_json::to_vec(&archive).unwrap()
                ],
            )
            .unwrap();
        assert_eq!(
            evidence.list_personas_with_listing_authority().unwrap()[0].authority_disposition,
            PersonaListingAuthorityDisposition::EvidenceOnly
        );
        assert!(matches!(
            evidence.persona_authority_disposition(&evidence_backup.persona.id),
            Err(StoreError::InvalidContinuity(_))
        ));
    }

    #[test]
    fn lookup_key_with_history_returns_one_validated_evidence_snapshot() {
        let (_, backup) = routine_archive_backup();
        let active_fingerprint = backup
            .keys
            .iter()
            .find(|key| key.status == KeyStatus::Active)
            .unwrap()
            .fingerprint
            .clone();
        let mut store = PersonaStore::open_in_memory().unwrap();
        store.import_persona_backup(&backup).unwrap();

        let (recognized, events) = store
            .lookup_key_with_history(&active_fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(recognized.persona.id, backup.persona.id);
        assert_eq!(recognized.key.fingerprint, active_fingerprint);
        assert_eq!(
            recognized.authority_disposition,
            PersonaAuthorityDisposition::EvidenceOnly
        );
        assert_eq!(events.len(), backup.events.len());
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            backup
                .events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            store
                .lookup_key_with_history("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn v5_archive_storage_is_immutable_exclusive_and_reverified_on_selected_reads() {
        let (live, backup) = routine_archive_backup();
        let archive = match &backup.continuity {
            Some(BackupContinuity::EvidenceArchive(archive)) => archive.clone(),
            other => panic!("expected evidence archive, got {other:?}"),
        };
        let archive_json = serde_json::to_vec(&archive).unwrap();

        // The reciprocal insert trigger rejects an archive beside an
        // operational root even if a caller bypasses the Rust API.
        assert!(
            live.connection
                .execute(
                    "INSERT INTO persona_continuity_archives
                     (persona_id, archive_json, imported_at) VALUES (?1, ?2, ?3)",
                    params![backup.persona.id, archive_json, backup.exported_at],
                )
                .is_err()
        );

        let mut quarantined = PersonaStore::open_in_memory().unwrap();
        quarantined.import_persona_backup(&backup).unwrap();
        let original_archive_row: (Vec<u8>, i64) = quarantined
            .connection
            .query_row(
                "SELECT archive_json, imported_at FROM persona_continuity_archives
                 WHERE persona_id = ?1",
                [&backup.persona.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            quarantined
                .connection
                .execute(
                    "INSERT OR REPLACE INTO persona_continuity_archives
                     (persona_id, archive_json, imported_at) VALUES (?1, ?2, ?3)",
                    params![
                        backup.persona.id,
                        b"{}".as_slice(),
                        original_archive_row.1 + 1
                    ],
                )
                .is_err()
        );
        let unchanged_archive_row: (Vec<u8>, i64) = quarantined
            .connection
            .query_row(
                "SELECT archive_json, imported_at FROM persona_continuity_archives
                 WHERE persona_id = ?1",
                [&backup.persona.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(unchanged_archive_row, original_archive_row);
        assert!(
            quarantined
                .connection
                .execute(
                    "UPDATE persona_continuity_archives SET imported_at = imported_at + 1
                     WHERE persona_id = ?1",
                    [&backup.persona.id],
                )
                .is_err()
        );
        assert!(
            quarantined
                .connection
                .execute(
                    "DELETE FROM persona_continuity_archives WHERE persona_id = ?1",
                    [&backup.persona.id],
                )
                .is_err()
        );

        let verified_root = verify_persona_root_proof(&archive.root.proof).unwrap();
        let root_proof_json = serde_json::to_vec(&archive.root.proof).unwrap();
        assert!(
            quarantined
                .connection
                .execute(
                    "INSERT INTO persona_continuity_roots
                     (persona_id, root_statement_sha256, persona_anchor,
                      initial_key_fingerprint, root_proof_json, issued_at, recorded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        backup.persona.id,
                        verified_root.root_statement_sha256,
                        verified_root.statement.persona_anchor,
                        verified_root.statement.initial_key_fingerprint,
                        root_proof_json,
                        verified_root.statement.issued_at,
                        archive
                            .root
                            .observed_at
                            .unwrap_or(backup.persona.created_at),
                    ],
                )
                .is_err()
        );
        quarantined
            .connection
            .execute_batch("DROP TRIGGER persona_continuity_roots_no_evidence_archive")
            .unwrap();
        quarantined
            .connection
            .execute(
                "INSERT INTO persona_continuity_roots
                 (persona_id, root_statement_sha256, persona_anchor,
                  initial_key_fingerprint, root_proof_json, issued_at, recorded_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    backup.persona.id,
                    verified_root.root_statement_sha256,
                    verified_root.statement.persona_anchor,
                    verified_root.statement.initial_key_fingerprint,
                    root_proof_json,
                    verified_root.statement.issued_at,
                    archive
                        .root
                        .observed_at
                        .unwrap_or(backup.persona.created_at),
                ],
            )
            .unwrap();
        assert!(matches!(
            PersonaStore::initialize(quarantined.connection),
            Err(StoreError::InvalidContinuity(_))
        ));

        let mut corrupt = PersonaStore::open_in_memory().unwrap();
        corrupt.import_persona_backup(&backup).unwrap();
        let unrelated = corrupt
            .create_persona("Unrelated operational persona", PersonaPurpose::Project)
            .unwrap();
        corrupt
            .enroll_key(&unrelated.id, KEY_ONE, KeyProvider::OpensshFile)
            .unwrap();
        corrupt
            .connection
            .execute_batch("DROP TRIGGER persona_continuity_archives_no_update")
            .unwrap();
        let mut tampered_archive = archive;
        tampered_archive
            .root
            .proof
            .signature
            .value
            .replace_range(0..1, "X");
        corrupt
            .connection
            .execute(
                "UPDATE persona_continuity_archives SET archive_json = ?2
                 WHERE persona_id = ?1",
                params![
                    backup.persona.id,
                    serde_json::to_vec(&tampered_archive).unwrap()
                ],
            )
            .unwrap();
        // Opening performs one non-cryptographic exclusivity query, not an
        // unbounded global signature sweep over unrelated archives.
        let reopened = PersonaStore::initialize(corrupt.connection).unwrap();
        assert_eq!(reopened.list_keys(&unrelated.id).unwrap().len(), 1);
        assert!(matches!(
            reopened.list_keys(&backup.persona.id),
            Err(StoreError::InvalidContinuity(_))
        ));
        assert!(matches!(
            reopened.persona_authority_disposition(&backup.persona.id),
            Err(StoreError::InvalidContinuity(_))
        ));
    }

    #[test]
    fn cryptographically_tampered_archive_import_rolls_back_all_state() {
        let (_, mut backup) = routine_archive_backup();
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut backup.continuity else {
            panic!("expected evidence archive");
        };
        archive.root.proof.signature.value.replace_range(0..1, "X");
        validate_persona_backup(&backup).unwrap();

        let mut destination = PersonaStore::open_in_memory().unwrap();
        assert!(matches!(
            destination.import_persona_backup(&backup),
            Err(StoreError::InvalidContinuity(_))
        ));
        assert!(destination.list_personas().unwrap().is_empty());
        let archive_count: i64 = destination
            .connection
            .query_row(
                "SELECT count(*) FROM persona_continuity_archives",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(archive_count, 0);
    }

    #[test]
    fn preopen_tamper_rejection_leaves_populated_v4_store_byte_exact() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy-v4.sqlite3");
        let persona_id = Uuid::new_v4().to_string();
        let key_fingerprint = fingerprint(KEY_ONE).unwrap();
        {
            let mut connection = Connection::open(&path).unwrap();
            migrate_v1(&mut connection).unwrap();
            migrate_v2(&mut connection).unwrap();
            migrate_v3(&mut connection).unwrap();
            migrate_v4(&mut connection).unwrap();
            connection
                .execute(
                    "INSERT INTO personas (id, label, purpose, created_at)
                     VALUES (?1, 'Unmigrated publisher', 'project', 1)",
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
        }
        let before = fs::read(&path).unwrap();

        let (_, mut tampered) = routine_archive_backup();
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut tampered.continuity else {
            panic!("expected evidence archive");
        };
        archive.root.proof.signature.value.replace_range(0..1, "X");
        assert!(matches!(
            verify_persona_backup_for_import(&tampered),
            Err(StoreError::InvalidContinuity(_))
        ));

        assert_eq!(fs::read(&path).unwrap(), before);
        let connection = Connection::open(&path).unwrap();
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 4);
        let content: (String, i64, i64) = connection
            .query_row(
                "SELECT p.label,
                        (SELECT count(*) FROM key_records),
                        (SELECT count(*) FROM key_events)
                 FROM personas p WHERE p.id = ?1",
                [&persona_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(content, ("Unmigrated publisher".to_owned(), 1, 1));
    }

    #[test]
    fn imported_future_observation_times_survive_destination_clock_skew() {
        let (_, mut backup) = routine_archive_backup();
        let future_observation = backup.exported_at + 3_600;
        backup.exported_at = future_observation;
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut backup.continuity else {
            panic!("expected evidence archive");
        };
        archive.root.observed_at = Some(future_observation);
        for transition in &mut archive.transitions {
            transition.observed_at = Some(future_observation);
        }
        validate_persona_backup(&backup).unwrap();

        let mut restored = PersonaStore::open_in_memory().unwrap();
        restored.import_persona_backup(&backup).unwrap();
        let reexported = restored.export_persona_backup(&backup.persona.id).unwrap();
        assert_eq!(reexported.exported_at, future_observation);
        assert_eq!(reexported.continuity, backup.continuity);
        verify_persona_backup_continuity(&reexported)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn recovery_policy_time_status_uses_explicit_verifier_time_not_export_time() {
        let directory = tempfile::tempdir().unwrap();
        let (online_path, online_public_key) = generate_key(directory.path(), "online-key");
        let (first_recovery_path, first_recovery_public_key) =
            generate_key(directory.path(), "first-recovery-key");
        let (second_recovery_path, second_recovery_public_key) =
            generate_key(directory.path(), "second-recovery-key");
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Recovery-aware publisher", PersonaPurpose::Project)
            .unwrap();
        let online = store
            .enroll_key(&persona.id, &online_public_key, KeyProvider::OpensshFile)
            .unwrap();
        let root_statement =
            new_persona_root_statement(&persona.label, 100, &online_public_key).unwrap();
        let root_proof =
            create_persona_root_proof(root_statement, &online_path, &online_public_key).unwrap();
        let verified_root = verify_persona_root_proof(&root_proof).unwrap();
        store
            .record_continuity_root(
                &persona.id,
                &root_proof,
                &verified_root.root_statement_sha256,
            )
            .unwrap();
        let authorities = vec![
            first_recovery_public_key.clone(),
            second_recovery_public_key.clone(),
        ];
        let policy_statement = new_initial_recovery_policy_statement(
            &verified_root,
            &authorities,
            2,
            RecoveryContinuityCheckpoint {
                transition_sequence: 0,
                transition_sha256: None,
            },
            200,
            300,
        )
        .unwrap();
        let policy_proof = create_initial_recovery_policy_proof(
            policy_statement,
            &[
                RecoverySigner {
                    private_key_path: first_recovery_path,
                    public_key: first_recovery_public_key,
                },
                RecoverySigner {
                    private_key_path: second_recovery_path,
                    public_key: second_recovery_public_key,
                },
            ],
        )
        .unwrap();
        let mut backup = store.export_persona_backup(&persona.id).unwrap();
        assert_eq!(
            backup
                .keys
                .iter()
                .find(|key| key.fingerprint == online.fingerprint)
                .unwrap()
                .status,
            KeyStatus::Active
        );
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut backup.continuity else {
            panic!("expected evidence archive");
        };
        archive
            .recovery_policies
            .push(BackupRecoveryPolicyEvidence {
                proof: policy_proof,
                observed_at: archive.root.observed_at,
            });
        validate_persona_backup(&backup).unwrap();

        for (checked_at, expected) in [
            (199, RecoveryPolicyTimeStatus::NotYetValid),
            (250, RecoveryPolicyTimeStatus::Active),
            (301, RecoveryPolicyTimeStatus::Expired),
        ] {
            let report = verify_persona_backup_continuity_at(&backup, checked_at)
                .unwrap()
                .unwrap();
            assert_eq!(report.checked_at, checked_at);
            assert_eq!(report.latest_policy_time_status, Some(expected));
            assert_eq!(report.recovery_policy_chain_verified, Some(true));
            assert_eq!(report.policy_transition_checkpoints_verified, Some(true));
        }
        assert!(verify_persona_backup_continuity_at(&backup, -1).is_err());
    }

    #[test]
    fn archive_structural_caps_and_signature_work_budget_are_fail_closed() {
        let (_, backup) = routine_archive_backup();

        let mut transition_boundary = backup.clone();
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut transition_boundary.continuity
        else {
            panic!("expected evidence archive");
        };
        let transition = archive.transitions[0].clone();
        archive.transitions.resize(
            MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS,
            transition.clone(),
        );
        validate_persona_backup(&transition_boundary).unwrap();
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut transition_boundary.continuity
        else {
            unreachable!();
        };
        archive.transitions.push(transition);
        assert!(validate_persona_backup(&transition_boundary).is_err());

        // Construct a structurally valid 32-authority enrollment proof with
        // inert signature text. Structural validation must count the exact
        // later verification work and reject before any signature process is
        // launched; cryptographic validity is intentionally irrelevant here.
        let mut signature_boundary = backup;
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut signature_boundary.continuity
        else {
            panic!("expected evidence archive");
        };
        let verified_root = verify_persona_root_proof(&archive.root.proof).unwrap();
        let authority_keys = (10_000..10_032)
            .map(synthetic_ed25519_public_key)
            .collect::<Vec<_>>();
        let statement = new_initial_recovery_policy_statement(
            &verified_root,
            &authority_keys,
            2,
            RecoveryContinuityCheckpoint {
                transition_sequence: 0,
                transition_sha256: None,
            },
            100,
            101,
        )
        .unwrap();
        let proof = RecoveryPolicyProof {
            schema: RECOVERY_POLICY_PROOF_SCHEMA.to_owned(),
            payload: URL_SAFE_NO_PAD
                .encode(canonical_recovery_policy_statement_bytes(&statement).unwrap()),
            authorization: RecoveryPolicyAuthorization::Enrollment {
                signatures: authority_keys
                    .into_iter()
                    .map(|public_key| RecoverySignature {
                        format: "sshsig".to_owned(),
                        namespace: RECOVERY_POLICY_ENROLLMENT_NAMESPACE.to_owned(),
                        value: "structural-test-only".to_owned(),
                        public_key_format: "openssh-public-key".to_owned(),
                        public_key,
                    })
                    .collect(),
            },
        };
        let evidence = BackupRecoveryPolicyEvidence {
            proof,
            observed_at: archive.root.observed_at,
        };
        archive.recovery_policies = vec![evidence.clone(); 31];
        validate_persona_backup(&signature_boundary).unwrap();
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut signature_boundary.continuity
        else {
            unreachable!();
        };
        archive.recovery_policies.push(evidence);
        assert!(matches!(
            validate_persona_backup(&signature_boundary),
            Err(StoreError::InvalidField {
                field: "persona backup",
                ..
            })
        ));
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut signature_boundary.continuity
        else {
            unreachable!();
        };
        let evidence = archive.recovery_policies[0].clone();
        archive
            .recovery_policies
            .resize(MAX_PERSONA_BACKUP_RECOVERY_POLICIES + 1, evidence);
        let error = validate_persona_backup(&signature_boundary).unwrap_err();
        assert!(error.to_string().contains("256 recovery policies"));
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
        backup.schema = "urn:a-quo:persona-metadata-backup:v999".to_owned();
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
    fn production_backup_byte_parser_round_trips_validated_metadata() {
        let backup = active_backup();
        let bytes = serde_json::to_vec_pretty(&backup).unwrap();

        assert_eq!(parse_persona_backup_bytes(&bytes).unwrap(), backup);
    }

    #[test]
    fn tracked_backup_fuzz_seeds_reach_their_intended_parser_outcomes() {
        let seed_directory =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/persona_backup_bytes");
        if !seed_directory.is_dir() {
            // The fuzz workspace is deliberately outside the publishable store crate.
            return;
        }

        for name in [
            "active_key",
            "recovery_and_compromise",
            "v2_unmanaged",
            "v2_evidence_archive_routine",
            "v2_evidence_archive_recovery",
        ] {
            let bytes = fs::read(seed_directory.join(name)).unwrap();
            parse_persona_backup_bytes(&bytes).unwrap();
        }

        for name in [
            "hostile_unknown_field",
            "v2_missing_continuity",
            "v2_unknown_continuity_tag",
        ] {
            let hostile = fs::read(seed_directory.join(name)).unwrap();
            assert!(parse_persona_backup_bytes(&hostile).is_err(), "seed {name}");
        }

        let recovery = fs::read(seed_directory.join("v2_evidence_archive_recovery")).unwrap();
        let mut recovery = parse_persona_backup_bytes(&recovery).unwrap();
        let Some(BackupContinuity::EvidenceArchive(archive)) = &mut recovery.continuity else {
            panic!("expected recovery archive seed");
        };
        archive.recovery_policies.clear();
        assert!(validate_persona_backup(&recovery).is_err());
    }

    #[test]
    fn production_backup_byte_parser_bounds_input_and_hides_hostile_fields() {
        let oversized = vec![b' '; usize::try_from(MAX_PERSONA_BACKUP_BYTES).unwrap() + 1];
        let oversized_error = parse_persona_backup_bytes(&oversized).unwrap_err();
        assert!(
            oversized_error
                .to_string()
                .contains("backup exceeds 4194304 bytes")
        );

        let hostile = br#"{"\u0001\u202e-hostile-field":true}"#;
        let parse_error = parse_persona_backup_bytes(hostile).unwrap_err();
        let rendered = parse_error.to_string();
        assert!(
            rendered
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
            "unsafe diagnostic: {rendered:?}"
        );
        assert!(!rendered.contains("hostile-field"));
        assert!(rendered.len() <= 256);

        for input in [
            b"{".as_slice(),
            br#"{"schema":"first","schema":"second"}"#.as_slice(),
        ] {
            let rendered = parse_persona_backup_bytes(input).unwrap_err().to_string();
            assert!(
                rendered
                    .bytes()
                    .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
                "unsafe diagnostic: {rendered:?}"
            );
            assert!(rendered.len() <= 256);
        }
    }

    #[test]
    fn production_backup_parser_rejects_event_limit_plus_one() {
        let mut backup = active_backup();
        backup.events = vec![backup.events[0].clone(); MAX_PERSONA_BACKUP_EVENTS + 1];

        let validation_error = validate_persona_backup(&backup).unwrap_err();
        assert!(
            validation_error
                .to_string()
                .contains("events cannot contain more than 4096 entries")
        );

        let bytes = serde_json::to_vec(&backup).unwrap();
        assert!(u64::try_from(bytes.len()).unwrap() <= MAX_PERSONA_BACKUP_BYTES);
        let parser_error = parse_persona_backup_bytes(&bytes).unwrap_err();
        assert!(
            parser_error
                .to_string()
                .contains("events cannot contain more than 4096 entries")
        );
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
        assert_eq!(version, 4);
        migrate_v5(&mut connection).unwrap();
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
