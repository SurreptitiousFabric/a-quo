use std::path::Path;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    EvidenceStatus, ProofError, Result, decode_payload, normalize_public_key,
    public_key_fingerprint, sshsig_sign, sshsig_verify, validate_key_fingerprint, validate_persona,
};

pub const PERSONA_ROOT_STATEMENT_SCHEMA: &str = "urn:a-quo:statement:persona-root:v1";
pub const PERSONA_ROOT_PROOF_SCHEMA: &str = "urn:a-quo:proof:persona-root:sshsig:v1";
pub const PERSONA_ROOT_NAMESPACE: &str = "a-quo-persona-root-v1";
pub const PERSONA_TRANSITION_STATEMENT_SCHEMA: &str = "urn:a-quo:statement:persona-transition:v1";
pub const PERSONA_TRANSITION_PROOF_SCHEMA: &str = "urn:a-quo:proof:persona-transition:sshsig:v1";
pub const PERSONA_TRANSITION_NAMESPACE: &str = "a-quo-persona-transition-v1";
pub const CONTINUITY_CANONICALIZATION: &str = "RFC8785";
pub const MAX_CONTINUITY_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_CONTINUITY_TRANSITIONS: usize = 4_096;

const PERSONA_ANCHOR_BYTES: usize = 32;
const MAX_CONTINUITY_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_JCS_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const SHA256_HEX_BYTES: usize = 64;
const SIGNATURE_FORMAT: &str = "sshsig";
const PUBLIC_KEY_FORMAT: &str = "openssh-public-key";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaRootStatement {
    pub schema: String,
    pub canonicalization: String,
    pub persona_anchor: String,
    pub persona: String,
    pub root_version: u32,
    pub issued_at: i64,
    pub initial_key_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaRootProof {
    pub schema: String,
    pub payload: String,
    pub signature: ContinuitySignature,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuitySignatureRole {
    Root,
    Previous,
    Next,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuitySignature {
    pub role: ContinuitySignatureRole,
    pub format: String,
    pub namespace: String,
    pub value: String,
    pub public_key_format: String,
    pub public_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaTransitionReason {
    Routine,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaTransitionStatement {
    pub schema: String,
    pub canonicalization: String,
    pub persona_anchor: String,
    pub persona: String,
    pub sequence: u32,
    pub issued_at: i64,
    pub root_statement_sha256: String,
    pub previous_transition_sha256: Option<String>,
    pub previous_key_fingerprint: String,
    pub next_key_fingerprint: String,
    pub reason: PersonaTransitionReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaTransitionProof {
    pub schema: String,
    pub payload: String,
    pub signatures: Vec<ContinuitySignature>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedPersonaRoot {
    pub statement: PersonaRootStatement,
    pub root_statement_sha256: String,
    pub initial_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedPersonaTransition {
    pub statement: PersonaTransitionStatement,
    pub transition_statement_sha256: String,
    pub previous_public_key: String,
    pub next_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContinuityChainReport {
    pub root_signature: EvidenceStatus,
    pub expected_root_digest: EvidenceStatus,
    pub chain: EvidenceStatus,
    pub persona: String,
    pub persona_anchor: String,
    pub root_statement_sha256: String,
    pub initial_key_fingerprint: String,
    pub current_key_fingerprint: String,
    pub transition_count: u32,
    pub last_issued_at: i64,
    pub last_transition_sha256: Option<String>,
    pub not_established: Vec<String>,
}

/// Construct a new self-asserted persona root with a random, persona-specific
/// 256-bit anchor. The resulting root becomes meaningful to other parties only
/// after they pin its digest through a separate trusted exchange.
pub fn new_persona_root_statement(
    persona: &str,
    issued_at: i64,
    initial_public_key: &str,
) -> Result<PersonaRootStatement> {
    let mut anchor = [0_u8; PERSONA_ANCHOR_BYTES];
    getrandom::fill(&mut anchor).map_err(|_| ProofError::EntropyUnavailable)?;
    new_persona_root_statement_with_anchor(
        &URL_SAFE_NO_PAD.encode(anchor),
        persona,
        issued_at,
        initial_public_key,
    )
}

/// Deterministic constructor for importers and protocol test vectors.
pub fn new_persona_root_statement_with_anchor(
    persona_anchor: &str,
    persona: &str,
    issued_at: i64,
    initial_public_key: &str,
) -> Result<PersonaRootStatement> {
    validate_persona_anchor(persona_anchor)?;
    let persona = validate_canonical_persona(persona)?;
    validate_jcs_time("root issued_at", issued_at)?;
    let initial_public_key = normalize_public_key(initial_public_key)?;
    let statement = PersonaRootStatement {
        schema: PERSONA_ROOT_STATEMENT_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        persona_anchor: persona_anchor.to_owned(),
        persona,
        root_version: 1,
        issued_at,
        initial_key_fingerprint: public_key_fingerprint(&initial_public_key)?,
    };
    validate_persona_root_statement(&statement)?;
    Ok(statement)
}

/// Return the RFC 8785 bytes signed by a persona-root proof.
pub fn canonical_persona_root_statement_bytes(statement: &PersonaRootStatement) -> Result<Vec<u8>> {
    validate_persona_root_statement(statement)?;
    let bytes = serde_json_canonicalizer::to_vec(statement)?;
    validate_payload_bound(&bytes)?;
    Ok(bytes)
}

pub fn persona_root_statement_sha256(statement: &PersonaRootStatement) -> Result<String> {
    Ok(sha256_hex(&canonical_persona_root_statement_bytes(
        statement,
    )?))
}

/// Sign a previously reviewed root statement with its initial key.
pub fn create_persona_root_proof(
    statement: PersonaRootStatement,
    private_key_path: impl AsRef<Path>,
    initial_public_key: &str,
) -> Result<PersonaRootProof> {
    let payload = canonical_persona_root_statement_bytes(&statement)?;
    let public_key = normalize_public_key(initial_public_key)?;
    if public_key_fingerprint(&public_key)? != statement.initial_key_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    let value = sshsig_sign(&payload, private_key_path.as_ref(), PERSONA_ROOT_NAMESPACE)?;
    sshsig_verify(&payload, &value, &public_key, PERSONA_ROOT_NAMESPACE)?;

    Ok(PersonaRootProof {
        schema: PERSONA_ROOT_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signature: new_signature(ContinuitySignatureRole::Root, value, public_key),
    })
}

/// Verify the root signature and canonical payload. This does not establish
/// that the root was pinned before a compromise or that the persona is legal.
pub fn verify_persona_root_proof(proof: &PersonaRootProof) -> Result<VerifiedPersonaRoot> {
    require_proof_schema(&proof.schema, PERSONA_ROOT_PROOF_SCHEMA)?;
    let payload = decode_continuity_payload(&proof.payload)?;
    let statement: PersonaRootStatement = serde_json::from_slice(&payload)?;
    let canonical = canonical_persona_root_statement_bytes(&statement)?;
    if canonical != payload {
        return Err(ProofError::NonCanonicalContinuityStatement);
    }
    let public_key = validate_signature(
        &proof.signature,
        ContinuitySignatureRole::Root,
        PERSONA_ROOT_NAMESPACE,
    )?;
    if public_key_fingerprint(&public_key)? != statement.initial_key_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    sshsig_verify(
        &payload,
        &proof.signature.value,
        &public_key,
        PERSONA_ROOT_NAMESPACE,
    )?;

    Ok(VerifiedPersonaRoot {
        root_statement_sha256: sha256_hex(&payload),
        statement,
        initial_public_key: public_key,
    })
}

/// Construct one routine old-key to new-key statement bound to a verified
/// persona root. Sequence 1 must start from the root's initial key.
#[allow(clippy::too_many_arguments)]
pub fn new_routine_transition_statement(
    root: &VerifiedPersonaRoot,
    sequence: u32,
    previous_transition_sha256: Option<&str>,
    previous_public_key: &str,
    next_public_key: &str,
    issued_at: i64,
) -> Result<PersonaTransitionStatement> {
    let previous_public_key = normalize_public_key(previous_public_key)?;
    let next_public_key = normalize_public_key(next_public_key)?;
    let previous_key_fingerprint = public_key_fingerprint(&previous_public_key)?;
    let next_key_fingerprint = public_key_fingerprint(&next_public_key)?;
    if sequence == 1 && previous_key_fingerprint != root.statement.initial_key_fingerprint {
        return Err(invalid_continuity_statement(
            "sequence 1 must start from the root's initial key",
        ));
    }
    if issued_at < root.statement.issued_at {
        return Err(invalid_continuity_statement(
            "a transition cannot predate its persona root",
        ));
    }

    let statement = PersonaTransitionStatement {
        schema: PERSONA_TRANSITION_STATEMENT_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        persona_anchor: root.statement.persona_anchor.clone(),
        persona: root.statement.persona.clone(),
        sequence,
        issued_at,
        root_statement_sha256: root.root_statement_sha256.clone(),
        previous_transition_sha256: previous_transition_sha256.map(ToOwned::to_owned),
        previous_key_fingerprint,
        next_key_fingerprint,
        reason: PersonaTransitionReason::Routine,
    };
    validate_persona_transition_statement(&statement)?;
    Ok(statement)
}

/// Return the RFC 8785 bytes signed independently by the previous and next
/// persona keys.
pub fn canonical_persona_transition_statement_bytes(
    statement: &PersonaTransitionStatement,
) -> Result<Vec<u8>> {
    validate_persona_transition_statement(statement)?;
    let bytes = serde_json_canonicalizer::to_vec(statement)?;
    validate_payload_bound(&bytes)?;
    Ok(bytes)
}

pub fn persona_transition_statement_sha256(
    statement: &PersonaTransitionStatement,
) -> Result<String> {
    Ok(sha256_hex(&canonical_persona_transition_statement_bytes(
        statement,
    )?))
}

/// Produce a custody proof from both sides of one routine transition.
#[allow(clippy::too_many_arguments)]
pub fn create_routine_transition_proof(
    statement: PersonaTransitionStatement,
    previous_private_key_path: impl AsRef<Path>,
    previous_public_key: &str,
    next_private_key_path: impl AsRef<Path>,
    next_public_key: &str,
) -> Result<PersonaTransitionProof> {
    let payload = canonical_persona_transition_statement_bytes(&statement)?;
    let previous_public_key = normalize_public_key(previous_public_key)?;
    let next_public_key = normalize_public_key(next_public_key)?;
    if public_key_fingerprint(&previous_public_key)? != statement.previous_key_fingerprint
        || public_key_fingerprint(&next_public_key)? != statement.next_key_fingerprint
    {
        return Err(ProofError::FingerprintMismatch);
    }

    let previous_value = sshsig_sign(
        &payload,
        previous_private_key_path.as_ref(),
        PERSONA_TRANSITION_NAMESPACE,
    )?;
    sshsig_verify(
        &payload,
        &previous_value,
        &previous_public_key,
        PERSONA_TRANSITION_NAMESPACE,
    )?;
    let next_value = sshsig_sign(
        &payload,
        next_private_key_path.as_ref(),
        PERSONA_TRANSITION_NAMESPACE,
    )?;
    sshsig_verify(
        &payload,
        &next_value,
        &next_public_key,
        PERSONA_TRANSITION_NAMESPACE,
    )?;

    Ok(PersonaTransitionProof {
        schema: PERSONA_TRANSITION_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signatures: vec![
            new_signature(
                ContinuitySignatureRole::Previous,
                previous_value,
                previous_public_key,
            ),
            new_signature(ContinuitySignatureRole::Next, next_value, next_public_key),
        ],
    })
}

/// Verify both signatures and their exact role-to-fingerprint bindings.
pub fn verify_persona_transition_proof(
    proof: &PersonaTransitionProof,
) -> Result<VerifiedPersonaTransition> {
    require_proof_schema(&proof.schema, PERSONA_TRANSITION_PROOF_SCHEMA)?;
    if proof.signatures.len() != 2 {
        return Err(invalid_continuity_proof(
            "a routine transition requires exactly two signatures",
        ));
    }
    let payload = decode_continuity_payload(&proof.payload)?;
    let statement: PersonaTransitionStatement = serde_json::from_slice(&payload)?;
    let canonical = canonical_persona_transition_statement_bytes(&statement)?;
    if canonical != payload {
        return Err(ProofError::NonCanonicalContinuityStatement);
    }

    let mut previous = None;
    let mut next = None;
    for signature in &proof.signatures {
        match signature.role {
            ContinuitySignatureRole::Previous if previous.is_none() => previous = Some(signature),
            ContinuitySignatureRole::Next if next.is_none() => next = Some(signature),
            ContinuitySignatureRole::Previous | ContinuitySignatureRole::Next => {
                return Err(invalid_continuity_proof(
                    "duplicate transition signature role",
                ));
            }
            ContinuitySignatureRole::Root => {
                return Err(invalid_continuity_proof(
                    "a root signature cannot authorize a routine transition role",
                ));
            }
        }
    }
    let previous = previous
        .ok_or_else(|| invalid_continuity_proof("missing previous-key transition signature"))?;
    let next =
        next.ok_or_else(|| invalid_continuity_proof("missing next-key transition signature"))?;
    let previous_public_key = validate_signature(
        previous,
        ContinuitySignatureRole::Previous,
        PERSONA_TRANSITION_NAMESPACE,
    )?;
    let next_public_key = validate_signature(
        next,
        ContinuitySignatureRole::Next,
        PERSONA_TRANSITION_NAMESPACE,
    )?;
    if public_key_fingerprint(&previous_public_key)? != statement.previous_key_fingerprint
        || public_key_fingerprint(&next_public_key)? != statement.next_key_fingerprint
    {
        return Err(ProofError::FingerprintMismatch);
    }
    sshsig_verify(
        &payload,
        &previous.value,
        &previous_public_key,
        PERSONA_TRANSITION_NAMESPACE,
    )?;
    sshsig_verify(
        &payload,
        &next.value,
        &next_public_key,
        PERSONA_TRANSITION_NAMESPACE,
    )?;

    Ok(VerifiedPersonaTransition {
        transition_statement_sha256: sha256_hex(&payload),
        statement,
        previous_public_key,
        next_public_key,
    })
}

/// Verify an ordered transition chain against a root digest obtained through a
/// separate trusted channel. Passing a digest copied from the untrusted proof
/// itself is not independent pinning.
pub fn verify_persona_continuity_chain(
    root_proof: &PersonaRootProof,
    transitions: &[PersonaTransitionProof],
    expected_root_statement_sha256: &str,
) -> Result<ContinuityChainReport> {
    validate_sha256(
        "expected root statement digest",
        expected_root_statement_sha256,
    )?;
    if transitions.len() > MAX_CONTINUITY_TRANSITIONS {
        return Err(ProofError::ContinuityChainMismatch(format!(
            "chain cannot contain more than {MAX_CONTINUITY_TRANSITIONS} transitions"
        )));
    }
    let root = verify_persona_root_proof(root_proof)?;
    if root.root_statement_sha256 != expected_root_statement_sha256 {
        return Err(ProofError::ContinuityChainMismatch(
            "root statement digest does not match the independently expected digest".to_owned(),
        ));
    }

    let mut current_key_fingerprint = root.statement.initial_key_fingerprint.clone();
    let mut previous_transition_sha256 = None;
    let mut previous_issued_at = root.statement.issued_at;
    for (index, proof) in transitions.iter().enumerate() {
        let verified = verify_persona_transition_proof(proof)?;
        let expected_sequence =
            u32::try_from(index + 1).expect("bounded continuity chain length fits in u32");
        let statement = &verified.statement;
        if statement.sequence != expected_sequence {
            return Err(ProofError::ContinuityChainMismatch(format!(
                "transition sequence {} is out of order; expected {expected_sequence}",
                statement.sequence
            )));
        }
        if statement.persona_anchor != root.statement.persona_anchor
            || statement.persona != root.statement.persona
            || statement.root_statement_sha256 != root.root_statement_sha256
        {
            return Err(ProofError::ContinuityChainMismatch(
                "transition is bound to a different persona root".to_owned(),
            ));
        }
        if statement.previous_transition_sha256 != previous_transition_sha256 {
            return Err(ProofError::ContinuityChainMismatch(
                "transition does not link to the exact previous statement".to_owned(),
            ));
        }
        if statement.previous_key_fingerprint != current_key_fingerprint {
            return Err(ProofError::ContinuityChainMismatch(
                "transition previous key is not the chain's current key".to_owned(),
            ));
        }
        if statement.issued_at < previous_issued_at {
            return Err(ProofError::ContinuityChainMismatch(
                "transition issuance times move backward".to_owned(),
            ));
        }

        current_key_fingerprint = statement.next_key_fingerprint.clone();
        previous_transition_sha256 = Some(verified.transition_statement_sha256);
        previous_issued_at = statement.issued_at;
    }

    Ok(ContinuityChainReport {
        root_signature: EvidenceStatus::Verified,
        expected_root_digest: EvidenceStatus::Verified,
        chain: EvidenceStatus::Verified,
        persona: root.statement.persona,
        persona_anchor: root.statement.persona_anchor,
        root_statement_sha256: root.root_statement_sha256,
        initial_key_fingerprint: root.statement.initial_key_fingerprint,
        current_key_fingerprint,
        transition_count: u32::try_from(transitions.len())
            .expect("bounded continuity chain length fits in u32"),
        last_issued_at: previous_issued_at,
        last_transition_sha256: previous_transition_sha256,
        not_established: vec![
            "when_or_how_the_root_digest_was_pinned".to_owned(),
            "legal_identity".to_owned(),
            "current_key_authorization_or_non_revocation".to_owned(),
            "recovery_authority".to_owned(),
            "artifact_or_software_safety".to_owned(),
        ],
    })
}

fn validate_persona_root_statement(statement: &PersonaRootStatement) -> Result<()> {
    if statement.schema != PERSONA_ROOT_STATEMENT_SCHEMA {
        return Err(invalid_continuity_statement(format!(
            "unsupported root schema {}",
            statement.schema
        )));
    }
    if statement.canonicalization != CONTINUITY_CANONICALIZATION {
        return Err(invalid_continuity_statement(format!(
            "unsupported canonicalization {}",
            statement.canonicalization
        )));
    }
    validate_persona_anchor(&statement.persona_anchor)?;
    validate_canonical_persona(&statement.persona)?;
    if statement.root_version != 1 {
        return Err(invalid_continuity_statement(
            "root_version must be exactly 1",
        ));
    }
    validate_jcs_time("root issued_at", statement.issued_at)?;
    validate_key_fingerprint(&statement.initial_key_fingerprint)?;
    Ok(())
}

fn validate_persona_transition_statement(statement: &PersonaTransitionStatement) -> Result<()> {
    if statement.schema != PERSONA_TRANSITION_STATEMENT_SCHEMA {
        return Err(invalid_continuity_statement(format!(
            "unsupported transition schema {}",
            statement.schema
        )));
    }
    if statement.canonicalization != CONTINUITY_CANONICALIZATION {
        return Err(invalid_continuity_statement(format!(
            "unsupported canonicalization {}",
            statement.canonicalization
        )));
    }
    validate_persona_anchor(&statement.persona_anchor)?;
    validate_canonical_persona(&statement.persona)?;
    if statement.sequence == 0 {
        return Err(invalid_continuity_statement(
            "transition sequence must start at 1",
        ));
    }
    validate_jcs_time("transition issued_at", statement.issued_at)?;
    validate_sha256("root statement digest", &statement.root_statement_sha256)?;
    match (
        statement.sequence,
        statement.previous_transition_sha256.as_deref(),
    ) {
        (1, None) => {}
        (1, Some(_)) => {
            return Err(invalid_continuity_statement(
                "transition 1 cannot name a previous transition digest",
            ));
        }
        (_, Some(digest)) => validate_sha256("previous transition digest", digest)?,
        (_, None) => {
            return Err(invalid_continuity_statement(
                "transitions after sequence 1 require a previous transition digest",
            ));
        }
    }
    validate_key_fingerprint(&statement.previous_key_fingerprint)?;
    validate_key_fingerprint(&statement.next_key_fingerprint)?;
    if statement.previous_key_fingerprint == statement.next_key_fingerprint {
        return Err(invalid_continuity_statement(
            "previous and next keys must be distinct",
        ));
    }
    if statement.reason != PersonaTransitionReason::Routine {
        return Err(invalid_continuity_statement(
            "this proof type supports routine dual-signed transitions only",
        ));
    }
    Ok(())
}

fn validate_persona_anchor(anchor: &str) -> Result<()> {
    let decoded = URL_SAFE_NO_PAD.decode(anchor).map_err(|_| {
        ProofError::InvalidContinuityAnchor("expected canonical unpadded Base64url".to_owned())
    })?;
    if decoded.len() != PERSONA_ANCHOR_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != anchor {
        return Err(ProofError::InvalidContinuityAnchor(
            "expected exactly 32 random bytes in canonical unpadded Base64url".to_owned(),
        ));
    }
    Ok(())
}

fn validate_canonical_persona(persona: &str) -> Result<String> {
    let canonical = validate_persona(persona)?;
    if canonical != persona {
        return Err(invalid_continuity_statement(
            "persona must not contain surrounding whitespace",
        ));
    }
    Ok(canonical)
}

fn validate_jcs_time(field: &str, value: i64) -> Result<()> {
    if (0..=MAX_JCS_SAFE_INTEGER).contains(&value) {
        Ok(())
    } else {
        Err(invalid_continuity_statement(format!(
            "{field} must be an exact non-negative RFC 8785 integer"
        )))
    }
}

fn validate_sha256(field: &str, value: &str) -> Result<()> {
    if value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(invalid_continuity_statement(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )))
    }
}

fn validate_payload_bound(payload: &[u8]) -> Result<()> {
    if payload.len() <= MAX_CONTINUITY_PAYLOAD_BYTES {
        Ok(())
    } else {
        Err(invalid_continuity_proof(format!(
            "payload exceeds {MAX_CONTINUITY_PAYLOAD_BYTES} bytes"
        )))
    }
}

fn decode_continuity_payload(encoded: &str) -> Result<Vec<u8>> {
    let payload = decode_payload(encoded)?;
    validate_payload_bound(&payload)?;
    if URL_SAFE_NO_PAD.encode(&payload) != encoded {
        return Err(invalid_continuity_proof(
            "payload is not canonical unpadded Base64url",
        ));
    }
    Ok(payload)
}

fn validate_signature(
    signature: &ContinuitySignature,
    expected_role: ContinuitySignatureRole,
    expected_namespace: &str,
) -> Result<String> {
    if signature.role != expected_role {
        return Err(invalid_continuity_proof(
            "signature role does not match its required key",
        ));
    }
    if signature.format != SIGNATURE_FORMAT {
        return Err(invalid_continuity_proof(format!(
            "unsupported signature format {}",
            signature.format
        )));
    }
    if signature.namespace != expected_namespace {
        return Err(invalid_continuity_proof(format!(
            "unsupported signature namespace {}",
            signature.namespace
        )));
    }
    if signature.public_key_format != PUBLIC_KEY_FORMAT {
        return Err(invalid_continuity_proof(format!(
            "unsupported public-key format {}",
            signature.public_key_format
        )));
    }
    if signature.value.is_empty() || signature.value.len() > MAX_CONTINUITY_SIGNATURE_BYTES {
        return Err(invalid_continuity_proof(format!(
            "signature must contain 1 through {MAX_CONTINUITY_SIGNATURE_BYTES} UTF-8 bytes"
        )));
    }
    normalize_public_key(&signature.public_key)
}

fn new_signature(
    role: ContinuitySignatureRole,
    value: String,
    public_key: String,
) -> ContinuitySignature {
    ContinuitySignature {
        role,
        format: SIGNATURE_FORMAT.to_owned(),
        namespace: match role {
            ContinuitySignatureRole::Root => PERSONA_ROOT_NAMESPACE,
            ContinuitySignatureRole::Previous | ContinuitySignatureRole::Next => {
                PERSONA_TRANSITION_NAMESPACE
            }
        }
        .to_owned(),
        value,
        public_key_format: PUBLIC_KEY_FORMAT.to_owned(),
        public_key,
    }
}

fn require_proof_schema(actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_continuity_proof(format!(
            "unsupported proof schema {actual}; expected {expected}"
        )))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid_continuity_statement(reason: impl Into<String>) -> ProofError {
    ProofError::InvalidContinuityStatement(reason.into())
}

fn invalid_continuity_proof(reason: impl Into<String>) -> ProofError {
    ProofError::InvalidContinuityProof(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ONE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";
    const KEY_TWO: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfX7hAdqGfF0mYz2oD88dL84M2yr2KoXqhh7sSRvqHQ";
    const ANCHOR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn root_uses_rfc8785_key_order_and_stable_digest() {
        let statement = new_persona_root_statement_with_anchor(
            ANCHOR,
            "Example Publisher",
            1_700_000_000,
            KEY_ONE,
        )
        .unwrap();
        let bytes = canonical_persona_root_statement_bytes(&statement).unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert_eq!(
            json,
            concat!(
                "{\"canonicalization\":\"RFC8785\",",
                "\"initial_key_fingerprint\":\"SHA256:EBjV72biEhKr3eNO5/nBKqwKEPMR2rTTFDw3KvmagoU\",",
                "\"issued_at\":1700000000,\"persona\":\"Example Publisher\",",
                "\"persona_anchor\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",",
                "\"root_version\":1,\"schema\":\"urn:a-quo:statement:persona-root:v1\"}"
            )
        );
        assert_eq!(
            persona_root_statement_sha256(&statement).unwrap(),
            sha256_hex(json.as_bytes())
        );
    }

    #[test]
    fn anchors_are_persona_specific_and_strictly_encoded() {
        let first = new_persona_root_statement("First", 1, KEY_ONE).unwrap();
        let second = new_persona_root_statement("Second", 1, KEY_ONE).unwrap();
        assert_ne!(first.persona_anchor, second.persona_anchor);
        validate_persona_anchor(&first.persona_anchor).unwrap();

        for invalid in ["", "AA==", "not+base64url", "AAAAAAAA"] {
            assert!(new_persona_root_statement_with_anchor(invalid, "First", 1, KEY_ONE).is_err());
        }
    }

    #[test]
    fn transition_structure_rejects_gaps_same_keys_and_unsafe_numbers() {
        let root_statement =
            new_persona_root_statement_with_anchor(ANCHOR, "Publisher", 10, KEY_ONE).unwrap();
        let root = VerifiedPersonaRoot {
            root_statement_sha256: persona_root_statement_sha256(&root_statement).unwrap(),
            initial_public_key: normalize_public_key(KEY_ONE).unwrap(),
            statement: root_statement,
        };
        assert!(new_routine_transition_statement(&root, 0, None, KEY_ONE, KEY_TWO, 11).is_err());
        assert!(
            new_routine_transition_statement(&root, 1, Some(&"0".repeat(64)), KEY_ONE, KEY_TWO, 11)
                .is_err()
        );
        assert!(new_routine_transition_statement(&root, 1, None, KEY_ONE, KEY_ONE, 11).is_err());
        assert!(
            new_persona_root_statement_with_anchor(
                ANCHOR,
                "Publisher",
                MAX_JCS_SAFE_INTEGER + 1,
                KEY_ONE
            )
            .is_err()
        );
    }
}
