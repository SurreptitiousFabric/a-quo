//! Portable, fail-closed coordination for a distributed recovery transition.
//!
//! The request is not authority. Each participant independently verifies the
//! complete root, policy, and continuity history plus three explicit pins
//! before signing the short-lived schema-v2 transition payload. Each response
//! binds both that role-specific payload and the exact portable request using
//! purpose-separated SSHSIG namespaces. Assembly retains the role-specific
//! signatures in the existing `RecoveryTransitionProof` wrapper.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::continuity::{
    CONTINUITY_CANONICALIZATION, MAX_CONTINUITY_TRANSITIONS, PersonaContinuityCheckpoint,
    PersonaRootProof, validate_persona_transition_proof_structure,
};
use crate::recovery::{
    MAX_RECOVERY_AUTHORITIES, MAX_RECOVERY_POLICY_VERSIONS, PersonaContinuityTransitionProof,
    RECOVERY_TRANSITION_AUTHORITY_NAMESPACE, RECOVERY_TRANSITION_NEXT_NAMESPACE,
    RECOVERY_TRANSITION_PROOF_SCHEMA, RECOVERY_TRANSITION_STATEMENT_SCHEMA_V2,
    RecoveryPolicyAuthorization, RecoveryPolicyProof, RecoverySignature, RecoverySigner,
    RecoveryTransitionProof, RecoveryTransitionReason, RecoveryTransitionStatement,
    VerifiedRecoveryAwareContinuityChain, VerifiedRecoveryPolicy,
    canonical_recovery_transition_statement_bytes, sign_one, validate_recovery_ceremony_candidate,
    validate_recovery_policy_proof_structure, validate_recovery_signature,
    validate_recovery_transition_proof_structure,
    validate_terminal_persona_revocation_proof_structure,
    validate_verified_recovery_aware_continuity_chain_extension,
    verify_persona_continuity_chain_with_recovery_with_verified_sequence_at_checkpoint,
    verify_recovery_transition_proof_with_receipt,
};
use crate::{
    ProofError, Result, normalize_public_key, parse_bounded_json, public_key_fingerprint,
    sshsig_verify,
};

pub const RECOVERY_TRANSITION_CEREMONY_REQUEST_SCHEMA: &str =
    "urn:a-quo:recovery-transition-ceremony-request:v1";
pub const RECOVERY_TRANSITION_CEREMONY_RESPONSE_SCHEMA: &str =
    "urn:a-quo:recovery-transition-ceremony-response:v1";
pub const RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE: &str =
    "a-quo-persona-recovery-ceremony-request-v1";

/// The whole request, including every embedded proof, is bounded before JSON
/// parsing or signature work. Individual proofs retain their own lower bounds.
pub const MAX_RECOVERY_CEREMONY_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RECOVERY_CEREMONY_RESPONSE_BYTES: usize = 128 * 1024;
pub const MAX_RECOVERY_CEREMONY_RESPONSES: usize = MAX_RECOVERY_AUTHORITIES + 1;
pub const MAX_RECOVERY_CEREMONY_SIGNATURE_VERIFICATIONS: usize = 2_048;

const MAX_JCS_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCeremonyRequest {
    pub schema: String,
    pub canonicalization: String,
    pub root_proof: PersonaRootProof,
    pub recovery_policies: Vec<RecoveryPolicyProof>,
    pub prior_transitions: Vec<PersonaContinuityTransitionProof>,
    pub expected_root_statement_sha256: String,
    pub expected_latest_policy_sha256: String,
    pub expected_head: PersonaContinuityCheckpoint,
    pub statement: RecoveryTransitionStatement,
    pub next_public_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCeremonyParticipantRole {
    RecoveryAuthority,
    NextKey,
}

impl RecoveryCeremonyParticipantRole {
    fn namespace(self) -> &'static str {
        match self {
            Self::RecoveryAuthority => RECOVERY_TRANSITION_AUTHORITY_NAMESPACE,
            Self::NextKey => RECOVERY_TRANSITION_NEXT_NAMESPACE,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCeremonyResponse {
    pub schema: String,
    pub canonicalization: String,
    pub request_sha256: String,
    pub participant_fingerprint: String,
    pub role: RecoveryCeremonyParticipantRole,
    /// Purpose-separated SSHSIG over the exact canonical portable request.
    pub request_binding_signature: RecoverySignature,
    /// Existing role-specific SSHSIG over the transition statement payload.
    pub signature: RecoverySignature,
}

/// Human-reviewable facts derived from one fully verified request and one
/// selected participant key. This does not claim that a human approved them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryCeremonyParticipantReview {
    pub request_sha256: String,
    pub ceremony_id: String,
    pub persona: String,
    pub role: RecoveryCeremonyParticipantRole,
    pub participant_fingerprint: String,
    pub root_statement_sha256: String,
    pub recovery_policy_sha256: String,
    pub recovery_policy_version: u32,
    pub previous_head: PersonaContinuityCheckpoint,
    pub sequence: u32,
    pub previous_key_fingerprint: String,
    pub next_key_fingerprint: String,
    pub reason: RecoveryTransitionReason,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Opaque result of verifying the complete portable request at a stated time.
/// Signing helpers accept this type rather than an unverified JSON model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecoveryCeremonyRequest {
    request: RecoveryCeremonyRequest,
    request_sha256: String,
    statement_payload: Vec<u8>,
    next_public_key: String,
    selected_policy: VerifiedRecoveryPolicy,
    chain: VerifiedRecoveryAwareContinuityChain,
    verified_at: i64,
}

impl VerifiedRecoveryCeremonyRequest {
    pub fn request(&self) -> &RecoveryCeremonyRequest {
        &self.request
    }

    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }

    pub fn statement(&self) -> &RecoveryTransitionStatement {
        &self.request.statement
    }

    pub fn selected_policy(&self) -> &VerifiedRecoveryPolicy {
        &self.selected_policy
    }

    pub fn next_public_key(&self) -> &str {
        &self.next_public_key
    }

    pub fn verified_at(&self) -> i64 {
        self.verified_at
    }
}

/// Opaque result of matching and cryptographically verifying one participant
/// response against one exact verified request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecoveryCeremonyResponse {
    response: RecoveryCeremonyResponse,
}

impl VerifiedRecoveryCeremonyResponse {
    pub fn response(&self) -> &RecoveryCeremonyResponse {
        &self.response
    }

    pub fn role(&self) -> RecoveryCeremonyParticipantRole {
        self.response.role
    }

    pub fn participant_fingerprint(&self) -> &str {
        &self.response.participant_fingerprint
    }
}

#[allow(clippy::too_many_arguments)]
pub fn new_recovery_ceremony_request(
    root_proof: PersonaRootProof,
    recovery_policies: Vec<RecoveryPolicyProof>,
    prior_transitions: Vec<PersonaContinuityTransitionProof>,
    expected_root_statement_sha256: String,
    expected_latest_policy_sha256: String,
    expected_head: PersonaContinuityCheckpoint,
    statement: RecoveryTransitionStatement,
    next_public_key: String,
) -> Result<RecoveryCeremonyRequest> {
    let request = RecoveryCeremonyRequest {
        schema: RECOVERY_TRANSITION_CEREMONY_REQUEST_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        root_proof,
        recovery_policies,
        prior_transitions,
        expected_root_statement_sha256,
        expected_latest_policy_sha256,
        expected_head,
        statement,
        next_public_key,
    };
    canonical_recovery_ceremony_request_bytes(&request)?;
    Ok(request)
}

pub fn canonical_recovery_ceremony_request_bytes(
    request: &RecoveryCeremonyRequest,
) -> Result<Vec<u8>> {
    validate_request_structure(request)?;
    let bytes = serde_json_canonicalizer::to_vec(request)?;
    require_bound(
        &bytes,
        MAX_RECOVERY_CEREMONY_REQUEST_BYTES,
        "recovery ceremony request",
    )?;
    Ok(bytes)
}

pub fn recovery_ceremony_request_sha256(request: &RecoveryCeremonyRequest) -> Result<String> {
    Ok(sha256_hex(&canonical_recovery_ceremony_request_bytes(
        request,
    )?))
}

/// Parse only an exact canonical request under the total byte bound. No
/// signature or trust claim is made until `verify_recovery_ceremony_request`.
pub fn parse_recovery_ceremony_request_bytes(bytes: &[u8]) -> Result<RecoveryCeremonyRequest> {
    let request: RecoveryCeremonyRequest = parse_bounded_json(
        bytes,
        MAX_RECOVERY_CEREMONY_REQUEST_BYTES,
        "recovery ceremony request",
    )
    .map_err(invalid_proof)?;
    let canonical = canonical_recovery_ceremony_request_bytes(&request)?;
    if canonical != bytes {
        return Err(ProofError::NonCanonicalContinuityStatement);
    }
    Ok(request)
}

/// Verify every embedded proof, all independent expectations, the exact head,
/// the unsigned candidate binding, next-key material, and the signed lifetime.
pub fn verify_recovery_ceremony_request(
    request: &RecoveryCeremonyRequest,
    checked_at: i64,
) -> Result<VerifiedRecoveryCeremonyRequest> {
    validate_jcs_time("recovery ceremony check time", checked_at)?;
    let request_bytes = canonical_recovery_ceremony_request_bytes(request)?;
    let chain = verify_persona_continuity_chain_with_recovery_with_verified_sequence_at_checkpoint(
        &request.root_proof,
        &request.prior_transitions,
        &request.recovery_policies,
        &request.expected_root_statement_sha256,
        &request.expected_latest_policy_sha256,
        checked_at,
        &request.expected_head,
    )?;
    let selected_policy =
        validate_recovery_ceremony_candidate(&chain, &request.statement, &request.next_public_key)?
            .clone();
    ensure_ceremony_current(&request.statement, checked_at)?;
    let statement_payload = canonical_recovery_transition_statement_bytes(&request.statement)?;
    let next_public_key = normalize_public_key(&request.next_public_key)?;
    Ok(VerifiedRecoveryCeremonyRequest {
        request: request.clone(),
        request_sha256: sha256_hex(&request_bytes),
        statement_payload,
        next_public_key,
        selected_policy,
        chain,
        verified_at: checked_at,
    })
}

pub fn review_recovery_ceremony_participant(
    verified: &VerifiedRecoveryCeremonyRequest,
    participant_public_key: &str,
    checked_at: i64,
) -> Result<RecoveryCeremonyParticipantReview> {
    ensure_not_before_prior_verification(verified, checked_at)?;
    ensure_ceremony_current(verified.statement(), checked_at)?;
    let public_key = normalize_public_key(participant_public_key)?;
    let participant_fingerprint = public_key_fingerprint(&public_key)?;
    let role = participant_role(verified, &participant_fingerprint)?;
    let statement = verified.statement();
    Ok(RecoveryCeremonyParticipantReview {
        request_sha256: verified.request_sha256.clone(),
        ceremony_id: statement
            .ceremony_id
            .clone()
            .expect("a verified ceremony request contains a schema-v2 statement"),
        persona: statement.persona.clone(),
        role,
        participant_fingerprint,
        root_statement_sha256: statement.root_statement_sha256.clone(),
        recovery_policy_sha256: statement.recovery_policy_sha256.clone(),
        recovery_policy_version: statement.recovery_policy_version,
        previous_head: verified.request.expected_head.clone(),
        sequence: statement.sequence,
        previous_key_fingerprint: statement.previous_key_fingerprint.clone(),
        next_key_fingerprint: statement.next_key_fingerprint.clone(),
        reason: statement.reason,
        issued_at: statement.issued_at,
        expires_at: statement
            .expires_at
            .expect("a verified ceremony request contains a schema-v2 statement"),
    })
}

/// Sign one derived role with two purpose-separated SSHSIGs: one over the
/// transition payload and one over the exact canonical portable request.
pub fn sign_recovery_ceremony_request(
    verified: &VerifiedRecoveryCeremonyRequest,
    signer: &RecoverySigner,
    checked_at: i64,
) -> Result<RecoveryCeremonyResponse> {
    let review = review_recovery_ceremony_participant(verified, &signer.public_key, checked_at)?;
    let signature = sign_one(
        &verified.statement_payload,
        &signer.private_key_path,
        &signer.public_key,
        review.role.namespace(),
    )?;
    let request_bytes = canonical_recovery_ceremony_request_bytes(verified.request())?;
    let request_binding_signature = sign_one(
        &request_bytes,
        &signer.private_key_path,
        &signer.public_key,
        RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE,
    )?;
    new_recovery_ceremony_response(verified, signature, request_binding_signature, checked_at)
}

/// Wrap externally produced transition and exact-request signatures. The
/// participant role remains derived from their shared normalized public key
/// and cannot be supplied by the caller.
pub fn new_recovery_ceremony_response(
    verified: &VerifiedRecoveryCeremonyRequest,
    signature: RecoverySignature,
    request_binding_signature: RecoverySignature,
    checked_at: i64,
) -> Result<RecoveryCeremonyResponse> {
    ensure_not_before_prior_verification(verified, checked_at)?;
    ensure_ceremony_current(verified.statement(), checked_at)?;
    let public_key = normalize_public_key(&signature.public_key)?;
    let participant_fingerprint = public_key_fingerprint(&public_key)?;
    let role = participant_role(verified, &participant_fingerprint)?;
    validate_recovery_signature(&signature, role.namespace())?;
    let binding_public_key = validate_recovery_signature(
        &request_binding_signature,
        RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE,
    )?;
    if public_key_fingerprint(&binding_public_key)? != participant_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    sshsig_verify(
        &verified.statement_payload,
        &signature.value,
        &public_key,
        role.namespace(),
    )?;
    let request_bytes = canonical_recovery_ceremony_request_bytes(verified.request())?;
    sshsig_verify(
        &request_bytes,
        &request_binding_signature.value,
        &binding_public_key,
        RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE,
    )?;
    let response = RecoveryCeremonyResponse {
        schema: RECOVERY_TRANSITION_CEREMONY_RESPONSE_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        request_sha256: verified.request_sha256.clone(),
        participant_fingerprint,
        role,
        request_binding_signature,
        signature,
    };
    canonical_recovery_ceremony_response_bytes(&response)?;
    Ok(response)
}

pub fn canonical_recovery_ceremony_response_bytes(
    response: &RecoveryCeremonyResponse,
) -> Result<Vec<u8>> {
    validate_response_structure(response)?;
    let bytes = serde_json_canonicalizer::to_vec(response)?;
    require_bound(
        &bytes,
        MAX_RECOVERY_CEREMONY_RESPONSE_BYTES,
        "recovery ceremony response",
    )?;
    Ok(bytes)
}

pub fn parse_recovery_ceremony_response_bytes(bytes: &[u8]) -> Result<RecoveryCeremonyResponse> {
    let response: RecoveryCeremonyResponse = parse_bounded_json(
        bytes,
        MAX_RECOVERY_CEREMONY_RESPONSE_BYTES,
        "recovery ceremony response",
    )
    .map_err(invalid_proof)?;
    let canonical = canonical_recovery_ceremony_response_bytes(&response)?;
    if canonical != bytes {
        return Err(ProofError::NonCanonicalContinuityStatement);
    }
    Ok(response)
}

pub fn verify_recovery_ceremony_response(
    verified: &VerifiedRecoveryCeremonyRequest,
    response: &RecoveryCeremonyResponse,
    checked_at: i64,
) -> Result<VerifiedRecoveryCeremonyResponse> {
    ensure_not_before_prior_verification(verified, checked_at)?;
    ensure_ceremony_current(verified.statement(), checked_at)?;
    canonical_recovery_ceremony_response_bytes(response)?;
    if response.request_sha256 != verified.request_sha256 {
        return Err(invalid_proof(
            "recovery ceremony response names a different request digest",
        ));
    }
    let public_key = validate_recovery_signature(&response.signature, response.role.namespace())?;
    let fingerprint = public_key_fingerprint(&public_key)?;
    if fingerprint != response.participant_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    let expected_role = participant_role(verified, &fingerprint)?;
    if expected_role != response.role {
        return Err(invalid_proof(
            "recovery ceremony response role is not authorized for its signing key",
        ));
    }
    let binding_public_key = validate_recovery_signature(
        &response.request_binding_signature,
        RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE,
    )?;
    if public_key_fingerprint(&binding_public_key)? != fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    sshsig_verify(
        &verified.statement_payload,
        &response.signature.value,
        &public_key,
        response.role.namespace(),
    )?;
    let request_bytes = canonical_recovery_ceremony_request_bytes(verified.request())?;
    sshsig_verify(
        &request_bytes,
        &response.request_binding_signature.value,
        &binding_public_key,
        RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE,
    )?;
    Ok(VerifiedRecoveryCeremonyResponse {
        response: response.clone(),
    })
}

/// Verify, de-duplicate, sort, and assemble participant responses into the
/// unchanged recovery proof wrapper. Exact duplicate responses are ignored;
/// two different responses from one fingerprint fail closed.
pub fn assemble_recovery_ceremony_proof(
    verified: &VerifiedRecoveryCeremonyRequest,
    responses: &[RecoveryCeremonyResponse],
    checked_at: i64,
) -> Result<RecoveryTransitionProof> {
    ensure_not_before_prior_verification(verified, checked_at)?;
    ensure_ceremony_current(verified.statement(), checked_at)?;
    if responses.is_empty() || responses.len() > MAX_RECOVERY_CEREMONY_RESPONSES {
        return Err(invalid_proof(format!(
            "recovery ceremony must contain 1 through {MAX_RECOVERY_CEREMONY_RESPONSES} responses"
        )));
    }

    let mut distinct = BTreeMap::<String, VerifiedRecoveryCeremonyResponse>::new();
    for response in responses {
        let candidate = verify_recovery_ceremony_response(verified, response, checked_at)?;
        match distinct.get(candidate.participant_fingerprint()) {
            Some(existing) if existing.response == candidate.response => continue,
            Some(_) => {
                return Err(invalid_proof(
                    "conflicting recovery ceremony responses use the same participant fingerprint",
                ));
            }
            None => {
                distinct.insert(candidate.participant_fingerprint().to_owned(), candidate);
            }
        }
    }

    let threshold = usize::try_from(verified.selected_policy.statement.threshold)
        .map_err(|_| invalid_proof("recovery threshold does not fit this platform"))?;
    let mut recovery_signatures = Vec::new();
    let mut next_signature = None;
    for response in distinct.into_values() {
        match response.role() {
            RecoveryCeremonyParticipantRole::RecoveryAuthority => {
                recovery_signatures.push(response.response.signature);
            }
            RecoveryCeremonyParticipantRole::NextKey => {
                if next_signature
                    .replace(response.response.signature)
                    .is_some()
                {
                    return Err(invalid_proof(
                        "recovery ceremony contains more than one next-key response",
                    ));
                }
            }
        }
    }
    if recovery_signatures.len() < threshold {
        return Err(invalid_proof(format!(
            "recovery ceremony requires at least {threshold} distinct authority responses"
        )));
    }
    let next_signature = next_signature
        .ok_or_else(|| invalid_proof("recovery ceremony requires the exact next key to sign"))?;
    let proof = RecoveryTransitionProof {
        schema: RECOVERY_TRANSITION_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD.encode(&verified.statement_payload),
        recovery_signatures,
        next_signature,
    };

    let receipt = verify_recovery_transition_proof_with_receipt(
        verified.chain.root(),
        &verified.selected_policy,
        &proof,
    )?;
    validate_verified_recovery_aware_continuity_chain_extension(&verified.chain, &receipt)?;
    Ok(proof)
}

fn validate_request_structure(request: &RecoveryCeremonyRequest) -> Result<()> {
    require_request_signature_work_bound(request)?;
    if request.schema != RECOVERY_TRANSITION_CEREMONY_REQUEST_SCHEMA {
        return Err(invalid_proof(
            "unsupported recovery ceremony request schema",
        ));
    }
    if request.canonicalization != CONTINUITY_CANONICALIZATION {
        return Err(invalid_proof(
            "unsupported recovery ceremony request canonicalization",
        ));
    }
    if request.recovery_policies.is_empty()
        || request.recovery_policies.len() > MAX_RECOVERY_POLICY_VERSIONS
    {
        return Err(invalid_proof(format!(
            "recovery ceremony policy chain must contain 1 through {MAX_RECOVERY_POLICY_VERSIONS} proofs"
        )));
    }
    if request.prior_transitions.len() > MAX_CONTINUITY_TRANSITIONS {
        return Err(invalid_proof(format!(
            "recovery ceremony history cannot contain more than {MAX_CONTINUITY_TRANSITIONS} transitions"
        )));
    }
    for policy in &request.recovery_policies {
        validate_recovery_policy_proof_structure(policy)?;
    }
    for transition in &request.prior_transitions {
        match transition {
            PersonaContinuityTransitionProof::Routine(proof) => {
                validate_persona_transition_proof_structure(proof)?;
            }
            PersonaContinuityTransitionProof::Recovery(proof) => {
                validate_recovery_transition_proof_structure(proof)?;
            }
            PersonaContinuityTransitionProof::TerminalRevocation(proof) => {
                validate_terminal_persona_revocation_proof_structure(proof)?;
            }
        }
    }
    validate_sha256(
        "expected root statement digest",
        &request.expected_root_statement_sha256,
    )?;
    validate_sha256(
        "expected latest recovery policy digest",
        &request.expected_latest_policy_sha256,
    )?;
    validate_head(&request.expected_head)?;
    if request.statement.schema != RECOVERY_TRANSITION_STATEMENT_SCHEMA_V2 {
        return Err(invalid_proof(
            "recovery ceremony request requires a schema-v2 transition statement",
        ));
    }
    canonical_recovery_transition_statement_bytes(&request.statement)?;
    let next_public_key = normalize_public_key(&request.next_public_key)?;
    if public_key_fingerprint(&next_public_key)? != request.statement.next_key_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    Ok(())
}

fn require_request_signature_work_bound(request: &RecoveryCeremonyRequest) -> Result<()> {
    let mut work = 1_usize; // Persona-root self-signature.
    for policy in &request.recovery_policies {
        let signatures = match &policy.authorization {
            RecoveryPolicyAuthorization::Enrollment { signatures } => signatures.len(),
            RecoveryPolicyAuthorization::Update {
                previous_policy_signatures,
                current_policy_signatures,
            } => previous_policy_signatures
                .len()
                .checked_add(current_policy_signatures.len())
                .ok_or_else(|| invalid_proof("recovery ceremony signature work overflowed"))?,
        };
        work = work
            .checked_add(signatures)
            .ok_or_else(|| invalid_proof("recovery ceremony signature work overflowed"))?;
    }
    for transition in &request.prior_transitions {
        let signatures = match transition {
            PersonaContinuityTransitionProof::Routine(proof) => proof.signatures.len(),
            PersonaContinuityTransitionProof::Recovery(proof) => proof
                .recovery_signatures
                .len()
                .checked_add(1)
                .ok_or_else(|| invalid_proof("recovery ceremony signature work overflowed"))?,
            PersonaContinuityTransitionProof::TerminalRevocation(proof) => {
                proof.recovery_signatures.len()
            }
        };
        work = work
            .checked_add(signatures)
            .ok_or_else(|| invalid_proof("recovery ceremony signature work overflowed"))?;
    }
    if work > MAX_RECOVERY_CEREMONY_SIGNATURE_VERIFICATIONS {
        return Err(invalid_proof(format!(
            "recovery ceremony requires {work} signature verifications; the limit is {MAX_RECOVERY_CEREMONY_SIGNATURE_VERIFICATIONS}"
        )));
    }
    Ok(())
}

fn validate_response_structure(response: &RecoveryCeremonyResponse) -> Result<()> {
    if response.schema != RECOVERY_TRANSITION_CEREMONY_RESPONSE_SCHEMA {
        return Err(invalid_proof(
            "unsupported recovery ceremony response schema",
        ));
    }
    if response.canonicalization != CONTINUITY_CANONICALIZATION {
        return Err(invalid_proof(
            "unsupported recovery ceremony response canonicalization",
        ));
    }
    validate_sha256("recovery ceremony request digest", &response.request_sha256)?;
    let public_key = validate_recovery_signature(&response.signature, response.role.namespace())?;
    let fingerprint = public_key_fingerprint(&public_key)?;
    if fingerprint != response.participant_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    let binding_public_key = validate_recovery_signature(
        &response.request_binding_signature,
        RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE,
    )?;
    if public_key_fingerprint(&binding_public_key)? != fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    Ok(())
}

fn participant_role(
    verified: &VerifiedRecoveryCeremonyRequest,
    fingerprint: &str,
) -> Result<RecoveryCeremonyParticipantRole> {
    if fingerprint == verified.statement().next_key_fingerprint {
        return Ok(RecoveryCeremonyParticipantRole::NextKey);
    }
    if verified
        .selected_policy
        .statement
        .recovery_key_fingerprints
        .binary_search_by(|candidate| candidate.as_str().cmp(fingerprint))
        .is_ok()
    {
        return Ok(RecoveryCeremonyParticipantRole::RecoveryAuthority);
    }
    Err(invalid_proof(
        "participant key is neither an authorized recovery authority nor the exact next key",
    ))
}

fn ensure_not_before_prior_verification(
    verified: &VerifiedRecoveryCeremonyRequest,
    checked_at: i64,
) -> Result<()> {
    validate_jcs_time("recovery ceremony check time", checked_at)?;
    if checked_at < verified.verified_at {
        return Err(invalid_proof(
            "recovery ceremony check time moved backward after request verification",
        ));
    }
    Ok(())
}

fn ensure_ceremony_current(statement: &RecoveryTransitionStatement, checked_at: i64) -> Result<()> {
    let expires_at = statement
        .expires_at
        .ok_or_else(|| invalid_proof("recovery ceremony statement has no signed expiry"))?;
    if checked_at < statement.issued_at {
        return Err(invalid_proof(
            "recovery ceremony statement is not yet valid at the checked time",
        ));
    }
    if checked_at >= expires_at {
        return Err(invalid_proof(
            "recovery ceremony statement expired at the checked time",
        ));
    }
    Ok(())
}

fn validate_head(head: &PersonaContinuityCheckpoint) -> Result<()> {
    let maximum = u32::try_from(MAX_CONTINUITY_TRANSITIONS).expect("continuity bound fits in u32");
    if head.transition_sequence > maximum {
        return Err(invalid_proof(format!(
            "expected recovery ceremony head cannot exceed transition {maximum}"
        )));
    }
    match (head.transition_sequence, head.transition_sha256.as_deref()) {
        (0, None) => Ok(()),
        (0, Some(_)) => Err(invalid_proof(
            "expected head sequence 0 cannot name a transition digest",
        )),
        (_, Some(digest)) => validate_sha256("expected head transition digest", digest),
        (_, None) => Err(invalid_proof(
            "a nonzero expected head requires a transition digest",
        )),
    }
}

fn validate_jcs_time(field: &str, value: i64) -> Result<()> {
    if (0..=MAX_JCS_SAFE_INTEGER).contains(&value) {
        Ok(())
    } else {
        Err(invalid_proof(format!(
            "{field} must be an exact non-negative RFC 8785 integer"
        )))
    }
}

fn validate_sha256(field: &str, value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(invalid_proof(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )))
    }
}

fn require_bound(bytes: &[u8], maximum: usize, description: &str) -> Result<()> {
    if bytes.len() <= maximum {
        Ok(())
    } else {
        Err(invalid_proof(format!(
            "{description} exceeds {maximum} bytes"
        )))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid_proof(reason: impl Into<String>) -> ProofError {
    ProofError::InvalidContinuityProof(reason.into())
}
