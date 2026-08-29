use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use a_quo_display::escape_untrusted_text_for_terminal;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::continuity::{
    CONTINUITY_CANONICALIZATION, MAX_CONTINUITY_PAYLOAD_BYTES, MAX_CONTINUITY_TRANSITIONS,
    PersonaContinuityCheckpoint, PersonaRootProof, PersonaTransitionProof, VerifiedPersonaRoot,
    match_continuity_head_checkpoint, validate_persona_transition_proof_structure,
    verify_persona_root_proof, verify_persona_transition_proof,
};
use crate::{
    EvidenceStatus, MAX_PROOF_BYTES, ProofError, Result, decode_payload, normalize_public_key,
    parse_bounded_json, public_key_fingerprint, sshsig_sign, sshsig_verify,
    validate_key_fingerprint, validate_persona,
};

pub const RECOVERY_POLICY_STATEMENT_SCHEMA: &str = "urn:a-quo:statement:persona-recovery-policy:v1";
pub const RECOVERY_POLICY_PROOF_SCHEMA: &str = "urn:a-quo:proof:persona-recovery-policy:sshsig:v1";
pub const RECOVERY_POLICY_ENROLLMENT_NAMESPACE: &str = "a-quo-recovery-policy-enrollment-v1";
pub const RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE: &str =
    "a-quo-recovery-policy-update-previous-v1";
pub const RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE: &str =
    "a-quo-recovery-policy-update-current-v1";
pub const RECOVERY_TRANSITION_STATEMENT_SCHEMA: &str =
    "urn:a-quo:statement:persona-recovery-transition:v1";
pub const RECOVERY_TRANSITION_PROOF_SCHEMA: &str =
    "urn:a-quo:proof:persona-recovery-transition:sshsig:v1";
pub const RECOVERY_TRANSITION_AUTHORITY_NAMESPACE: &str = "a-quo-persona-recovery-authority-v1";
pub const RECOVERY_TRANSITION_NEXT_NAMESPACE: &str = "a-quo-persona-recovery-next-v1";

pub const MIN_RECOVERY_AUTHORITIES: usize = 2;
pub const MAX_RECOVERY_AUTHORITIES: usize = 32;
pub const MAX_RECOVERY_POLICY_VERSIONS: usize = 1_024;
pub const MAX_RECOVERY_POLICY_VALIDITY_SECONDS: i64 = 315_576_000;

const PERSONA_ANCHOR_BYTES: usize = 32;
const MAX_CONTINUITY_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_JCS_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const SIGNATURE_FORMAT: &str = "sshsig";
const PUBLIC_KEY_FORMAT: &str = "openssh-public-key";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyStatement {
    pub schema: String,
    pub canonicalization: String,
    pub persona_anchor: String,
    pub persona: String,
    pub root_statement_sha256: String,
    pub policy_version: u32,
    pub previous_policy_sha256: Option<String>,
    pub continuity_checkpoint: RecoveryContinuityCheckpoint,
    pub issued_at: i64,
    pub expires_at: i64,
    pub threshold: u32,
    pub recovery_key_fingerprints: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContinuityCheckpoint {
    pub transition_sequence: u32,
    pub transition_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySignature {
    pub format: String,
    pub namespace: String,
    pub value: String,
    pub public_key_format: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryPolicyAuthorization {
    Enrollment {
        signatures: Vec<RecoverySignature>,
    },
    Update {
        previous_policy_signatures: Vec<RecoverySignature>,
        current_policy_signatures: Vec<RecoverySignature>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyProof {
    pub schema: String,
    pub payload: String,
    pub authorization: RecoveryPolicyAuthorization,
}

/// One recovery private-key reference and its public verification material.
/// The private key bytes are never copied into A Quo; the path is handed to
/// the installed OpenSSH signer and may refer to a hardware-backed key stub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverySigner {
    pub private_key_path: PathBuf,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedRecoveryPolicy {
    pub statement: RecoveryPolicyStatement,
    pub policy_statement_sha256: String,
    pub previous_authorization_fingerprints: Vec<String>,
    pub current_authorization_fingerprints: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPolicyTimeStatus {
    Active,
    NotYetValid,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryPolicyChainReport {
    pub root_signature: EvidenceStatus,
    pub expected_root_digest: EvidenceStatus,
    pub enrollment_proof: EvidenceStatus,
    pub update_chain: EvidenceStatus,
    pub expected_latest_policy_digest: EvidenceStatus,
    pub persona: String,
    pub persona_anchor: String,
    pub root_statement_sha256: String,
    pub initial_policy_sha256: String,
    pub latest_policy_sha256: String,
    pub latest_policy_version: u32,
    pub threshold: u32,
    pub authority_count: u32,
    pub latest_checkpoint_sequence: u32,
    pub latest_checkpoint_sha256: Option<String>,
    pub checkpoint_against_transition_chain: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub checked_at: i64,
    pub time_status: RecoveryPolicyTimeStatus,
    pub not_established: Vec<String>,
}

/// Opaque output from one complete recovery-policy chain verification.
///
/// The root, ordered policies, and report all come from the same cryptographic
/// pass. Keeping construction private prevents callers from presenting an
/// independently assembled sequence as the result of this verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecoveryPolicyChain {
    root: VerifiedPersonaRoot,
    policies: Vec<VerifiedRecoveryPolicy>,
    report: RecoveryPolicyChainReport,
}

impl VerifiedRecoveryPolicyChain {
    pub fn root(&self) -> &VerifiedPersonaRoot {
        &self.root
    }

    pub fn policies(&self) -> &[VerifiedRecoveryPolicy] {
        &self.policies
    }

    pub fn report(&self) -> &RecoveryPolicyChainReport {
        &self.report
    }

    pub fn into_parts(
        self,
    ) -> (
        VerifiedPersonaRoot,
        Vec<VerifiedRecoveryPolicy>,
        RecoveryPolicyChainReport,
    ) {
        (self.root, self.policies, self.report)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryTransitionReason {
    Recovery,
    Compromise,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransitionStatement {
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
    pub recovery_policy_sha256: String,
    pub recovery_policy_version: u32,
    pub reason: RecoveryTransitionReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransitionProof {
    pub schema: String,
    pub payload: String,
    pub recovery_signatures: Vec<RecoverySignature>,
    pub next_signature: RecoverySignature,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedRecoveryTransition {
    pub statement: RecoveryTransitionStatement,
    pub transition_statement_sha256: String,
    pub recovery_signer_fingerprints: Vec<String>,
    pub next_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PersonaContinuityTransitionProof {
    Routine(PersonaTransitionProof),
    Recovery(RecoveryTransitionProof),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryAwareContinuityChainReport {
    pub root_signature: EvidenceStatus,
    pub expected_root_digest: EvidenceStatus,
    pub policy_chain: EvidenceStatus,
    pub policy_transition_checkpoints: EvidenceStatus,
    pub expected_latest_policy_digest: EvidenceStatus,
    pub transition_chain: EvidenceStatus,
    pub persona: String,
    pub persona_anchor: String,
    pub root_statement_sha256: String,
    pub latest_policy_sha256: String,
    pub latest_policy_version: u32,
    pub latest_policy_time_status: RecoveryPolicyTimeStatus,
    pub latest_policy_checkpoint_sequence: u32,
    pub latest_policy_checkpoint_sha256: Option<String>,
    pub chain_tip_key_fingerprint: String,
    pub transition_count: u32,
    pub routine_transition_count: u32,
    pub recovery_transition_count: u32,
    pub last_issued_at: i64,
    pub last_transition_sha256: Option<String>,
    pub checked_at: i64,
    pub expected_head_checkpoint: Option<EvidenceStatus>,
    pub not_established: Vec<String>,
}

/// Parse and structurally validate a bounded recovery-policy proof without
/// claiming that any SSH signature is valid or that a policy chain is current.
pub fn parse_recovery_policy_proof_bytes(bytes: &[u8]) -> Result<RecoveryPolicyProof> {
    let proof: RecoveryPolicyProof = parse_bounded_json(
        bytes,
        usize::try_from(MAX_PROOF_BYTES).expect("proof bound fits in usize"),
        "recovery policy proof",
    )
    .map_err(invalid_proof)?;
    preflight_recovery_policy_proof(&proof)?;
    Ok(proof)
}

/// Parse and structurally validate a bounded recovery-transition proof without
/// claiming that its SSH signatures are valid or authorized by a current policy.
pub fn parse_recovery_transition_proof_bytes(bytes: &[u8]) -> Result<RecoveryTransitionProof> {
    let proof: RecoveryTransitionProof = parse_bounded_json(
        bytes,
        usize::try_from(MAX_PROOF_BYTES).expect("proof bound fits in usize"),
        "recovery transition proof",
    )
    .map_err(invalid_proof)?;
    preflight_recovery_transition_proof(&proof)?;
    Ok(proof)
}

/// Parse either supported transition proof at the same bounded byte boundary
/// used by the CLI. This validates structure and canonical payloads only.
pub fn parse_persona_continuity_transition_proof_bytes(
    bytes: &[u8],
) -> Result<PersonaContinuityTransitionProof> {
    let proof: PersonaContinuityTransitionProof = parse_bounded_json(
        bytes,
        usize::try_from(MAX_PROOF_BYTES).expect("proof bound fits in usize"),
        "routine or recovery transition proof",
    )
    .map_err(invalid_proof)?;
    match &proof {
        PersonaContinuityTransitionProof::Routine(proof) => {
            validate_persona_transition_proof_structure(proof)?;
        }
        PersonaContinuityTransitionProof::Recovery(proof) => {
            preflight_recovery_transition_proof(proof)?;
        }
    }
    Ok(proof)
}

/// Create version 1 of a recovery policy. Every listed recovery key must later
/// sign the enrollment proof; the threshold controls recovery, not enrollment.
pub fn new_initial_recovery_policy_statement(
    root: &VerifiedPersonaRoot,
    authority_public_keys: &[String],
    threshold: u32,
    continuity_checkpoint: RecoveryContinuityCheckpoint,
    issued_at: i64,
    expires_at: i64,
) -> Result<RecoveryPolicyStatement> {
    if issued_at < root.statement.issued_at {
        return Err(invalid_statement(
            "a recovery policy cannot predate its persona root",
        ));
    }
    let statement = RecoveryPolicyStatement {
        schema: RECOVERY_POLICY_STATEMENT_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        persona_anchor: root.statement.persona_anchor.clone(),
        persona: root.statement.persona.clone(),
        root_statement_sha256: root.root_statement_sha256.clone(),
        policy_version: 1,
        previous_policy_sha256: None,
        continuity_checkpoint,
        issued_at,
        expires_at,
        threshold,
        recovery_key_fingerprints: authority_fingerprints(authority_public_keys)?,
    };
    validate_recovery_policy_statement(&statement)?;
    validate_policy_root_binding(root, &statement)?;
    if statement
        .recovery_key_fingerprints
        .binary_search(&root.statement.initial_key_fingerprint)
        .is_ok()
    {
        return Err(invalid_statement(
            "the online persona key cannot also be a recovery authority key",
        ));
    }
    Ok(statement)
}

/// Construct the exact next recovery-policy version. Its proof must be signed
/// under distinct namespaces by both the previous and current policy sets.
pub fn new_recovery_policy_update_statement(
    previous: &VerifiedRecoveryPolicy,
    authority_public_keys: &[String],
    threshold: u32,
    continuity_checkpoint: RecoveryContinuityCheckpoint,
    issued_at: i64,
    expires_at: i64,
) -> Result<RecoveryPolicyStatement> {
    if issued_at < previous.statement.issued_at {
        return Err(invalid_statement(
            "recovery policy issuance times cannot move backward",
        ));
    }
    let policy_version = previous
        .statement
        .policy_version
        .checked_add(1)
        .ok_or_else(|| invalid_statement("recovery policy version overflow"))?;
    let statement = RecoveryPolicyStatement {
        schema: RECOVERY_POLICY_STATEMENT_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        persona_anchor: previous.statement.persona_anchor.clone(),
        persona: previous.statement.persona.clone(),
        root_statement_sha256: previous.statement.root_statement_sha256.clone(),
        policy_version,
        previous_policy_sha256: Some(previous.policy_statement_sha256.clone()),
        continuity_checkpoint,
        issued_at,
        expires_at,
        threshold,
        recovery_key_fingerprints: authority_fingerprints(authority_public_keys)?,
    };
    validate_recovery_policy_statement(&statement)?;
    validate_policy_successor(previous, &statement)?;
    Ok(statement)
}

pub fn canonical_recovery_policy_statement_bytes(
    statement: &RecoveryPolicyStatement,
) -> Result<Vec<u8>> {
    validate_recovery_policy_statement(statement)?;
    let bytes = serde_json_canonicalizer::to_vec(statement)?;
    validate_payload_bound(&bytes)?;
    Ok(bytes)
}

pub fn recovery_policy_statement_sha256(statement: &RecoveryPolicyStatement) -> Result<String> {
    Ok(sha256_hex(&canonical_recovery_policy_statement_bytes(
        statement,
    )?))
}

/// Sign an initial policy with every listed authority. Requiring proof of
/// possession for all enrollment keys prevents silent dead or mistyped keys.
pub fn create_initial_recovery_policy_proof(
    statement: RecoveryPolicyStatement,
    signers: &[RecoverySigner],
) -> Result<RecoveryPolicyProof> {
    if statement.policy_version != 1 || statement.previous_policy_sha256.is_some() {
        return Err(invalid_proof(
            "an enrollment proof requires policy version 1 without a predecessor",
        ));
    }
    let payload = canonical_recovery_policy_statement_bytes(&statement)?;
    let signatures = sign_with_authorities(
        &payload,
        signers,
        &statement.recovery_key_fingerprints,
        statement.recovery_key_fingerprints.len(),
        true,
        RECOVERY_POLICY_ENROLLMENT_NAMESPACE,
    )?;
    Ok(RecoveryPolicyProof {
        schema: RECOVERY_POLICY_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        authorization: RecoveryPolicyAuthorization::Enrollment { signatures },
    })
}

/// Sign an update with at least the previous threshold and with every newly
/// listed key. Verifiers require the new threshold; creation is stricter so a
/// newly enrolled key cannot be silently dead or mistyped.
pub fn create_recovery_policy_update_proof(
    statement: RecoveryPolicyStatement,
    previous: &VerifiedRecoveryPolicy,
    previous_signers: &[RecoverySigner],
    current_signers: &[RecoverySigner],
) -> Result<RecoveryPolicyProof> {
    validate_policy_successor(previous, &statement)?;
    let payload = canonical_recovery_policy_statement_bytes(&statement)?;
    let previous_threshold = usize::try_from(previous.statement.threshold)
        .map_err(|_| invalid_proof("previous recovery threshold does not fit this platform"))?;
    let previous_policy_signatures = sign_with_authorities(
        &payload,
        previous_signers,
        &previous.statement.recovery_key_fingerprints,
        previous_threshold,
        false,
        RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE,
    )?;
    let current_policy_signatures = sign_with_authorities(
        &payload,
        current_signers,
        &statement.recovery_key_fingerprints,
        statement.recovery_key_fingerprints.len(),
        true,
        RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE,
    )?;
    Ok(RecoveryPolicyProof {
        schema: RECOVERY_POLICY_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        authorization: RecoveryPolicyAuthorization::Update {
            previous_policy_signatures,
            current_policy_signatures,
        },
    })
}

pub fn verify_initial_recovery_policy_proof(
    root: &VerifiedPersonaRoot,
    proof: &RecoveryPolicyProof,
) -> Result<VerifiedRecoveryPolicy> {
    verify_recovery_policy_proof(root, None, proof)
}

pub fn verify_recovery_policy_update_proof(
    root: &VerifiedPersonaRoot,
    previous: &VerifiedRecoveryPolicy,
    proof: &RecoveryPolicyProof,
) -> Result<VerifiedRecoveryPolicy> {
    verify_recovery_policy_proof(root, Some(previous), proof)
}

pub fn verify_recovery_policy_chain(
    root_proof: &PersonaRootProof,
    policies: &[RecoveryPolicyProof],
    expected_root_statement_sha256: &str,
    expected_latest_policy_sha256: &str,
    checked_at: i64,
) -> Result<RecoveryPolicyChainReport> {
    Ok(verify_recovery_policy_chain_with_verified_sequence(
        root_proof,
        policies,
        expected_root_statement_sha256,
        expected_latest_policy_sha256,
        checked_at,
    )?
    .report)
}

/// Verify a recovery-policy chain once and retain the exact verified root and
/// ordered policy sequence used to produce its report.
pub fn verify_recovery_policy_chain_with_verified_sequence(
    root_proof: &PersonaRootProof,
    policies: &[RecoveryPolicyProof],
    expected_root_statement_sha256: &str,
    expected_latest_policy_sha256: &str,
    checked_at: i64,
) -> Result<VerifiedRecoveryPolicyChain> {
    let sequence = verified_recovery_policy_sequence(
        root_proof,
        policies,
        expected_root_statement_sha256,
        expected_latest_policy_sha256,
    )?;
    let report = recovery_policy_chain_report(&sequence, checked_at)?;
    Ok(VerifiedRecoveryPolicyChain {
        root: sequence.root,
        policies: sequence.policies,
        report,
    })
}

fn recovery_policy_chain_report(
    chain: &VerifiedRecoveryPolicySequence,
    checked_at: i64,
) -> Result<RecoveryPolicyChainReport> {
    validate_jcs_time("recovery policy check time", checked_at)?;
    let initial = chain
        .policies
        .first()
        .expect("a verified recovery policy chain is non-empty");
    let latest = chain
        .policies
        .last()
        .expect("a verified recovery policy chain is non-empty");
    let time_status = policy_time_status(&latest.statement, checked_at);

    Ok(RecoveryPolicyChainReport {
        root_signature: EvidenceStatus::Verified,
        expected_root_digest: EvidenceStatus::Verified,
        enrollment_proof: EvidenceStatus::Verified,
        update_chain: EvidenceStatus::Verified,
        expected_latest_policy_digest: EvidenceStatus::Verified,
        persona: chain.root.statement.persona.clone(),
        persona_anchor: chain.root.statement.persona_anchor.clone(),
        root_statement_sha256: chain.root.root_statement_sha256.clone(),
        initial_policy_sha256: initial.policy_statement_sha256.clone(),
        latest_policy_sha256: latest.policy_statement_sha256.clone(),
        latest_policy_version: latest.statement.policy_version,
        threshold: latest.statement.threshold,
        authority_count: u32::try_from(latest.statement.recovery_key_fingerprints.len())
            .expect("bounded authority count fits in u32"),
        latest_checkpoint_sequence: latest.statement.continuity_checkpoint.transition_sequence,
        latest_checkpoint_sha256: latest
            .statement
            .continuity_checkpoint
            .transition_sha256
            .clone(),
        checkpoint_against_transition_chain: "not_checked_without_transition_chain".to_owned(),
        issued_at: latest.statement.issued_at,
        expires_at: latest.statement.expires_at,
        checked_at,
        time_status,
        not_established: vec![
            "when_or_how_the_root_and_latest_policy_digests_were_pinned".to_owned(),
            "whether_a_newer_policy_was_withheld_from_the_verifier".to_owned(),
            "whether_policy_checkpoints_match_the_transition_chain".to_owned(),
            "a_trusted_timestamp_for_policy_issuance".to_owned(),
            "the_legal_identity_or_independence_of_recovery_key_holders".to_owned(),
            "artifact_or_software_safety".to_owned(),
        ],
    })
}

/// Verify an ordered policy sequence against an already verified persona root.
/// This establishes signature continuity only; callers that make trust
/// decisions must separately pin the root and latest policy digests.
pub fn verify_recovery_policy_proof_sequence(
    root: &VerifiedPersonaRoot,
    policies: &[RecoveryPolicyProof],
) -> Result<Vec<VerifiedRecoveryPolicy>> {
    if policies.is_empty() || policies.len() > MAX_RECOVERY_POLICY_VERSIONS {
        return Err(chain_mismatch(format!(
            "recovery policy chain must contain 1 through {MAX_RECOVERY_POLICY_VERSIONS} proofs"
        )));
    }
    let mut verified = Vec::with_capacity(policies.len());
    for proof in policies {
        let policy = verify_recovery_policy_proof(root, verified.last(), proof)?;
        verified.push(policy);
    }
    Ok(verified)
}

struct VerifiedRecoveryPolicySequence {
    root: VerifiedPersonaRoot,
    policies: Vec<VerifiedRecoveryPolicy>,
}

fn verified_recovery_policy_sequence(
    root_proof: &PersonaRootProof,
    policies: &[RecoveryPolicyProof],
    expected_root_statement_sha256: &str,
    expected_latest_policy_sha256: &str,
) -> Result<VerifiedRecoveryPolicySequence> {
    validate_sha256(
        "expected root statement digest",
        expected_root_statement_sha256,
    )?;
    validate_sha256(
        "expected latest recovery policy digest",
        expected_latest_policy_sha256,
    )?;
    let root = verify_persona_root_proof(root_proof)?;
    if root.root_statement_sha256 != expected_root_statement_sha256 {
        return Err(chain_mismatch(
            "root statement digest does not match the independently expected digest",
        ));
    }

    let verified = verify_recovery_policy_proof_sequence(&root, policies)?;
    let latest = verified
        .last()
        .expect("a non-empty policy input produces a non-empty verified chain");
    if latest.policy_statement_sha256 != expected_latest_policy_sha256 {
        return Err(chain_mismatch(
            "latest recovery policy digest does not match the independently expected digest",
        ));
    }
    Ok(VerifiedRecoveryPolicySequence {
        root,
        policies: verified,
    })
}

fn verify_recovery_policy_proof(
    root: &VerifiedPersonaRoot,
    previous: Option<&VerifiedRecoveryPolicy>,
    proof: &RecoveryPolicyProof,
) -> Result<VerifiedRecoveryPolicy> {
    let (payload, statement) = preflight_recovery_policy_proof(proof)?;
    validate_policy_root_binding(root, &statement)?;
    let policy_statement_sha256 = sha256_hex(&payload);

    let (previous_authorization_fingerprints, current_authorization_fingerprints) =
        match (previous, &proof.authorization) {
            (None, RecoveryPolicyAuthorization::Enrollment { signatures }) => {
                if statement.policy_version != 1 || statement.previous_policy_sha256.is_some() {
                    return Err(invalid_proof(
                        "an enrollment proof requires policy version 1 without a predecessor",
                    ));
                }
                let current = verify_authority_signatures(
                    &payload,
                    signatures,
                    &statement.recovery_key_fingerprints,
                    statement.recovery_key_fingerprints.len(),
                    true,
                    RECOVERY_POLICY_ENROLLMENT_NAMESPACE,
                )?;
                (Vec::new(), current)
            }
            (
                Some(previous),
                RecoveryPolicyAuthorization::Update {
                    previous_policy_signatures,
                    current_policy_signatures,
                },
            ) => {
                validate_policy_successor(previous, &statement)?;
                let previous_threshold =
                    usize::try_from(previous.statement.threshold).map_err(|_| {
                        invalid_proof("previous recovery threshold does not fit this platform")
                    })?;
                let previous_fingerprints = verify_authority_signatures(
                    &payload,
                    previous_policy_signatures,
                    &previous.statement.recovery_key_fingerprints,
                    previous_threshold,
                    false,
                    RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE,
                )?;
                let current_threshold = usize::try_from(statement.threshold).map_err(|_| {
                    invalid_proof("current recovery threshold does not fit this platform")
                })?;
                let current_fingerprints = verify_authority_signatures(
                    &payload,
                    current_policy_signatures,
                    &statement.recovery_key_fingerprints,
                    current_threshold,
                    false,
                    RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE,
                )?;
                (previous_fingerprints, current_fingerprints)
            }
            (None, RecoveryPolicyAuthorization::Update { .. }) => {
                return Err(invalid_proof(
                    "the initial recovery policy cannot use update authorization",
                ));
            }
            (Some(_), RecoveryPolicyAuthorization::Enrollment { .. }) => {
                return Err(invalid_proof(
                    "a recovery policy successor cannot use enrollment authorization",
                ));
            }
        };

    Ok(VerifiedRecoveryPolicy {
        statement,
        policy_statement_sha256,
        previous_authorization_fingerprints,
        current_authorization_fingerprints,
    })
}

fn preflight_recovery_policy_proof(
    proof: &RecoveryPolicyProof,
) -> Result<(Vec<u8>, RecoveryPolicyStatement)> {
    require_schema(&proof.schema, RECOVERY_POLICY_PROOF_SCHEMA)?;
    let payload = decode_canonical_payload(&proof.payload)?;
    let statement: RecoveryPolicyStatement = parse_bounded_json(
        &payload,
        MAX_CONTINUITY_PAYLOAD_BYTES,
        "recovery policy statement",
    )
    .map_err(invalid_statement)?;
    let canonical = canonical_recovery_policy_statement_bytes(&statement)?;
    if canonical != payload {
        return Err(ProofError::NonCanonicalContinuityStatement);
    }

    match &proof.authorization {
        RecoveryPolicyAuthorization::Enrollment { signatures } => {
            if statement.policy_version != 1 || statement.previous_policy_sha256.is_some() {
                return Err(invalid_proof(
                    "an enrollment proof requires policy version 1 without a predecessor",
                ));
            }
            preflight_authority_signatures(
                signatures,
                &statement.recovery_key_fingerprints,
                statement.recovery_key_fingerprints.len(),
                true,
                RECOVERY_POLICY_ENROLLMENT_NAMESPACE,
            )?;
        }
        RecoveryPolicyAuthorization::Update {
            previous_policy_signatures,
            current_policy_signatures,
        } => {
            if statement.policy_version <= 1 || statement.previous_policy_sha256.is_none() {
                return Err(invalid_proof(
                    "an update proof requires a policy version after 1 and a predecessor digest",
                ));
            }
            preflight_unbound_signature_set(
                previous_policy_signatures,
                RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE,
            )?;
            let current_threshold = usize::try_from(statement.threshold).map_err(|_| {
                invalid_proof("current recovery threshold does not fit this platform")
            })?;
            preflight_authority_signatures(
                current_policy_signatures,
                &statement.recovery_key_fingerprints,
                current_threshold,
                false,
                RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE,
            )?;
        }
    }

    Ok((payload, statement))
}

/// Construct a recovery transition. The unavailable current key is named but
/// does not sign; an active policy threshold authorizes the replacement and
/// the proposed next key separately proves custody.
#[allow(clippy::too_many_arguments)]
pub fn new_recovery_transition_statement(
    root: &VerifiedPersonaRoot,
    sequence: u32,
    previous_transition_sha256: Option<&str>,
    previous_key_fingerprint: &str,
    next_public_key: &str,
    policy: &VerifiedRecoveryPolicy,
    issued_at: i64,
    reason: RecoveryTransitionReason,
) -> Result<RecoveryTransitionStatement> {
    validate_policy_root_binding(root, &policy.statement)?;
    validate_key_fingerprint(previous_key_fingerprint)?;
    if sequence == 1 && previous_key_fingerprint != root.statement.initial_key_fingerprint {
        return Err(chain_mismatch(
            "recovery transition 1 must replace the root's initial key",
        ));
    }
    if issued_at < root.statement.issued_at {
        return Err(invalid_statement(
            "a recovery transition cannot predate its persona root",
        ));
    }
    let next_public_key = normalize_public_key(next_public_key)?;
    let statement = RecoveryTransitionStatement {
        schema: RECOVERY_TRANSITION_STATEMENT_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        persona_anchor: root.statement.persona_anchor.clone(),
        persona: root.statement.persona.clone(),
        sequence,
        issued_at,
        root_statement_sha256: root.root_statement_sha256.clone(),
        previous_transition_sha256: previous_transition_sha256.map(ToOwned::to_owned),
        previous_key_fingerprint: previous_key_fingerprint.to_owned(),
        next_key_fingerprint: public_key_fingerprint(&next_public_key)?,
        recovery_policy_sha256: policy.policy_statement_sha256.clone(),
        recovery_policy_version: policy.statement.policy_version,
        reason,
    };
    validate_recovery_transition_statement(&statement)?;
    validate_recovery_transition_binding(root, policy, &statement)?;
    Ok(statement)
}

pub fn canonical_recovery_transition_statement_bytes(
    statement: &RecoveryTransitionStatement,
) -> Result<Vec<u8>> {
    validate_recovery_transition_statement(statement)?;
    let bytes = serde_json_canonicalizer::to_vec(statement)?;
    validate_payload_bound(&bytes)?;
    Ok(bytes)
}

pub fn recovery_transition_statement_sha256(
    statement: &RecoveryTransitionStatement,
) -> Result<String> {
    Ok(sha256_hex(&canonical_recovery_transition_statement_bytes(
        statement,
    )?))
}

pub fn create_recovery_transition_proof(
    statement: RecoveryTransitionStatement,
    policy: &VerifiedRecoveryPolicy,
    authority_signers: &[RecoverySigner],
    next_private_key_path: impl AsRef<Path>,
    next_public_key: &str,
) -> Result<RecoveryTransitionProof> {
    validate_recovery_transition_policy_binding(policy, &statement)?;
    let payload = canonical_recovery_transition_statement_bytes(&statement)?;
    let threshold = usize::try_from(policy.statement.threshold)
        .map_err(|_| invalid_proof("recovery threshold does not fit this platform"))?;
    let recovery_signatures = sign_with_authorities(
        &payload,
        authority_signers,
        &policy.statement.recovery_key_fingerprints,
        threshold,
        false,
        RECOVERY_TRANSITION_AUTHORITY_NAMESPACE,
    )?;
    let next_public_key = normalize_public_key(next_public_key)?;
    if public_key_fingerprint(&next_public_key)? != statement.next_key_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    let next_signature = sign_one(
        &payload,
        next_private_key_path.as_ref(),
        &next_public_key,
        RECOVERY_TRANSITION_NEXT_NAMESPACE,
    )?;
    Ok(RecoveryTransitionProof {
        schema: RECOVERY_TRANSITION_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        recovery_signatures,
        next_signature,
    })
}

pub fn verify_recovery_transition_proof(
    root: &VerifiedPersonaRoot,
    policy: &VerifiedRecoveryPolicy,
    proof: &RecoveryTransitionProof,
) -> Result<VerifiedRecoveryTransition> {
    let RecoveryTransitionProofPreflight {
        payload,
        statement,
        next_public_key,
    } = preflight_recovery_transition_proof(proof)?;
    validate_recovery_transition_binding(root, policy, &statement)?;
    let threshold = usize::try_from(policy.statement.threshold)
        .map_err(|_| invalid_proof("recovery threshold does not fit this platform"))?;
    let recovery_signer_fingerprints = verify_authority_signatures(
        &payload,
        &proof.recovery_signatures,
        &policy.statement.recovery_key_fingerprints,
        threshold,
        false,
        RECOVERY_TRANSITION_AUTHORITY_NAMESPACE,
    )?;
    sshsig_verify(
        &payload,
        &proof.next_signature.value,
        &next_public_key,
        RECOVERY_TRANSITION_NEXT_NAMESPACE,
    )?;
    Ok(VerifiedRecoveryTransition {
        transition_statement_sha256: sha256_hex(&payload),
        statement,
        recovery_signer_fingerprints,
        next_public_key,
    })
}

/// Decode and validate the canonical transition statement without verifying
/// its signatures or ordered chain position. This is suitable only for
/// selecting the exact already-verified policy named by the proof.
pub fn inspect_recovery_transition_proof(
    proof: &RecoveryTransitionProof,
) -> Result<RecoveryTransitionStatement> {
    Ok(preflight_recovery_transition_proof(proof)?.statement)
}

/// Verify one ordered history containing routine and recovery transitions.
/// The latest recovery-policy digest must come from a separate trusted channel;
/// this proves consistency with that pin, not that no newer policy was hidden.
#[allow(clippy::too_many_arguments)]
pub fn verify_persona_continuity_chain_with_recovery(
    root_proof: &PersonaRootProof,
    transitions: &[PersonaContinuityTransitionProof],
    policies: &[RecoveryPolicyProof],
    expected_root_statement_sha256: &str,
    expected_latest_policy_sha256: &str,
    checked_at: i64,
) -> Result<RecoveryAwareContinuityChainReport> {
    if transitions.len() > MAX_CONTINUITY_TRANSITIONS {
        return Err(chain_mismatch(format!(
            "chain cannot contain more than {MAX_CONTINUITY_TRANSITIONS} transitions"
        )));
    }
    validate_jcs_time("continuity check time", checked_at)?;
    let policy_chain = verified_recovery_policy_sequence(
        root_proof,
        policies,
        expected_root_statement_sha256,
        expected_latest_policy_sha256,
    )?;
    let root = &policy_chain.root;
    let latest_policy = policy_chain
        .policies
        .last()
        .expect("a verified recovery policy chain is non-empty");

    let mut current_key_fingerprint = root.statement.initial_key_fingerprint.clone();
    let mut previous_transition_sha256 = None;
    let mut previous_issued_at = root.statement.issued_at;
    let mut routine_transition_count = 0_u32;
    let mut recovery_transition_count = 0_u32;
    let mut transition_statement_sha256s = Vec::with_capacity(transitions.len());
    let mut transition_issued_ats = Vec::with_capacity(transitions.len());
    let mut online_key_fingerprints = BTreeSet::new();
    online_key_fingerprints.insert(root.statement.initial_key_fingerprint.clone());

    for (index, proof) in transitions.iter().enumerate() {
        let expected_sequence =
            u32::try_from(index + 1).expect("bounded continuity chain length fits in u32");
        let (
            sequence,
            persona_anchor,
            persona,
            root_statement_sha256,
            linked_previous_transition,
            previous_key,
            next_key,
            issued_at,
            statement_sha256,
        ) = match proof {
            PersonaContinuityTransitionProof::Routine(proof) => {
                let verified = verify_persona_transition_proof(proof)?;
                routine_transition_count = routine_transition_count
                    .checked_add(1)
                    .expect("bounded transition count fits in u32");
                (
                    verified.statement.sequence,
                    verified.statement.persona_anchor,
                    verified.statement.persona,
                    verified.statement.root_statement_sha256,
                    verified.statement.previous_transition_sha256,
                    verified.statement.previous_key_fingerprint,
                    verified.statement.next_key_fingerprint,
                    verified.statement.issued_at,
                    verified.transition_statement_sha256,
                )
            }
            PersonaContinuityTransitionProof::Recovery(proof) => {
                let (_, unverified_statement) = decode_recovery_transition_proof(proof)?;
                let policy_index = policy_chain
                    .policies
                    .iter()
                    .position(|candidate| {
                        candidate.policy_statement_sha256
                            == unverified_statement.recovery_policy_sha256
                    })
                    .ok_or_else(|| {
                        chain_mismatch(
                            "recovery transition references a policy outside the verified chain",
                        )
                    })?;
                let policy = &policy_chain.policies[policy_index];
                if unverified_statement.sequence
                    <= policy.statement.continuity_checkpoint.transition_sequence
                {
                    return Err(chain_mismatch(
                        "recovery transition is not after its policy's signed continuity checkpoint",
                    ));
                }
                if let Some(successor) = policy_chain.policies.get(policy_index + 1)
                    && unverified_statement.sequence
                        > successor
                            .statement
                            .continuity_checkpoint
                            .transition_sequence
                {
                    return Err(chain_mismatch(
                        "recovery transition uses a superseded policy beyond its successor's signed continuity checkpoint",
                    ));
                }
                let verified = verify_recovery_transition_proof(root, policy, proof)?;
                recovery_transition_count = recovery_transition_count
                    .checked_add(1)
                    .expect("bounded transition count fits in u32");
                (
                    verified.statement.sequence,
                    verified.statement.persona_anchor,
                    verified.statement.persona,
                    verified.statement.root_statement_sha256,
                    verified.statement.previous_transition_sha256,
                    verified.statement.previous_key_fingerprint,
                    verified.statement.next_key_fingerprint,
                    verified.statement.issued_at,
                    verified.transition_statement_sha256,
                )
            }
        };

        if sequence != expected_sequence {
            return Err(chain_mismatch(format!(
                "transition sequence {sequence} is out of order; expected {expected_sequence}"
            )));
        }
        if persona_anchor != root.statement.persona_anchor
            || persona != root.statement.persona
            || root_statement_sha256 != root.root_statement_sha256
        {
            return Err(chain_mismatch(
                "transition is bound to a different persona root",
            ));
        }
        if linked_previous_transition != previous_transition_sha256 {
            return Err(chain_mismatch(
                "transition does not link to the exact previous statement",
            ));
        }
        if previous_key != current_key_fingerprint {
            return Err(chain_mismatch(
                "transition previous key is not the chain's current key",
            ));
        }
        if issued_at < previous_issued_at {
            return Err(chain_mismatch("transition issuance times move backward"));
        }

        current_key_fingerprint = next_key;
        online_key_fingerprints.insert(current_key_fingerprint.clone());
        transition_statement_sha256s.push(statement_sha256.clone());
        transition_issued_ats.push(issued_at);
        previous_transition_sha256 = Some(statement_sha256);
        previous_issued_at = issued_at;
    }

    for policy in &policy_chain.policies {
        let checkpoint = &policy.statement.continuity_checkpoint;
        if checkpoint.transition_sequence == 0 {
            continue;
        }
        let checkpoint_index = usize::try_from(checkpoint.transition_sequence - 1)
            .expect("bounded transition sequence fits in usize");
        let actual_digest = transition_statement_sha256s
            .get(checkpoint_index)
            .ok_or_else(|| {
                chain_mismatch(format!(
                    "recovery policy v{} checkpoints transition {}, but the supplied chain ends at {}",
                    policy.statement.policy_version,
                    checkpoint.transition_sequence,
                    transitions.len()
                ))
            })?;
        if checkpoint.transition_sha256.as_deref() != Some(actual_digest.as_str()) {
            return Err(chain_mismatch(format!(
                "recovery policy v{} checkpoint does not match transition {}",
                policy.statement.policy_version, checkpoint.transition_sequence
            )));
        }
        let transition_issued_at = transition_issued_ats[checkpoint_index];
        if policy.statement.issued_at < transition_issued_at {
            return Err(chain_mismatch(format!(
                "recovery policy v{} claims to predate its checkpointed transition",
                policy.statement.policy_version
            )));
        }
    }

    for policy in &policy_chain.policies {
        if policy
            .statement
            .recovery_key_fingerprints
            .iter()
            .any(|fingerprint| online_key_fingerprints.contains(fingerprint))
        {
            return Err(chain_mismatch(format!(
                "recovery policy v{} reuses an online persona key as a recovery authority",
                policy.statement.policy_version
            )));
        }
    }

    Ok(RecoveryAwareContinuityChainReport {
        root_signature: EvidenceStatus::Verified,
        expected_root_digest: EvidenceStatus::Verified,
        policy_chain: EvidenceStatus::Verified,
        policy_transition_checkpoints: EvidenceStatus::Verified,
        expected_latest_policy_digest: EvidenceStatus::Verified,
        transition_chain: EvidenceStatus::Verified,
        persona: root.statement.persona.clone(),
        persona_anchor: root.statement.persona_anchor.clone(),
        root_statement_sha256: root.root_statement_sha256.clone(),
        latest_policy_sha256: latest_policy.policy_statement_sha256.clone(),
        latest_policy_version: latest_policy.statement.policy_version,
        latest_policy_time_status: policy_time_status(&latest_policy.statement, checked_at),
        latest_policy_checkpoint_sequence: latest_policy
            .statement
            .continuity_checkpoint
            .transition_sequence,
        latest_policy_checkpoint_sha256: latest_policy
            .statement
            .continuity_checkpoint
            .transition_sha256
            .clone(),
        chain_tip_key_fingerprint: current_key_fingerprint,
        transition_count: u32::try_from(transitions.len())
            .expect("bounded transition count fits in u32"),
        routine_transition_count,
        recovery_transition_count,
        last_issued_at: previous_issued_at,
        last_transition_sha256: previous_transition_sha256,
        checked_at,
        expected_head_checkpoint: None,
        not_established: vec![
            "when_or_how_the_root_and_latest_policy_digests_were_pinned".to_owned(),
            "whether_a_newer_policy_or_transition_was_withheld".to_owned(),
            "trusted_time_for_policy_or_transition_issuance".to_owned(),
            "legal_identity_or_guardian_independence".to_owned(),
            "current_online_key_non_revocation".to_owned(),
            "artifact_or_software_safety".to_owned(),
        ],
    })
}

/// Verify a recovery-aware history and require its supplied tip to match an
/// independently obtained continuity checkpoint.
pub fn verify_persona_continuity_chain_with_recovery_at_checkpoint(
    root_proof: &PersonaRootProof,
    transitions: &[PersonaContinuityTransitionProof],
    policy_proofs: &[RecoveryPolicyProof],
    expected_root_statement_sha256: &str,
    expected_latest_policy_sha256: &str,
    checked_at: i64,
    expected_head: &PersonaContinuityCheckpoint,
) -> Result<RecoveryAwareContinuityChainReport> {
    let mut report = verify_persona_continuity_chain_with_recovery(
        root_proof,
        transitions,
        policy_proofs,
        expected_root_statement_sha256,
        expected_latest_policy_sha256,
        checked_at,
    )?;
    match_continuity_head_checkpoint(
        report.transition_count,
        report.last_transition_sha256.as_deref(),
        expected_head,
    )?;
    report.expected_head_checkpoint = Some(EvidenceStatus::Verified);
    report
        .not_established
        .retain(|claim| claim != "whether_a_newer_policy_or_transition_was_withheld");
    report.not_established.extend([
        "when_or_how_the_head_checkpoint_was_pinned".to_owned(),
        "whether_a_newer_policy_was_withheld".to_owned(),
        "whether_a_competing_transition_or_policy_branch_was_also_authorized_or_withheld"
            .to_owned(),
        "whether_a_newer_transition_exists_after_the_expected_checkpoint".to_owned(),
    ]);
    Ok(report)
}

fn decode_recovery_transition_proof(
    proof: &RecoveryTransitionProof,
) -> Result<(Vec<u8>, RecoveryTransitionStatement)> {
    require_schema(&proof.schema, RECOVERY_TRANSITION_PROOF_SCHEMA)?;
    let payload = decode_canonical_payload(&proof.payload)?;
    let statement: RecoveryTransitionStatement = parse_bounded_json(
        &payload,
        MAX_CONTINUITY_PAYLOAD_BYTES,
        "recovery transition statement",
    )
    .map_err(invalid_statement)?;
    let canonical = canonical_recovery_transition_statement_bytes(&statement)?;
    if canonical != payload {
        return Err(ProofError::NonCanonicalContinuityStatement);
    }
    Ok((payload, statement))
}

struct RecoveryTransitionProofPreflight {
    payload: Vec<u8>,
    statement: RecoveryTransitionStatement,
    next_public_key: String,
}

fn preflight_recovery_transition_proof(
    proof: &RecoveryTransitionProof,
) -> Result<RecoveryTransitionProofPreflight> {
    let (payload, statement) = decode_recovery_transition_proof(proof)?;
    preflight_unbound_signature_set(
        &proof.recovery_signatures,
        RECOVERY_TRANSITION_AUTHORITY_NAMESPACE,
    )?;
    let next_public_key =
        validate_recovery_signature(&proof.next_signature, RECOVERY_TRANSITION_NEXT_NAMESPACE)?;
    if public_key_fingerprint(&next_public_key)? != statement.next_key_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    Ok(RecoveryTransitionProofPreflight {
        payload,
        statement,
        next_public_key,
    })
}

fn validate_recovery_transition_statement(statement: &RecoveryTransitionStatement) -> Result<()> {
    if statement.schema != RECOVERY_TRANSITION_STATEMENT_SCHEMA {
        return Err(invalid_statement(format!(
            "unsupported recovery transition schema {}",
            escape_untrusted_text_for_terminal(&statement.schema)
        )));
    }
    if statement.canonicalization != CONTINUITY_CANONICALIZATION {
        return Err(invalid_statement(format!(
            "unsupported recovery transition canonicalization {}",
            escape_untrusted_text_for_terminal(&statement.canonicalization)
        )));
    }
    validate_persona_anchor(&statement.persona_anchor)?;
    validate_canonical_persona(&statement.persona)?;
    if statement.sequence == 0 {
        return Err(invalid_statement(
            "recovery transition sequence must start at 1",
        ));
    }
    validate_jcs_time("recovery transition issued_at", statement.issued_at)?;
    validate_sha256(
        "recovery transition root digest",
        &statement.root_statement_sha256,
    )?;
    match (
        statement.sequence,
        statement.previous_transition_sha256.as_deref(),
    ) {
        (1, None) => {}
        (1, Some(_)) => {
            return Err(invalid_statement(
                "recovery transition 1 cannot name a previous transition digest",
            ));
        }
        (_, Some(digest)) => validate_sha256("previous transition digest", digest)?,
        (_, None) => {
            return Err(invalid_statement(
                "recovery transitions after sequence 1 require a previous transition digest",
            ));
        }
    }
    validate_key_fingerprint(&statement.previous_key_fingerprint)?;
    validate_key_fingerprint(&statement.next_key_fingerprint)?;
    if statement.previous_key_fingerprint == statement.next_key_fingerprint {
        return Err(invalid_statement(
            "recovery must replace the current key with a distinct next key",
        ));
    }
    validate_sha256(
        "recovery transition policy digest",
        &statement.recovery_policy_sha256,
    )?;
    if statement.recovery_policy_version == 0 {
        return Err(invalid_statement(
            "recovery transition policy version must start at 1",
        ));
    }
    Ok(())
}

fn validate_recovery_transition_policy_binding(
    policy: &VerifiedRecoveryPolicy,
    statement: &RecoveryTransitionStatement,
) -> Result<()> {
    if statement.persona_anchor != policy.statement.persona_anchor
        || statement.persona != policy.statement.persona
        || statement.root_statement_sha256 != policy.statement.root_statement_sha256
        || statement.recovery_policy_sha256 != policy.policy_statement_sha256
        || statement.recovery_policy_version != policy.statement.policy_version
    {
        return Err(chain_mismatch(
            "recovery transition is not bound to the selected recovery policy",
        ));
    }
    if policy_time_status(&policy.statement, statement.issued_at)
        != RecoveryPolicyTimeStatus::Active
    {
        return Err(chain_mismatch(
            "recovery transition was not issued during the selected policy's claimed validity window",
        ));
    }
    if policy
        .statement
        .recovery_key_fingerprints
        .binary_search(&statement.previous_key_fingerprint)
        .is_ok()
    {
        return Err(chain_mismatch(
            "the replaced online key must be distinct from every recovery authority key",
        ));
    }
    if policy
        .statement
        .recovery_key_fingerprints
        .binary_search(&statement.next_key_fingerprint)
        .is_ok()
    {
        return Err(chain_mismatch(
            "the new online signing key must be distinct from every recovery authority key",
        ));
    }
    Ok(())
}

fn validate_recovery_transition_binding(
    root: &VerifiedPersonaRoot,
    policy: &VerifiedRecoveryPolicy,
    statement: &RecoveryTransitionStatement,
) -> Result<()> {
    validate_recovery_transition_statement(statement)?;
    validate_policy_root_binding(root, &policy.statement)?;
    validate_recovery_transition_policy_binding(policy, statement)?;
    if statement.persona_anchor != root.statement.persona_anchor
        || statement.persona != root.statement.persona
        || statement.root_statement_sha256 != root.root_statement_sha256
    {
        return Err(chain_mismatch(
            "recovery transition is bound to a different persona root",
        ));
    }
    if statement.issued_at < root.statement.issued_at {
        return Err(chain_mismatch(
            "recovery transition predates its persona root",
        ));
    }
    Ok(())
}

fn validate_recovery_policy_statement(statement: &RecoveryPolicyStatement) -> Result<()> {
    if statement.schema != RECOVERY_POLICY_STATEMENT_SCHEMA {
        return Err(invalid_statement(format!(
            "unsupported recovery policy schema {}",
            escape_untrusted_text_for_terminal(&statement.schema)
        )));
    }
    if statement.canonicalization != CONTINUITY_CANONICALIZATION {
        return Err(invalid_statement(format!(
            "unsupported recovery policy canonicalization {}",
            escape_untrusted_text_for_terminal(&statement.canonicalization)
        )));
    }
    validate_persona_anchor(&statement.persona_anchor)?;
    validate_canonical_persona(&statement.persona)?;
    validate_sha256(
        "recovery policy root digest",
        &statement.root_statement_sha256,
    )?;
    match (
        statement.policy_version,
        statement.previous_policy_sha256.as_deref(),
    ) {
        (0, _) => return Err(invalid_statement("recovery policy version must start at 1")),
        (1, None) => {}
        (1, Some(_)) => {
            return Err(invalid_statement(
                "recovery policy version 1 cannot name a predecessor",
            ));
        }
        (_, Some(digest)) => validate_sha256("previous recovery policy digest", digest)?,
        (_, None) => {
            return Err(invalid_statement(
                "recovery policy versions after 1 require a predecessor digest",
            ));
        }
    }
    validate_recovery_checkpoint(&statement.continuity_checkpoint)?;
    validate_jcs_time("recovery policy issued_at", statement.issued_at)?;
    validate_jcs_time("recovery policy expires_at", statement.expires_at)?;
    let validity = statement
        .expires_at
        .checked_sub(statement.issued_at)
        .ok_or_else(|| invalid_statement("recovery policy validity underflow"))?;
    if validity <= 0 || validity > MAX_RECOVERY_POLICY_VALIDITY_SECONDS {
        return Err(invalid_statement(format!(
            "recovery policy validity must be 1 through {MAX_RECOVERY_POLICY_VALIDITY_SECONDS} seconds"
        )));
    }
    if !(MIN_RECOVERY_AUTHORITIES..=MAX_RECOVERY_AUTHORITIES)
        .contains(&statement.recovery_key_fingerprints.len())
    {
        return Err(invalid_statement(format!(
            "recovery policy must contain {MIN_RECOVERY_AUTHORITIES} through {MAX_RECOVERY_AUTHORITIES} authority keys"
        )));
    }
    let threshold = usize::try_from(statement.threshold)
        .map_err(|_| invalid_statement("recovery threshold does not fit this platform"))?;
    if threshold < MIN_RECOVERY_AUTHORITIES || threshold > statement.recovery_key_fingerprints.len()
    {
        return Err(invalid_statement(
            "recovery threshold must be at least 2 and no greater than the authority count",
        ));
    }
    let mut previous = None;
    for fingerprint in &statement.recovery_key_fingerprints {
        validate_key_fingerprint(fingerprint)?;
        if previous.is_some_and(|value: &String| value >= fingerprint) {
            return Err(invalid_statement(
                "recovery key fingerprints must be distinct and sorted",
            ));
        }
        previous = Some(fingerprint);
    }
    Ok(())
}

fn validate_policy_root_binding(
    root: &VerifiedPersonaRoot,
    statement: &RecoveryPolicyStatement,
) -> Result<()> {
    if statement.persona_anchor != root.statement.persona_anchor
        || statement.persona != root.statement.persona
        || statement.root_statement_sha256 != root.root_statement_sha256
    {
        return Err(chain_mismatch(
            "recovery policy is bound to a different persona root",
        ));
    }
    if statement.issued_at < root.statement.issued_at {
        return Err(chain_mismatch("recovery policy predates its persona root"));
    }
    Ok(())
}

fn validate_policy_successor(
    previous: &VerifiedRecoveryPolicy,
    statement: &RecoveryPolicyStatement,
) -> Result<()> {
    validate_recovery_policy_statement(statement)?;
    if statement.persona_anchor != previous.statement.persona_anchor
        || statement.persona != previous.statement.persona
        || statement.root_statement_sha256 != previous.statement.root_statement_sha256
    {
        return Err(chain_mismatch(
            "recovery policy successor is bound to a different persona root",
        ));
    }
    let expected_version = previous
        .statement
        .policy_version
        .checked_add(1)
        .ok_or_else(|| chain_mismatch("recovery policy version overflow"))?;
    if statement.policy_version != expected_version
        || statement.previous_policy_sha256.as_deref()
            != Some(previous.policy_statement_sha256.as_str())
    {
        return Err(chain_mismatch(
            "recovery policies must advance by one and bind the exact previous statement digest",
        ));
    }
    if statement.issued_at < previous.statement.issued_at {
        return Err(chain_mismatch(
            "recovery policy issuance times move backward",
        ));
    }
    let previous_checkpoint = &previous.statement.continuity_checkpoint;
    let current_checkpoint = &statement.continuity_checkpoint;
    if current_checkpoint.transition_sequence < previous_checkpoint.transition_sequence
        || (current_checkpoint.transition_sequence == previous_checkpoint.transition_sequence
            && current_checkpoint.transition_sha256 != previous_checkpoint.transition_sha256)
    {
        return Err(chain_mismatch(
            "recovery policy continuity checkpoints cannot move backward or rewrite the same sequence",
        ));
    }
    Ok(())
}

fn validate_recovery_checkpoint(checkpoint: &RecoveryContinuityCheckpoint) -> Result<()> {
    let maximum_sequence =
        u32::try_from(MAX_CONTINUITY_TRANSITIONS).expect("continuity transition bound fits in u32");
    if checkpoint.transition_sequence > maximum_sequence {
        return Err(invalid_statement(format!(
            "continuity checkpoint cannot exceed transition {maximum_sequence}"
        )));
    }
    match (
        checkpoint.transition_sequence,
        checkpoint.transition_sha256.as_deref(),
    ) {
        (0, None) => Ok(()),
        (0, Some(_)) => Err(invalid_statement(
            "continuity checkpoint sequence 0 cannot name a transition digest",
        )),
        (_, Some(digest)) => validate_sha256("continuity checkpoint transition digest", digest),
        (_, None) => Err(invalid_statement(
            "a nonzero continuity checkpoint requires a transition digest",
        )),
    }
}

fn authority_fingerprints(public_keys: &[String]) -> Result<Vec<String>> {
    if !(MIN_RECOVERY_AUTHORITIES..=MAX_RECOVERY_AUTHORITIES).contains(&public_keys.len()) {
        return Err(invalid_statement(format!(
            "recovery policy must contain {MIN_RECOVERY_AUTHORITIES} through {MAX_RECOVERY_AUTHORITIES} authority keys"
        )));
    }
    let mut fingerprints = public_keys
        .iter()
        .map(|key| normalize_public_key(key).and_then(|key| public_key_fingerprint(&key)))
        .collect::<Result<Vec<_>>>()?;
    fingerprints.sort();
    if fingerprints.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_statement(
            "recovery authority public keys must be distinct",
        ));
    }
    Ok(fingerprints)
}

fn sign_with_authorities(
    payload: &[u8],
    signers: &[RecoverySigner],
    allowed_fingerprints: &[String],
    minimum: usize,
    require_all: bool,
    namespace: &str,
) -> Result<Vec<RecoverySignature>> {
    if signers.len() < minimum || signers.len() > allowed_fingerprints.len() {
        return Err(invalid_proof(format!(
            "signature set requires {minimum} through {} distinct authorized keys",
            allowed_fingerprints.len()
        )));
    }
    let allowed = allowed_fingerprints.iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut signed = Vec::with_capacity(signers.len());
    for signer in signers {
        let public_key = normalize_public_key(&signer.public_key)?;
        let fingerprint = public_key_fingerprint(&public_key)?;
        if !allowed.contains(&fingerprint) {
            return Err(invalid_proof(
                "a signing key is not authorized by the recovery policy",
            ));
        }
        if !seen.insert(fingerprint.clone()) {
            return Err(invalid_proof(
                "a recovery authority key cannot count more than once",
            ));
        }
        let value = sshsig_sign(payload, &signer.private_key_path, namespace)?;
        sshsig_verify(payload, &value, &public_key, namespace)?;
        signed.push((
            fingerprint,
            RecoverySignature {
                format: SIGNATURE_FORMAT.to_owned(),
                namespace: namespace.to_owned(),
                value,
                public_key_format: PUBLIC_KEY_FORMAT.to_owned(),
                public_key,
            },
        ));
    }
    if require_all && seen.len() != allowed.len() {
        return Err(invalid_proof(
            "every newly enrolled recovery authority must prove key possession",
        ));
    }
    signed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(signed.into_iter().map(|(_, signature)| signature).collect())
}

fn sign_one(
    payload: &[u8],
    private_key_path: &Path,
    public_key: &str,
    namespace: &str,
) -> Result<RecoverySignature> {
    let public_key = normalize_public_key(public_key)?;
    let value = sshsig_sign(payload, private_key_path, namespace)?;
    sshsig_verify(payload, &value, &public_key, namespace)?;
    Ok(RecoverySignature {
        format: SIGNATURE_FORMAT.to_owned(),
        namespace: namespace.to_owned(),
        value,
        public_key_format: PUBLIC_KEY_FORMAT.to_owned(),
        public_key,
    })
}

fn verify_authority_signatures(
    payload: &[u8],
    signatures: &[RecoverySignature],
    allowed_fingerprints: &[String],
    minimum: usize,
    require_all: bool,
    namespace: &str,
) -> Result<Vec<String>> {
    let preflight = preflight_authority_signatures(
        signatures,
        allowed_fingerprints,
        minimum,
        require_all,
        namespace,
    )?;
    for check in &preflight.checks {
        sshsig_verify(
            payload,
            &check.signature.value,
            &check.public_key,
            namespace,
        )?;
    }
    Ok(preflight.fingerprints)
}

struct RecoverySignatureCheck<'a> {
    signature: &'a RecoverySignature,
    public_key: String,
    fingerprint: String,
}

struct AuthoritySignaturePreflight<'a> {
    checks: Vec<RecoverySignatureCheck<'a>>,
    fingerprints: Vec<String>,
}

fn preflight_unbound_signature_set<'a>(
    signatures: &'a [RecoverySignature],
    namespace: &str,
) -> Result<AuthoritySignaturePreflight<'a>> {
    if !(MIN_RECOVERY_AUTHORITIES..=MAX_RECOVERY_AUTHORITIES).contains(&signatures.len()) {
        return Err(invalid_proof(format!(
            "recovery signature set must contain {MIN_RECOVERY_AUTHORITIES} through {MAX_RECOVERY_AUTHORITIES} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut checks = Vec::with_capacity(signatures.len());
    for signature in signatures {
        let public_key = validate_recovery_signature(signature, namespace)?;
        let fingerprint = public_key_fingerprint(&public_key)?;
        if !seen.insert(fingerprint.clone()) {
            return Err(invalid_proof(
                "a recovery authority key cannot count more than once",
            ));
        }
        checks.push(RecoverySignatureCheck {
            signature,
            public_key,
            fingerprint,
        });
    }
    Ok(AuthoritySignaturePreflight {
        checks,
        fingerprints: seen.into_iter().collect(),
    })
}

fn preflight_authority_signatures<'a>(
    signatures: &'a [RecoverySignature],
    allowed_fingerprints: &[String],
    minimum: usize,
    require_all: bool,
    namespace: &str,
) -> Result<AuthoritySignaturePreflight<'a>> {
    if signatures.len() < minimum || signatures.len() > allowed_fingerprints.len() {
        return Err(invalid_proof(format!(
            "signature set requires {minimum} through {} distinct authorized keys",
            allowed_fingerprints.len()
        )));
    }
    let allowed = allowed_fingerprints.iter().collect::<BTreeSet<_>>();
    let preflight = preflight_unbound_signature_set(signatures, namespace)?;
    for check in &preflight.checks {
        if !allowed.contains(&check.fingerprint) {
            return Err(invalid_proof(
                "a signature key is not authorized by the recovery policy",
            ));
        }
    }
    if require_all && preflight.fingerprints.len() != allowed.len() {
        return Err(invalid_proof(
            "every enrolled recovery authority must prove key possession",
        ));
    }
    Ok(preflight)
}

fn validate_recovery_signature(signature: &RecoverySignature, namespace: &str) -> Result<String> {
    if signature.format != SIGNATURE_FORMAT
        || signature.namespace != namespace
        || signature.public_key_format != PUBLIC_KEY_FORMAT
        || signature.value.is_empty()
        || signature.value.len() > MAX_CONTINUITY_SIGNATURE_BYTES
    {
        return Err(invalid_proof(
            "recovery signature format, namespace, key format, or size is invalid",
        ));
    }
    normalize_public_key(&signature.public_key)
}

fn policy_time_status(
    statement: &RecoveryPolicyStatement,
    checked_at: i64,
) -> RecoveryPolicyTimeStatus {
    if checked_at < statement.issued_at {
        RecoveryPolicyTimeStatus::NotYetValid
    } else if checked_at >= statement.expires_at {
        RecoveryPolicyTimeStatus::Expired
    } else {
        RecoveryPolicyTimeStatus::Active
    }
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
        return Err(invalid_statement(
            "persona must not contain surrounding whitespace",
        ));
    }
    Ok(canonical)
}

fn validate_jcs_time(field: &str, value: i64) -> Result<()> {
    if (0..=MAX_JCS_SAFE_INTEGER).contains(&value) {
        Ok(())
    } else {
        Err(invalid_statement(format!(
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
        Err(invalid_statement(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )))
    }
}

fn validate_payload_bound(payload: &[u8]) -> Result<()> {
    if payload.len() <= MAX_CONTINUITY_PAYLOAD_BYTES {
        Ok(())
    } else {
        Err(invalid_proof(format!(
            "payload exceeds {MAX_CONTINUITY_PAYLOAD_BYTES} bytes"
        )))
    }
}

fn decode_canonical_payload(encoded: &str) -> Result<Vec<u8>> {
    let payload = decode_payload(encoded)?;
    validate_payload_bound(&payload)?;
    if URL_SAFE_NO_PAD.encode(&payload) != encoded {
        return Err(invalid_proof("payload is not canonical unpadded Base64url"));
    }
    Ok(payload)
}

fn require_schema(actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_proof(format!(
            "unsupported proof schema {}; expected {expected}",
            escape_untrusted_text_for_terminal(actual)
        )))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid_statement(reason: impl Into<String>) -> ProofError {
    ProofError::InvalidContinuityStatement(reason.into())
}

fn invalid_proof(reason: impl Into<String>) -> ProofError {
    ProofError::InvalidContinuityProof(reason.into())
}

fn chain_mismatch(reason: impl Into<String>) -> ProofError {
    ProofError::ContinuityChainMismatch(reason.into())
}
