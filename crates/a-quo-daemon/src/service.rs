use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a_quo_approval::{
    ApprovalDecision, ApprovalPrompt, ArtifactKind as PromptArtifactKind, PeerIdentity,
    PersonaPurpose as PromptPersonaPurpose,
};
use a_quo_core::{
    ArtifactDescriptor, DomainControlReview, DomainControlStatement,
    PersonaContinuityTransitionProof, PersonaRootProof, PersonaRootReview, PersonaRootStatement,
    PersonaTransitionProof, PersonaTransitionReview, PersonaTransitionStatement, ProofBundle,
    create_domain_control_proof_for_statement, create_persona_root_proof,
    create_routine_transition_proof, create_sshsig_proof_for_descriptor,
    new_routine_transition_statement, public_key_fingerprint,
    review_domain_control_statement_bytes, review_persona_root_statement,
    review_persona_root_statement_bytes, review_persona_transition_statement,
    verify_domain_control_proof, verify_persona_continuity_chain,
    verify_persona_continuity_chain_with_recovery, verify_persona_root_proof,
    verify_persona_transition_proof,
};
use a_quo_ipc::{
    ArtifactKind as IpcArtifactKind, ConnectionState, MAX_ARTIFACT_BYTES,
    MAX_DOMAIN_STATEMENT_BYTES, MAX_PERSONA_ROOT_STATEMENT_BYTES,
    MAX_PERSONA_TRANSITION_PUBLIC_KEY_BYTES, PeerCredentials, ReceivedSignRequest, RejectionCode,
    SealedProof, SignRequest, SignSubject, TransitionKeyProvider, connection_state,
    receive_sign_request, seal_proof_bytes, send_sign_approved, send_sign_rejected,
    snapshot_artifact,
};
use a_quo_store::{
    ActiveSigner, KeyProvider, LiveContinuitySnapshot, PersonaPurpose, PersonaStore,
    RoutineRotationCandidate, RoutineTransitionIntent,
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ApprovalError {
    #[error("trusted approval process is unavailable")]
    Unavailable,

    #[error("trusted approval process timed out")]
    TimedOut,

    #[error("trusted approval process failed")]
    Failed,
}

pub trait ApprovalBackend {
    fn decide(&mut self, prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError>;
}

pub struct UnavailableApprovalBackend;

impl ApprovalBackend for UnavailableApprovalBackend {
    fn decide(&mut self, _prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    InvalidRequest,
    ClientCancelled,
    PersonaUnavailable,
    ConsentUnavailable,
    UserDeclined,
    SignerUnavailable,
    Internal,
}

impl FailureClass {
    fn rejection_code(self) -> RejectionCode {
        match self {
            Self::InvalidRequest => RejectionCode::InvalidRequest,
            Self::ClientCancelled => RejectionCode::Cancelled,
            Self::PersonaUnavailable => RejectionCode::PersonaUnavailable,
            Self::ConsentUnavailable => RejectionCode::ConsentUnavailable,
            Self::UserDeclined => RejectionCode::UserDeclined,
            Self::SignerUnavailable => RejectionCode::SignerUnavailable,
            Self::Internal => RejectionCode::InternalError,
        }
    }
}

#[derive(Debug)]
pub enum DaemonOutcome {
    Approved {
        request_id: String,
        signer_fingerprint: String,
        subject: ApprovedSubject,
        proof: SealedProof,
    },
    Rejected {
        request_id: Option<String>,
        failure: FailureClass,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovedSubject {
    Artifact(ArtifactDescriptor),
    DomainControl(DomainControlReview),
    PersonaRoot(PersonaRootReview),
    PersonaTransition(Box<PersonaTransitionReview>),
}

impl DaemonOutcome {
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Approved { request_id, .. } => Some(request_id),
            Self::Rejected { request_id, .. } => request_id.as_deref(),
        }
    }
}

pub fn handle_connection(
    connection: &OwnedFd,
    store: &mut PersonaStore,
    approval: &mut dyn ApprovalBackend,
) -> DaemonOutcome {
    let received = match receive_sign_request(connection) {
        Ok(request) => request,
        Err(_) => {
            let _ = send_sign_rejected(connection, RejectionCode::InvalidRequest);
            return DaemonOutcome::Rejected {
                request_id: None,
                failure: FailureClass::InvalidRequest,
            };
        }
    };

    if let Some(failure) = connection_failure(connection) {
        if failure == FailureClass::InvalidRequest {
            let _ = send_sign_rejected(connection, failure.rejection_code());
        }
        return rejected(None, failure);
    }

    let mut connection_interrupted = || connection_failure(connection);
    let outcome =
        process_received_request_inner(received, store, approval, &mut connection_interrupted);
    match outcome {
        DaemonOutcome::Approved {
            request_id,
            signer_fingerprint,
            subject,
            proof,
        } => {
            if let Some(failure) = connection_failure(connection) {
                if failure == FailureClass::InvalidRequest {
                    let _ = send_sign_rejected(connection, failure.rejection_code());
                }
                return rejected(Some(request_id), failure);
            }
            if send_sign_approved(connection, &proof).is_err() {
                return DaemonOutcome::Rejected {
                    request_id: Some(request_id),
                    failure: FailureClass::ClientCancelled,
                };
            }
            DaemonOutcome::Approved {
                request_id,
                signer_fingerprint,
                subject,
                proof,
            }
        }
        DaemonOutcome::Rejected {
            request_id,
            failure,
        } => {
            let _ = send_sign_rejected(connection, failure.rejection_code());
            DaemonOutcome::Rejected {
                request_id,
                failure,
            }
        }
    }
}

pub fn process_received_request(
    received: ReceivedSignRequest,
    store: &mut PersonaStore,
    approval: &mut dyn ApprovalBackend,
) -> DaemonOutcome {
    process_received_request_inner(received, store, approval, &mut || None)
}

fn process_received_request_inner(
    received: ReceivedSignRequest,
    store: &mut PersonaStore,
    approval: &mut dyn ApprovalBackend,
    connection_interrupted: &mut impl FnMut() -> Option<FailureClass>,
) -> DaemonOutcome {
    let request_uuid = Uuid::new_v4();
    let request_id = request_uuid.to_string();
    let ReceivedSignRequest {
        request,
        input,
        peer,
    } = received;
    if matches!(&request.subject, SignSubject::PersonaTransition { .. }) {
        return process_persona_transition(
            request_uuid,
            request,
            input,
            peer,
            store,
            approval,
            connection_interrupted,
        );
    }
    let signer = match store.active_signer_for_persona(&request.persona_id) {
        Ok(signer) => signer,
        Err(_) => {
            return rejected(Some(request_id), FailureClass::PersonaUnavailable);
        }
    };
    let maximum = match request.subject {
        SignSubject::Artifact { .. } => MAX_ARTIFACT_BYTES,
        SignSubject::DomainControl => MAX_DOMAIN_STATEMENT_BYTES,
        SignSubject::PersonaRoot => MAX_PERSONA_ROOT_STATEMENT_BYTES,
        SignSubject::PersonaTransition { .. } => unreachable!("handled above"),
    };
    let snapshot = match snapshot_artifact(input, maximum) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return rejected(Some(request_id), FailureClass::InvalidRequest);
        }
    };
    let prepared = match prepare_request(&request, &snapshot, &signer) {
        Ok(prepared) => prepared,
        Err(failure) => return rejected(Some(request_id), failure),
    };
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }
    let prompt = match approval_prompt(request_uuid, &prepared, peer, &signer) {
        Ok(prompt) => prompt,
        Err(()) => return rejected(Some(request_id), FailureClass::Internal),
    };
    match approval.decide(&prompt) {
        Ok(ApprovalDecision::Decline) => {
            return rejected(Some(request_id), FailureClass::UserDeclined);
        }
        Ok(ApprovalDecision::Cancel) => {
            return rejected(Some(request_id), FailureClass::ClientCancelled);
        }
        Err(_) => {
            return rejected(Some(request_id), FailureClass::ConsentUnavailable);
        }
        Ok(ApprovalDecision::Approve) => {}
    }
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }

    let signer = match store.active_signer_for_persona(&request.persona_id) {
        Ok(current_signer) if current_signer == signer => current_signer,
        Ok(_) | Err(_) => {
            return rejected(Some(request_id), FailureClass::PersonaUnavailable);
        }
    };

    let (proof, subject) = match sign_prepared_request(prepared, &signer) {
        Ok(result) => result,
        Err(failure) => return rejected(Some(request_id), failure),
    };
    if !matches!(
        store.active_signer_for_persona(&request.persona_id),
        Ok(current_signer) if current_signer == signer
    ) {
        return rejected(Some(request_id), FailureClass::PersonaUnavailable);
    }
    if let (SignedProof::PersonaRoot(root_proof), ApprovedSubject::PersonaRoot(review)) =
        (&proof, &subject)
    {
        if let Some(failure) = connection_interrupted() {
            return rejected(Some(request_id), failure);
        }
        if store
            .record_continuity_root(
                &request.persona_id,
                root_proof,
                &review.root_statement_sha256,
            )
            .is_err()
        {
            return rejected(Some(request_id), FailureClass::InvalidRequest);
        }
    }
    let proof = match sealed_proof(&proof) {
        Ok(proof) => proof,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };

    DaemonOutcome::Approved {
        request_id,
        signer_fingerprint: signer.key.fingerprint,
        subject,
        proof,
    }
}

#[derive(Clone, Debug)]
struct TransitionRequest {
    persona_id: String,
    expected_sequence: u32,
    expected_root_sha256: String,
    expected_previous_transition_sha256: Option<String>,
    next_key_provider: KeyProvider,
    next_signing_reference: PathBuf,
}

#[allow(clippy::too_many_arguments)]
fn process_persona_transition(
    request_uuid: Uuid,
    request: SignRequest,
    input: OwnedFd,
    peer: PeerCredentials,
    store: &mut PersonaStore,
    approval: &mut dyn ApprovalBackend,
    connection_interrupted: &mut impl FnMut() -> Option<FailureClass>,
) -> DaemonOutcome {
    let request_id = request_uuid.to_string();
    let transition_request = match transition_request(request) {
        Ok(request) => request,
        Err(failure) => return rejected(Some(request_id), failure),
    };
    let snapshot = match snapshot_artifact(input, MAX_PERSONA_TRANSITION_PUBLIC_KEY_BYTES) {
        Ok(snapshot) => snapshot,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let next_public_key_bytes =
        match snapshot.read_bytes_bounded(MAX_PERSONA_TRANSITION_PUBLIC_KEY_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
        };
    let next_public_key = match std::str::from_utf8(&next_public_key_bytes) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let next_key_fingerprint = match public_key_fingerprint(&next_public_key) {
        Ok(fingerprint) => fingerprint,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let continuity = match store.continuity_snapshot(&transition_request.persona_id) {
        Ok(snapshot) => snapshot,
        Err(_) => return rejected(Some(request_id), FailureClass::PersonaUnavailable),
    };

    match exact_transition_retry(
        store,
        &continuity,
        &transition_request,
        &next_public_key,
        &next_key_fingerprint,
    ) {
        Ok(Some((proof, review))) => {
            if let Some(failure) = connection_interrupted() {
                return rejected(Some(request_id), failure);
            }
            let proof = match sealed_proof(&SignedProof::PersonaTransition(proof)) {
                Ok(proof) => proof,
                Err(_) => return rejected(Some(request_id), FailureClass::Internal),
            };
            return DaemonOutcome::Approved {
                request_id,
                signer_fingerprint: review.previous_key_fingerprint.clone(),
                subject: ApprovedSubject::PersonaTransition(Box::new(review)),
                proof,
            };
        }
        Ok(None) => {}
        Err(failure) => return rejected(Some(request_id), failure),
    }

    if !transition_request_matches_head(&transition_request, &continuity) {
        return rejected(Some(request_id), FailureClass::InvalidRequest);
    }
    let previous_signer = match store.active_signer_for_persona(&transition_request.persona_id) {
        Ok(signer) if signer.key.fingerprint == continuity.head.current_key_fingerprint => signer,
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::PersonaUnavailable),
    };
    let candidate = match store.validate_routine_rotation_candidate(
        &transition_request.persona_id,
        &next_public_key,
        transition_request.next_key_provider,
        &transition_request.next_signing_reference,
    ) {
        Ok(candidate) => candidate,
        Err(_) => return rejected(Some(request_id), FailureClass::SignerUnavailable),
    };
    if candidate.signing_reference.key_fingerprint != next_key_fingerprint {
        return rejected(Some(request_id), FailureClass::Internal);
    }
    let root = match verify_persona_root_proof(&continuity.root.proof) {
        Ok(root) => root,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let statement = match new_routine_transition_statement(
        &root,
        candidate.intent.sequence,
        candidate.intent.previous_transition_sha256.as_deref(),
        &previous_signer.key.public_key,
        &candidate.public_key,
        candidate.intent.issued_at,
    ) {
        Ok(statement) => statement,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let now = match current_unix_time() {
        Ok(now) => now,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };
    let review = match review_persona_transition_statement(
        &statement,
        now,
        &root,
        transition_request.expected_sequence,
        transition_request
            .expected_previous_transition_sha256
            .as_deref(),
        &previous_signer.key.public_key,
        &candidate.public_key,
    ) {
        Ok(review) => review,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    if review.root_statement_sha256 != transition_request.expected_root_sha256 {
        return rejected(Some(request_id), FailureClass::InvalidRequest);
    }
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }
    let prompt = match transition_approval_prompt(request_uuid, &review, peer, &previous_signer) {
        Ok(prompt) => prompt,
        Err(()) => return rejected(Some(request_id), FailureClass::Internal),
    };
    match approval.decide(&prompt) {
        Ok(ApprovalDecision::Decline) => {
            return rejected(Some(request_id), FailureClass::UserDeclined);
        }
        Ok(ApprovalDecision::Cancel) => {
            return rejected(Some(request_id), FailureClass::ClientCancelled);
        }
        Err(_) => return rejected(Some(request_id), FailureClass::ConsentUnavailable),
        Ok(ApprovalDecision::Approve) => {}
    }
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }

    let current_continuity = match store.continuity_snapshot(&transition_request.persona_id) {
        Ok(snapshot) if snapshot == continuity => snapshot,
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::PersonaUnavailable),
    };
    let current_previous_signer =
        match store.active_signer_for_persona(&transition_request.persona_id) {
            Ok(signer) if signer == previous_signer => signer,
            Ok(_) | Err(_) => {
                return rejected(Some(request_id), FailureClass::PersonaUnavailable);
            }
        };
    let current_candidate = match store.validate_routine_rotation_candidate(
        &transition_request.persona_id,
        &next_public_key,
        transition_request.next_key_provider,
        &transition_request.next_signing_reference,
    ) {
        Ok(current) if same_rotation_candidate(&candidate, &current) => current,
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::SignerUnavailable),
    };
    if !same_rotation_candidate(&candidate, &current_candidate) {
        return rejected(Some(request_id), FailureClass::SignerUnavailable);
    }
    let current_root = match verify_persona_root_proof(&current_continuity.root.proof) {
        Ok(root) => root,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let current_review = match current_unix_time().and_then(|now| {
        review_persona_transition_statement(
            &statement,
            now,
            &current_root,
            transition_request.expected_sequence,
            transition_request
                .expected_previous_transition_sha256
                .as_deref(),
            &current_previous_signer.key.public_key,
            &current_candidate.public_key,
        )
        .map_err(|_| ())
    }) {
        Ok(current_review) if current_review == review => current_review,
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };

    let proof = match create_routine_transition_proof(
        statement.clone(),
        &current_previous_signer.signing_reference.locator,
        &current_previous_signer.key.public_key,
        &current_candidate.signing_reference.locator,
        &current_candidate.public_key,
    ) {
        Ok(proof) => proof,
        Err(_) => return rejected(Some(request_id), FailureClass::SignerUnavailable),
    };
    if verify_new_transition(&proof, &statement, &current_review, &current_continuity).is_err() {
        return rejected(Some(request_id), FailureClass::Internal);
    }
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }
    let committed = match store.commit_routine_transition(
        &transition_request.persona_id,
        &proof,
        current_candidate.provider,
        &current_candidate.signing_reference.locator,
    ) {
        Ok(committed) if committed.proof == proof => committed,
        Ok(_) => return rejected(Some(request_id), FailureClass::Internal),
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let persisted = match store.continuity_snapshot(&transition_request.persona_id) {
        Ok(snapshot)
            if snapshot.head.transition_sequence == review.sequence
                && snapshot.head.current_key_fingerprint == review.next_key_fingerprint
                && snapshot.transitions.last().is_some_and(|stored| {
                    matches!(
                        stored,
                        PersonaContinuityTransitionProof::Routine(proof)
                            if proof == &committed.proof
                    )
                }) =>
        {
            committed.proof
        }
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };
    let proof = match sealed_proof(&SignedProof::PersonaTransition(persisted)) {
        Ok(proof) => proof,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };

    DaemonOutcome::Approved {
        request_id,
        signer_fingerprint: review.previous_key_fingerprint.clone(),
        subject: ApprovedSubject::PersonaTransition(Box::new(review)),
        proof,
    }
}

fn transition_request(request: SignRequest) -> Result<TransitionRequest, FailureClass> {
    let SignSubject::PersonaTransition {
        expected_sequence,
        expected_root_sha256,
        expected_previous_transition_sha256,
        next_key_provider,
        next_signing_reference,
    } = request.subject
    else {
        return Err(FailureClass::InvalidRequest);
    };
    Ok(TransitionRequest {
        persona_id: request.persona_id,
        expected_sequence,
        expected_root_sha256: encode_sha256(expected_root_sha256),
        expected_previous_transition_sha256: expected_previous_transition_sha256.map(encode_sha256),
        next_key_provider: store_key_provider(next_key_provider),
        next_signing_reference: PathBuf::from(next_signing_reference),
    })
}

fn transition_request_matches_head(
    request: &TransitionRequest,
    snapshot: &LiveContinuitySnapshot,
) -> bool {
    snapshot
        .head
        .transition_sequence
        .checked_add(1)
        .is_some_and(|sequence| sequence == request.expected_sequence)
        && snapshot.root.root_statement_sha256 == request.expected_root_sha256
        && snapshot.head.last_transition_sha256 == request.expected_previous_transition_sha256
}

fn exact_transition_retry(
    store: &PersonaStore,
    snapshot: &LiveContinuitySnapshot,
    request: &TransitionRequest,
    next_public_key: &str,
    next_key_fingerprint: &str,
) -> Result<Option<(PersonaTransitionProof, PersonaTransitionReview)>, FailureClass> {
    if snapshot.head.transition_sequence != request.expected_sequence {
        return Ok(None);
    }
    let proof = match snapshot.transitions.last() {
        Some(PersonaContinuityTransitionProof::Routine(proof)) => proof,
        Some(PersonaContinuityTransitionProof::Recovery(_)) => return Ok(None),
        None => return Err(FailureClass::InvalidRequest),
    };
    let verified =
        verify_persona_transition_proof(proof).map_err(|_| FailureClass::InvalidRequest)?;
    let statement = &verified.statement;
    if snapshot.root.root_statement_sha256 != request.expected_root_sha256
        || statement.sequence != request.expected_sequence
        || statement.root_statement_sha256 != request.expected_root_sha256
        || statement.previous_transition_sha256 != request.expected_previous_transition_sha256
        || statement.next_key_fingerprint != next_key_fingerprint
        || verified.next_public_key != normalized_public_key_text(next_public_key)
    {
        return Ok(None);
    }
    let retry_intent = RoutineTransitionIntent {
        persona_id: request.persona_id.clone(),
        sequence: statement.sequence,
        root_statement_sha256: statement.root_statement_sha256.clone(),
        previous_transition_sha256: statement.previous_transition_sha256.clone(),
        previous_key_fingerprint: statement.previous_key_fingerprint.clone(),
        next_key_fingerprint: statement.next_key_fingerprint.clone(),
        issued_at: statement.issued_at,
    };
    let retry_metadata = store
        .committed_routine_transition_retry_metadata(&retry_intent)
        .map_err(|_| FailureClass::InvalidRequest)?
        .ok_or(FailureClass::InvalidRequest)?;
    let locator_matches = retry_locator_matches(
        &request.next_signing_reference,
        &retry_metadata.signing_locator,
    )?;
    if retry_metadata.persona_id != request.persona_id
        || retry_metadata.current_key_fingerprint != statement.next_key_fingerprint
        || retry_metadata.provider != request.next_key_provider
        || !locator_matches
    {
        return Ok(None);
    }
    Ok(Some((
        proof.clone(),
        PersonaTransitionReview {
            persona: statement.persona.clone(),
            persona_anchor: statement.persona_anchor.clone(),
            root_statement_sha256: statement.root_statement_sha256.clone(),
            sequence: statement.sequence,
            previous_transition_sha256: statement.previous_transition_sha256.clone(),
            previous_key_fingerprint: statement.previous_key_fingerprint.clone(),
            next_key_fingerprint: statement.next_key_fingerprint.clone(),
            issued_at: statement.issued_at,
            transition_statement_sha256: verified.transition_statement_sha256,
        },
    )))
}

fn normalized_public_key_text(public_key: &str) -> String {
    let mut fields = public_key.split_whitespace();
    let algorithm = fields.next().unwrap_or_default();
    let encoded = fields.next().unwrap_or_default();
    format!("{algorithm} {encoded}")
}

fn retry_locator_matches(path: &Path, stored: &Path) -> Result<bool, FailureClass> {
    if path == stored {
        return Ok(true);
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(FailureClass::SignerUnavailable),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    std::fs::canonicalize(path)
        .map(|canonical| canonical == stored)
        .map_err(|_| FailureClass::SignerUnavailable)
}

fn same_rotation_candidate(
    expected: &RoutineRotationCandidate,
    actual: &RoutineRotationCandidate,
) -> bool {
    expected.intent.persona_id == actual.intent.persona_id
        && expected.intent.sequence == actual.intent.sequence
        && expected.intent.root_statement_sha256 == actual.intent.root_statement_sha256
        && expected.intent.previous_transition_sha256 == actual.intent.previous_transition_sha256
        && expected.intent.previous_key_fingerprint == actual.intent.previous_key_fingerprint
        && expected.intent.next_key_fingerprint == actual.intent.next_key_fingerprint
        && expected.public_key == actual.public_key
        && expected.provider == actual.provider
        && expected.signing_reference.key_fingerprint == actual.signing_reference.key_fingerprint
        && expected.signing_reference.locator == actual.signing_reference.locator
}

fn verify_new_transition(
    proof: &PersonaTransitionProof,
    statement: &PersonaTransitionStatement,
    review: &PersonaTransitionReview,
    previous: &LiveContinuitySnapshot,
) -> Result<(), ()> {
    let verified = verify_persona_transition_proof(proof).map_err(|_| ())?;
    if verified.statement != *statement
        || verified.transition_statement_sha256 != review.transition_statement_sha256
    {
        return Err(());
    }
    let mut chain = previous.transitions.clone();
    chain.push(PersonaContinuityTransitionProof::Routine(proof.clone()));
    let (transition_count, chain_tip_key_fingerprint, last_transition_sha256) =
        if let Some(policy_head) = &previous.recovery_policy_head {
            let policies = previous
                .recovery_policies
                .iter()
                .map(|recorded| recorded.proof.clone())
                .collect::<Vec<_>>();
            let report = verify_persona_continuity_chain_with_recovery(
                &previous.root.proof,
                &chain,
                &policies,
                &previous.root.root_statement_sha256,
                &policy_head.latest_policy_sha256,
                current_unix_time().map_err(|_| ())?,
            )
            .map_err(|_| ())?;
            (
                report.transition_count,
                report.chain_tip_key_fingerprint,
                report.last_transition_sha256,
            )
        } else {
            if !previous.recovery_policies.is_empty() {
                return Err(());
            }
            let routine_chain = chain
                .into_iter()
                .map(|proof| match proof {
                    PersonaContinuityTransitionProof::Routine(proof) => Ok(proof),
                    PersonaContinuityTransitionProof::Recovery(_) => Err(()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let report = verify_persona_continuity_chain(
                &previous.root.proof,
                &routine_chain,
                &previous.root.root_statement_sha256,
            )
            .map_err(|_| ())?;
            (
                report.transition_count,
                report.chain_tip_key_fingerprint,
                report.last_transition_sha256,
            )
        };
    if transition_count != review.sequence
        || chain_tip_key_fingerprint != review.next_key_fingerprint
        || last_transition_sha256.as_deref() != Some(review.transition_statement_sha256.as_str())
    {
        return Err(());
    }
    Ok(())
}

fn transition_approval_prompt(
    request_id: Uuid,
    review: &PersonaTransitionReview,
    peer: PeerCredentials,
    signer: &ActiveSigner,
) -> Result<ApprovalPrompt, ()> {
    ApprovalPrompt::new_persona_transition(
        request_id,
        Uuid::parse_str(&signer.persona.id).map_err(|_| ())?,
        signer.persona.label.clone(),
        prompt_persona_purpose(signer.persona.purpose),
        review.previous_key_fingerprint.clone(),
        review.persona_anchor.clone(),
        decode_sha256(&review.root_statement_sha256)?,
        review.sequence,
        review
            .previous_transition_sha256
            .as_deref()
            .map(decode_sha256)
            .transpose()?,
        review.issued_at,
        review.next_key_fingerprint.clone(),
        decode_sha256(&review.transition_statement_sha256)?,
        PeerIdentity {
            pid: u32::try_from(peer.pid).map_err(|_| ())?,
            uid: peer.uid,
            gid: peer.gid,
        },
    )
    .map_err(|_| ())
}

fn store_key_provider(provider: TransitionKeyProvider) -> KeyProvider {
    match provider {
        TransitionKeyProvider::OpensshFile => KeyProvider::OpensshFile,
        TransitionKeyProvider::SshAgent => KeyProvider::SshAgent,
        TransitionKeyProvider::Fido2 => KeyProvider::Fido2,
    }
}

fn encode_sha256(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

enum PreparedRequest {
    Artifact {
        descriptor: ArtifactDescriptor,
        artifact_kind: IpcArtifactKind,
        artifact_label: String,
    },
    DomainControl {
        statement: DomainControlStatement,
        review: DomainControlReview,
    },
    PersonaRoot {
        statement: PersonaRootStatement,
        review: PersonaRootReview,
    },
}

fn prepare_request(
    request: &a_quo_ipc::SignRequest,
    snapshot: &a_quo_ipc::SealedArtifact,
    signer: &ActiveSigner,
) -> Result<PreparedRequest, FailureClass> {
    match &request.subject {
        SignSubject::Artifact {
            artifact_kind,
            artifact_label,
        } => Ok(PreparedRequest::Artifact {
            descriptor: snapshot.descriptor().clone(),
            artifact_kind: *artifact_kind,
            artifact_label: artifact_label.clone(),
        }),
        SignSubject::DomainControl => {
            let bytes = snapshot
                .read_bytes_bounded(MAX_DOMAIN_STATEMENT_BYTES)
                .map_err(|_| FailureClass::InvalidRequest)?;
            let now = current_unix_time().map_err(|_| FailureClass::Internal)?;
            let (statement, review) = review_domain_control_statement_bytes(
                &bytes,
                now,
                &signer.key.public_key,
                &signer.persona.label,
            )
            .map_err(|_| FailureClass::InvalidRequest)?;
            Ok(PreparedRequest::DomainControl { statement, review })
        }
        SignSubject::PersonaRoot => {
            let bytes = snapshot
                .read_bytes_bounded(MAX_PERSONA_ROOT_STATEMENT_BYTES)
                .map_err(|_| FailureClass::InvalidRequest)?;
            let now = current_unix_time().map_err(|_| FailureClass::Internal)?;
            let (statement, review) = review_persona_root_statement_bytes(
                &bytes,
                now,
                &signer.key.public_key,
                &signer.persona.label,
            )
            .map_err(|_| FailureClass::InvalidRequest)?;
            Ok(PreparedRequest::PersonaRoot { statement, review })
        }
        SignSubject::PersonaTransition { .. } => unreachable!("handled before preparation"),
    }
}

enum SignedProof {
    Bundle(ProofBundle),
    PersonaRoot(PersonaRootProof),
    PersonaTransition(PersonaTransitionProof),
}

fn sign_prepared_request(
    prepared: PreparedRequest,
    signer: &ActiveSigner,
) -> Result<(SignedProof, ApprovedSubject), FailureClass> {
    match prepared {
        PreparedRequest::Artifact { descriptor, .. } => {
            let proof = create_sshsig_proof_for_descriptor(
                descriptor.clone(),
                &signer.signing_reference.locator,
                &signer.key.public_key,
                &signer.persona.label,
            )
            .map_err(|_| FailureClass::SignerUnavailable)?;
            Ok((
                SignedProof::Bundle(proof),
                ApprovedSubject::Artifact(descriptor),
            ))
        }
        PreparedRequest::DomainControl { statement, review } => {
            let proof = create_domain_control_proof_for_statement(
                statement,
                &signer.signing_reference.locator,
                &signer.key.public_key,
            )
            .map_err(|_| FailureClass::SignerUnavailable)?;
            let now = current_unix_time().map_err(|_| FailureClass::Internal)?;
            let verified = verify_domain_control_proof(&proof, now)
                .map_err(|_| FailureClass::InvalidRequest)?;
            if verified.domain != review.domain
                || verified.dns_record_name != review.dns_record_name
                || verified.dns_txt_value != review.dns_txt_value
                || verified.issued_at != review.issued_at
                || verified.expires_at != review.expires_at
                || verified.signer.persona != signer.persona.label
                || verified.signer.key_fingerprint != signer.key.fingerprint
            {
                return Err(FailureClass::Internal);
            }
            Ok((
                SignedProof::Bundle(proof),
                ApprovedSubject::DomainControl(review),
            ))
        }
        PreparedRequest::PersonaRoot { statement, review } => {
            let now = current_unix_time().map_err(|_| FailureClass::Internal)?;
            let current_review = review_persona_root_statement(
                &statement,
                now,
                &signer.key.public_key,
                &signer.persona.label,
            )
            .map_err(|_| FailureClass::InvalidRequest)?;
            if current_review != review {
                return Err(FailureClass::Internal);
            }
            let proof = create_persona_root_proof(
                statement.clone(),
                &signer.signing_reference.locator,
                &signer.key.public_key,
            )
            .map_err(|_| FailureClass::SignerUnavailable)?;
            let verified =
                verify_persona_root_proof(&proof).map_err(|_| FailureClass::InvalidRequest)?;
            if verified.statement != statement
                || verified.root_statement_sha256 != review.root_statement_sha256
                || verified.statement.persona != signer.persona.label
                || verified.statement.initial_key_fingerprint != signer.key.fingerprint
            {
                return Err(FailureClass::Internal);
            }
            Ok((
                SignedProof::PersonaRoot(proof),
                ApprovedSubject::PersonaRoot(review),
            ))
        }
    }
}

fn approval_prompt(
    request_id: Uuid,
    prepared: &PreparedRequest,
    peer: PeerCredentials,
    signer: &ActiveSigner,
) -> Result<ApprovalPrompt, ()> {
    let persona_id = Uuid::parse_str(&signer.persona.id).map_err(|_| ())?;
    let persona_purpose = prompt_persona_purpose(signer.persona.purpose);
    let peer = PeerIdentity {
        pid: u32::try_from(peer.pid).map_err(|_| ())?,
        uid: peer.uid,
        gid: peer.gid,
    };
    match prepared {
        PreparedRequest::Artifact {
            descriptor,
            artifact_kind,
            artifact_label,
        } => ApprovalPrompt::new(
            request_id,
            persona_id,
            signer.persona.label.clone(),
            persona_purpose,
            signer.key.fingerprint.clone(),
            prompt_artifact_kind(*artifact_kind),
            artifact_label.clone(),
            decode_sha256(&descriptor.digest.value)?,
            descriptor.size,
            peer,
        ),
        PreparedRequest::DomainControl { review, .. } => ApprovalPrompt::new_domain(
            request_id,
            persona_id,
            signer.persona.label.clone(),
            persona_purpose,
            signer.key.fingerprint.clone(),
            review.domain.clone(),
            review.dns_txt_value.clone(),
            review.issued_at,
            review.expires_at,
            peer,
        ),
        PreparedRequest::PersonaRoot { review, .. } => ApprovalPrompt::new_persona_root(
            request_id,
            persona_id,
            signer.persona.label.clone(),
            persona_purpose,
            signer.key.fingerprint.clone(),
            review.persona_anchor.clone(),
            decode_sha256(&review.root_statement_sha256)?,
            review.issued_at,
            peer,
        ),
    }
    .map_err(|_| ())
}

fn current_unix_time() -> Result<i64, ()> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| ())
}

fn prompt_artifact_kind(kind: IpcArtifactKind) -> PromptArtifactKind {
    match kind {
        IpcArtifactKind::Generic => PromptArtifactKind::Generic,
        IpcArtifactKind::SoftwareRelease => PromptArtifactKind::SoftwareRelease,
        IpcArtifactKind::Article => PromptArtifactKind::Article,
        IpcArtifactKind::Image => PromptArtifactKind::Image,
    }
}

fn prompt_persona_purpose(purpose: PersonaPurpose) -> PromptPersonaPurpose {
    match purpose {
        PersonaPurpose::Personal => PromptPersonaPurpose::Personal,
        PersonaPurpose::Pseudonymous => PromptPersonaPurpose::Pseudonymous,
        PersonaPurpose::Project => PromptPersonaPurpose::Project,
        PersonaPurpose::Organization => PromptPersonaPurpose::Organization,
        PersonaPurpose::LegalBridge => PromptPersonaPurpose::LegalBridge,
    }
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64 {
        return Err(());
    }
    let mut digest = [0_u8; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        let high = decode_hex_digit(pair[0]).ok_or(())?;
        let low = decode_hex_digit(pair[1]).ok_or(())?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn decode_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn sealed_proof(proof: &SignedProof) -> Result<SealedProof, ()> {
    let mut bytes = match proof {
        SignedProof::Bundle(proof) => serde_json::to_vec_pretty(proof),
        SignedProof::PersonaRoot(proof) => serde_json::to_vec_pretty(proof),
        SignedProof::PersonaTransition(proof) => serde_json::to_vec_pretty(proof),
    }
    .map_err(|_| ())?;
    bytes.push(b'\n');
    seal_proof_bytes(&bytes).map_err(|_| ())
}

fn rejected(request_id: Option<String>, failure: FailureClass) -> DaemonOutcome {
    DaemonOutcome::Rejected {
        request_id,
        failure,
    }
}

fn connection_failure(connection: &OwnedFd) -> Option<FailureClass> {
    match connection_state(connection) {
        Ok(ConnectionState::Waiting) => None,
        Ok(ConnectionState::ExtraData) => Some(FailureClass::InvalidRequest),
        Ok(ConnectionState::Closed) | Err(_) => Some(FailureClass::ClientCancelled),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    use a_quo_approval::ApprovalSubject;
    use a_quo_core::{
        DOMAIN_DEFAULT_VALIDITY_SECONDS, EvidenceStatus, PersonaContinuityCheckpoint,
        RecoveryContinuityCheckpoint, RecoverySigner, RecoveryTransitionReason,
        VerifiedPersonaRoot, VerifiedRecoveryPolicy, canonical_domain_control_statement_bytes,
        canonical_persona_root_statement_bytes, create_initial_recovery_policy_proof,
        create_recovery_transition_proof, new_domain_control_statement,
        new_initial_recovery_policy_statement, new_persona_root_statement,
        new_recovery_transition_statement, recovery_transition_statement_sha256,
        verify_domain_control_proof, verify_initial_recovery_policy_proof,
        verify_persona_root_proof, verify_persona_transition_proof,
        verify_sshsig_proof_for_descriptor,
    };
    use a_quo_ipc::{
        LinuxIpcError, SignRequest, SignResponse, peer_credentials, receive_sign_response,
        send_sign_request,
    };
    use a_quo_store::{
        BackupContinuityArchive, BackupPersonaRootEvidence, KeyProvider, PersonaPurpose,
    };
    use rustix::net::{AddressFamily, Protocol, SocketFlags, SocketType, socketpair};
    use tempfile::{TempDir, tempdir, tempfile};

    use super::*;

    struct RecordingApproval {
        decision: Result<ApprovalDecision, ApprovalError>,
        prompt: Option<ApprovalPrompt>,
        mutate_after_snapshot: Option<std::path::PathBuf>,
    }

    struct UnbindingApproval {
        store_path: std::path::PathBuf,
        fingerprint: String,
        prompt: Option<ApprovalPrompt>,
    }

    impl ApprovalBackend for UnbindingApproval {
        fn decide(&mut self, prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
            self.prompt = Some(prompt.clone());
            PersonaStore::open(&self.store_path)
                .unwrap()
                .unbind_signing_reference(&self.fingerprint)
                .unwrap();
            Ok(ApprovalDecision::Approve)
        }
    }

    impl ApprovalBackend for RecordingApproval {
        fn decide(&mut self, prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
            self.prompt = Some(prompt.clone());
            if let Some(path) = &self.mutate_after_snapshot {
                fs::write(path, b"changed after immutable snapshot").unwrap();
            }
            self.decision
        }
    }

    #[test]
    fn approved_request_signs_only_the_immutable_snapshot() {
        let mut fixture = fixture();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: Some(fixture.artifact_path.clone()),
        };

        let outcome = process_received_request(fixture.received, &mut fixture.store, &mut approval);
        let DaemonOutcome::Approved {
            subject,
            proof,
            signer_fingerprint,
            ..
        } = outcome
        else {
            panic!("expected approved outcome");
        };
        let ApprovedSubject::Artifact(artifact) = subject else {
            panic!("expected artifact subject");
        };
        assert_eq!(signer_fingerprint, fixture.fingerprint);
        assert_eq!(artifact.size, b"reviewed artifact bytes".len() as u64);
        let prompt = approval.prompt.unwrap();
        assert_eq!(prompt.persona_label, "Daemon test publisher");
        let ApprovalSubject::Artifact(prompt_artifact) = prompt.subject else {
            panic!("expected artifact prompt");
        };
        assert_eq!(prompt_artifact.artifact_size, artifact.size);
        assert_eq!(prompt_artifact.sha256_hex(), artifact.digest.value);
        assert_eq!(prompt_artifact.artifact_label, "release.tar.zst");

        let mut proof_file = proof.into_file();
        proof_file.seek(SeekFrom::Start(0)).unwrap();
        let mut proof_bytes = Vec::new();
        proof_file.read_to_end(&mut proof_bytes).unwrap();
        let proof: ProofBundle = serde_json::from_slice(&proof_bytes).unwrap();
        let report = verify_sshsig_proof_for_descriptor(&artifact, &proof).unwrap();
        assert_eq!(report.signature, EvidenceStatus::Verified);
    }

    #[test]
    fn approved_domain_request_prompts_and_returns_the_exact_namespaced_proof() {
        let mut fixture = fixture();
        let persona_id = fixture.received.request.persona_id.clone();
        let signer = fixture
            .store
            .active_signer_for_persona(&persona_id)
            .unwrap();
        let now = current_unix_time().unwrap();
        let statement = new_domain_control_statement(
            "a-quo.ch",
            now,
            now + DOMAIN_DEFAULT_VALIDITY_SECONDS,
            &signer.key.public_key,
            &signer.persona.label,
        )
        .unwrap();
        let bytes = canonical_domain_control_statement_bytes(&statement).unwrap();
        let mut input = tempfile().unwrap();
        input.write_all(&bytes).unwrap();
        fixture.received.request = SignRequest::new_domain(persona_id).unwrap();
        fixture.received.input = input.into();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        let outcome = process_received_request(fixture.received, &mut fixture.store, &mut approval);
        let DaemonOutcome::Approved { subject, proof, .. } = outcome else {
            panic!("expected approved domain outcome");
        };
        let ApprovedSubject::DomainControl(review) = subject else {
            panic!("expected domain subject");
        };
        let prompt = approval.prompt.unwrap();
        let ApprovalSubject::Domain(domain_prompt) = prompt.subject else {
            panic!("expected domain prompt");
        };
        assert_eq!(domain_prompt.domain, review.domain);
        assert_eq!(domain_prompt.dns_txt_value, review.dns_txt_value);
        assert_eq!(domain_prompt.expires_at, statement.expires_at);

        let proof_bytes = proof.read_bytes().unwrap();
        let proof: ProofBundle = serde_json::from_slice(&proof_bytes).unwrap();
        let report = verify_domain_control_proof(&proof, now).unwrap();
        assert_eq!(report.domain, statement.domain);
        assert_eq!(report.dns_txt_value, review.dns_txt_value);
        assert_eq!(report.signer.key_fingerprint, fixture.fingerprint);
    }

    #[test]
    fn noncanonical_domain_statement_never_reaches_approval() {
        let mut fixture = fixture();
        let persona_id = fixture.received.request.persona_id.clone();
        let signer = fixture
            .store
            .active_signer_for_persona(&persona_id)
            .unwrap();
        let now = current_unix_time().unwrap();
        let statement = new_domain_control_statement(
            "a-quo.ch",
            now,
            now + DOMAIN_DEFAULT_VALIDITY_SECONDS,
            &signer.key.public_key,
            &signer.persona.label,
        )
        .unwrap();
        let mut bytes = vec![b' '];
        bytes.extend_from_slice(&canonical_domain_control_statement_bytes(&statement).unwrap());
        let mut input = tempfile().unwrap();
        input.write_all(&bytes).unwrap();
        fixture.received.request = SignRequest::new_domain(persona_id).unwrap();
        fixture.received.input = input.into();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        assert!(matches!(
            process_received_request(fixture.received, &mut fixture.store, &mut approval),
            DaemonOutcome::Rejected {
                failure: FailureClass::InvalidRequest,
                ..
            }
        ));
        assert!(approval.prompt.is_none());
    }

    #[test]
    fn approved_persona_root_prompts_and_returns_the_exact_namespaced_proof() {
        let mut fixture = fixture();
        let persona_id = fixture.received.request.persona_id.clone();
        let signer = fixture
            .store
            .active_signer_for_persona(&persona_id)
            .unwrap();
        let now = current_unix_time().unwrap();
        let statement =
            new_persona_root_statement(&signer.persona.label, now, &signer.key.public_key).unwrap();
        let bytes = canonical_persona_root_statement_bytes(&statement).unwrap();
        let mut input = tempfile().unwrap();
        input.write_all(&bytes).unwrap();
        fixture.received.request = SignRequest::new_persona_root(persona_id).unwrap();
        fixture.received.input = input.into();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        let outcome = process_received_request(fixture.received, &mut fixture.store, &mut approval);
        let DaemonOutcome::Approved { subject, proof, .. } = outcome else {
            panic!("expected approved persona-root outcome");
        };
        let ApprovedSubject::PersonaRoot(review) = subject else {
            panic!("expected persona-root subject");
        };
        let prompt = approval.prompt.unwrap();
        let ApprovalSubject::PersonaRoot(root_prompt) = prompt.subject else {
            panic!("expected persona-root prompt");
        };
        assert_eq!(root_prompt.persona_anchor, review.persona_anchor);
        assert_eq!(root_prompt.root_sha256_hex(), review.root_statement_sha256);
        assert_eq!(root_prompt.issued_at, statement.issued_at);

        let proof_bytes = proof.read_bytes().unwrap();
        let proof: PersonaRootProof = serde_json::from_slice(&proof_bytes).unwrap();
        let verified = verify_persona_root_proof(&proof).unwrap();
        assert_eq!(verified.statement, statement);
        assert_eq!(verified.root_statement_sha256, review.root_statement_sha256);
        assert_eq!(
            verified.statement.initial_key_fingerprint,
            fixture.fingerprint
        );
    }

    #[test]
    fn stale_or_noncanonical_persona_root_never_reaches_approval() {
        for make_stale in [false, true] {
            let mut fixture = fixture();
            let persona_id = fixture.received.request.persona_id.clone();
            let signer = fixture
                .store
                .active_signer_for_persona(&persona_id)
                .unwrap();
            let now = current_unix_time().unwrap();
            let issued_at = if make_stale {
                now - a_quo_core::CONTINUITY_ROOT_CLOCK_SKEW_SECONDS - 1
            } else {
                now
            };
            let statement = new_persona_root_statement(
                &signer.persona.label,
                issued_at,
                &signer.key.public_key,
            )
            .unwrap();
            let mut bytes = canonical_persona_root_statement_bytes(&statement).unwrap();
            if !make_stale {
                bytes.insert(0, b' ');
            }
            let mut input = tempfile().unwrap();
            input.write_all(&bytes).unwrap();
            fixture.received.request = SignRequest::new_persona_root(persona_id).unwrap();
            fixture.received.input = input.into();
            let mut approval = RecordingApproval {
                decision: Ok(ApprovalDecision::Approve),
                prompt: None,
                mutate_after_snapshot: None,
            };

            assert!(matches!(
                process_received_request(fixture.received, &mut fixture.store, &mut approval),
                DaemonOutcome::Rejected {
                    failure: FailureClass::InvalidRequest,
                    ..
                }
            ));
            assert!(approval.prompt.is_none());
        }
    }

    #[test]
    fn disconnect_after_root_signing_leaves_no_continuity_journal() {
        let mut fixture = fixture();
        let persona_id = fixture.received.request.persona_id.clone();
        let signer = fixture
            .store
            .active_signer_for_persona(&persona_id)
            .unwrap();
        let statement = new_persona_root_statement(
            &signer.persona.label,
            current_unix_time().unwrap(),
            &signer.key.public_key,
        )
        .unwrap();
        let mut input = tempfile().unwrap();
        input
            .write_all(&canonical_persona_root_statement_bytes(&statement).unwrap())
            .unwrap();
        fixture.received.request = SignRequest::new_persona_root(persona_id.clone()).unwrap();
        fixture.received.input = input.into();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };
        let mut checks = 0;
        let mut disconnect_after_signing = || {
            checks += 1;
            (checks == 3).then_some(FailureClass::ClientCancelled)
        };

        assert!(matches!(
            process_received_request_inner(
                fixture.received,
                &mut fixture.store,
                &mut approval,
                &mut disconnect_after_signing,
            ),
            DaemonOutcome::Rejected {
                failure: FailureClass::ClientCancelled,
                ..
            }
        ));
        assert!(approval.prompt.is_some());
        assert!(
            fixture
                .store
                .recorded_continuity_root(&persona_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn decline_and_unavailable_approval_never_return_a_proof() {
        for decision in [
            Ok(ApprovalDecision::Decline),
            Err(ApprovalError::Unavailable),
        ] {
            let mut fixture = fixture();
            let mut approval = RecordingApproval {
                decision,
                prompt: None,
                mutate_after_snapshot: None,
            };
            let outcome =
                process_received_request(fixture.received, &mut fixture.store, &mut approval);
            assert!(matches!(outcome, DaemonOutcome::Rejected { .. }));
        }
    }

    #[test]
    fn missing_persona_never_reaches_approval() {
        let mut fixture = fixture();
        fixture.received.request.persona_id = Uuid::new_v4().to_string();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        let outcome = process_received_request(fixture.received, &mut fixture.store, &mut approval);
        assert!(matches!(
            outcome,
            DaemonOutcome::Rejected {
                failure: FailureClass::PersonaUnavailable,
                ..
            }
        ));
        assert!(approval.prompt.is_none());
    }

    #[test]
    fn evidence_only_persona_rejects_every_ipc_subject_before_consent_or_signing() {
        let (mut fixture, persona_id, persona_label, public_key, root_digest) =
            evidence_only_fixture();
        fs::remove_file(&fixture.key_path).unwrap();

        let artifact = ReceivedSignRequest {
            request: SignRequest::new(
                persona_id.clone(),
                IpcArtifactKind::SoftwareRelease,
                "quarantined-release.tar.zst",
            )
            .unwrap(),
            input: File::open(&fixture.artifact_path).unwrap().into(),
            peer: fixture.received.peer,
        };
        assert_evidence_only_ipc_rejected(artifact, &mut fixture.store);

        let now = current_unix_time().unwrap();
        let domain_statement = new_domain_control_statement(
            "evidence-only-aquo.ch",
            now,
            now + DOMAIN_DEFAULT_VALIDITY_SECONDS,
            &public_key,
            &persona_label,
        )
        .unwrap();
        let mut domain_input = tempfile().unwrap();
        domain_input
            .write_all(&canonical_domain_control_statement_bytes(&domain_statement).unwrap())
            .unwrap();
        let domain = ReceivedSignRequest {
            request: SignRequest::new_domain(persona_id.clone()).unwrap(),
            input: domain_input.into(),
            peer: fixture.received.peer,
        };
        assert_evidence_only_ipc_rejected(domain, &mut fixture.store);

        let root_statement = new_persona_root_statement(&persona_label, now, &public_key).unwrap();
        let mut root_input = tempfile().unwrap();
        root_input
            .write_all(&canonical_persona_root_statement_bytes(&root_statement).unwrap())
            .unwrap();
        let root = ReceivedSignRequest {
            request: SignRequest::new_persona_root(persona_id.clone()).unwrap(),
            input: root_input.into(),
            peer: fixture.received.peer,
        };
        assert_evidence_only_ipc_rejected(root, &mut fixture.store);

        let next_key_path = fixture._directory.path().join("quarantined-next-key");
        generate_key(&next_key_path);
        let next_public_key_path = next_key_path.with_extension("pub");
        let transition = ReceivedSignRequest {
            request: SignRequest::new_persona_transition(
                persona_id,
                1,
                root_digest,
                None,
                TransitionKeyProvider::OpensshFile,
                next_key_path.to_str().unwrap(),
            )
            .unwrap(),
            input: File::open(&next_public_key_path).unwrap().into(),
            peer: fixture.received.peer,
        };
        assert_evidence_only_ipc_rejected(transition, &mut fixture.store);
    }

    #[test]
    fn disconnect_after_approval_cancels_before_signing() {
        let mut fixture = fixture();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };
        let mut checks = 0;
        let mut cancelled = || {
            checks += 1;
            (checks == 2).then_some(FailureClass::ClientCancelled)
        };

        let outcome = process_received_request_inner(
            fixture.received,
            &mut fixture.store,
            &mut approval,
            &mut cancelled,
        );
        assert!(matches!(
            outcome,
            DaemonOutcome::Rejected {
                failure: FailureClass::ClientCancelled,
                ..
            }
        ));
        assert!(approval.prompt.is_some());
    }

    #[test]
    fn signer_policy_change_during_approval_prevents_signing() {
        let mut fixture = fixture();
        let mut approval = UnbindingApproval {
            store_path: fixture.store_path.clone(),
            fingerprint: fixture.fingerprint.clone(),
            prompt: None,
        };

        let outcome = process_received_request(fixture.received, &mut fixture.store, &mut approval);
        assert!(matches!(
            outcome,
            DaemonOutcome::Rejected {
                failure: FailureClass::PersonaUnavailable,
                ..
            }
        ));
        assert!(approval.prompt.is_some());
    }

    #[test]
    fn swapped_signing_key_cannot_escape_as_a_false_proof() {
        let mut fixture = fixture();
        fs::remove_file(&fixture.key_path).unwrap();
        fs::remove_file(fixture.key_path.with_extension("pub")).unwrap();
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&fixture.key_path)
            .status()
            .unwrap();
        assert!(status.success());
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        let outcome = process_received_request(fixture.received, &mut fixture.store, &mut approval);
        assert!(matches!(
            outcome,
            DaemonOutcome::Rejected {
                failure: FailureClass::SignerUnavailable,
                ..
            }
        ));
    }

    #[test]
    fn approved_persona_transition_reviews_both_keys_and_commits_exact_proof() {
        let mut fixture = transition_fixture();
        let received = transition_received(
            &fixture.fixture,
            1,
            fixture.root_digest,
            None,
            &fixture.next_key_path,
            &fixture.next_public_key_path,
        );
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        let outcome = process_received_request(received, &mut fixture.fixture.store, &mut approval);
        let DaemonOutcome::Approved {
            subject,
            proof,
            signer_fingerprint,
            ..
        } = outcome
        else {
            panic!("expected approved persona transition");
        };
        let ApprovedSubject::PersonaTransition(review) = subject else {
            panic!("expected persona-transition subject");
        };
        assert_eq!(signer_fingerprint, fixture.fixture.fingerprint);
        assert_eq!(review.sequence, 1);
        assert_eq!(
            review.root_statement_sha256,
            encode_sha256(fixture.root_digest)
        );
        assert_eq!(review.previous_transition_sha256, None);
        assert_eq!(review.previous_key_fingerprint, fixture.fixture.fingerprint);
        assert_eq!(review.next_key_fingerprint, fixture.next_fingerprint);

        let prompt = approval.prompt.expect("approval prompt");
        assert_eq!(prompt.key_fingerprint, fixture.fixture.fingerprint);
        let ApprovalSubject::PersonaTransition(transition) = prompt.subject else {
            panic!("expected persona-transition prompt");
        };
        assert_eq!(transition.persona_anchor, review.persona_anchor);
        assert_eq!(transition.root_sha256_hex(), review.root_statement_sha256);
        assert_eq!(transition.sequence, review.sequence);
        assert_eq!(transition.previous_sha256_hex(), None);
        assert_eq!(
            transition.previous_key_fingerprint,
            review.previous_key_fingerprint
        );
        assert_eq!(transition.next_key_fingerprint, review.next_key_fingerprint);
        assert_eq!(
            transition.transition_sha256_hex(),
            review.transition_statement_sha256
        );

        let proof: PersonaTransitionProof =
            serde_json::from_slice(&proof.read_bytes().unwrap()).unwrap();
        let verified = verify_persona_transition_proof(&proof).unwrap();
        assert_eq!(verified.statement.sequence, 1);
        assert_eq!(
            verified.transition_statement_sha256,
            review.transition_statement_sha256
        );
        let snapshot = fixture
            .fixture
            .store
            .continuity_snapshot(&fixture.persona_id)
            .unwrap();
        assert_eq!(snapshot.head.transition_sequence, 1);
        assert_eq!(
            snapshot.head.current_key_fingerprint,
            fixture.next_fingerprint
        );
        assert_eq!(
            snapshot.transitions,
            vec![PersonaContinuityTransitionProof::Routine(proof)]
        );
    }

    #[test]
    fn routine_transition_continues_after_recovery_policy_enrollment() {
        let mut fixture = transition_fixture();
        let recovery = enroll_recovery_policy(&mut fixture);
        let received = transition_received(
            &fixture.fixture,
            1,
            fixture.root_digest,
            None,
            &fixture.next_key_path,
            &fixture.next_public_key_path,
        );
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        let DaemonOutcome::Approved { proof, .. } =
            process_received_request(received, &mut fixture.fixture.store, &mut approval)
        else {
            panic!("routine transition after policy enrollment should succeed");
        };
        let proof: PersonaTransitionProof =
            serde_json::from_slice(&proof.read_bytes().unwrap()).unwrap();
        let snapshot = fixture
            .fixture
            .store
            .continuity_snapshot(&fixture.persona_id)
            .unwrap();
        assert_eq!(
            snapshot
                .recovery_policy_head
                .as_ref()
                .unwrap()
                .latest_policy_sha256,
            recovery.verified_policy.policy_statement_sha256
        );
        assert!(matches!(
            snapshot.transitions.as_slice(),
            [PersonaContinuityTransitionProof::Routine(stored)] if stored == &proof
        ));
    }

    #[test]
    fn routine_transition_continues_after_recovery_transition() {
        let mut fixture = transition_fixture();
        let recovery = enroll_recovery_policy(&mut fixture);
        let recovered_key_path = fixture.fixture._directory.path().join("recovered-key");
        generate_key(&recovered_key_path);
        let recovered_public_key =
            fs::read_to_string(recovered_key_path.with_extension("pub")).unwrap();
        let recovered_fingerprint = public_key_fingerprint(&recovered_public_key).unwrap();
        let statement = new_recovery_transition_statement(
            &recovery.root,
            1,
            None,
            &fixture.fixture.fingerprint,
            &recovered_public_key,
            &recovery.verified_policy,
            current_unix_time().unwrap(),
            RecoveryTransitionReason::Recovery,
        )
        .unwrap();
        let recovery_digest = recovery_transition_statement_sha256(&statement).unwrap();
        let recovery_proof = create_recovery_transition_proof(
            statement,
            &recovery.verified_policy,
            &recovery.authority_signers[..2],
            &recovered_key_path,
            &recovered_public_key,
        )
        .unwrap();
        fixture
            .fixture
            .store
            .commit_recovery_transition(
                &fixture.persona_id,
                &recovery_proof,
                &recovery.root.root_statement_sha256,
                &recovery.verified_policy.policy_statement_sha256,
                &PersonaContinuityCheckpoint {
                    transition_sequence: 0,
                    transition_sha256: None,
                },
                KeyProvider::OpensshFile,
                &recovered_key_path,
            )
            .unwrap();

        let received = transition_received(
            &fixture.fixture,
            2,
            fixture.root_digest,
            Some(decode_sha256(&recovery_digest).unwrap()),
            &fixture.next_key_path,
            &fixture.next_public_key_path,
        );
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };
        let DaemonOutcome::Approved {
            proof,
            signer_fingerprint,
            ..
        } = process_received_request(received, &mut fixture.fixture.store, &mut approval)
        else {
            panic!("routine transition after recovery should succeed");
        };
        assert_eq!(signer_fingerprint, recovered_fingerprint);
        let routine_proof: PersonaTransitionProof =
            serde_json::from_slice(&proof.read_bytes().unwrap()).unwrap();
        let snapshot = fixture
            .fixture
            .store
            .continuity_snapshot(&fixture.persona_id)
            .unwrap();
        assert_eq!(snapshot.head.transition_sequence, 2);
        assert_eq!(
            snapshot.head.current_key_fingerprint,
            fixture.next_fingerprint
        );
        assert!(matches!(
            snapshot.transitions.as_slice(),
            [
                PersonaContinuityTransitionProof::Recovery(stored_recovery),
                PersonaContinuityTransitionProof::Routine(stored_routine),
            ] if stored_recovery == &recovery_proof && stored_routine == &routine_proof
        ));
    }

    #[test]
    fn declined_and_cancelled_persona_transitions_do_not_mutate_the_journal() {
        for decision in [ApprovalDecision::Decline, ApprovalDecision::Cancel] {
            let mut fixture = transition_fixture();
            let received = transition_received(
                &fixture.fixture,
                1,
                fixture.root_digest,
                None,
                &fixture.next_key_path,
                &fixture.next_public_key_path,
            );
            let mut approval = RecordingApproval {
                decision: Ok(decision),
                prompt: None,
                mutate_after_snapshot: None,
            };

            assert!(matches!(
                process_received_request(received, &mut fixture.fixture.store, &mut approval),
                DaemonOutcome::Rejected { .. }
            ));
            assert!(approval.prompt.is_some());
            assert_unrotated(&fixture);
        }
    }

    #[test]
    fn disconnect_after_transition_signing_cancels_before_commit() {
        let mut fixture = transition_fixture();
        let received = transition_received(
            &fixture.fixture,
            1,
            fixture.root_digest,
            None,
            &fixture.next_key_path,
            &fixture.next_public_key_path,
        );
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };
        let mut checks = 0;
        let mut disconnect_before_commit = || {
            checks += 1;
            (checks == 3).then_some(FailureClass::ClientCancelled)
        };

        assert!(matches!(
            process_received_request_inner(
                received,
                &mut fixture.fixture.store,
                &mut approval,
                &mut disconnect_before_commit,
            ),
            DaemonOutcome::Rejected {
                failure: FailureClass::ClientCancelled,
                ..
            }
        ));
        assert!(approval.prompt.is_some());
        assert_unrotated(&fixture);
    }

    #[test]
    fn stale_root_sequence_and_prior_never_reach_transition_approval() {
        for request_variant in 0..3 {
            let mut fixture = transition_fixture();
            let mut root = fixture.root_digest;
            let (sequence, prior) = match request_variant {
                0 => {
                    root[0] ^= 0xff;
                    (1, None)
                }
                1 => (2, Some([0x41; 32])),
                _ => (2, Some([0x42; 32])),
            };
            let received = transition_received(
                &fixture.fixture,
                sequence,
                root,
                prior,
                &fixture.next_key_path,
                &fixture.next_public_key_path,
            );
            let mut approval = RecordingApproval {
                decision: Ok(ApprovalDecision::Approve),
                prompt: None,
                mutate_after_snapshot: None,
            };

            assert!(matches!(
                process_received_request(received, &mut fixture.fixture.store, &mut approval),
                DaemonOutcome::Rejected {
                    failure: FailureClass::InvalidRequest,
                    ..
                }
            ));
            assert!(approval.prompt.is_none());
            assert_unrotated(&fixture);
        }
    }

    #[test]
    fn substituted_next_private_key_cannot_commit_a_false_transition() {
        let mut fixture = transition_fixture();
        let substituted_key_path = fixture.fixture._directory.path().join("substituted-key");
        generate_key(&substituted_key_path);
        let received = transition_received(
            &fixture.fixture,
            1,
            fixture.root_digest,
            None,
            &substituted_key_path,
            &fixture.next_public_key_path,
        );
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        assert!(matches!(
            process_received_request(received, &mut fixture.fixture.store, &mut approval),
            DaemonOutcome::Rejected {
                failure: FailureClass::SignerUnavailable,
                ..
            }
        ));
        assert!(approval.prompt.is_some());
        assert_unrotated(&fixture);
    }

    #[test]
    fn exact_transition_retry_returns_identical_proof_without_reapproval() {
        let mut fixture = transition_fixture();
        let first_received = transition_received(
            &fixture.fixture,
            1,
            fixture.root_digest,
            None,
            &fixture.next_key_path,
            &fixture.next_public_key_path,
        );
        let mut first_approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };
        let DaemonOutcome::Approved {
            proof: first_proof, ..
        } = process_received_request(
            first_received,
            &mut fixture.fixture.store,
            &mut first_approval,
        )
        else {
            panic!("initial transition should succeed");
        };
        let first_bytes = first_proof.read_bytes().unwrap();
        fs::remove_file(&fixture.next_key_path).unwrap();

        let retry_received = transition_received(
            &fixture.fixture,
            1,
            fixture.root_digest,
            None,
            &fixture.next_key_path,
            &fixture.next_public_key_path,
        );
        let mut unavailable_approval = RecordingApproval {
            decision: Err(ApprovalError::Unavailable),
            prompt: None,
            mutate_after_snapshot: None,
        };
        let DaemonOutcome::Approved {
            proof: retry_proof, ..
        } = process_received_request(
            retry_received,
            &mut fixture.fixture.store,
            &mut unavailable_approval,
        )
        else {
            panic!("exact committed retry should succeed");
        };
        assert!(unavailable_approval.prompt.is_none());
        assert_eq!(retry_proof.read_bytes().unwrap(), first_bytes);
        let altered_locator = fixture.fixture._directory.path().join("altered-locator");
        generate_key(&altered_locator);
        let altered_retry = transition_received(
            &fixture.fixture,
            1,
            fixture.root_digest,
            None,
            &altered_locator,
            &fixture.next_public_key_path,
        );
        let mut altered_approval = RecordingApproval {
            decision: Err(ApprovalError::Unavailable),
            prompt: None,
            mutate_after_snapshot: None,
        };
        assert!(matches!(
            process_received_request(
                altered_retry,
                &mut fixture.fixture.store,
                &mut altered_approval,
            ),
            DaemonOutcome::Rejected {
                failure: FailureClass::InvalidRequest,
                ..
            }
        ));
        assert!(altered_approval.prompt.is_none());
        assert_eq!(
            fixture
                .fixture
                .store
                .continuity_snapshot(&fixture.persona_id)
                .unwrap()
                .transitions
                .len(),
            1
        );
    }

    #[test]
    fn production_handler_round_trips_a_sealed_proof() {
        let mut fixture = fixture();
        let (client, server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None::<Protocol>,
        )
        .unwrap();
        if matches!(
            peer_credentials(&server),
            Err(LinuxIpcError::Socket(rustix::io::Errno::PERM))
        ) {
            return;
        }
        send_sign_request(&client, &fixture.received.request, &fixture.received.input).unwrap();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        let outcome = handle_connection(&server, &mut fixture.store, &mut approval);
        assert!(matches!(outcome, DaemonOutcome::Approved { .. }));
        let response = receive_sign_response(&client).unwrap();
        assert_eq!(response.response, SignResponse::Approved);
        assert!(response.proof.is_some());
    }

    struct Fixture {
        _directory: TempDir,
        store: PersonaStore,
        received: ReceivedSignRequest,
        artifact_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
        store_path: std::path::PathBuf,
        fingerprint: String,
    }

    struct TransitionFixture {
        fixture: Fixture,
        persona_id: String,
        root_digest: [u8; 32],
        next_key_path: std::path::PathBuf,
        next_public_key_path: std::path::PathBuf,
        next_fingerprint: String,
    }

    struct RecoveryPolicyFixture {
        root: VerifiedPersonaRoot,
        verified_policy: VerifiedRecoveryPolicy,
        authority_signers: Vec<RecoverySigner>,
    }

    fn fixture() -> Fixture {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key_path = directory.path().join("signing-key");
        let artifact_path = directory.path().join("release.tar.zst");
        let store_path = directory.path().join("personas.db");
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key_path)
            .status()
            .unwrap();
        assert!(status.success());
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&artifact_path, b"reviewed artifact bytes").unwrap();

        let mut store = PersonaStore::open(&store_path).unwrap();
        let persona = store
            .create_persona("Daemon test publisher", PersonaPurpose::Project)
            .unwrap();
        let public_key = fs::read_to_string(key_path.with_extension("pub")).unwrap();
        let key = store
            .enroll_key(&persona.id, &public_key, KeyProvider::OpensshFile)
            .unwrap();
        store
            .bind_signing_reference(&key.fingerprint, &key_path)
            .unwrap();
        let artifact = File::open(&artifact_path).unwrap();
        let received = ReceivedSignRequest {
            request: SignRequest::new(
                persona.id,
                IpcArtifactKind::SoftwareRelease,
                "release.tar.zst",
            )
            .unwrap(),
            input: artifact.into(),
            peer: PeerCredentials {
                pid: rustix::process::getpid().as_raw_pid(),
                uid: rustix::process::getuid().as_raw(),
                gid: rustix::process::getgid().as_raw(),
            },
        };
        Fixture {
            _directory: directory,
            store,
            received,
            artifact_path,
            key_path,
            store_path,
            fingerprint: key.fingerprint,
        }
    }

    fn evidence_only_fixture() -> (Fixture, String, String, String, [u8; 32]) {
        let mut fixture = fixture();
        let persona_id = fixture.received.request.persona_id.clone();
        let signer = fixture
            .store
            .active_signer_for_persona(&persona_id)
            .unwrap();
        let persona_label = signer.persona.label.clone();
        let public_key = signer.key.public_key.clone();
        let statement =
            new_persona_root_statement(&persona_label, current_unix_time().unwrap(), &public_key)
                .unwrap();
        let proof =
            create_persona_root_proof(statement, &signer.signing_reference.locator, &public_key)
                .unwrap();
        let verified = verify_persona_root_proof(&proof).unwrap();
        let archive = BackupContinuityArchive {
            root: BackupPersonaRootEvidence {
                proof,
                observed_at: None,
            },
            recovery_policies: Vec::new(),
            transitions: Vec::new(),
        };
        let backup = fixture
            .store
            .export_persona_backup_with_archive(&persona_id, Some(archive))
            .unwrap();
        let mut evidence_store = PersonaStore::open_in_memory().unwrap();
        evidence_store.import_persona_backup(&backup).unwrap();
        fixture.store = evidence_store;
        (
            fixture,
            persona_id,
            persona_label,
            public_key,
            decode_sha256(&verified.root_statement_sha256).unwrap(),
        )
    }

    fn assert_evidence_only_ipc_rejected(received: ReceivedSignRequest, store: &mut PersonaStore) {
        let (client, server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None::<Protocol>,
        )
        .unwrap();
        if matches!(
            peer_credentials(&server),
            Err(LinuxIpcError::Socket(rustix::io::Errno::PERM))
        ) {
            return;
        }
        send_sign_request(&client, &received.request, &received.input).unwrap();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: None,
        };

        assert!(matches!(
            handle_connection(&server, store, &mut approval),
            DaemonOutcome::Rejected {
                failure: FailureClass::PersonaUnavailable,
                ..
            }
        ));
        let response = receive_sign_response(&client).unwrap();
        assert_eq!(
            response.response,
            SignResponse::Rejected(RejectionCode::PersonaUnavailable)
        );
        assert!(response.proof.is_none());
        assert!(approval.prompt.is_none());
    }

    fn transition_fixture() -> TransitionFixture {
        let mut fixture = fixture();
        let persona_id = fixture.received.request.persona_id.clone();
        let signer = fixture
            .store
            .active_signer_for_persona(&persona_id)
            .unwrap();
        let statement = new_persona_root_statement(
            &signer.persona.label,
            current_unix_time().unwrap(),
            &signer.key.public_key,
        )
        .unwrap();
        let proof = create_persona_root_proof(
            statement,
            &signer.signing_reference.locator,
            &signer.key.public_key,
        )
        .unwrap();
        let verified = verify_persona_root_proof(&proof).unwrap();
        fixture
            .store
            .record_continuity_root(&persona_id, &proof, &verified.root_statement_sha256)
            .unwrap();

        let next_key_path = fixture._directory.path().join("next-key");
        generate_key(&next_key_path);
        let next_public_key_path = next_key_path.with_extension("pub");
        let next_public_key = fs::read_to_string(&next_public_key_path).unwrap();
        let next_fingerprint = public_key_fingerprint(&next_public_key).unwrap();
        TransitionFixture {
            fixture,
            persona_id,
            root_digest: decode_sha256(&verified.root_statement_sha256).unwrap(),
            next_key_path,
            next_public_key_path,
            next_fingerprint,
        }
    }

    fn transition_received(
        fixture: &Fixture,
        sequence: u32,
        root_digest: [u8; 32],
        previous_digest: Option<[u8; 32]>,
        next_key_path: &Path,
        next_public_key_path: &Path,
    ) -> ReceivedSignRequest {
        ReceivedSignRequest {
            request: SignRequest::new_persona_transition(
                fixture.received.request.persona_id.clone(),
                sequence,
                root_digest,
                previous_digest,
                TransitionKeyProvider::OpensshFile,
                next_key_path.to_str().unwrap(),
            )
            .unwrap(),
            input: File::open(next_public_key_path).unwrap().into(),
            peer: fixture.received.peer,
        }
    }

    fn enroll_recovery_policy(fixture: &mut TransitionFixture) -> RecoveryPolicyFixture {
        let root = verify_persona_root_proof(
            &fixture
                .fixture
                .store
                .continuity_snapshot(&fixture.persona_id)
                .unwrap()
                .root
                .proof,
        )
        .unwrap();
        let authority_signers = (1..=3)
            .map(|index| {
                let private_key_path = fixture
                    .fixture
                    ._directory
                    .path()
                    .join(format!("recovery-{index}"));
                generate_key(&private_key_path);
                RecoverySigner {
                    public_key: fs::read_to_string(private_key_path.with_extension("pub")).unwrap(),
                    private_key_path,
                }
            })
            .collect::<Vec<_>>();
        let authority_public_keys = authority_signers
            .iter()
            .map(|signer| signer.public_key.clone())
            .collect::<Vec<_>>();
        let now = current_unix_time().unwrap();
        let statement = new_initial_recovery_policy_statement(
            &root,
            &authority_public_keys,
            2,
            RecoveryContinuityCheckpoint {
                transition_sequence: 0,
                transition_sha256: None,
            },
            now,
            now + 3_600,
        )
        .unwrap();
        let proof = create_initial_recovery_policy_proof(statement, &authority_signers).unwrap();
        let verified_policy = verify_initial_recovery_policy_proof(&root, &proof).unwrap();
        fixture
            .fixture
            .store
            .record_recovery_policy_chain(
                &fixture.persona_id,
                std::slice::from_ref(&proof),
                &root.root_statement_sha256,
                &verified_policy.policy_statement_sha256,
                &PersonaContinuityCheckpoint {
                    transition_sequence: 0,
                    transition_sha256: None,
                },
            )
            .unwrap();
        RecoveryPolicyFixture {
            root,
            verified_policy,
            authority_signers,
        }
    }

    fn assert_unrotated(fixture: &TransitionFixture) {
        let snapshot = fixture
            .fixture
            .store
            .continuity_snapshot(&fixture.persona_id)
            .unwrap();
        assert_eq!(snapshot.head.transition_sequence, 0);
        assert_eq!(
            snapshot.head.current_key_fingerprint,
            fixture.fixture.fingerprint
        );
        assert!(snapshot.transitions.is_empty());
    }

    fn generate_key(path: &Path) {
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
