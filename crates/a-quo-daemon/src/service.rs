use std::os::fd::OwnedFd;
use std::time::{SystemTime, UNIX_EPOCH};

use a_quo_approval::{
    ApprovalDecision, ApprovalPrompt, ArtifactKind as PromptArtifactKind, PeerIdentity,
    PersonaPurpose as PromptPersonaPurpose,
};
use a_quo_core::{
    ArtifactDescriptor, DomainControlReview, DomainControlStatement, PersonaRootProof,
    PersonaRootReview, PersonaRootStatement, ProofBundle,
    create_domain_control_proof_for_statement, create_persona_root_proof,
    create_sshsig_proof_for_descriptor, review_domain_control_statement_bytes,
    review_persona_root_statement, review_persona_root_statement_bytes,
    verify_domain_control_proof, verify_persona_root_proof,
};
use a_quo_ipc::{
    ArtifactKind as IpcArtifactKind, ConnectionState, MAX_ARTIFACT_BYTES,
    MAX_DOMAIN_STATEMENT_BYTES, MAX_PERSONA_ROOT_STATEMENT_BYTES, PeerCredentials,
    ReceivedSignRequest, RejectionCode, SealedProof, SignSubject, connection_state,
    receive_sign_request, seal_proof_bytes, send_sign_approved, send_sign_rejected,
    snapshot_artifact,
};
use a_quo_store::{ActiveSigner, PersonaPurpose, PersonaStore};
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
    store: &PersonaStore,
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
    store: &PersonaStore,
    approval: &mut dyn ApprovalBackend,
) -> DaemonOutcome {
    process_received_request_inner(received, store, approval, &mut || None)
}

fn process_received_request_inner(
    received: ReceivedSignRequest,
    store: &PersonaStore,
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
    }
}

enum SignedProof {
    Bundle(ProofBundle),
    PersonaRoot(PersonaRootProof),
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
        DOMAIN_DEFAULT_VALIDITY_SECONDS, EvidenceStatus, canonical_domain_control_statement_bytes,
        canonical_persona_root_statement_bytes, new_domain_control_statement,
        new_persona_root_statement, verify_domain_control_proof, verify_persona_root_proof,
        verify_sshsig_proof_for_descriptor,
    };
    use a_quo_ipc::{
        LinuxIpcError, SignRequest, SignResponse, peer_credentials, receive_sign_response,
        send_sign_request,
    };
    use a_quo_store::{KeyProvider, PersonaPurpose};
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
        let fixture = fixture();
        let mut approval = RecordingApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
            mutate_after_snapshot: Some(fixture.artifact_path.clone()),
        };

        let outcome = process_received_request(fixture.received, &fixture.store, &mut approval);
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

        let outcome = process_received_request(fixture.received, &fixture.store, &mut approval);
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
            process_received_request(fixture.received, &fixture.store, &mut approval),
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

        let outcome = process_received_request(fixture.received, &fixture.store, &mut approval);
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
                process_received_request(fixture.received, &fixture.store, &mut approval),
                DaemonOutcome::Rejected {
                    failure: FailureClass::InvalidRequest,
                    ..
                }
            ));
            assert!(approval.prompt.is_none());
        }
    }

    #[test]
    fn decline_and_unavailable_approval_never_return_a_proof() {
        for decision in [
            Ok(ApprovalDecision::Decline),
            Err(ApprovalError::Unavailable),
        ] {
            let fixture = fixture();
            let mut approval = RecordingApproval {
                decision,
                prompt: None,
                mutate_after_snapshot: None,
            };
            let outcome = process_received_request(fixture.received, &fixture.store, &mut approval);
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

        let outcome = process_received_request(fixture.received, &fixture.store, &mut approval);
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
    fn disconnect_after_approval_cancels_before_signing() {
        let fixture = fixture();
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
            &fixture.store,
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
        let fixture = fixture();
        let mut approval = UnbindingApproval {
            store_path: fixture.store_path.clone(),
            fingerprint: fixture.fingerprint.clone(),
            prompt: None,
        };

        let outcome = process_received_request(fixture.received, &fixture.store, &mut approval);
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
        let fixture = fixture();
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

        let outcome = process_received_request(fixture.received, &fixture.store, &mut approval);
        assert!(matches!(
            outcome,
            DaemonOutcome::Rejected {
                failure: FailureClass::SignerUnavailable,
                ..
            }
        ));
    }

    #[test]
    fn production_handler_round_trips_a_sealed_proof() {
        let fixture = fixture();
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

        let outcome = handle_connection(&server, &fixture.store, &mut approval);
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
}
