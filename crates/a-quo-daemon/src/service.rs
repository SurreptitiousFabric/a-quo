use std::os::fd::OwnedFd;

use a_quo_core::{ArtifactDescriptor, ProofBundle, create_sshsig_proof_for_descriptor};
use a_quo_ipc::{
    ArtifactKind, ConnectionState, MAX_ARTIFACT_BYTES, PeerCredentials, ReceivedSignRequest,
    RejectionCode, SealedProof, connection_state, receive_sign_request, seal_proof_bytes,
    send_sign_approved, send_sign_rejected, snapshot_artifact,
};
use a_quo_store::{ActiveSigner, PersonaPurpose, PersonaStore};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approve,
    Decline,
    Cancel,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPrompt {
    pub request_id: String,
    pub persona_id: String,
    pub persona_label: String,
    pub persona_purpose: PersonaPurpose,
    pub key_fingerprint: String,
    pub artifact_kind: ArtifactKind,
    pub artifact_label: String,
    pub artifact: ArtifactDescriptor,
    pub peer: PeerCredentials,
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
        artifact: ArtifactDescriptor,
        proof: SealedProof,
    },
    Rejected {
        request_id: Option<String>,
        failure: FailureClass,
    },
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
    approval: &mut impl ApprovalBackend,
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
            artifact,
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
                artifact,
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
    approval: &mut impl ApprovalBackend,
) -> DaemonOutcome {
    process_received_request_inner(received, store, approval, &mut || None)
}

fn process_received_request_inner(
    received: ReceivedSignRequest,
    store: &PersonaStore,
    approval: &mut impl ApprovalBackend,
    connection_interrupted: &mut impl FnMut() -> Option<FailureClass>,
) -> DaemonOutcome {
    let request_id = Uuid::new_v4().to_string();
    let ReceivedSignRequest {
        request,
        artifact,
        peer,
    } = received;
    let signer = match store.active_signer_for_persona(&request.persona_id) {
        Ok(signer) => signer,
        Err(_) => {
            return rejected(Some(request_id), FailureClass::PersonaUnavailable);
        }
    };
    let snapshot = match snapshot_artifact(artifact, MAX_ARTIFACT_BYTES) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return rejected(Some(request_id), FailureClass::InvalidRequest);
        }
    };
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }
    let prompt = approval_prompt(&request_id, &request, peer, snapshot.descriptor(), &signer);
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

    let proof = match create_sshsig_proof_for_descriptor(
        snapshot.descriptor().clone(),
        &signer.signing_reference.locator,
        &signer.key.public_key,
        &signer.persona.label,
    ) {
        Ok(proof) => proof,
        Err(_) => {
            return rejected(Some(request_id), FailureClass::SignerUnavailable);
        }
    };
    let proof = match sealed_proof(&proof) {
        Ok(proof) => proof,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };

    DaemonOutcome::Approved {
        request_id,
        signer_fingerprint: signer.key.fingerprint,
        artifact: snapshot.descriptor().clone(),
        proof,
    }
}

fn approval_prompt(
    request_id: &str,
    request: &a_quo_ipc::SignRequest,
    peer: PeerCredentials,
    artifact: &ArtifactDescriptor,
    signer: &ActiveSigner,
) -> ApprovalPrompt {
    ApprovalPrompt {
        request_id: request_id.to_owned(),
        persona_id: signer.persona.id.clone(),
        persona_label: signer.persona.label.clone(),
        persona_purpose: signer.persona.purpose,
        key_fingerprint: signer.key.fingerprint.clone(),
        artifact_kind: request.artifact_kind,
        artifact_label: request.artifact_label.clone(),
        artifact: artifact.clone(),
        peer,
    }
}

fn sealed_proof(proof: &ProofBundle) -> Result<SealedProof, ()> {
    let mut bytes = serde_json::to_vec_pretty(proof).map_err(|_| ())?;
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
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    use a_quo_core::{EvidenceStatus, verify_sshsig_proof_for_descriptor};
    use a_quo_ipc::{
        LinuxIpcError, SignRequest, SignResponse, peer_credentials, receive_sign_response,
        send_sign_request,
    };
    use a_quo_store::{KeyProvider, PersonaPurpose};
    use rustix::net::{AddressFamily, Protocol, SocketFlags, SocketType, socketpair};
    use tempfile::{TempDir, tempdir};

    use super::*;

    struct RecordingApproval {
        decision: Result<ApprovalDecision, ApprovalError>,
        prompt: Option<ApprovalPrompt>,
        mutate_after_snapshot: Option<std::path::PathBuf>,
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
            artifact,
            proof,
            signer_fingerprint,
            ..
        } = outcome
        else {
            panic!("expected approved outcome");
        };
        assert_eq!(signer_fingerprint, fixture.fingerprint);
        assert_eq!(artifact.size, b"reviewed artifact bytes".len() as u64);
        let prompt = approval.prompt.unwrap();
        assert_eq!(prompt.artifact, artifact);
        assert_eq!(prompt.persona_label, "Daemon test publisher");
        assert_eq!(prompt.artifact_label, "release.tar.zst");

        let mut proof_file = proof.into_file();
        proof_file.seek(SeekFrom::Start(0)).unwrap();
        let mut proof_bytes = Vec::new();
        proof_file.read_to_end(&mut proof_bytes).unwrap();
        let proof: ProofBundle = serde_json::from_slice(&proof_bytes).unwrap();
        let report = verify_sshsig_proof_for_descriptor(&artifact, &proof).unwrap();
        assert_eq!(report.signature, EvidenceStatus::Verified);
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
        send_sign_request(
            &client,
            &fixture.received.request,
            &fixture.received.artifact,
        )
        .unwrap();
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
        fingerprint: String,
    }

    fn fixture() -> Fixture {
        let directory = tempdir().unwrap();
        let key_path = directory.path().join("signing-key");
        let artifact_path = directory.path().join("release.tar.zst");
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key_path)
            .status()
            .unwrap();
        assert!(status.success());
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&artifact_path, b"reviewed artifact bytes").unwrap();

        let mut store = PersonaStore::open_in_memory().unwrap();
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
            request: SignRequest::new(persona.id, ArtifactKind::SoftwareRelease, "release.tar.zst")
                .unwrap(),
            artifact: artifact.into(),
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
            fingerprint: key.fingerprint,
        }
    }
}
