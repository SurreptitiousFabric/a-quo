use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use a_quo_approval::{
    ApprovalDecision, ApprovalPrompt, PeerIdentity, RecoveryParticipantRole as PromptRole,
    RecoveryReason as PromptReason,
};
use a_quo_core::{
    RecoveryCeremonyParticipantReview, RecoveryCeremonyParticipantRole, RecoverySigner,
    RecoveryTransitionReason, canonical_recovery_ceremony_response_bytes,
    parse_recovery_ceremony_request_bytes, public_key_fingerprint,
    review_recovery_ceremony_participant, sign_recovery_ceremony_request,
    verify_recovery_ceremony_request, verify_recovery_ceremony_response,
};
use a_quo_ipc::{
    MAX_RECOVERY_PARTICIPATION_REQUEST_BYTES, PeerCredentials, RecoveryParticipantKeyProvider,
    SignRequest, SignSubject, seal_proof_bytes, snapshot_artifact,
};
use uuid::Uuid;

use super::{
    ApprovalBackend, ApprovalError, ApprovedSubject, DaemonOutcome, FailureClass,
    current_unix_time, decode_sha256, rejected,
};

const MAX_PRIVATE_SIGNING_REFERENCE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParticipantRequest {
    provider: RecoveryParticipantKeyProvider,
    signing_reference: PathBuf,
    public_key: String,
    expected_root_sha256: [u8; 32],
    expected_policy_version: u32,
    expected_policy_sha256: [u8; 32],
    expected_policy_threshold: u32,
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SigningReferenceIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    owner: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

pub(super) fn process(
    request_uuid: Uuid,
    request: SignRequest,
    input: OwnedFd,
    peer: PeerCredentials,
    approval: &mut dyn ApprovalBackend,
    connection_interrupted: &mut impl FnMut() -> Option<FailureClass>,
) -> DaemonOutcome {
    process_with_clock(
        request_uuid,
        request,
        input,
        peer,
        approval,
        connection_interrupted,
        &mut current_unix_time,
    )
}

fn process_with_clock(
    request_uuid: Uuid,
    request: SignRequest,
    input: OwnedFd,
    peer: PeerCredentials,
    approval: &mut dyn ApprovalBackend,
    connection_interrupted: &mut impl FnMut() -> Option<FailureClass>,
    clock: &mut impl FnMut() -> Result<i64, ()>,
) -> DaemonOutcome {
    let request_id = request_uuid.to_string();
    let participant = match participant_request(request) {
        Ok(participant) => participant,
        Err(failure) => return rejected(Some(request_id), failure),
    };
    let snapshot = match snapshot_artifact(input, MAX_RECOVERY_PARTICIPATION_REQUEST_BYTES) {
        Ok(snapshot) => snapshot,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let request_bytes = match snapshot.read_bytes_bounded(MAX_RECOVERY_PARTICIPATION_REQUEST_BYTES)
    {
        Ok(bytes) => bytes,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let now = match clock() {
        Ok(now) => now,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };
    let request = match parse_recovery_ceremony_request_bytes(&request_bytes) {
        Ok(request) => request,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let verified = match verify_recovery_ceremony_request(&request, now) {
        Ok(verified) => verified,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let review = match review_recovery_ceremony_participant(&verified, &participant.public_key, now)
    {
        Ok(review) => review,
        Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    if !pins_match(&participant, &review, &verified) {
        return rejected(Some(request_id), FailureClass::InvalidRequest);
    }
    let signing_identity = match validate_signing_reference(&participant) {
        Ok(identity) => identity,
        Err(failure) => return rejected(Some(request_id), failure),
    };
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }
    let prompt = match approval_prompt(request_uuid, &review, &verified, peer) {
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
        Err(ApprovalError::Unavailable | ApprovalError::TimedOut | ApprovalError::Failed) => {
            return rejected(Some(request_id), FailureClass::ConsentUnavailable);
        }
        Ok(ApprovalDecision::Approve) => {}
    }
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }

    // Treat approval as authorization for the exact reviewed request only.
    // Reparse the immutable snapshot, re-verify every embedded proof and pin,
    // and use a fresh clock reading so expiry during review fails closed.
    let checked_at = match clock() {
        Ok(now) => now,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };
    if checked_at < now {
        return rejected(Some(request_id), FailureClass::InvalidRequest);
    }
    let current_request = match parse_recovery_ceremony_request_bytes(&request_bytes) {
        Ok(current) if current == request => current,
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let current_verified = match verify_recovery_ceremony_request(&current_request, checked_at) {
        Ok(current) if current.request_sha256() == verified.request_sha256() => current,
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    let current_review = match review_recovery_ceremony_participant(
        &current_verified,
        &participant.public_key,
        checked_at,
    ) {
        Ok(current) if current == review => current,
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::InvalidRequest),
    };
    if !pins_match(&participant, &current_review, &current_verified) {
        return rejected(Some(request_id), FailureClass::InvalidRequest);
    }
    let current_signing_identity = match validate_signing_reference(&participant) {
        Ok(current) if current == signing_identity => current,
        Ok(_) | Err(_) => return rejected(Some(request_id), FailureClass::SignerUnavailable),
    };
    let signer = RecoverySigner {
        private_key_path: current_signing_identity.canonical_path,
        public_key: participant.public_key,
    };
    let response = match sign_recovery_ceremony_request(&current_verified, &signer, checked_at) {
        Ok(response) => response,
        Err(_) => return rejected(Some(request_id), FailureClass::SignerUnavailable),
    };
    if let Some(failure) = connection_interrupted() {
        return rejected(Some(request_id), failure);
    }
    let completed_at = match clock() {
        Ok(now) => now,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };
    if verify_recovery_ceremony_response(&current_verified, &response, completed_at).is_err() {
        return rejected(Some(request_id), FailureClass::InvalidRequest);
    }
    let response_bytes = match canonical_recovery_ceremony_response_bytes(&response) {
        Ok(bytes) => bytes,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };
    let proof = match seal_proof_bytes(&response_bytes) {
        Ok(proof) => proof,
        Err(_) => return rejected(Some(request_id), FailureClass::Internal),
    };

    DaemonOutcome::Approved {
        request_id,
        signer_fingerprint: current_review.participant_fingerprint.clone(),
        subject: ApprovedSubject::RecoveryParticipation(Box::new(current_review)),
        proof,
    }
}

fn participant_request(request: SignRequest) -> Result<ParticipantRequest, FailureClass> {
    if request.persona_id.is_some() {
        return Err(FailureClass::InvalidRequest);
    }
    let SignSubject::RecoveryParticipation {
        participant_key_provider,
        participant_signing_reference,
        participant_public_key,
        expected_root_sha256,
        expected_policy_version,
        expected_policy_sha256,
        expected_policy_threshold,
        expected_previous_head_sequence,
        expected_previous_head_sha256,
    } = request.subject
    else {
        return Err(FailureClass::InvalidRequest);
    };
    Ok(ParticipantRequest {
        provider: participant_key_provider,
        signing_reference: PathBuf::from(participant_signing_reference),
        public_key: participant_public_key,
        expected_root_sha256,
        expected_policy_version,
        expected_policy_sha256,
        expected_policy_threshold,
        expected_previous_head_sequence,
        expected_previous_head_sha256,
    })
}

fn pins_match(
    participant: &ParticipantRequest,
    review: &RecoveryCeremonyParticipantReview,
    verified: &a_quo_core::VerifiedRecoveryCeremonyRequest,
) -> bool {
    decode_sha256(&review.root_statement_sha256).ok() == Some(participant.expected_root_sha256)
        && review.recovery_policy_version == participant.expected_policy_version
        && decode_sha256(&review.recovery_policy_sha256).ok()
            == Some(participant.expected_policy_sha256)
        && verified.selected_policy().statement.threshold == participant.expected_policy_threshold
        && review.previous_head.transition_sequence == participant.expected_previous_head_sequence
        && review
            .previous_head
            .transition_sha256
            .as_deref()
            .map(decode_sha256)
            .transpose()
            .ok()
            .flatten()
            == participant.expected_previous_head_sha256
}

fn validate_signing_reference(
    participant: &ParticipantRequest,
) -> Result<SigningReferenceIdentity, FailureClass> {
    public_key_fingerprint(&participant.public_key).map_err(|_| FailureClass::InvalidRequest)?;
    if participant.provider == RecoveryParticipantKeyProvider::Fido2 {
        let algorithm = participant
            .public_key
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if !matches!(
            algorithm,
            "sk-ssh-ed25519@openssh.com" | "sk-ecdsa-sha2-nistp256@openssh.com"
        ) {
            return Err(FailureClass::SignerUnavailable);
        }
    }
    if participant.signing_reference.as_os_str().is_empty()
        || !participant.signing_reference.is_absolute()
    {
        return Err(FailureClass::SignerUnavailable);
    }
    let entry = fs::symlink_metadata(&participant.signing_reference)
        .map_err(|_| FailureClass::SignerUnavailable)?;
    if entry.file_type().is_symlink() || !entry.is_file() || entry.len() == 0 {
        return Err(FailureClass::SignerUnavailable);
    }
    let canonical_path = fs::canonicalize(&participant.signing_reference)
        .map_err(|_| FailureClass::SignerUnavailable)?;
    let metadata =
        fs::symlink_metadata(&canonical_path).map_err(|_| FailureClass::SignerUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_PRIVATE_SIGNING_REFERENCE_BYTES
    {
        return Err(FailureClass::SignerUnavailable);
    }
    let current_uid = rustix::process::geteuid().as_raw();
    let root_owned_agent_stub =
        participant.provider == RecoveryParticipantKeyProvider::SshAgent && metadata.uid() == 0;
    if metadata.uid() != current_uid && !root_owned_agent_stub {
        return Err(FailureClass::SignerUnavailable);
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0
        || (participant.provider != RecoveryParticipantKeyProvider::SshAgent && mode & 0o077 != 0)
    {
        return Err(FailureClass::SignerUnavailable);
    }
    // The locator/public-key binding is ultimately established by producing
    // and self-verifying the exact role signature after approval. Avoid
    // reading or copying a private key merely to inspect it here.
    Ok(file_identity(canonical_path, &metadata))
}

fn file_identity(path: PathBuf, metadata: &fs::Metadata) -> SigningReferenceIdentity {
    SigningReferenceIdentity {
        canonical_path: path,
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        owner: metadata.uid(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn approval_prompt(
    request_id: Uuid,
    review: &RecoveryCeremonyParticipantReview,
    verified: &a_quo_core::VerifiedRecoveryCeremonyRequest,
    peer: PeerCredentials,
) -> Result<ApprovalPrompt, ()> {
    ApprovalPrompt::new_recovery_participation(
        request_id,
        review.persona.clone(),
        review.participant_fingerprint.clone(),
        decode_sha256(&review.request_sha256)?,
        review.ceremony_id.clone(),
        review.expires_at,
        verified.statement().persona_anchor.clone(),
        decode_sha256(&review.root_statement_sha256)?,
        review.recovery_policy_version,
        decode_sha256(&review.recovery_policy_sha256)?,
        verified.selected_policy().statement.threshold,
        review.previous_head.transition_sequence,
        review
            .previous_head
            .transition_sha256
            .as_deref()
            .map(decode_sha256)
            .transpose()?,
        prompt_reason(review.reason),
        review.previous_key_fingerprint.clone(),
        review.next_key_fingerprint.clone(),
        prompt_role(review.role),
        PeerIdentity {
            pid: u32::try_from(peer.pid).map_err(|_| ())?,
            uid: peer.uid,
            gid: peer.gid,
        },
    )
    .map_err(|_| ())
}

fn prompt_role(role: RecoveryCeremonyParticipantRole) -> PromptRole {
    match role {
        RecoveryCeremonyParticipantRole::RecoveryAuthority => PromptRole::RecoveryAuthority,
        RecoveryCeremonyParticipantRole::NextKey => PromptRole::NextSigningKey,
    }
}

fn prompt_reason(reason: RecoveryTransitionReason) -> PromptReason {
    match reason {
        RecoveryTransitionReason::Recovery => PromptReason::Recovery,
        RecoveryTransitionReason::Compromise => PromptReason::Compromise,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::Path;
    use std::process::Command;

    use a_quo_approval::ApprovalSubject;
    use a_quo_core::{
        PersonaContinuityCheckpoint, RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE,
        RecoveryCeremonyResponse, RecoveryContinuityCheckpoint,
        create_initial_recovery_policy_proof, create_persona_root_proof,
        new_initial_recovery_policy_statement, new_persona_root_statement,
        new_recovery_ceremony_request, new_recovery_transition_ceremony_statement,
        parse_recovery_ceremony_response_bytes, verify_initial_recovery_policy_proof,
        verify_persona_root_proof,
    };
    use a_quo_ipc::{
        LinuxIpcError, ReceivedSignRequest, SignResponse, peer_credentials, receive_sign_response,
        send_sign_request, snapshot_stream,
    };
    use a_quo_store::PersonaStore;
    use rustix::net::{AddressFamily, Protocol, SocketFlags, SocketType, socketpair};
    use tempfile::TempDir;

    use super::*;

    #[derive(Clone)]
    struct TestKey {
        private: PathBuf,
        public: String,
    }

    impl TestKey {
        fn signer(&self) -> RecoverySigner {
            RecoverySigner {
                private_key_path: self.private.clone(),
                public_key: self.public.clone(),
            }
        }
    }

    struct CeremonyFixture {
        _directory: TempDir,
        request_bytes: Vec<u8>,
        sign_request: SignRequest,
        participant: TestKey,
        outsider: TestKey,
        now: i64,
        expires_at: i64,
    }

    struct CaptureApproval {
        decision: Result<ApprovalDecision, ApprovalError>,
        prompt: Option<ApprovalPrompt>,
    }

    impl ApprovalBackend for CaptureApproval {
        fn decide(&mut self, prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
            self.prompt = Some(prompt.clone());
            self.decision
        }
    }

    struct MutatingApproval {
        path: PathBuf,
        prompt: Option<ApprovalPrompt>,
    }

    impl ApprovalBackend for MutatingApproval {
        fn decide(&mut self, prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
            self.prompt = Some(prompt.clone());
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o644)).unwrap();
            Ok(ApprovalDecision::Approve)
        }
    }

    #[test]
    fn verified_recovery_participation_is_stateless_and_returns_an_exact_response() {
        let fixture = ceremony_fixture();
        let mut store = PersonaStore::open_in_memory().unwrap();
        assert!(store.list_personas().unwrap().is_empty());
        let mut approval = CaptureApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
        };

        let outcome = super::super::process_received_request(
            fixture.received(fixture.sign_request.clone(), &fixture.request_bytes),
            &mut store,
            &mut approval,
        );
        let DaemonOutcome::Approved {
            signer_fingerprint,
            subject,
            proof,
            ..
        } = outcome
        else {
            panic!("expected approved recovery participation");
        };
        let ApprovedSubject::RecoveryParticipation(review) = subject else {
            panic!("expected recovery-participation review");
        };
        assert_eq!(signer_fingerprint, review.participant_fingerprint);
        assert_eq!(
            signer_fingerprint,
            public_key_fingerprint(&fixture.participant.public).unwrap()
        );
        let prompt = approval.prompt.expect("verified prompt");
        assert_eq!(prompt.persona_id, None);
        assert_eq!(prompt.persona_purpose, None);
        let ApprovalSubject::RecoveryParticipation(prompt_review) = prompt.subject else {
            panic!("expected recovery prompt");
        };
        assert_eq!(prompt_review.ceremony_id, review.ceremony_id);
        assert_eq!(
            prompt_review.participant_key_fingerprint,
            review.participant_fingerprint
        );

        let response_bytes = proof.read_bytes().unwrap();
        let response: RecoveryCeremonyResponse =
            parse_recovery_ceremony_response_bytes(&response_bytes).unwrap();
        let request = parse_recovery_ceremony_request_bytes(&fixture.request_bytes).unwrap();
        let checked_at = current_unix_time().unwrap();
        let verified = verify_recovery_ceremony_request(&request, checked_at).unwrap();
        verify_recovery_ceremony_response(&verified, &response, checked_at).unwrap();
        assert_eq!(
            response.request_binding_signature.namespace,
            RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE
        );
        assert_eq!(
            public_key_fingerprint(&response.request_binding_signature.public_key).unwrap(),
            signer_fingerprint
        );
        let mut tampered_binding = response;
        tampered_binding.request_binding_signature.value.push('x');
        assert!(
            verify_recovery_ceremony_response(&verified, &tampered_binding, checked_at).is_err()
        );
        assert!(store.list_personas().unwrap().is_empty());

        let wire = fixture.received(fixture.sign_request.clone(), &fixture.request_bytes);
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
        send_sign_request(&client, &wire.request, &wire.input).unwrap();
        let mut approval = CaptureApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
        };
        assert!(matches!(
            super::super::handle_connection(&server, &mut store, &mut approval),
            DaemonOutcome::Approved {
                subject: ApprovedSubject::RecoveryParticipation(_),
                ..
            }
        ));
        let received = receive_sign_response(&client).unwrap();
        assert_eq!(received.response, SignResponse::Approved);
        let response_bytes = received.proof.unwrap().read_bytes().unwrap();
        let response = parse_recovery_ceremony_response_bytes(&response_bytes).unwrap();
        let checked_at = current_unix_time().unwrap();
        let verified = verify_recovery_ceremony_request(&request, checked_at).unwrap();
        verify_recovery_ceremony_response(&verified, &response, checked_at).unwrap();
        assert!(store.list_personas().unwrap().is_empty());
    }

    #[test]
    fn tampering_unauthorized_keys_and_wrong_locators_fail_closed() {
        let fixture = ceremony_fixture();

        let mut malformed = fixture.request_bytes.clone();
        malformed.insert(0, b' ');
        let mut wrong_pin = fixture.sign_request.clone();
        let SignSubject::RecoveryParticipation {
            expected_root_sha256,
            ..
        } = &mut wrong_pin.subject
        else {
            unreachable!();
        };
        *expected_root_sha256 = [0x55; 32];
        let mut unauthorized = fixture.sign_request.clone();
        let SignSubject::RecoveryParticipation {
            participant_signing_reference,
            participant_public_key,
            ..
        } = &mut unauthorized.subject
        else {
            unreachable!();
        };
        *participant_signing_reference = fixture.outsider.private.to_string_lossy().into_owned();
        *participant_public_key = fixture.outsider.public.clone();
        let mut leaked_persona_id = fixture.sign_request.clone();
        leaked_persona_id.persona_id = Some(Uuid::new_v4().to_string());

        for (request, bytes) in [
            (fixture.sign_request.clone(), malformed.as_slice()),
            (wrong_pin, fixture.request_bytes.as_slice()),
            (unauthorized, fixture.request_bytes.as_slice()),
            (leaked_persona_id, fixture.request_bytes.as_slice()),
        ] {
            let mut store = PersonaStore::open_in_memory().unwrap();
            let mut approval = CaptureApproval {
                decision: Ok(ApprovalDecision::Approve),
                prompt: None,
            };
            assert!(matches!(
                super::super::process_received_request(
                    fixture.received(request, bytes),
                    &mut store,
                    &mut approval,
                ),
                DaemonOutcome::Rejected {
                    failure: FailureClass::InvalidRequest,
                    ..
                }
            ));
            assert!(approval.prompt.is_none());
            assert!(store.list_personas().unwrap().is_empty());
        }

        let mut wrong_locator = fixture.sign_request.clone();
        let SignSubject::RecoveryParticipation {
            participant_signing_reference,
            ..
        } = &mut wrong_locator.subject
        else {
            unreachable!();
        };
        *participant_signing_reference = fixture.outsider.private.to_string_lossy().into_owned();
        let mut store = PersonaStore::open_in_memory().unwrap();
        let mut approval = CaptureApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
        };
        assert!(matches!(
            super::super::process_received_request(
                fixture.received(wrong_locator, &fixture.request_bytes),
                &mut store,
                &mut approval,
            ),
            DaemonOutcome::Rejected {
                failure: FailureClass::SignerUnavailable,
                ..
            }
        ));
        assert!(approval.prompt.is_some());
        assert!(store.list_personas().unwrap().is_empty());
    }

    #[test]
    fn decline_cancel_backend_failure_disconnect_mutation_and_expiry_return_no_response() {
        let fixture = ceremony_fixture();

        for (decision, expected) in [
            (Ok(ApprovalDecision::Decline), FailureClass::UserDeclined),
            (Ok(ApprovalDecision::Cancel), FailureClass::ClientCancelled),
            (Err(ApprovalError::Failed), FailureClass::ConsentUnavailable),
        ] {
            let mut store = PersonaStore::open_in_memory().unwrap();
            let mut approval = CaptureApproval {
                decision,
                prompt: None,
            };
            assert!(matches!(
                super::super::process_received_request(
                    fixture.received(fixture.sign_request.clone(), &fixture.request_bytes),
                    &mut store,
                    &mut approval,
                ),
                DaemonOutcome::Rejected { failure, .. } if failure == expected
            ));
            assert!(approval.prompt.is_some());
            assert!(store.list_personas().unwrap().is_empty());
        }

        let mut mutation = MutatingApproval {
            path: fixture.participant.private.clone(),
            prompt: None,
        };
        assert!(matches!(
            run_with_clock(
                &fixture,
                fixture.sign_request.clone(),
                &mut mutation,
                &mut [fixture.now, fixture.now, fixture.now].into_iter(),
                &mut || None,
            ),
            DaemonOutcome::Rejected {
                failure: FailureClass::SignerUnavailable,
                ..
            }
        ));
        assert!(mutation.prompt.is_some());

        // Restore only this ephemeral test key so the remaining independent
        // failure paths can reach consent. No signature is released above.
        fs::set_permissions(
            &fixture.participant.private,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let mut approval = CaptureApproval {
            decision: Ok(ApprovalDecision::Approve),
            prompt: None,
        };
        let mut interruption_calls = 0_u8;
        let mut interrupted = || {
            interruption_calls += 1;
            (interruption_calls == 2).then_some(FailureClass::ClientCancelled)
        };
        assert!(matches!(
            run_with_clock(
                &fixture,
                fixture.sign_request.clone(),
                &mut approval,
                &mut [fixture.now].into_iter(),
                &mut interrupted,
            ),
            DaemonOutcome::Rejected {
                failure: FailureClass::ClientCancelled,
                ..
            }
        ));

        for times in [
            vec![fixture.now, fixture.expires_at],
            vec![fixture.now, fixture.now - 1],
            vec![fixture.now, fixture.now, fixture.expires_at],
        ] {
            let mut approval = CaptureApproval {
                decision: Ok(ApprovalDecision::Approve),
                prompt: None,
            };
            assert!(matches!(
                run_with_clock(
                    &fixture,
                    fixture.sign_request.clone(),
                    &mut approval,
                    &mut times.into_iter(),
                    &mut || None,
                ),
                DaemonOutcome::Rejected {
                    failure: FailureClass::InvalidRequest,
                    ..
                }
            ));
            assert!(approval.prompt.is_some());
        }
    }

    #[test]
    fn fido_provider_rejects_a_non_hardware_public_key() {
        let participant = ParticipantRequest {
            provider: RecoveryParticipantKeyProvider::Fido2,
            signing_reference: PathBuf::from("/does/not/matter"),
            public_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBtzXl/UCZTFJSe+DcBFF1ZP/sA7qB1xXbsTVhzpNVt6"
                    .to_owned(),
            expected_root_sha256: [0; 32],
            expected_policy_version: 1,
            expected_policy_sha256: [0; 32],
            expected_policy_threshold: 2,
            expected_previous_head_sequence: 0,
            expected_previous_head_sha256: None,
        };
        assert_eq!(
            validate_signing_reference(&participant),
            Err(FailureClass::SignerUnavailable)
        );
    }

    #[test]
    fn signing_reference_rejects_symlinks_and_permissive_private_files() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("key");
        fs::write(&key, b"not secret test material").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let participant = ParticipantRequest {
            provider: RecoveryParticipantKeyProvider::OpensshFile,
            signing_reference: key.clone(),
            public_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBtzXl/UCZTFJSe+DcBFF1ZP/sA7qB1xXbsTVhzpNVt6"
                    .to_owned(),
            expected_root_sha256: [0; 32],
            expected_policy_version: 1,
            expected_policy_sha256: [0; 32],
            expected_policy_threshold: 2,
            expected_previous_head_sequence: 0,
            expected_previous_head_sha256: None,
        };
        assert_eq!(
            validate_signing_reference(&participant),
            Err(FailureClass::SignerUnavailable)
        );

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("link");
        symlink(&key, &link).unwrap();
        assert_eq!(
            validate_signing_reference(&ParticipantRequest {
                signing_reference: link,
                ..participant
            }),
            Err(FailureClass::SignerUnavailable)
        );
    }

    impl CeremonyFixture {
        fn received(&self, request: SignRequest, bytes: &[u8]) -> ReceivedSignRequest {
            let snapshot =
                snapshot_stream(Cursor::new(bytes), MAX_RECOVERY_PARTICIPATION_REQUEST_BYTES)
                    .unwrap();
            ReceivedSignRequest {
                request,
                input: snapshot.into_file().into(),
                peer: PeerCredentials {
                    pid: rustix::process::getpid().as_raw_pid(),
                    uid: rustix::process::getuid().as_raw(),
                    gid: rustix::process::getgid().as_raw(),
                },
            }
        }
    }

    fn run_with_clock(
        fixture: &CeremonyFixture,
        request: SignRequest,
        approval: &mut dyn ApprovalBackend,
        times: &mut impl Iterator<Item = i64>,
        interrupted: &mut impl FnMut() -> Option<FailureClass>,
    ) -> DaemonOutcome {
        process_with_clock(
            Uuid::new_v4(),
            request,
            fixture
                .received(fixture.sign_request.clone(), &fixture.request_bytes)
                .input,
            PeerCredentials {
                pid: rustix::process::getpid().as_raw_pid(),
                uid: rustix::process::getuid().as_raw(),
                gid: rustix::process::getgid().as_raw(),
            },
            approval,
            interrupted,
            &mut || times.next().ok_or(()),
        )
    }

    fn ceremony_fixture() -> CeremonyFixture {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let online = key(directory.path(), "online");
        let next = key(directory.path(), "next");
        let participant = key(directory.path(), "authority-one");
        let authority_two = key(directory.path(), "authority-two");
        let authority_three = key(directory.path(), "authority-three");
        let outsider = key(directory.path(), "outsider");
        let now = current_unix_time().unwrap();
        let expires_at = now + 300;

        let root_statement =
            new_persona_root_statement("Juniper Quill", now - 20, &online.public).unwrap();
        let root_proof =
            create_persona_root_proof(root_statement, &online.private, &online.public).unwrap();
        let root = verify_persona_root_proof(&root_proof).unwrap();
        let authority_signers = vec![
            participant.signer(),
            authority_two.signer(),
            authority_three.signer(),
        ];
        let policy_statement = new_initial_recovery_policy_statement(
            &root,
            &authority_signers
                .iter()
                .map(|signer| signer.public_key.clone())
                .collect::<Vec<_>>(),
            2,
            RecoveryContinuityCheckpoint {
                transition_sequence: 0,
                transition_sha256: None,
            },
            now - 10,
            now + 3_600,
        )
        .unwrap();
        let policy_proof =
            create_initial_recovery_policy_proof(policy_statement, &authority_signers).unwrap();
        let policy = verify_initial_recovery_policy_proof(&root, &policy_proof).unwrap();
        let statement = new_recovery_transition_ceremony_statement(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &next.public,
            &policy,
            now - 1,
            expires_at,
            RecoveryTransitionReason::Recovery,
        )
        .unwrap();
        let request = new_recovery_ceremony_request(
            root_proof,
            vec![policy_proof],
            Vec::new(),
            root.root_statement_sha256.clone(),
            policy.policy_statement_sha256.clone(),
            PersonaContinuityCheckpoint {
                transition_sequence: 0,
                transition_sha256: None,
            },
            statement,
            next.public,
        )
        .unwrap();
        let request_bytes =
            a_quo_core::canonical_recovery_ceremony_request_bytes(&request).unwrap();
        let sign_request = SignRequest::new_recovery_participation(
            RecoveryParticipantKeyProvider::OpensshFile,
            participant.private.to_string_lossy(),
            participant.public.clone(),
            decode_sha256(&root.root_statement_sha256).unwrap(),
            policy.statement.policy_version,
            decode_sha256(&policy.policy_statement_sha256).unwrap(),
            policy.statement.threshold,
            0,
            None,
        )
        .unwrap();
        CeremonyFixture {
            _directory: directory,
            request_bytes,
            sign_request,
            participant,
            outsider,
            now,
            expires_at,
        }
    }

    fn key(directory: &Path, name: &str) -> TestKey {
        let private = directory.join(name);
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&private)
            .status()
            .unwrap();
        assert!(status.success());
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
        let public_file = fs::read_to_string(private.with_extension("pub")).unwrap();
        let mut fields = public_file.split_whitespace();
        let public = format!(
            "{} {}",
            fields.next().expect("test public-key algorithm"),
            fields.next().expect("test public-key blob")
        );
        TestKey { private, public }
    }
}
