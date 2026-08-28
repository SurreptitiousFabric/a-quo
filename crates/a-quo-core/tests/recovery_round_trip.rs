use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use a_quo_core::{
    EvidenceStatus, MAX_CONTINUITY_TRANSITIONS, PERSONA_TRANSITION_NAMESPACE,
    PersonaContinuityTransitionProof, RECOVERY_POLICY_ENROLLMENT_NAMESPACE,
    RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE, RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE,
    RECOVERY_TRANSITION_AUTHORITY_NAMESPACE, RECOVERY_TRANSITION_NEXT_NAMESPACE,
    RecoveryContinuityCheckpoint, RecoveryPolicyTimeStatus, RecoverySigner,
    RecoveryTransitionReason, create_initial_recovery_policy_proof, create_persona_root_proof,
    create_recovery_policy_update_proof, create_recovery_transition_proof,
    create_routine_transition_proof, new_initial_recovery_policy_statement,
    new_persona_root_statement, new_recovery_policy_update_statement,
    new_recovery_transition_statement, new_routine_transition_statement,
    verify_initial_recovery_policy_proof, verify_persona_continuity_chain_with_recovery,
    verify_persona_root_proof, verify_recovery_policy_chain, verify_recovery_policy_update_proof,
    verify_recovery_transition_proof,
};
use tempfile::tempdir;

const START: i64 = 1_700_000_000;

#[test]
fn threshold_recovery_can_be_followed_by_routine_rotation() {
    let directory = tempdir().unwrap();
    let online_one = key(directory.path(), "online_one");
    let online_two = key(directory.path(), "online_two");
    let online_three = key(directory.path(), "online_three");
    let authority_one = key(directory.path(), "authority_one");
    let authority_two = key(directory.path(), "authority_two");
    let authority_three = key(directory.path(), "authority_three");

    let root_statement =
        new_persona_root_statement("Recovered publisher", START, &online_one.public).unwrap();
    let root_proof =
        create_persona_root_proof(root_statement, &online_one.private, &online_one.public).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();

    let authorities = vec![
        authority_one.signer(),
        authority_two.signer(),
        authority_three.signer(),
    ];
    assert!(
        new_initial_recovery_policy_statement(
            &root,
            &public_keys(&authorities),
            2,
            RecoveryContinuityCheckpoint {
                transition_sequence: u32::try_from(MAX_CONTINUITY_TRANSITIONS).unwrap() + 1,
                transition_sha256: Some("0".repeat(64)),
            },
            START + 10,
            START + 10_000,
        )
        .is_err()
    );
    let policy_statement = new_initial_recovery_policy_statement(
        &root,
        &public_keys(&authorities),
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        },
        START + 10,
        START + 10_000,
    )
    .unwrap();
    let policy_proof =
        create_initial_recovery_policy_proof(policy_statement, &authorities).unwrap();
    let policy = verify_initial_recovery_policy_proof(&root, &policy_proof).unwrap();
    let policy_report = verify_recovery_policy_chain(
        &root_proof,
        std::slice::from_ref(&policy_proof),
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        START + 20,
    )
    .unwrap();
    assert_eq!(policy_report.enrollment_proof, EvidenceStatus::Verified);
    assert_eq!(policy_report.threshold, 2);
    assert_eq!(policy_report.authority_count, 3);
    assert_eq!(policy_report.latest_checkpoint_sequence, 0);
    assert_eq!(
        policy_report.checkpoint_against_transition_chain,
        "not_checked_without_transition_chain"
    );
    assert_eq!(policy_report.time_status, RecoveryPolicyTimeStatus::Active);
    let enrollment_signatures = match &policy_proof.authorization {
        a_quo_core::RecoveryPolicyAuthorization::Enrollment { signatures } => signatures,
        _ => panic!("initial policy used update authorization"),
    };
    assert!(
        enrollment_signatures
            .iter()
            .all(|signature| { signature.namespace == RECOVERY_POLICY_ENROLLMENT_NAMESPACE })
    );

    let recovery_statement = new_recovery_transition_statement(
        &root,
        1,
        None,
        &root.statement.initial_key_fingerprint,
        &online_two.public,
        &policy,
        START + 30,
        RecoveryTransitionReason::Compromise,
    )
    .unwrap();
    let recovery_proof = create_recovery_transition_proof(
        recovery_statement,
        &policy,
        &authorities[..2],
        &online_two.private,
        &online_two.public,
    )
    .unwrap();
    assert!(
        recovery_proof
            .recovery_signatures
            .iter()
            .all(|signature| { signature.namespace == RECOVERY_TRANSITION_AUTHORITY_NAMESPACE })
    );
    assert_eq!(
        recovery_proof.next_signature.namespace,
        RECOVERY_TRANSITION_NEXT_NAMESPACE
    );
    let recovered = verify_recovery_transition_proof(&root, &policy, &recovery_proof).unwrap();
    assert_eq!(recovered.recovery_signer_fingerprints.len(), 2);

    let routine_statement = new_routine_transition_statement(
        &root,
        2,
        Some(&recovered.transition_statement_sha256),
        &online_two.public,
        &online_three.public,
        START + 40,
    )
    .unwrap();
    let routine_proof = create_routine_transition_proof(
        routine_statement,
        &online_two.private,
        &online_two.public,
        &online_three.private,
        &online_three.public,
    )
    .unwrap();
    assert!(
        routine_proof
            .signatures
            .iter()
            .all(|signature| signature.namespace == PERSONA_TRANSITION_NAMESPACE)
    );

    let transitions = vec![
        PersonaContinuityTransitionProof::Recovery(recovery_proof.clone()),
        PersonaContinuityTransitionProof::Routine(routine_proof),
    ];
    let report = verify_persona_continuity_chain_with_recovery(
        &root_proof,
        &transitions,
        std::slice::from_ref(&policy_proof),
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        START + 50,
    )
    .unwrap();
    assert_eq!(report.transition_chain, EvidenceStatus::Verified);
    assert_eq!(
        report.policy_transition_checkpoints,
        EvidenceStatus::Verified
    );
    assert_eq!(report.recovery_transition_count, 1);
    assert_eq!(report.routine_transition_count, 1);
    assert_eq!(report.transition_count, 2);
    assert_eq!(
        report.current_key_fingerprint,
        a_quo_core::public_key_fingerprint(&online_three.public).unwrap()
    );

    let mut too_few = recovery_proof.clone();
    too_few.recovery_signatures.pop();
    assert!(verify_recovery_transition_proof(&root, &policy, &too_few).is_err());

    let mut duplicate = recovery_proof.clone();
    duplicate.recovery_signatures[1] = duplicate.recovery_signatures[0].clone();
    assert!(verify_recovery_transition_proof(&root, &policy, &duplicate).is_err());

    let mut wrong_namespace = recovery_proof.clone();
    wrong_namespace.recovery_signatures[0].namespace =
        RECOVERY_POLICY_ENROLLMENT_NAMESPACE.to_owned();
    assert!(verify_recovery_transition_proof(&root, &policy, &wrong_namespace).is_err());

    assert!(
        new_recovery_transition_statement(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &online_two.public,
            &policy,
            policy.statement.expires_at,
            RecoveryTransitionReason::Recovery,
        )
        .is_err()
    );
    assert!(
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &transitions,
            std::slice::from_ref(&policy_proof),
            &root.root_statement_sha256,
            &"0".repeat(64),
            START + 50,
        )
        .is_err()
    );
}

#[test]
fn policy_updates_need_old_and_new_thresholds_and_supersede_old_recovery() {
    let directory = tempdir().unwrap();
    let online_one = key(directory.path(), "online_one");
    let online_two = key(directory.path(), "online_two");
    let online_three = key(directory.path(), "online_three");
    let authority_one = key(directory.path(), "authority_one");
    let authority_two = key(directory.path(), "authority_two");
    let authority_three = key(directory.path(), "authority_three");
    let authority_four = key(directory.path(), "authority_four");

    let root_statement =
        new_persona_root_statement("Policy publisher", START, &online_one.public).unwrap();
    let root_proof =
        create_persona_root_proof(root_statement, &online_one.private, &online_one.public).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();
    let initial_signers = vec![
        authority_one.signer(),
        authority_two.signer(),
        authority_three.signer(),
    ];
    let initial_statement = new_initial_recovery_policy_statement(
        &root,
        &public_keys(&initial_signers),
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        },
        START + 10,
        START + 10_000,
    )
    .unwrap();
    let initial_proof =
        create_initial_recovery_policy_proof(initial_statement, &initial_signers).unwrap();
    let initial = verify_initial_recovery_policy_proof(&root, &initial_proof).unwrap();

    let historical_statement = new_recovery_transition_statement(
        &root,
        1,
        None,
        &root.statement.initial_key_fingerprint,
        &online_two.public,
        &initial,
        START + 50,
        RecoveryTransitionReason::Recovery,
    )
    .unwrap();
    let historical_proof = create_recovery_transition_proof(
        historical_statement,
        &initial,
        &initial_signers[..2],
        &online_two.private,
        &online_two.public,
    )
    .unwrap();
    let historical = verify_recovery_transition_proof(&root, &initial, &historical_proof).unwrap();

    let current_signers = vec![
        authority_two.signer(),
        authority_three.signer(),
        authority_four.signer(),
    ];
    let false_checkpoint_statement = new_recovery_policy_update_statement(
        &initial,
        &public_keys(&current_signers),
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 1,
            transition_sha256: Some("0".repeat(64)),
        },
        START + 100,
        START + 20_000,
    )
    .unwrap();
    let false_checkpoint_proof = create_recovery_policy_update_proof(
        false_checkpoint_statement,
        &initial,
        &initial_signers[..2],
        &current_signers,
    )
    .unwrap();
    let false_checkpoint =
        verify_recovery_policy_update_proof(&root, &initial, &false_checkpoint_proof).unwrap();
    assert!(
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &[PersonaContinuityTransitionProof::Recovery(
                historical_proof.clone(),
            )],
            &[initial_proof.clone(), false_checkpoint_proof],
            &root.root_statement_sha256,
            &false_checkpoint.policy_statement_sha256,
            START + 101,
        )
        .is_err()
    );

    let update_statement = new_recovery_policy_update_statement(
        &initial,
        &public_keys(&current_signers),
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 1,
            transition_sha256: Some(historical.transition_statement_sha256.clone()),
        },
        START + 100,
        START + 20_000,
    )
    .unwrap();
    let update_proof = create_recovery_policy_update_proof(
        update_statement,
        &initial,
        &initial_signers[..2],
        &current_signers,
    )
    .unwrap();
    let updated = verify_recovery_policy_update_proof(&root, &initial, &update_proof).unwrap();
    let (previous_signatures, current_signatures) = match &update_proof.authorization {
        a_quo_core::RecoveryPolicyAuthorization::Update {
            previous_policy_signatures,
            current_policy_signatures,
        } => (previous_policy_signatures, current_policy_signatures),
        _ => panic!("policy update used enrollment authorization"),
    };
    assert!(
        previous_signatures
            .iter()
            .all(|signature| { signature.namespace == RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE })
    );
    assert!(
        current_signatures
            .iter()
            .all(|signature| { signature.namespace == RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE })
    );

    let policy_chain = vec![initial_proof.clone(), update_proof.clone()];
    let report = verify_recovery_policy_chain(
        &root_proof,
        &policy_chain,
        &root.root_statement_sha256,
        &updated.policy_statement_sha256,
        START + 101,
    )
    .unwrap();
    assert_eq!(report.latest_policy_version, 2);
    assert_eq!(report.update_chain, EvidenceStatus::Verified);
    assert_eq!(report.latest_checkpoint_sequence, 1);

    let historical_report = verify_persona_continuity_chain_with_recovery(
        &root_proof,
        &[PersonaContinuityTransitionProof::Recovery(
            historical_proof.clone(),
        )],
        &policy_chain,
        &root.root_statement_sha256,
        &updated.policy_statement_sha256,
        START + 101,
    )
    .unwrap();
    assert_eq!(
        historical_report.policy_transition_checkpoints,
        EvidenceStatus::Verified
    );
    assert_eq!(historical_report.latest_policy_checkpoint_sequence, 1);

    let colliding_signers = vec![
        authority_two.signer(),
        authority_three.signer(),
        online_two.signer(),
    ];
    let colliding_statement = new_recovery_policy_update_statement(
        &initial,
        &public_keys(&colliding_signers),
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 1,
            transition_sha256: Some(historical.transition_statement_sha256.clone()),
        },
        START + 100,
        START + 20_000,
    )
    .unwrap();
    let colliding_proof = create_recovery_policy_update_proof(
        colliding_statement,
        &initial,
        &initial_signers[..2],
        &colliding_signers,
    )
    .unwrap();
    let colliding = verify_recovery_policy_update_proof(&root, &initial, &colliding_proof).unwrap();
    assert!(
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &[PersonaContinuityTransitionProof::Recovery(
                historical_proof.clone(),
            )],
            &[initial_proof.clone(), colliding_proof],
            &root.root_statement_sha256,
            &colliding.policy_statement_sha256,
            START + 101,
        )
        .is_err()
    );

    let mut missing_previous = update_proof.clone();
    match &mut missing_previous.authorization {
        a_quo_core::RecoveryPolicyAuthorization::Update {
            previous_policy_signatures,
            ..
        } => {
            previous_policy_signatures.pop();
        }
        _ => unreachable!(),
    }
    assert!(verify_recovery_policy_update_proof(&root, &initial, &missing_previous).is_err());

    assert!(
        new_recovery_policy_update_statement(
            &updated,
            &public_keys(&current_signers),
            2,
            RecoveryContinuityCheckpoint {
                transition_sequence: 0,
                transition_sha256: None,
            },
            START + 200,
            START + 30_000,
        )
        .is_err()
    );

    let stale_statement = new_recovery_transition_statement(
        &root,
        2,
        Some(&historical.transition_statement_sha256),
        &a_quo_core::public_key_fingerprint(&online_two.public).unwrap(),
        &online_three.public,
        &initial,
        START + 110,
        RecoveryTransitionReason::Recovery,
    )
    .unwrap();
    let stale_proof = create_recovery_transition_proof(
        stale_statement,
        &initial,
        &initial_signers[..2],
        &online_three.private,
        &online_three.public,
    )
    .unwrap();
    verify_recovery_transition_proof(&root, &initial, &stale_proof).unwrap();
    assert!(
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &[
                PersonaContinuityTransitionProof::Recovery(historical_proof),
                PersonaContinuityTransitionProof::Recovery(stale_proof),
            ],
            &policy_chain,
            &root.root_statement_sha256,
            &updated.policy_statement_sha256,
            START + 120,
        )
        .is_err()
    );
}

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

fn public_keys(signers: &[RecoverySigner]) -> Vec<String> {
    signers
        .iter()
        .map(|signer| signer.public_key.clone())
        .collect()
}

fn key(directory: &Path, name: &str) -> TestKey {
    let private = directory.join(name);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&private)
        .status()
        .expect("OpenSSH ssh-keygen must be installed for the integration test");
    assert!(status.success());
    let public = fs::read_to_string(private.with_extension("pub"))
        .unwrap()
        .trim()
        .to_owned();
    TestKey { private, public }
}
