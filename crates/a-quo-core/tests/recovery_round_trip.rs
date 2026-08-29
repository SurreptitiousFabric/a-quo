use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;

use a_quo_core::{
    EvidenceStatus, MAX_CONTINUITY_TRANSITIONS, PERSONA_TRANSITION_NAMESPACE,
    PersonaContinuityCheckpoint, PersonaContinuityTransitionProof,
    RECOVERY_POLICY_ENROLLMENT_NAMESPACE, RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE,
    RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE, RECOVERY_TRANSITION_AUTHORITY_NAMESPACE,
    RECOVERY_TRANSITION_NEXT_NAMESPACE, RecoveryContinuityCheckpoint, RecoveryPolicyCapability,
    RecoveryPolicyTimeStatus, RecoverySigner, RecoveryTransitionReason,
    TERMINAL_PERSONA_REVOCATION_AUTHORITY_NAMESPACE, TERMINAL_PERSONA_REVOCATION_EFFECT,
    TerminalPersonaRevocationReason, VerifiedPersonaContinuityTransition,
    canonical_recovery_policy_statement_bytes,
    canonical_terminal_persona_revocation_statement_bytes, create_initial_recovery_policy_proof,
    create_persona_root_proof, create_recovery_policy_update_proof,
    create_recovery_transition_proof, create_routine_transition_proof,
    create_terminal_persona_revocation_proof, inspect_terminal_persona_revocation_proof,
    new_initial_recovery_policy_statement, new_initial_recovery_policy_statement_with_capabilities,
    new_persona_root_statement, new_recovery_policy_update_statement,
    new_recovery_policy_update_statement_with_capabilities, new_recovery_transition_statement,
    new_routine_transition_statement, new_terminal_persona_revocation_statement,
    parse_persona_continuity_transition_proof_bytes, parse_terminal_persona_revocation_proof_bytes,
    terminal_persona_revocation_statement_sha256,
    validate_verified_recovery_aware_continuity_chain_extension,
    validate_verified_recovery_aware_continuity_chain_routine_extension,
    validate_verified_recovery_aware_continuity_chain_terminal_revocation_extension,
    verify_initial_recovery_policy_proof, verify_persona_continuity_chain_with_recovery,
    verify_persona_continuity_chain_with_recovery_at_checkpoint,
    verify_persona_continuity_chain_with_recovery_with_verified_sequence,
    verify_persona_root_proof, verify_persona_transition_proof_with_receipt,
    verify_recovery_policy_chain, verify_recovery_policy_chain_with_verified_sequence,
    verify_recovery_policy_update_proof, verify_recovery_transition_proof,
    verify_recovery_transition_proof_with_receipt, verify_terminal_persona_revocation_proof,
    verify_terminal_persona_revocation_proof_with_receipt,
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
    let authority_four = key(directory.path(), "authority_four");

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
    let verified_policy_chain = verify_recovery_policy_chain_with_verified_sequence(
        &root_proof,
        std::slice::from_ref(&policy_proof),
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        START + 20,
    )
    .unwrap();
    assert_eq!(verified_policy_chain.root(), &root);
    assert_eq!(
        verified_policy_chain.policies(),
        std::slice::from_ref(&policy)
    );
    assert_eq!(verified_policy_chain.report().checked_at, START + 20);
    let (reported_root, reported_policies, policy_report) = verified_policy_chain.into_parts();
    assert_eq!(reported_root, root);
    assert_eq!(reported_policies, vec![policy.clone()]);
    assert_eq!(policy_report.enrollment_proof, EvidenceStatus::Verified);
    assert_eq!(policy_report.threshold, 2);
    assert_eq!(policy_report.authority_count, 3);
    assert_eq!(policy_report.latest_checkpoint_sequence, 0);
    assert_eq!(
        policy_report.checkpoint_against_transition_chain,
        "not_checked_without_transition_chain"
    );
    assert_eq!(policy_report.time_status, RecoveryPolicyTimeStatus::Active);
    let empty_verified_chain =
        verify_persona_continuity_chain_with_recovery_with_verified_sequence(
            &root_proof,
            &[],
            std::slice::from_ref(&policy_proof),
            &root.root_statement_sha256,
            &policy.policy_statement_sha256,
            START + 20,
        )
        .unwrap();
    assert_eq!(empty_verified_chain.root(), &root);
    assert_eq!(
        empty_verified_chain.policies(),
        std::slice::from_ref(&policy)
    );
    assert!(empty_verified_chain.transitions().is_empty());
    assert_eq!(empty_verified_chain.report().transition_count, 0);
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
    let recovery_receipt =
        verify_recovery_transition_proof_with_receipt(&root, &policy, &recovery_proof).unwrap();
    let recovered = verify_recovery_transition_proof(&root, &policy, &recovery_proof).unwrap();
    assert_eq!(recovery_receipt.transition(), &recovered);
    assert_eq!(recovered.recovery_signer_fingerprints.len(), 2);
    validate_verified_recovery_aware_continuity_chain_extension(
        &empty_verified_chain,
        &recovery_receipt,
    )
    .unwrap();

    let forged_authorities = vec![authority_one.signer(), authority_four.signer()];
    let forged_policy_statement = new_initial_recovery_policy_statement(
        &root,
        &public_keys(&forged_authorities),
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        },
        START + 10,
        START + 10_000,
    )
    .unwrap();
    let forged_policy_proof =
        create_initial_recovery_policy_proof(forged_policy_statement, &forged_authorities).unwrap();
    let mut forged_policy =
        verify_initial_recovery_policy_proof(&root, &forged_policy_proof).unwrap();
    forged_policy.policy_statement_sha256 = policy.policy_statement_sha256.clone();
    let forged_recovery_statement = new_recovery_transition_statement(
        &root,
        1,
        None,
        &root.statement.initial_key_fingerprint,
        &online_two.public,
        &forged_policy,
        START + 30,
        RecoveryTransitionReason::Compromise,
    )
    .unwrap();
    let forged_recovery_proof = create_recovery_transition_proof(
        forged_recovery_statement,
        &forged_policy,
        &forged_authorities,
        &online_two.private,
        &online_two.public,
    )
    .unwrap();
    let forged_receipt = verify_recovery_transition_proof_with_receipt(
        &root,
        &forged_policy,
        &forged_recovery_proof,
    )
    .unwrap();
    assert!(
        validate_verified_recovery_aware_continuity_chain_extension(
            &empty_verified_chain,
            &forged_receipt
        )
        .is_err()
    );

    let mut tampered_recovery_proof = recovery_proof.clone();
    tampered_recovery_proof.recovery_signatures[0].value = "tampered".to_owned();
    assert!(
        verify_recovery_transition_proof_with_receipt(&root, &policy, &tampered_recovery_proof)
            .is_err()
    );

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
    let routine_receipt = verify_persona_transition_proof_with_receipt(&routine_proof).unwrap();
    let recovered_verified_chain =
        verify_persona_continuity_chain_with_recovery_with_verified_sequence(
            &root_proof,
            &[PersonaContinuityTransitionProof::Recovery(
                recovery_proof.clone(),
            )],
            std::slice::from_ref(&policy_proof),
            &root.root_statement_sha256,
            &policy.policy_statement_sha256,
            START + 40,
        )
        .unwrap();
    validate_verified_recovery_aware_continuity_chain_routine_extension(
        &recovered_verified_chain,
        &routine_receipt,
    )
    .unwrap();

    let authority_collision_statement = new_routine_transition_statement(
        &root,
        2,
        Some(&recovered.transition_statement_sha256),
        &online_two.public,
        &authority_one.public,
        START + 40,
    )
    .unwrap();
    let authority_collision_proof = create_routine_transition_proof(
        authority_collision_statement,
        &online_two.private,
        &online_two.public,
        &authority_one.private,
        &authority_one.public,
    )
    .unwrap();
    let authority_collision_receipt =
        verify_persona_transition_proof_with_receipt(&authority_collision_proof).unwrap();
    assert!(
        validate_verified_recovery_aware_continuity_chain_routine_extension(
            &recovered_verified_chain,
            &authority_collision_receipt,
        )
        .is_err()
    );

    let wrong_link_statement = new_routine_transition_statement(
        &root,
        2,
        Some(&"0".repeat(64)),
        &online_two.public,
        &online_three.public,
        START + 40,
    )
    .unwrap();
    let wrong_link_proof = create_routine_transition_proof(
        wrong_link_statement,
        &online_two.private,
        &online_two.public,
        &online_three.private,
        &online_three.public,
    )
    .unwrap();
    let wrong_link_receipt =
        verify_persona_transition_proof_with_receipt(&wrong_link_proof).unwrap();
    assert!(
        validate_verified_recovery_aware_continuity_chain_routine_extension(
            &recovered_verified_chain,
            &wrong_link_receipt,
        )
        .is_err()
    );

    let mut tampered_routine_proof = routine_proof.clone();
    tampered_routine_proof.signatures[0].value = "tampered".to_owned();
    assert!(verify_persona_transition_proof_with_receipt(&tampered_routine_proof).is_err());
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
    let verified_chain = verify_persona_continuity_chain_with_recovery_with_verified_sequence(
        &root_proof,
        &transitions,
        std::slice::from_ref(&policy_proof),
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        START + 50,
    )
    .unwrap();
    assert_eq!(verified_chain.report(), &report);
    assert!(matches!(
        verified_chain.transitions(),
        [
            VerifiedPersonaContinuityTransition::Recovery(_),
            VerifiedPersonaContinuityTransition::Routine(_)
        ]
    ));
    assert!(
        validate_verified_recovery_aware_continuity_chain_extension(
            &verified_chain,
            &recovery_receipt
        )
        .is_err()
    );
    assert!(
        validate_verified_recovery_aware_continuity_chain_routine_extension(
            &verified_chain,
            &routine_receipt,
        )
        .is_err()
    );
    assert_eq!(report.transition_chain, EvidenceStatus::Verified);
    assert_eq!(
        report.policy_transition_checkpoints,
        EvidenceStatus::Verified
    );
    assert_eq!(report.recovery_transition_count, 1);
    assert_eq!(report.routine_transition_count, 1);
    assert_eq!(report.transition_count, 2);
    assert_eq!(
        report.chain_tip_key_fingerprint,
        a_quo_core::public_key_fingerprint(&online_three.public).unwrap()
    );
    let expected_head = PersonaContinuityCheckpoint {
        transition_sequence: report.transition_count,
        transition_sha256: report.last_transition_sha256.clone(),
    };
    let checkpoint_report = verify_persona_continuity_chain_with_recovery_at_checkpoint(
        &root_proof,
        &transitions,
        std::slice::from_ref(&policy_proof),
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        START + 50,
        &expected_head,
    )
    .unwrap();
    assert_eq!(
        checkpoint_report.expected_head_checkpoint,
        Some(EvidenceStatus::Verified)
    );
    assert!(
        checkpoint_report.not_established.contains(
            &"whether_a_competing_transition_or_policy_branch_was_also_authorized_or_withheld"
                .to_owned()
        )
    );
    assert!(
        verify_persona_continuity_chain_with_recovery_at_checkpoint(
            &root_proof,
            &transitions[..1],
            std::slice::from_ref(&policy_proof),
            &root.root_statement_sha256,
            &policy.policy_statement_sha256,
            START + 50,
            &expected_head,
        )
        .is_err()
    );
    let wrong_head = PersonaContinuityCheckpoint {
        transition_sequence: report.transition_count,
        transition_sha256: Some("0".repeat(64)),
    };
    assert!(
        verify_persona_continuity_chain_with_recovery_at_checkpoint(
            &root_proof,
            &transitions,
            std::slice::from_ref(&policy_proof),
            &root.root_statement_sha256,
            &policy.policy_statement_sha256,
            START + 50,
            &wrong_head,
        )
        .is_err()
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
    let current_chain = verify_persona_continuity_chain_with_recovery_with_verified_sequence(
        &root_proof,
        &[PersonaContinuityTransitionProof::Recovery(
            historical_proof.clone(),
        )],
        &policy_chain,
        &root.root_statement_sha256,
        &updated.policy_statement_sha256,
        START + 120,
    )
    .unwrap();
    let stale_receipt =
        verify_recovery_transition_proof_with_receipt(&root, &initial, &stale_proof).unwrap();
    assert!(
        validate_verified_recovery_aware_continuity_chain_extension(&current_chain, &stale_receipt)
            .is_err()
    );
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

#[test]
fn terminal_revocation_is_explicit_threshold_authority_and_a_final_leaf() {
    let directory = tempdir().unwrap();
    let online_one = key(directory.path(), "terminal_online_one");
    let online_two = key(directory.path(), "terminal_online_two");
    let authority_one = key(directory.path(), "terminal_authority_one");
    let authority_two = key(directory.path(), "terminal_authority_two");

    let root_statement =
        new_persona_root_statement("Terminal publisher", START, &online_one.public).unwrap();
    let root_proof =
        create_persona_root_proof(root_statement, &online_one.private, &online_one.public).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();
    let authorities = vec![authority_one.signer(), authority_two.signer()];
    let authority_public_keys = public_keys(&authorities);

    // The old constructor remains byte-for-byte schema-v1 compatible and
    // cannot silently gain terminal authority.
    let v1_statement = new_initial_recovery_policy_statement(
        &root,
        &authority_public_keys,
        2,
        root_checkpoint(),
        START + 5,
        START + 10_000,
    )
    .unwrap();
    assert_eq!(
        canonical_recovery_policy_statement_bytes(&v1_statement).unwrap(),
        legacy_v1_policy_statement_bytes(&v1_statement),
    );
    assert!(v1_statement.capabilities.is_empty());
    assert!(v1_statement.authorizes(RecoveryPolicyCapability::KeyRecovery));
    assert!(!v1_statement.authorizes(RecoveryPolicyCapability::TerminalRevocation));
    assert_eq!(
        v1_statement.effective_capabilities(),
        vec![RecoveryPolicyCapability::KeyRecovery]
    );
    let v1_policy_proof = create_initial_recovery_policy_proof(v1_statement, &authorities).unwrap();
    let v1_policy = verify_initial_recovery_policy_proof(&root, &v1_policy_proof).unwrap();
    assert!(
        new_terminal_persona_revocation_statement(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &v1_policy,
            START + 30,
            TerminalPersonaRevocationReason::Cessation,
        )
        .is_err()
    );

    assert!(
        new_initial_recovery_policy_statement_with_capabilities(
            &root,
            &authority_public_keys,
            2,
            &[],
            root_checkpoint(),
            START + 10,
            START + 10_000,
        )
        .is_err()
    );
    assert!(
        new_initial_recovery_policy_statement_with_capabilities(
            &root,
            &authority_public_keys,
            2,
            &[
                RecoveryPolicyCapability::KeyRecovery,
                RecoveryPolicyCapability::KeyRecovery,
            ],
            root_checkpoint(),
            START + 10,
            START + 10_000,
        )
        .is_err()
    );

    let initial_statement = new_initial_recovery_policy_statement_with_capabilities(
        &root,
        &authority_public_keys,
        2,
        &[
            RecoveryPolicyCapability::TerminalRevocation,
            RecoveryPolicyCapability::KeyRecovery,
        ],
        root_checkpoint(),
        START + 10,
        START + 10_000,
    )
    .unwrap();
    assert_eq!(
        initial_statement.capabilities,
        vec![
            RecoveryPolicyCapability::KeyRecovery,
            RecoveryPolicyCapability::TerminalRevocation,
        ]
    );
    let mut unsorted_statement = initial_statement.clone();
    unsorted_statement.capabilities.reverse();
    assert!(create_initial_recovery_policy_proof(unsorted_statement, &authorities).is_err());
    let initial_proof =
        create_initial_recovery_policy_proof(initial_statement, &authorities).unwrap();
    let initial = verify_initial_recovery_policy_proof(&root, &initial_proof).unwrap();

    // Once a policy chain opts into v2, the legacy constructor cannot create
    // an implicit-capability v1 successor.
    assert!(
        new_recovery_policy_update_statement(
            &initial,
            &authority_public_keys,
            2,
            root_checkpoint(),
            START + 20,
            START + 20_000,
        )
        .is_err()
    );
    let current_statement = new_recovery_policy_update_statement_with_capabilities(
        &initial,
        &authority_public_keys,
        2,
        &[
            RecoveryPolicyCapability::KeyRecovery,
            RecoveryPolicyCapability::TerminalRevocation,
        ],
        root_checkpoint(),
        START + 20,
        START + 20_000,
    )
    .unwrap();
    let current_proof = create_recovery_policy_update_proof(
        current_statement,
        &initial,
        &authorities,
        &authorities,
    )
    .unwrap();
    let current = verify_recovery_policy_update_proof(&root, &initial, &current_proof).unwrap();
    let policy_chain = vec![initial_proof.clone(), current_proof.clone()];

    // Each v2 capability is enforced independently.
    let key_only_statement = new_initial_recovery_policy_statement_with_capabilities(
        &root,
        &authority_public_keys,
        2,
        &[RecoveryPolicyCapability::KeyRecovery],
        root_checkpoint(),
        START + 6,
        START + 10_000,
    )
    .unwrap();
    let key_only_proof =
        create_initial_recovery_policy_proof(key_only_statement, &authorities).unwrap();
    let key_only = verify_initial_recovery_policy_proof(&root, &key_only_proof).unwrap();
    assert!(
        new_terminal_persona_revocation_statement(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &key_only,
            START + 30,
            TerminalPersonaRevocationReason::Cessation,
        )
        .is_err()
    );
    let terminal_only_statement = new_initial_recovery_policy_statement_with_capabilities(
        &root,
        &authority_public_keys,
        2,
        &[RecoveryPolicyCapability::TerminalRevocation],
        root_checkpoint(),
        START + 7,
        START + 10_000,
    )
    .unwrap();
    let terminal_only_proof =
        create_initial_recovery_policy_proof(terminal_only_statement, &authorities).unwrap();
    let terminal_only = verify_initial_recovery_policy_proof(&root, &terminal_only_proof).unwrap();
    assert!(
        new_recovery_transition_statement(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &online_two.public,
            &terminal_only,
            START + 30,
            RecoveryTransitionReason::Recovery,
        )
        .is_err()
    );

    let stale_terminal_statement = new_terminal_persona_revocation_statement(
        &root,
        1,
        None,
        &root.statement.initial_key_fingerprint,
        &initial,
        START + 30,
        TerminalPersonaRevocationReason::Cessation,
    )
    .unwrap();
    let stale_terminal_proof =
        create_terminal_persona_revocation_proof(stale_terminal_statement, &initial, &authorities)
            .unwrap();
    verify_terminal_persona_revocation_proof(&root, &initial, &stale_terminal_proof).unwrap();
    assert!(
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &[PersonaContinuityTransitionProof::TerminalRevocation(
                stale_terminal_proof,
            )],
            &policy_chain,
            &root.root_statement_sha256,
            &current.policy_statement_sha256,
            START + 40,
        )
        .is_err()
    );

    assert!(
        new_terminal_persona_revocation_statement(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &current,
            current.statement.issued_at - 1,
            TerminalPersonaRevocationReason::Cessation,
        )
        .is_err()
    );
    assert!(
        new_terminal_persona_revocation_statement(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &current,
            current.statement.expires_at,
            TerminalPersonaRevocationReason::Cessation,
        )
        .is_err()
    );
    let terminal_statement = new_terminal_persona_revocation_statement(
        &root,
        1,
        None,
        &root.statement.initial_key_fingerprint,
        &current,
        START + 30,
        TerminalPersonaRevocationReason::Cessation,
    )
    .unwrap();
    assert_eq!(
        terminal_statement.effect,
        TERMINAL_PERSONA_REVOCATION_EFFECT
    );
    assert_eq!(terminal_statement.recovery_policy_version, 2);
    assert_eq!(
        terminal_statement.recovery_policy_sha256,
        current.policy_statement_sha256
    );
    let terminal_statement_digest =
        terminal_persona_revocation_statement_sha256(&terminal_statement).unwrap();
    let terminal_proof = create_terminal_persona_revocation_proof(
        terminal_statement.clone(),
        &current,
        &authorities,
    )
    .unwrap();
    assert_eq!(terminal_proof.recovery_signatures.len(), 2);
    assert!(terminal_proof.recovery_signatures.iter().all(|signature| {
        signature.namespace == TERMINAL_PERSONA_REVOCATION_AUTHORITY_NAMESPACE
    }));
    let proof_json = serde_json::to_value(&terminal_proof).unwrap();
    assert!(proof_json.get("next_signature").is_none());
    let payload_json: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&terminal_proof.payload).unwrap()).unwrap();
    assert!(payload_json.get("next_key_fingerprint").is_none());

    let encoded_terminal_proof = serde_json::to_vec(&terminal_proof).unwrap();
    assert_eq!(
        parse_terminal_persona_revocation_proof_bytes(&encoded_terminal_proof).unwrap(),
        terminal_proof
    );
    assert!(matches!(
        parse_persona_continuity_transition_proof_bytes(&encoded_terminal_proof).unwrap(),
        PersonaContinuityTransitionProof::TerminalRevocation(_)
    ));
    assert_eq!(
        inspect_terminal_persona_revocation_proof(&terminal_proof).unwrap(),
        terminal_statement
    );

    let receipt =
        verify_terminal_persona_revocation_proof_with_receipt(&root, &current, &terminal_proof)
            .unwrap();
    let terminal =
        verify_terminal_persona_revocation_proof(&root, &current, &terminal_proof).unwrap();
    assert_eq!(receipt.revocation(), &terminal);
    assert_eq!(
        terminal.revocation_statement_sha256,
        terminal_statement_digest
    );
    assert_eq!(terminal.recovery_signer_fingerprints.len(), 2);

    let mut too_few = terminal_proof.clone();
    too_few.recovery_signatures.pop();
    assert!(verify_terminal_persona_revocation_proof(&root, &current, &too_few).is_err());
    let mut duplicate = terminal_proof.clone();
    duplicate.recovery_signatures[1] = duplicate.recovery_signatures[0].clone();
    assert!(verify_terminal_persona_revocation_proof(&root, &current, &duplicate).is_err());
    let mut wrong_namespace = terminal_proof.clone();
    wrong_namespace.recovery_signatures[0].namespace =
        RECOVERY_TRANSITION_AUTHORITY_NAMESPACE.to_owned();
    assert!(verify_terminal_persona_revocation_proof(&root, &current, &wrong_namespace).is_err());
    let mut tampered = terminal_proof.clone();
    let mut tampered_statement = terminal_statement.clone();
    tampered_statement.reason = TerminalPersonaRevocationReason::Compromise;
    tampered.payload = URL_SAFE_NO_PAD.encode(
        canonical_terminal_persona_revocation_statement_bytes(&tampered_statement).unwrap(),
    );
    assert!(verify_terminal_persona_revocation_proof(&root, &current, &tampered).is_err());

    let active_chain = verify_persona_continuity_chain_with_recovery_with_verified_sequence(
        &root_proof,
        &[],
        &policy_chain,
        &root.root_statement_sha256,
        &current.policy_statement_sha256,
        START + 40,
    )
    .unwrap();
    validate_verified_recovery_aware_continuity_chain_terminal_revocation_extension(
        &active_chain,
        &receipt,
    )
    .unwrap();

    let transitions = vec![PersonaContinuityTransitionProof::TerminalRevocation(
        terminal_proof.clone(),
    )];
    let terminal_chain = verify_persona_continuity_chain_with_recovery_with_verified_sequence(
        &root_proof,
        &transitions,
        &policy_chain,
        &root.root_statement_sha256,
        &current.policy_statement_sha256,
        START + 40,
    )
    .unwrap();
    assert!(matches!(
        terminal_chain.transitions(),
        [VerifiedPersonaContinuityTransition::TerminalRevocation(_)]
    ));
    let report = terminal_chain.report();
    assert_eq!(report.root_statement_sha256, root.root_statement_sha256);
    assert_eq!(report.latest_policy_sha256, current.policy_statement_sha256);
    assert_eq!(report.latest_policy_version, 2);
    assert_eq!(
        report.chain_tip_key_fingerprint,
        root.statement.initial_key_fingerprint
    );
    assert_eq!(report.current_key_fingerprint, None);
    assert!(report.terminally_revoked);
    assert_eq!(report.terminal_revocation_count, 1);
    assert_eq!(
        report.terminal_revocation_statement_sha256.as_deref(),
        Some(terminal_statement_digest.as_str())
    );
    assert_eq!(
        report.terminal_revoked_key_fingerprint.as_deref(),
        Some(root.statement.initial_key_fingerprint.as_str())
    );
    assert_eq!(
        report.terminal_revocation_reason,
        Some(TerminalPersonaRevocationReason::Cessation)
    );
    assert!(
        report
            .not_established
            .contains(&"legal_identity_or_guardian_independence".to_owned())
    );
    assert!(
        report
            .not_established
            .contains(&"whether_recovery_signers_are_distinct_people_or_devices".to_owned())
    );

    let checkpoint_report = verify_persona_continuity_chain_with_recovery_at_checkpoint(
        &root_proof,
        &transitions,
        &policy_chain,
        &root.root_statement_sha256,
        &current.policy_statement_sha256,
        START + 40,
        &PersonaContinuityCheckpoint {
            transition_sequence: 1,
            transition_sha256: Some(terminal_statement_digest.clone()),
        },
    )
    .unwrap();
    assert_eq!(
        checkpoint_report.expected_head_checkpoint,
        Some(EvidenceStatus::Verified)
    );
    assert!(
        !checkpoint_report.not_established.contains(
            &"whether_a_newer_transition_exists_after_the_expected_checkpoint".to_owned()
        )
    );

    let routine_successor_statement = new_routine_transition_statement(
        &root,
        2,
        Some(&terminal_statement_digest),
        &online_one.public,
        &online_two.public,
        START + 31,
    )
    .unwrap();
    let routine_successor_proof = create_routine_transition_proof(
        routine_successor_statement,
        &online_one.private,
        &online_one.public,
        &online_two.private,
        &online_two.public,
    )
    .unwrap();
    let routine_successor_receipt =
        verify_persona_transition_proof_with_receipt(&routine_successor_proof).unwrap();
    assert!(
        validate_verified_recovery_aware_continuity_chain_routine_extension(
            &terminal_chain,
            &routine_successor_receipt,
        )
        .is_err()
    );
    assert!(
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &[
                PersonaContinuityTransitionProof::TerminalRevocation(terminal_proof.clone()),
                PersonaContinuityTransitionProof::Routine(routine_successor_proof),
            ],
            &policy_chain,
            &root.root_statement_sha256,
            &current.policy_statement_sha256,
            START + 40,
        )
        .is_err()
    );

    let recovery_successor_statement = new_recovery_transition_statement(
        &root,
        2,
        Some(&terminal_statement_digest),
        &root.statement.initial_key_fingerprint,
        &online_two.public,
        &current,
        START + 31,
        RecoveryTransitionReason::Compromise,
    )
    .unwrap();
    let recovery_successor_proof = create_recovery_transition_proof(
        recovery_successor_statement,
        &current,
        &authorities,
        &online_two.private,
        &online_two.public,
    )
    .unwrap();
    let recovery_successor_receipt =
        verify_recovery_transition_proof_with_receipt(&root, &current, &recovery_successor_proof)
            .unwrap();
    assert!(
        validate_verified_recovery_aware_continuity_chain_extension(
            &terminal_chain,
            &recovery_successor_receipt,
        )
        .is_err()
    );
    assert!(
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &[
                PersonaContinuityTransitionProof::TerminalRevocation(terminal_proof.clone()),
                PersonaContinuityTransitionProof::Recovery(recovery_successor_proof),
            ],
            &policy_chain,
            &root.root_statement_sha256,
            &current.policy_statement_sha256,
            START + 40,
        )
        .is_err()
    );

    let second_terminal_statement = new_terminal_persona_revocation_statement(
        &root,
        2,
        Some(&terminal_statement_digest),
        &root.statement.initial_key_fingerprint,
        &current,
        START + 31,
        TerminalPersonaRevocationReason::Compromise,
    )
    .unwrap();
    let second_terminal_proof =
        create_terminal_persona_revocation_proof(second_terminal_statement, &current, &authorities)
            .unwrap();
    let second_terminal_receipt = verify_terminal_persona_revocation_proof_with_receipt(
        &root,
        &current,
        &second_terminal_proof,
    )
    .unwrap();
    assert!(
        validate_verified_recovery_aware_continuity_chain_terminal_revocation_extension(
            &terminal_chain,
            &second_terminal_receipt,
        )
        .is_err()
    );
    assert!(
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &[
                PersonaContinuityTransitionProof::TerminalRevocation(terminal_proof),
                PersonaContinuityTransitionProof::TerminalRevocation(second_terminal_proof),
            ],
            &policy_chain,
            &root.root_statement_sha256,
            &current.policy_statement_sha256,
            START + 40,
        )
        .is_err()
    );
}

#[derive(Serialize)]
struct LegacyRecoveryPolicyStatementV1<'a> {
    schema: &'a str,
    canonicalization: &'a str,
    persona_anchor: &'a str,
    persona: &'a str,
    root_statement_sha256: &'a str,
    policy_version: u32,
    previous_policy_sha256: &'a Option<String>,
    continuity_checkpoint: &'a RecoveryContinuityCheckpoint,
    issued_at: i64,
    expires_at: i64,
    threshold: u32,
    recovery_key_fingerprints: &'a [String],
}

fn legacy_v1_policy_statement_bytes(statement: &a_quo_core::RecoveryPolicyStatement) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(&LegacyRecoveryPolicyStatementV1 {
        schema: &statement.schema,
        canonicalization: &statement.canonicalization,
        persona_anchor: &statement.persona_anchor,
        persona: &statement.persona,
        root_statement_sha256: &statement.root_statement_sha256,
        policy_version: statement.policy_version,
        previous_policy_sha256: &statement.previous_policy_sha256,
        continuity_checkpoint: &statement.continuity_checkpoint,
        issued_at: statement.issued_at,
        expires_at: statement.expires_at,
        threshold: statement.threshold,
        recovery_key_fingerprints: &statement.recovery_key_fingerprints,
    })
    .unwrap()
}

fn root_checkpoint() -> RecoveryContinuityCheckpoint {
    RecoveryContinuityCheckpoint {
        transition_sequence: 0,
        transition_sha256: None,
    }
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
