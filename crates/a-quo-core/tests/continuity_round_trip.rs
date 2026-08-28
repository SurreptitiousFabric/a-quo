use std::fs;
use std::path::Path;
use std::process::Command;

use a_quo_core::{
    ContinuitySignatureRole, EvidenceStatus, PERSONA_ROOT_NAMESPACE, PERSONA_TRANSITION_NAMESPACE,
    PersonaContinuityCheckpoint, PersonaRootProof, canonical_persona_transition_statement_bytes,
    create_persona_root_proof, create_routine_transition_proof, new_persona_root_statement,
    new_routine_transition_statement, verify_persona_continuity_chain,
    verify_persona_continuity_chain_at_checkpoint, verify_persona_root_proof,
    verify_persona_transition_proof,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn dual_signed_transitions_form_a_pinned_ordered_chain() {
    let directory = tempdir().unwrap();
    let first_key = directory.path().join("first_key");
    let second_key = directory.path().join("second_key");
    let third_key = directory.path().join("third_key");
    generate_key(&first_key);
    generate_key(&second_key);
    generate_key(&third_key);
    let first_public = read_public_key(&first_key);
    let second_public = read_public_key(&second_key);
    let third_public = read_public_key(&third_key);

    let root_statement =
        new_persona_root_statement("Release publisher", 1_700_000_000, &first_public).unwrap();
    let root_proof = create_persona_root_proof(root_statement, &first_key, &first_public).unwrap();
    assert_eq!(root_proof.signature.namespace, PERSONA_ROOT_NAMESPACE);
    let root = verify_persona_root_proof(&root_proof).unwrap();

    let first_transition = new_routine_transition_statement(
        &root,
        1,
        None,
        &first_public,
        &second_public,
        1_700_000_100,
    )
    .unwrap();
    let first_proof = create_routine_transition_proof(
        first_transition,
        &first_key,
        &first_public,
        &second_key,
        &second_public,
    )
    .unwrap();
    assert!(
        first_proof
            .signatures
            .iter()
            .all(|signature| signature.namespace == PERSONA_TRANSITION_NAMESPACE)
    );
    let first_verified = verify_persona_transition_proof(&first_proof).unwrap();

    let second_transition = new_routine_transition_statement(
        &root,
        2,
        Some(&first_verified.transition_statement_sha256),
        &second_public,
        &third_public,
        1_700_000_200,
    )
    .unwrap();
    let second_proof = create_routine_transition_proof(
        second_transition,
        &second_key,
        &second_public,
        &third_key,
        &third_public,
    )
    .unwrap();

    let report = verify_persona_continuity_chain(
        &root_proof,
        &[first_proof.clone(), second_proof.clone()],
        &root.root_statement_sha256,
    )
    .unwrap();
    assert_eq!(report.root_signature, EvidenceStatus::Verified);
    assert_eq!(report.expected_root_digest, EvidenceStatus::Verified);
    assert_eq!(report.chain, EvidenceStatus::Verified);
    assert_eq!(report.persona, "Release publisher");
    assert_eq!(report.transition_count, 2);
    assert_eq!(report.last_issued_at, 1_700_000_200);
    assert_eq!(
        report.chain_tip_key_fingerprint,
        verify_persona_transition_proof(&second_proof)
            .unwrap()
            .statement
            .next_key_fingerprint
    );
    assert!(
        report
            .not_established
            .contains(&"when_or_how_the_root_digest_was_pinned".to_owned())
    );

    let mut order_independent_signatures = first_proof.clone();
    order_independent_signatures.signatures.swap(0, 1);
    verify_persona_transition_proof(&order_independent_signatures).unwrap();

    let wrong_link_statement = new_routine_transition_statement(
        &root,
        2,
        Some(&"0".repeat(64)),
        &second_public,
        &third_public,
        1_700_000_250,
    )
    .unwrap();
    let wrong_link_proof = create_routine_transition_proof(
        wrong_link_statement,
        &second_key,
        &second_public,
        &third_key,
        &third_public,
    )
    .unwrap();
    assert!(
        verify_persona_continuity_chain(
            &root_proof,
            &[first_proof.clone(), wrong_link_proof],
            &root.root_statement_sha256,
        )
        .is_err()
    );

    let backward_time_statement = new_routine_transition_statement(
        &root,
        2,
        Some(&first_verified.transition_statement_sha256),
        &second_public,
        &third_public,
        1_700_000_050,
    )
    .unwrap();
    let backward_time_proof = create_routine_transition_proof(
        backward_time_statement,
        &second_key,
        &second_public,
        &third_key,
        &third_public,
    )
    .unwrap();
    assert!(
        verify_persona_continuity_chain(
            &root_proof,
            &[first_proof.clone(), backward_time_proof],
            &root.root_statement_sha256,
        )
        .is_err()
    );

    assert!(
        verify_persona_continuity_chain(
            &root_proof,
            std::slice::from_ref(&second_proof),
            &root.root_statement_sha256,
        )
        .is_err()
    );
    assert!(
        verify_persona_continuity_chain(
            &root_proof,
            &[second_proof, first_proof],
            &root.root_statement_sha256,
        )
        .is_err()
    );
    assert!(verify_persona_continuity_chain(&root_proof, &[], &"0".repeat(64)).is_err());
}

#[test]
fn transition_proofs_fail_closed_for_tampering_roles_namespaces_and_json() {
    let directory = tempdir().unwrap();
    let first_key = directory.path().join("first_key");
    let second_key = directory.path().join("second_key");
    generate_key(&first_key);
    generate_key(&second_key);
    let first_public = read_public_key(&first_key);
    let second_public = read_public_key(&second_key);

    let root_statement = new_persona_root_statement("Publisher", 100, &first_public).unwrap();
    let root_proof = create_persona_root_proof(root_statement, &first_key, &first_public).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();
    let statement =
        new_routine_transition_statement(&root, 1, None, &first_public, &second_public, 101)
            .unwrap();
    let proof = create_routine_transition_proof(
        statement,
        &first_key,
        &first_public,
        &second_key,
        &second_public,
    )
    .unwrap();

    let mut duplicate_role = proof.clone();
    duplicate_role.signatures[1].role = ContinuitySignatureRole::Previous;
    assert!(verify_persona_transition_proof(&duplicate_role).is_err());

    let mut wrong_namespace = proof.clone();
    wrong_namespace.signatures[0].namespace = PERSONA_ROOT_NAMESPACE.to_owned();
    assert!(verify_persona_transition_proof(&wrong_namespace).is_err());

    let mut noncanonical_payload = proof.clone();
    let payload = URL_SAFE_NO_PAD.decode(&proof.payload).unwrap();
    let mut spaced = Vec::with_capacity(payload.len() + 1);
    spaced.push(b'{');
    spaced.push(b' ');
    spaced.extend_from_slice(&payload[1..]);
    noncanonical_payload.payload = URL_SAFE_NO_PAD.encode(spaced);
    assert!(verify_persona_transition_proof(&noncanonical_payload).is_err());

    let mut changed_statement = verify_persona_transition_proof(&proof).unwrap().statement;
    changed_statement.issued_at += 1;
    let changed_payload = canonical_persona_transition_statement_bytes(&changed_statement).unwrap();
    let mut signed_bytes_changed = proof.clone();
    signed_bytes_changed.payload = URL_SAFE_NO_PAD.encode(changed_payload);
    assert!(verify_persona_transition_proof(&signed_bytes_changed).is_err());

    let mut root_value = serde_json::to_value(&root_proof).unwrap();
    root_value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), Value::Bool(true));
    assert!(serde_json::from_value::<PersonaRootProof>(root_value).is_err());
}

#[test]
fn expected_head_rejects_prefixes_forks_duplicates_reordering_and_cross_persona_splices() {
    let directory = tempdir().unwrap();
    let key_paths = (0..7)
        .map(|index| {
            let path = directory.path().join(format!("matrix_key_{index}"));
            generate_key(&path);
            path
        })
        .collect::<Vec<_>>();
    let public_keys = key_paths
        .iter()
        .map(|path| read_public_key(path))
        .collect::<Vec<_>>();

    let root_statement =
        new_persona_root_statement("Matrix publisher", 1_700_001_000, &public_keys[0]).unwrap();
    let root_proof =
        create_persona_root_proof(root_statement, &key_paths[0], &public_keys[0]).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();
    let mut transitions = Vec::new();
    let mut previous_digest = None;
    for index in 0..3 {
        let statement = new_routine_transition_statement(
            &root,
            u32::try_from(index + 1).unwrap(),
            previous_digest.as_deref(),
            &public_keys[index],
            &public_keys[index + 1],
            1_700_001_100 + i64::try_from(index).unwrap(),
        )
        .unwrap();
        let proof = create_routine_transition_proof(
            statement,
            &key_paths[index],
            &public_keys[index],
            &key_paths[index + 1],
            &public_keys[index + 1],
        )
        .unwrap();
        previous_digest = Some(
            verify_persona_transition_proof(&proof)
                .unwrap()
                .transition_statement_sha256,
        );
        transitions.push(proof);
    }
    let expected_head = PersonaContinuityCheckpoint {
        transition_sequence: 3,
        transition_sha256: previous_digest.clone(),
    };
    let report = verify_persona_continuity_chain_at_checkpoint(
        &root_proof,
        &transitions,
        &root.root_statement_sha256,
        &expected_head,
    )
    .unwrap();
    assert_eq!(
        report.expected_head_checkpoint,
        Some(EvidenceStatus::Verified)
    );
    assert!(
        report
            .not_established
            .contains(&"whether_a_competing_transition_was_also_authorized_or_withheld".to_owned())
    );

    for prefix_length in 0..transitions.len() {
        let prefix = &transitions[..prefix_length];
        let prefix_report =
            verify_persona_continuity_chain(&root_proof, prefix, &root.root_statement_sha256)
                .unwrap();
        assert!(
            prefix_report
                .not_established
                .contains(&"whether_a_newer_or_competing_transition_was_withheld".to_owned())
        );
        assert!(
            verify_persona_continuity_chain_at_checkpoint(
                &root_proof,
                prefix,
                &root.root_statement_sha256,
                &expected_head,
            )
            .is_err()
        );
    }

    for omitted in 0..transitions.len() {
        let mut candidate = transitions.clone();
        candidate.remove(omitted);
        assert!(
            verify_persona_continuity_chain_at_checkpoint(
                &root_proof,
                &candidate,
                &root.root_statement_sha256,
                &expected_head,
            )
            .is_err()
        );
    }

    for duplicated in 0..transitions.len() {
        for insertion in 0..=transitions.len() {
            let mut candidate = transitions.clone();
            candidate.insert(insertion, transitions[duplicated].clone());
            assert!(
                verify_persona_continuity_chain_at_checkpoint(
                    &root_proof,
                    &candidate,
                    &root.root_statement_sha256,
                    &expected_head,
                )
                .is_err()
            );
        }
    }

    for order in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let candidate = order.map(|index| transitions[index].clone());
        assert!(
            verify_persona_continuity_chain_at_checkpoint(
                &root_proof,
                &candidate,
                &root.root_statement_sha256,
                &expected_head,
            )
            .is_err()
        );
    }

    let first_digest = verify_persona_transition_proof(&transitions[0])
        .unwrap()
        .transition_statement_sha256;
    let fork_statement = new_routine_transition_statement(
        &root,
        2,
        Some(&first_digest),
        &public_keys[1],
        &public_keys[4],
        1_700_001_101,
    )
    .unwrap();
    let fork = create_routine_transition_proof(
        fork_statement,
        &key_paths[1],
        &public_keys[1],
        &key_paths[4],
        &public_keys[4],
    )
    .unwrap();
    verify_persona_continuity_chain(
        &root_proof,
        &[transitions[0].clone(), fork.clone()],
        &root.root_statement_sha256,
    )
    .unwrap();
    let second_digest = verify_persona_transition_proof(&transitions[1])
        .unwrap()
        .transition_statement_sha256;
    let expected_second = PersonaContinuityCheckpoint {
        transition_sequence: 2,
        transition_sha256: Some(second_digest),
    };
    assert!(
        verify_persona_continuity_chain_at_checkpoint(
            &root_proof,
            &[transitions[0].clone(), fork],
            &root.root_statement_sha256,
            &expected_second,
        )
        .is_err()
    );

    let other_root_statement =
        new_persona_root_statement("Other publisher", 1_700_001_000, &public_keys[5]).unwrap();
    let other_root_proof =
        create_persona_root_proof(other_root_statement, &key_paths[5], &public_keys[5]).unwrap();
    let other_root = verify_persona_root_proof(&other_root_proof).unwrap();
    let other_statement = new_routine_transition_statement(
        &other_root,
        1,
        None,
        &public_keys[5],
        &public_keys[6],
        1_700_001_100,
    )
    .unwrap();
    let other_transition = create_routine_transition_proof(
        other_statement,
        &key_paths[5],
        &public_keys[5],
        &key_paths[6],
        &public_keys[6],
    )
    .unwrap();
    for insertion in 0..transitions.len() {
        let mut candidate = transitions.clone();
        candidate[insertion] = other_transition.clone();
        assert!(
            verify_persona_continuity_chain_at_checkpoint(
                &root_proof,
                &candidate,
                &root.root_statement_sha256,
                &expected_head,
            )
            .is_err()
        );
    }

    let root_checkpoint = PersonaContinuityCheckpoint {
        transition_sequence: 0,
        transition_sha256: None,
    };
    verify_persona_continuity_chain_at_checkpoint(
        &root_proof,
        &[],
        &root.root_statement_sha256,
        &root_checkpoint,
    )
    .unwrap();
    for invalid_checkpoint in [
        PersonaContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: Some("0".repeat(64)),
        },
        PersonaContinuityCheckpoint {
            transition_sequence: 1,
            transition_sha256: None,
        },
        PersonaContinuityCheckpoint {
            transition_sequence: 4_097,
            transition_sha256: Some("0".repeat(64)),
        },
    ] {
        assert!(
            verify_persona_continuity_chain_at_checkpoint(
                &root_proof,
                &transitions,
                &root.root_statement_sha256,
                &invalid_checkpoint,
            )
            .is_err()
        );
    }
}

fn read_public_key(private_key: &Path) -> String {
    fs::read_to_string(private_key.with_extension("pub"))
        .unwrap()
        .trim()
        .to_owned()
}

fn generate_key(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("OpenSSH ssh-keygen must be installed for the integration test");
    assert!(status.success());
}
