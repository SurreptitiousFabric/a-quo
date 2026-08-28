use std::fs;
use std::path::Path;
use std::process::Command;

use a_quo_core::{
    ContinuitySignatureRole, EvidenceStatus, PERSONA_ROOT_NAMESPACE, PERSONA_TRANSITION_NAMESPACE,
    PersonaRootProof, canonical_persona_transition_statement_bytes, create_persona_root_proof,
    create_routine_transition_proof, new_persona_root_statement, new_routine_transition_statement,
    verify_persona_continuity_chain, verify_persona_root_proof, verify_persona_transition_proof,
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
        report.current_key_fingerprint,
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
