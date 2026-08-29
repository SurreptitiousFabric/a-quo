use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use a_quo_core::{
    MAX_CONTINUITY_TRANSITIONS, MAX_RECOVERY_CEREMONY_REQUEST_BYTES,
    MAX_RECOVERY_CEREMONY_RESPONSE_BYTES, MAX_RECOVERY_CEREMONY_RESPONSES,
    MAX_RECOVERY_CEREMONY_SIGNATURE_VERIFICATIONS, MAX_RECOVERY_CEREMONY_VALIDITY_SECONDS,
    MAX_RECOVERY_POLICY_VERSIONS, PersonaContinuityCheckpoint, PersonaContinuityTransitionProof,
    RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE, RECOVERY_TRANSITION_AUTHORITY_NAMESPACE,
    RECOVERY_TRANSITION_NEXT_NAMESPACE, RECOVERY_TRANSITION_STATEMENT_SCHEMA,
    RECOVERY_TRANSITION_STATEMENT_SCHEMA_V2, RecoveryCeremonyParticipantRole, RecoverySigner,
    RecoveryTransitionReason, assemble_recovery_ceremony_proof,
    canonical_recovery_ceremony_request_bytes, canonical_recovery_ceremony_response_bytes,
    canonical_recovery_transition_statement_bytes, create_initial_recovery_policy_proof,
    create_persona_root_proof, new_initial_recovery_policy_statement, new_persona_root_statement,
    new_recovery_ceremony_request, new_recovery_ceremony_response,
    new_recovery_transition_ceremony_statement_with_id, new_recovery_transition_statement,
    parse_recovery_ceremony_request_bytes, parse_recovery_ceremony_response_bytes,
    recovery_ceremony_request_sha256, review_recovery_ceremony_participant,
    sign_recovery_ceremony_request, verify_initial_recovery_policy_proof,
    verify_persona_root_proof, verify_recovery_ceremony_request, verify_recovery_ceremony_response,
    verify_recovery_transition_proof,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use tempfile::tempdir;

const START: i64 = 1_700_000_000;

#[derive(Serialize)]
struct LegacyRecoveryTransitionStatement<'a> {
    schema: &'a str,
    canonicalization: &'a str,
    persona_anchor: &'a str,
    persona: &'a str,
    sequence: u32,
    issued_at: i64,
    root_statement_sha256: &'a str,
    previous_transition_sha256: Option<&'a str>,
    previous_key_fingerprint: &'a str,
    next_key_fingerprint: &'a str,
    recovery_policy_sha256: &'a str,
    recovery_policy_version: u32,
    reason: RecoveryTransitionReason,
}

#[test]
fn distributed_recovery_ceremony_is_bounded_purpose_separated_and_deterministic() {
    let directory = tempdir().unwrap();
    let online = key(directory.path(), "online", "ed25519");
    let next = key(directory.path(), "next", "ed25519");
    let authority_one = key(directory.path(), "authority_one", "ecdsa");
    let authority_two = key(directory.path(), "authority_two", "ed25519");
    let authority_three = key(directory.path(), "authority_three", "ed25519");
    let outsider = key(directory.path(), "outsider", "ed25519");

    let root_statement =
        new_persona_root_statement("Juniper Quill", START, &online.public).unwrap();
    let root_proof =
        create_persona_root_proof(root_statement, &online.private, &online.public).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();
    let authority_signers = vec![
        authority_one.signer(),
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
        a_quo_core::RecoveryContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        },
        START + 10,
        START + 700_000,
    )
    .unwrap();
    let policy_proof =
        create_initial_recovery_policy_proof(policy_statement, &authority_signers).unwrap();
    let policy = verify_initial_recovery_policy_proof(&root, &policy_proof).unwrap();

    // Adding optional v2 fields did not change schema-v1 canonical bytes.
    let v1 = new_recovery_transition_statement(
        &root,
        1,
        None,
        &root.statement.initial_key_fingerprint,
        &next.public,
        &policy,
        START + 20,
        RecoveryTransitionReason::Recovery,
    )
    .unwrap();
    assert_eq!(v1.schema, RECOVERY_TRANSITION_STATEMENT_SCHEMA);
    assert_eq!(v1.ceremony_id, None);
    assert_eq!(v1.expires_at, None);
    let legacy = LegacyRecoveryTransitionStatement {
        schema: &v1.schema,
        canonicalization: &v1.canonicalization,
        persona_anchor: &v1.persona_anchor,
        persona: &v1.persona,
        sequence: v1.sequence,
        issued_at: v1.issued_at,
        root_statement_sha256: &v1.root_statement_sha256,
        previous_transition_sha256: v1.previous_transition_sha256.as_deref(),
        previous_key_fingerprint: &v1.previous_key_fingerprint,
        next_key_fingerprint: &v1.next_key_fingerprint,
        recovery_policy_sha256: &v1.recovery_policy_sha256,
        recovery_policy_version: v1.recovery_policy_version,
        reason: v1.reason,
    };
    assert_eq!(
        canonical_recovery_transition_statement_bytes(&v1).unwrap(),
        serde_json_canonicalizer::to_vec(&legacy).unwrap()
    );

    let ceremony_id = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let statement = new_recovery_transition_ceremony_statement_with_id(
        &root,
        1,
        None,
        &root.statement.initial_key_fingerprint,
        &next.public,
        &policy,
        START + 30,
        START + 300,
        RecoveryTransitionReason::Compromise,
        &ceremony_id,
    )
    .unwrap();
    assert_eq!(statement.schema, RECOVERY_TRANSITION_STATEMENT_SCHEMA_V2);
    assert_eq!(statement.ceremony_id.as_deref(), Some(ceremony_id.as_str()));
    assert_eq!(statement.expires_at, Some(START + 300));

    let request = new_recovery_ceremony_request(
        root_proof.clone(),
        vec![policy_proof.clone()],
        Vec::new(),
        root.root_statement_sha256.clone(),
        policy.policy_statement_sha256.clone(),
        PersonaContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        },
        statement.clone(),
        next.public.clone(),
    )
    .unwrap();
    let request_bytes = canonical_recovery_ceremony_request_bytes(&request).unwrap();
    assert_eq!(
        parse_recovery_ceremony_request_bytes(&request_bytes).unwrap(),
        request
    );
    let verified = verify_recovery_ceremony_request(&request, START + 30).unwrap();
    assert_eq!(
        verified.request_sha256(),
        recovery_ceremony_request_sha256(&request).unwrap()
    );
    assert_eq!(verified.selected_policy(), &policy);

    let authority_review =
        review_recovery_ceremony_participant(&verified, &authority_one.public, START + 31).unwrap();
    assert_eq!(
        authority_review.role,
        RecoveryCeremonyParticipantRole::RecoveryAuthority
    );
    assert_eq!(authority_review.ceremony_id, ceremony_id);
    let next_review =
        review_recovery_ceremony_participant(&verified, &next.public, START + 31).unwrap();
    assert_eq!(next_review.role, RecoveryCeremonyParticipantRole::NextKey);
    assert!(review_recovery_ceremony_participant(&verified, &outsider.public, START + 31).is_err());

    let response_one =
        sign_recovery_ceremony_request(&verified, &authority_one.signer(), START + 31).unwrap();
    let response_two =
        sign_recovery_ceremony_request(&verified, &authority_two.signer(), START + 31).unwrap();
    let response_next =
        sign_recovery_ceremony_request(&verified, &next.signer(), START + 31).unwrap();
    assert_eq!(
        new_recovery_ceremony_response(
            &verified,
            response_one.signature.clone(),
            response_one.request_binding_signature.clone(),
            START + 31,
        )
        .unwrap(),
        response_one
    );
    assert_eq!(
        response_one.signature.namespace,
        RECOVERY_TRANSITION_AUTHORITY_NAMESPACE
    );
    assert_eq!(
        response_next.signature.namespace,
        RECOVERY_TRANSITION_NEXT_NAMESPACE
    );
    assert_eq!(
        response_one.request_binding_signature.namespace,
        RECOVERY_CEREMONY_REQUEST_BINDING_NAMESPACE
    );
    for response in [&response_one, &response_two, &response_next] {
        let bytes = canonical_recovery_ceremony_response_bytes(response).unwrap();
        assert_eq!(
            parse_recovery_ceremony_response_bytes(&bytes).unwrap(),
            *response
        );
        verify_recovery_ceremony_response(&verified, response, START + 31).unwrap();
    }

    let proof = assemble_recovery_ceremony_proof(
        &verified,
        &[
            response_next.clone(),
            response_one.clone(),
            response_two.clone(),
            response_one.clone(),
        ],
        START + 31,
    )
    .unwrap();
    let reordered = assemble_recovery_ceremony_proof(
        &verified,
        &[
            response_two.clone(),
            response_one.clone(),
            response_next.clone(),
        ],
        START + 31,
    )
    .unwrap();
    assert_eq!(proof, reordered);
    assert_eq!(proof.recovery_signatures.len(), 2);
    assert_eq!(
        verify_recovery_transition_proof(&root, &policy, &proof)
            .unwrap()
            .statement,
        statement
    );

    let mut too_many_policies = request.clone();
    too_many_policies.recovery_policies =
        vec![policy_proof.clone(); MAX_RECOVERY_POLICY_VERSIONS + 1];
    assert!(canonical_recovery_ceremony_request_bytes(&too_many_policies).is_err());
    let mut too_many_transitions = request.clone();
    too_many_transitions.prior_transitions =
        vec![
            PersonaContinuityTransitionProof::Recovery(proof.clone());
            MAX_CONTINUITY_TRANSITIONS + 1
        ];
    assert!(canonical_recovery_ceremony_request_bytes(&too_many_transitions).is_err());

    // The aggregate crypto-work cap runs before embedded proof validation or
    // any ssh-keygen verifier. One deliberately invalid signature proves the
    // failure is the request-wide work bound, not a later signature error.
    let mut invalid_policy = policy_proof.clone();
    let a_quo_core::RecoveryPolicyAuthorization::Enrollment { signatures } =
        &mut invalid_policy.authorization
    else {
        panic!("initial policy must use enrollment authorization");
    };
    signatures[0].value = "deliberately-invalid".to_owned();
    let policy_copies = (MAX_RECOVERY_CEREMONY_SIGNATURE_VERIFICATIONS / signatures.len()) + 1;
    let mut excessive_crypto_work = request.clone();
    excessive_crypto_work.recovery_policies = vec![invalid_policy; policy_copies];
    let work_error = canonical_recovery_ceremony_request_bytes(&excessive_crypto_work)
        .expect_err("excessive aggregate signature work must fail before verification");
    assert!(
        work_error
            .to_string()
            .contains("signature verifications; the limit is 2048"),
        "unexpected work-bound error: {work_error}"
    );

    assert!(
        assemble_recovery_ceremony_proof(
            &verified,
            &[response_one.clone(), response_next.clone()],
            START + 31,
        )
        .is_err()
    );
    assert!(
        assemble_recovery_ceremony_proof(
            &verified,
            &[response_one.clone(), response_two.clone()],
            START + 31,
        )
        .is_err()
    );
    assert!(
        assemble_recovery_ceremony_proof(
            &verified,
            &vec![response_one.clone(); MAX_RECOVERY_CEREMONY_RESPONSES + 1],
            START + 31,
        )
        .is_err()
    );

    // ECDSA generates distinct valid signatures for the same exact payload;
    // accepting both would ambiguously count one participant twice.
    let conflicting_one =
        sign_recovery_ceremony_request(&verified, &authority_one.signer(), START + 31).unwrap();
    assert_ne!(response_one, conflicting_one);
    assert!(
        assemble_recovery_ceremony_proof(
            &verified,
            &[
                response_one.clone(),
                conflicting_one,
                response_two.clone(),
                response_next.clone(),
            ],
            START + 31,
        )
        .is_err()
    );

    let mut wrong_root = request.clone();
    wrong_root.expected_root_statement_sha256 = "0".repeat(64);
    assert!(verify_recovery_ceremony_request(&wrong_root, START + 30).is_err());
    let mut wrong_policy = request.clone();
    wrong_policy.expected_latest_policy_sha256 = "0".repeat(64);
    assert!(verify_recovery_ceremony_request(&wrong_policy, START + 30).is_err());
    let mut wrong_head = request.clone();
    wrong_head.expected_head = PersonaContinuityCheckpoint {
        transition_sequence: 1,
        transition_sha256: Some("0".repeat(64)),
    };
    assert!(verify_recovery_ceremony_request(&wrong_head, START + 30).is_err());
    let mut substituted_next = request.clone();
    substituted_next.next_public_key = outsider.public.clone();
    assert!(canonical_recovery_ceremony_request_bytes(&substituted_next).is_err());

    let mut other_ceremony = request.clone();
    other_ceremony.statement.ceremony_id = Some(URL_SAFE_NO_PAD.encode([8_u8; 32]));
    let other_verified = verify_recovery_ceremony_request(&other_ceremony, START + 30).unwrap();
    assert!(verify_recovery_ceremony_response(&other_verified, &response_one, START + 31).is_err());
    let mut tampered_response = response_one.clone();
    tampered_response.signature.value.push('x');
    assert!(verify_recovery_ceremony_response(&verified, &tampered_response, START + 31).is_err());
    let mut tampered_request_binding = response_one.clone();
    tampered_request_binding
        .request_binding_signature
        .value
        .push('x');
    assert!(
        verify_recovery_ceremony_response(&verified, &tampered_request_binding, START + 31)
            .is_err()
    );
    let mut wrong_binding_namespace = response_one.clone();
    wrong_binding_namespace.request_binding_signature.namespace =
        RECOVERY_TRANSITION_AUTHORITY_NAMESPACE.to_owned();
    assert!(canonical_recovery_ceremony_response_bytes(&wrong_binding_namespace).is_err());
    let mut wrong_role = response_one.clone();
    wrong_role.role = RecoveryCeremonyParticipantRole::NextKey;
    assert!(canonical_recovery_ceremony_response_bytes(&wrong_role).is_err());

    // Equivalent signed evidence can have different wrapper bytes. Relabeling
    // an old response with the replacement request digest must still fail
    // because its second purpose-separated signature covers the exact request.
    let mut equivalent_request = request.clone();
    let a_quo_core::RecoveryPolicyAuthorization::Enrollment { signatures } =
        &mut equivalent_request.recovery_policies[0].authorization
    else {
        panic!("initial policy must use enrollment authorization");
    };
    signatures.swap(0, 1);
    let equivalent_verified =
        verify_recovery_ceremony_request(&equivalent_request, START + 30).unwrap();
    assert_ne!(
        equivalent_verified.request_sha256(),
        verified.request_sha256()
    );
    let mut relabeled_response = response_one.clone();
    relabeled_response.request_sha256 = equivalent_verified.request_sha256().to_owned();
    assert!(
        verify_recovery_ceremony_response(&equivalent_verified, &relabeled_response, START + 31,)
            .is_err()
    );

    assert!(verify_recovery_ceremony_request(&request, START + 29).is_err());
    assert!(
        sign_recovery_ceremony_request(&verified, &authority_one.signer(), START + 300).is_err()
    );
    assert!(verify_recovery_ceremony_response(&verified, &response_one, START + 300).is_err());
    assert!(
        assemble_recovery_ceremony_proof(
            &verified,
            &[
                response_one.clone(),
                response_two.clone(),
                response_next.clone()
            ],
            START + 300,
        )
        .is_err()
    );
    assert!(
        review_recovery_ceremony_participant(&verified, &authority_one.public, START + 29).is_err()
    );

    let invalid_id = format!("{}=", URL_SAFE_NO_PAD.encode([9_u8; 32]));
    assert!(
        new_recovery_transition_ceremony_statement_with_id(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &next.public,
            &policy,
            START + 30,
            START + 300,
            RecoveryTransitionReason::Recovery,
            &invalid_id,
        )
        .is_err()
    );
    assert!(
        new_recovery_transition_ceremony_statement_with_id(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &next.public,
            &policy,
            START + 30,
            START + 30,
            RecoveryTransitionReason::Recovery,
            &URL_SAFE_NO_PAD.encode([9_u8; 32]),
        )
        .is_err()
    );
    assert!(
        new_recovery_transition_ceremony_statement_with_id(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &next.public,
            &policy,
            START + 30,
            START + 30 + MAX_RECOVERY_CEREMONY_VALIDITY_SECONDS + 1,
            RecoveryTransitionReason::Recovery,
            &URL_SAFE_NO_PAD.encode([9_u8; 32]),
        )
        .is_err()
    );
    assert!(
        new_recovery_transition_ceremony_statement_with_id(
            &root,
            1,
            None,
            &root.statement.initial_key_fingerprint,
            &next.public,
            &policy,
            START + 699_900,
            START + 700_001,
            RecoveryTransitionReason::Recovery,
            &URL_SAFE_NO_PAD.encode([9_u8; 32]),
        )
        .is_err()
    );

    let pretty_request = serde_json::to_vec_pretty(&request).unwrap();
    assert!(parse_recovery_ceremony_request_bytes(&pretty_request).is_err());
    assert!(parse_recovery_ceremony_request_bytes(b"{").is_err());
    let request_text = String::from_utf8(request_bytes).unwrap();
    let duplicate_request = format!("{{\"schema\":\"duplicate\",{}", &request_text[1..]);
    assert!(parse_recovery_ceremony_request_bytes(duplicate_request.as_bytes()).is_err());
    let mut request_value = serde_json::to_value(&request).unwrap();
    request_value
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), serde_json::Value::Bool(true));
    let unknown_request = serde_json_canonicalizer::to_vec(&request_value).unwrap();
    assert!(parse_recovery_ceremony_request_bytes(&unknown_request).is_err());
    assert!(
        parse_recovery_ceremony_request_bytes(&vec![b' '; MAX_RECOVERY_CEREMONY_REQUEST_BYTES + 1])
            .is_err()
    );

    let pretty_response = serde_json::to_vec_pretty(&response_one).unwrap();
    assert!(parse_recovery_ceremony_response_bytes(&pretty_response).is_err());
    assert!(parse_recovery_ceremony_response_bytes(b"{").is_err());
    let response_text =
        String::from_utf8(canonical_recovery_ceremony_response_bytes(&response_one).unwrap())
            .unwrap();
    let duplicate_response = format!("{{\"schema\":\"duplicate\",{}", &response_text[1..]);
    assert!(parse_recovery_ceremony_response_bytes(duplicate_response.as_bytes()).is_err());
    let mut response_value = serde_json::to_value(&response_one).unwrap();
    response_value
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), serde_json::Value::Bool(true));
    let unknown_response = serde_json_canonicalizer::to_vec(&response_value).unwrap();
    assert!(parse_recovery_ceremony_response_bytes(&unknown_response).is_err());
    assert!(
        parse_recovery_ceremony_response_bytes(&vec![
            b' ';
            MAX_RECOVERY_CEREMONY_RESPONSE_BYTES + 1
        ])
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

fn key(directory: &Path, name: &str, key_type: &str) -> TestKey {
    let private = directory.join(name);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", key_type, "-N", "", "-f"])
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
