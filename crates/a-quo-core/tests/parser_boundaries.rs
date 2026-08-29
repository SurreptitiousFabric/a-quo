use std::fs;
use std::path::Path;

use a_quo_core::{
    CONTINUITY_CANONICALIZATION, ContinuitySignature, ContinuitySignatureRole, MAX_PROOF_BYTES,
    MAX_RECOVERY_AUTHORITIES, PERSONA_ROOT_NAMESPACE, PERSONA_ROOT_PROOF_SCHEMA,
    PERSONA_TRANSITION_NAMESPACE, PERSONA_TRANSITION_PROOF_SCHEMA,
    PersonaContinuityTransitionProof, PersonaRootProof, PersonaTransitionProof,
    RECOVERY_POLICY_ENROLLMENT_NAMESPACE, RECOVERY_POLICY_PROOF_SCHEMA,
    RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE, RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE,
    RECOVERY_TRANSITION_AUTHORITY_NAMESPACE, RECOVERY_TRANSITION_NEXT_NAMESPACE,
    RECOVERY_TRANSITION_PROOF_SCHEMA, RECOVERY_TRANSITION_STATEMENT_SCHEMA,
    RecoveryContinuityCheckpoint, RecoveryPolicyAuthorization, RecoveryPolicyProof,
    RecoveryPolicyStatement, RecoverySignature, RecoveryTransitionProof, RecoveryTransitionReason,
    RecoveryTransitionStatement, VerifiedPersonaRoot, VerifiedRecoveryPolicy,
    canonical_persona_root_statement_bytes, canonical_persona_transition_statement_bytes,
    canonical_recovery_policy_statement_bytes, canonical_recovery_transition_statement_bytes,
    new_initial_recovery_policy_statement, new_persona_root_statement_with_anchor,
    new_recovery_policy_update_statement, new_routine_transition_statement,
    parse_persona_continuity_transition_proof_bytes, parse_persona_root_proof_bytes,
    parse_persona_transition_proof_bytes, parse_recovery_ceremony_request_bytes,
    parse_recovery_ceremony_response_bytes, parse_recovery_policy_proof_bytes,
    parse_recovery_transition_proof_bytes, parse_terminal_persona_revocation_proof_bytes,
    persona_root_statement_sha256, public_key_fingerprint, recovery_policy_statement_sha256,
    review_persona_root_statement_bytes, review_persona_transition_statement_bytes,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const KEY_ONE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";
const KEY_TWO: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfX7hAdqGfF0mYz2oD88dL84M2yr2KoXqhh7sSRvqHQ";
const KEY_THREE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD";
const ANCHOR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ISSUED_AT: i64 = 1_700_000_000;

fn continuity_signature(
    role: ContinuitySignatureRole,
    namespace: &str,
    public_key: &str,
) -> ContinuitySignature {
    ContinuitySignature {
        role,
        format: "sshsig".to_owned(),
        namespace: namespace.to_owned(),
        value: "synthetic-public-test-signature".to_owned(),
        public_key_format: "openssh-public-key".to_owned(),
        public_key: public_key.to_owned(),
    }
}

fn recovery_signature(namespace: &str, public_key: &str) -> RecoverySignature {
    RecoverySignature {
        format: "sshsig".to_owned(),
        namespace: namespace.to_owned(),
        value: "synthetic-public-test-signature".to_owned(),
        public_key_format: "openssh-public-key".to_owned(),
        public_key: public_key.to_owned(),
    }
}

fn structural_proofs() -> (
    PersonaRootProof,
    PersonaTransitionProof,
    RecoveryPolicyProof,
    RecoveryPolicyProof,
    RecoveryTransitionProof,
) {
    let root_statement =
        new_persona_root_statement_with_anchor(ANCHOR, "Parser Test", ISSUED_AT, KEY_ONE).unwrap();
    let root_payload = canonical_persona_root_statement_bytes(&root_statement).unwrap();
    let root_proof = PersonaRootProof {
        schema: PERSONA_ROOT_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD.encode(&root_payload),
        signature: continuity_signature(
            ContinuitySignatureRole::Root,
            PERSONA_ROOT_NAMESPACE,
            KEY_ONE,
        ),
    };
    let root = VerifiedPersonaRoot {
        root_statement_sha256: persona_root_statement_sha256(&root_statement).unwrap(),
        statement: root_statement,
        initial_public_key: KEY_ONE.to_owned(),
    };

    let transition_statement =
        new_routine_transition_statement(&root, 1, None, KEY_ONE, KEY_TWO, ISSUED_AT + 1).unwrap();
    let transition_proof = PersonaTransitionProof {
        schema: PERSONA_TRANSITION_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD
            .encode(canonical_persona_transition_statement_bytes(&transition_statement).unwrap()),
        signatures: vec![
            continuity_signature(
                ContinuitySignatureRole::Previous,
                PERSONA_TRANSITION_NAMESPACE,
                KEY_ONE,
            ),
            continuity_signature(
                ContinuitySignatureRole::Next,
                PERSONA_TRANSITION_NAMESPACE,
                KEY_TWO,
            ),
        ],
    };

    let authority_keys = vec![KEY_TWO.to_owned(), KEY_THREE.to_owned()];
    let policy_statement = new_initial_recovery_policy_statement(
        &root,
        &authority_keys,
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        },
        ISSUED_AT + 1,
        ISSUED_AT + 10_000,
    )
    .unwrap();
    let policy_proof = RecoveryPolicyProof {
        schema: RECOVERY_POLICY_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD
            .encode(canonical_recovery_policy_statement_bytes(&policy_statement).unwrap()),
        authorization: RecoveryPolicyAuthorization::Enrollment {
            signatures: vec![
                recovery_signature(RECOVERY_POLICY_ENROLLMENT_NAMESPACE, KEY_TWO),
                recovery_signature(RECOVERY_POLICY_ENROLLMENT_NAMESPACE, KEY_THREE),
            ],
        },
    };

    let verified_policy = VerifiedRecoveryPolicy {
        statement: policy_statement.clone(),
        policy_statement_sha256: recovery_policy_statement_sha256(&policy_statement).unwrap(),
        previous_authorization_fingerprints: Vec::new(),
        current_authorization_fingerprints: authority_keys
            .iter()
            .map(|key| public_key_fingerprint(key).unwrap())
            .collect(),
    };
    let policy_update_statement = new_recovery_policy_update_statement(
        &verified_policy,
        &authority_keys,
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        },
        ISSUED_AT + 2,
        ISSUED_AT + 10_001,
    )
    .unwrap();
    let policy_update_proof = RecoveryPolicyProof {
        schema: RECOVERY_POLICY_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD
            .encode(canonical_recovery_policy_statement_bytes(&policy_update_statement).unwrap()),
        authorization: RecoveryPolicyAuthorization::Update {
            previous_policy_signatures: vec![
                recovery_signature(RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE, KEY_TWO),
                recovery_signature(RECOVERY_POLICY_UPDATE_PREVIOUS_NAMESPACE, KEY_THREE),
            ],
            current_policy_signatures: vec![
                recovery_signature(RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE, KEY_TWO),
                recovery_signature(RECOVERY_POLICY_UPDATE_CURRENT_NAMESPACE, KEY_THREE),
            ],
        },
    };

    let recovery_statement = RecoveryTransitionStatement {
        schema: RECOVERY_TRANSITION_STATEMENT_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        persona_anchor: root.statement.persona_anchor.clone(),
        persona: root.statement.persona.clone(),
        sequence: 1,
        issued_at: ISSUED_AT + 2,
        root_statement_sha256: root.root_statement_sha256,
        previous_transition_sha256: None,
        previous_key_fingerprint: public_key_fingerprint(KEY_ONE).unwrap(),
        next_key_fingerprint: public_key_fingerprint(KEY_TWO).unwrap(),
        recovery_policy_sha256: recovery_policy_statement_sha256(&policy_statement).unwrap(),
        recovery_policy_version: 1,
        reason: RecoveryTransitionReason::Recovery,
        ceremony_id: None,
        expires_at: None,
    };
    let recovery_proof = RecoveryTransitionProof {
        schema: RECOVERY_TRANSITION_PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD
            .encode(canonical_recovery_transition_statement_bytes(&recovery_statement).unwrap()),
        recovery_signatures: vec![
            recovery_signature(RECOVERY_TRANSITION_AUTHORITY_NAMESPACE, KEY_TWO),
            recovery_signature(RECOVERY_TRANSITION_AUTHORITY_NAMESPACE, KEY_THREE),
        ],
        next_signature: recovery_signature(RECOVERY_TRANSITION_NEXT_NAMESPACE, KEY_TWO),
    };

    (
        root_proof,
        transition_proof,
        policy_proof,
        policy_update_proof,
        recovery_proof,
    )
}

#[test]
fn production_byte_parsers_reach_every_continuity_and_recovery_variant() {
    let (root, routine, policy, policy_update, recovery) = structural_proofs();

    let root_bytes = serde_json::to_vec_pretty(&root).unwrap();
    assert_eq!(parse_persona_root_proof_bytes(&root_bytes).unwrap(), root);

    let routine_bytes = serde_json::to_vec_pretty(&routine).unwrap();
    assert_eq!(
        parse_persona_transition_proof_bytes(&routine_bytes).unwrap(),
        routine
    );
    assert!(matches!(
        parse_persona_continuity_transition_proof_bytes(&routine_bytes).unwrap(),
        PersonaContinuityTransitionProof::Routine(_)
    ));

    let policy_bytes = serde_json::to_vec_pretty(&policy).unwrap();
    assert_eq!(
        parse_recovery_policy_proof_bytes(&policy_bytes).unwrap(),
        policy
    );

    let policy_update_bytes = serde_json::to_vec_pretty(&policy_update).unwrap();
    assert_eq!(
        parse_recovery_policy_proof_bytes(&policy_update_bytes).unwrap(),
        policy_update
    );

    let recovery_bytes = serde_json::to_vec_pretty(&recovery).unwrap();
    assert_eq!(
        parse_recovery_transition_proof_bytes(&recovery_bytes).unwrap(),
        recovery
    );
    assert!(matches!(
        parse_persona_continuity_transition_proof_bytes(&recovery_bytes).unwrap(),
        PersonaContinuityTransitionProof::Recovery(_)
    ));
}

#[test]
fn tracked_continuity_fuzz_seeds_reach_their_intended_parser_arms() {
    fn seed_payload(seed_directory: &Path, name: &str, expected_selector: u8) -> Vec<u8> {
        let bytes = fs::read(seed_directory.join(name)).unwrap();
        assert_eq!(
            bytes.first(),
            Some(&expected_selector),
            "wrong selector for {name}"
        );
        bytes[1..].to_vec()
    }

    let seed_directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/continuity_recovery_bytes");
    if !seed_directory.is_dir() {
        // The fuzz workspace is deliberately outside the publishable core crate.
        return;
    }

    let root = seed_payload(&seed_directory, "root_proof", b'0');
    parse_persona_root_proof_bytes(&root).unwrap();

    let routine = seed_payload(&seed_directory, "routine_proof", b'1');
    parse_persona_transition_proof_bytes(&routine).unwrap();

    for name in ["recovery_policy", "recovery_policy_update"] {
        let policy = seed_payload(&seed_directory, name, b'2');
        let proof = parse_recovery_policy_proof_bytes(&policy).unwrap();
        assert_eq!(
            matches!(
                proof.authorization,
                RecoveryPolicyAuthorization::Update { .. }
            ),
            name == "recovery_policy_update"
        );
    }

    let recovery = seed_payload(&seed_directory, "recovery_transition", b'3');
    let recovery = parse_recovery_transition_proof_bytes(&recovery).unwrap();
    assert_eq!(recovery.recovery_signatures.len(), 2);
    assert_ne!(
        recovery.recovery_signatures[0].public_key,
        recovery.recovery_signatures[1].public_key
    );

    let routine_union = seed_payload(&seed_directory, "transition_union_routine", b'4');
    assert!(matches!(
        parse_persona_continuity_transition_proof_bytes(&routine_union).unwrap(),
        PersonaContinuityTransitionProof::Routine(_)
    ));
    let recovery_union = seed_payload(&seed_directory, "transition_union_recovery", b'4');
    assert!(matches!(
        parse_persona_continuity_transition_proof_bytes(&recovery_union).unwrap(),
        PersonaContinuityTransitionProof::Recovery(_)
    ));
    let malformed_union = seed_payload(&seed_directory, "transition_union_malformed", b'4');
    assert!(parse_persona_continuity_transition_proof_bytes(&malformed_union).is_err());

    let root_statement = seed_payload(&seed_directory, "root_statement", b'5');
    review_persona_root_statement_bytes(&root_statement, ISSUED_AT, KEY_ONE, "Parser Test")
        .unwrap();

    let expected_statement =
        new_persona_root_statement_with_anchor(ANCHOR, "Parser Test", ISSUED_AT, KEY_ONE).unwrap();
    let expected_root = VerifiedPersonaRoot {
        root_statement_sha256: persona_root_statement_sha256(&expected_statement).unwrap(),
        statement: expected_statement,
        initial_public_key: KEY_ONE.to_owned(),
    };
    let routine_statement = seed_payload(&seed_directory, "routine_statement", b'6');
    review_persona_transition_statement_bytes(
        &routine_statement,
        ISSUED_AT + 1,
        &expected_root,
        1,
        None,
        KEY_ONE,
        KEY_TWO,
    )
    .unwrap();

    let terminal = seed_payload(&seed_directory, "terminal_revocation_malformed", b'7');
    assert!(parse_terminal_persona_revocation_proof_bytes(&terminal).is_err());
    let ceremony_request =
        seed_payload(&seed_directory, "recovery_ceremony_request_malformed", b'8');
    assert!(parse_recovery_ceremony_request_bytes(&ceremony_request).is_err());
    let ceremony_response = seed_payload(
        &seed_directory,
        "recovery_ceremony_response_malformed",
        b'9',
    );
    assert!(parse_recovery_ceremony_response_bytes(&ceremony_response).is_err());
}

#[test]
fn production_byte_parsers_reject_noncanonical_signed_payloads() {
    let (mut root, _, _, _, _) = structural_proofs();
    let payload = URL_SAFE_NO_PAD.decode(&root.payload).unwrap();
    let statement: a_quo_core::PersonaRootStatement = serde_json::from_slice(&payload).unwrap();
    root.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec_pretty(&statement).unwrap());

    assert!(parse_persona_root_proof_bytes(&serde_json::to_vec(&root).unwrap()).is_err());
}

#[test]
fn production_byte_parsers_bound_input_before_deserialization() {
    let oversized = vec![b' '; usize::try_from(MAX_PROOF_BYTES).unwrap() + 1];
    for error in [
        parse_persona_root_proof_bytes(&oversized).unwrap_err(),
        parse_persona_transition_proof_bytes(&oversized).unwrap_err(),
        parse_recovery_policy_proof_bytes(&oversized).unwrap_err(),
        parse_recovery_transition_proof_bytes(&oversized).unwrap_err(),
        parse_persona_continuity_transition_proof_bytes(&oversized).unwrap_err(),
    ] {
        assert!(error.to_string().contains("exceeds 1048576 bytes"));
    }

    let oversized_statement = vec![b' '; a_quo_core::MAX_CONTINUITY_PAYLOAD_BYTES + 1];
    assert!(
        review_persona_root_statement_bytes(
            &oversized_statement,
            ISSUED_AT,
            KEY_ONE,
            "Parser Test"
        )
        .unwrap_err()
        .to_string()
        .contains("exceeds 65536 bytes")
    );
}

#[test]
fn production_byte_parsers_reject_recovery_authority_limit_plus_one() {
    let (_, _, mut policy, _, mut recovery) = structural_proofs();

    let payload = URL_SAFE_NO_PAD.decode(&policy.payload).unwrap();
    let mut statement: RecoveryPolicyStatement = serde_json::from_slice(&payload).unwrap();
    statement.recovery_key_fingerprints =
        vec![statement.recovery_key_fingerprints[0].clone(); MAX_RECOVERY_AUTHORITIES + 1];
    policy.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&statement).unwrap());
    let policy_error =
        parse_recovery_policy_proof_bytes(&serde_json::to_vec(&policy).unwrap()).unwrap_err();
    assert!(
        policy_error
            .to_string()
            .contains("2 through 32 authority keys")
    );
    assert_safe_diagnostic(&policy_error.to_string());

    recovery.recovery_signatures =
        vec![recovery.recovery_signatures[0].clone(); MAX_RECOVERY_AUTHORITIES + 1];
    let transition_error =
        parse_recovery_transition_proof_bytes(&serde_json::to_vec(&recovery).unwrap()).unwrap_err();
    assert!(
        transition_error
            .to_string()
            .contains("2 through 32 entries")
    );
    assert_safe_diagnostic(&transition_error.to_string());
}

#[test]
fn production_byte_parsers_reject_truncated_and_duplicate_json() {
    let truncated = b"{";
    let duplicate = br#"{"schema":"first","schema":"second"}"#;

    for input in [truncated.as_slice(), duplicate.as_slice()] {
        for error in [
            parse_persona_root_proof_bytes(input).unwrap_err(),
            parse_persona_transition_proof_bytes(input).unwrap_err(),
            parse_recovery_policy_proof_bytes(input).unwrap_err(),
            parse_recovery_transition_proof_bytes(input).unwrap_err(),
            parse_persona_continuity_transition_proof_bytes(input).unwrap_err(),
        ] {
            assert_safe_diagnostic(&error.to_string());
        }
    }
}

#[test]
fn hostile_json_and_semantic_values_have_bounded_ascii_diagnostics() {
    let hostile_json = br#"{"\u0001\u202e-hostile-field":true}"#;
    let malformed_error = parse_persona_root_proof_bytes(hostile_json).unwrap_err();
    assert_safe_diagnostic(&malformed_error.to_string());
    assert!(!malformed_error.to_string().contains("hostile-field"));

    let (mut root, _, _, _, _) = structural_proofs();
    root.schema = format!("bad\n\u{202e}{}", "x".repeat(2_000));
    let semantic_error =
        parse_persona_root_proof_bytes(&serde_json::to_vec(&root).unwrap()).unwrap_err();
    assert_safe_diagnostic(&semantic_error.to_string());
    assert!(semantic_error.to_string().contains("...; expected "));
    assert!(
        semantic_error
            .to_string()
            .contains(PERSONA_ROOT_PROOF_SCHEMA)
    );
}

fn assert_safe_diagnostic(rendered: &str) {
    assert!(
        rendered
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
        "unsafe diagnostic: {rendered:?}"
    );
    assert!(
        rendered.len() <= 1_100,
        "unbounded diagnostic: {rendered:?}"
    );
}
