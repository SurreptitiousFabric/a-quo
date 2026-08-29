#![no_main]

use a_quo_core::{
    PersonaContinuityTransitionProof, ProofError, VerifiedPersonaRoot,
    canonical_persona_root_statement_bytes, canonical_persona_transition_statement_bytes,
    new_persona_root_statement_with_anchor, parse_persona_continuity_transition_proof_bytes,
    parse_persona_root_proof_bytes, parse_persona_transition_proof_bytes,
    parse_recovery_policy_proof_bytes, parse_recovery_transition_proof_bytes,
    parse_terminal_persona_revocation_proof_bytes, persona_root_statement_sha256,
    review_persona_root_statement_bytes, review_persona_transition_statement_bytes,
};
use libfuzzer_sys::fuzz_target;

const KEY_ONE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";
const KEY_TWO: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfX7hAdqGfF0mYz2oD88dL84M2yr2KoXqhh7sSRvqHQ";
const ANCHOR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PERSONA: &str = "Parser Test";
const ISSUED_AT: i64 = 1_700_000_000;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    let mode = match selector {
        b'0'..=b'7' => selector - b'0',
        _ => selector % 8,
    };
    match mode {
        0 => check_root_proof(bytes),
        1 => check_routine_proof(bytes),
        2 => check_recovery_policy(bytes),
        3 => check_recovery_transition(bytes),
        4 => check_terminal_revocation(bytes),
        5 => check_transition_union(bytes),
        6 => check_root_statement(bytes),
        7 => check_routine_statement(bytes),
        _ => unreachable!(),
    }
});

fn check_root_proof(bytes: &[u8]) {
    match parse_persona_root_proof_bytes(bytes) {
        Ok(proof) => {
            let canonical_outer = serde_json::to_vec(&proof).unwrap();
            assert_eq!(
                parse_persona_root_proof_bytes(&canonical_outer).unwrap(),
                proof
            );
        }
        Err(error) => assert_safe(error),
    }
}

fn check_terminal_revocation(bytes: &[u8]) {
    match parse_terminal_persona_revocation_proof_bytes(bytes) {
        Ok(proof) => {
            let canonical_outer = serde_json::to_vec(&proof).unwrap();
            assert_eq!(
                parse_terminal_persona_revocation_proof_bytes(&canonical_outer).unwrap(),
                proof
            );
            assert!(matches!(
                parse_persona_continuity_transition_proof_bytes(&canonical_outer).unwrap(),
                PersonaContinuityTransitionProof::TerminalRevocation(_)
            ));
        }
        Err(error) => assert_safe(error),
    }
}

fn check_routine_proof(bytes: &[u8]) {
    match parse_persona_transition_proof_bytes(bytes) {
        Ok(proof) => {
            let canonical_outer = serde_json::to_vec(&proof).unwrap();
            assert_eq!(
                parse_persona_transition_proof_bytes(&canonical_outer).unwrap(),
                proof
            );
            assert!(matches!(
                parse_persona_continuity_transition_proof_bytes(&canonical_outer).unwrap(),
                PersonaContinuityTransitionProof::Routine(_)
            ));
        }
        Err(error) => assert_safe(error),
    }
}

fn check_recovery_policy(bytes: &[u8]) {
    match parse_recovery_policy_proof_bytes(bytes) {
        Ok(proof) => {
            let canonical_outer = serde_json::to_vec(&proof).unwrap();
            assert_eq!(
                parse_recovery_policy_proof_bytes(&canonical_outer).unwrap(),
                proof
            );
        }
        Err(error) => assert_safe(error),
    }
}

fn check_recovery_transition(bytes: &[u8]) {
    match parse_recovery_transition_proof_bytes(bytes) {
        Ok(proof) => {
            let canonical_outer = serde_json::to_vec(&proof).unwrap();
            assert_eq!(
                parse_recovery_transition_proof_bytes(&canonical_outer).unwrap(),
                proof
            );
            assert!(matches!(
                parse_persona_continuity_transition_proof_bytes(&canonical_outer).unwrap(),
                PersonaContinuityTransitionProof::Recovery(_)
            ));
        }
        Err(error) => assert_safe(error),
    }
}

fn check_transition_union(bytes: &[u8]) {
    match parse_persona_continuity_transition_proof_bytes(bytes) {
        Ok(proof) => {
            let canonical_outer = serde_json::to_vec(&proof).unwrap();
            assert_eq!(
                parse_persona_continuity_transition_proof_bytes(&canonical_outer).unwrap(),
                proof
            );
        }
        Err(error) => assert_safe(error),
    }
}

fn check_root_statement(bytes: &[u8]) {
    match review_persona_root_statement_bytes(bytes, ISSUED_AT, KEY_ONE, PERSONA) {
        Ok((statement, _)) => {
            assert_eq!(
                canonical_persona_root_statement_bytes(&statement).unwrap(),
                bytes
            );
        }
        Err(error) => assert_safe(error),
    }
}

fn check_routine_statement(bytes: &[u8]) {
    let root = expected_root();
    match review_persona_transition_statement_bytes(
        bytes,
        ISSUED_AT + 1,
        &root,
        1,
        None,
        KEY_ONE,
        KEY_TWO,
    ) {
        Ok((statement, _)) => {
            assert_eq!(
                canonical_persona_transition_statement_bytes(&statement).unwrap(),
                bytes
            );
        }
        Err(error) => assert_safe(error),
    }
}

fn expected_root() -> VerifiedPersonaRoot {
    let statement =
        new_persona_root_statement_with_anchor(ANCHOR, PERSONA, ISSUED_AT, KEY_ONE).unwrap();
    VerifiedPersonaRoot {
        root_statement_sha256: persona_root_statement_sha256(&statement).unwrap(),
        statement,
        initial_public_key: KEY_ONE.to_owned(),
    }
}

fn assert_safe(error: ProofError) {
    let rendered = error.to_string();
    assert!(
        rendered
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic()),
        "unsafe diagnostic: {rendered:?}"
    );
    assert!(
        rendered.len() <= 2_048,
        "unbounded diagnostic: {rendered:?}"
    );
}
