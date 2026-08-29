use a_quo_core::{
    PERSONA_ROOT_CARD_SCHEMA, PERSONA_ROOT_PIN_SCHEMA, PERSONA_ROOT_PIN_URI_PREFIX,
    PERSONA_ROOT_PROOF_SCHEMA, PersonaRootClaimStatus, PersonaRootMatchStatus,
    PersonaRootSignatureStatus, PersonaRootTrustBasis, compare_persona_root_distribution,
    parse_persona_root_card_bytes, parse_persona_root_pin_bytes, parse_persona_root_proof_bytes,
    persona_root_card_from_proof, verify_persona_root_proof,
};
use a_quo_root_card::{render_root_card_html, render_root_card_text};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const PROOF: &[u8] = include_bytes!("../../../fixtures/persona-root-v1/root-proof.json");
const CARD: &[u8] = include_bytes!("../../../fixtures/persona-root-v1/root-card.json");
const PIN_TOFU: &[u8] = include_bytes!("../../../fixtures/persona-root-v1/root-pin-tofu.json");
const PIN_SAME_CHANNEL: &[u8] =
    include_bytes!("../../../fixtures/persona-root-v1/root-pin-same-channel.json");
const PIN_OUT_OF_BAND: &[u8] =
    include_bytes!("../../../fixtures/persona-root-v1/root-pin-out-of-band.json");
const PIN_URI: &str = include_str!("../../../fixtures/persona-root-v1/pin-uri.txt");
const VECTOR: &[u8] = include_bytes!("../../../fixtures/persona-root-v1/vector.json");

#[test]
fn public_vector_verifies_and_renders_on_the_portable_subset() {
    let vector: Value = serde_json::from_slice(VECTOR).unwrap();
    let proof = parse_persona_root_proof_bytes(PROOF).unwrap();
    let verified = verify_persona_root_proof(&proof).unwrap();
    let card = parse_persona_root_card_bytes(CARD).unwrap();

    assert_eq!(
        vector["component_schemas"]["root_proof"].as_str().unwrap(),
        PERSONA_ROOT_PROOF_SCHEMA
    );
    assert_eq!(
        vector["component_schemas"]["root_card"].as_str().unwrap(),
        PERSONA_ROOT_CARD_SCHEMA
    );
    assert_eq!(
        vector["component_schemas"]["root_pin"].as_str().unwrap(),
        PERSONA_ROOT_PIN_SCHEMA
    );
    assert_eq!(
        vector["component_schemas"]["pin_uri"].as_str().unwrap(),
        PERSONA_ROOT_PIN_URI_PREFIX
    );

    assert_eq!(verified.statement.persona, "JuniperQuill");
    assert_eq!(
        verified.root_statement_sha256,
        vector["root_statement_sha256"].as_str().unwrap()
    );
    assert_eq!(persona_root_card_from_proof(&proof).unwrap(), card);
    assert_eq!(card.pin_uri, PIN_URI);
    assert_eq!(card.pin_uri, vector["pin_uri"].as_str().unwrap());
    assert_eq!(
        sha256(PIN_URI.as_bytes()),
        vector["files"]["pin-uri.txt"].as_str().unwrap()
    );

    for (name, bytes, expected_basis) in [
        (
            "root-pin-tofu.json",
            PIN_TOFU,
            PersonaRootTrustBasis::TrustOnFirstUse,
        ),
        (
            "root-pin-same-channel.json",
            PIN_SAME_CHANNEL,
            PersonaRootTrustBasis::SameChannelCopy,
        ),
        (
            "root-pin-out-of-band.json",
            PIN_OUT_OF_BAND,
            PersonaRootTrustBasis::OutOfBandUserConfirmed,
        ),
    ] {
        let pin = parse_persona_root_pin_bytes(bytes).unwrap();
        let report =
            compare_persona_root_distribution(&proof, Some(&card), &pin, pin.recorded_at + 1)
                .unwrap();
        assert_eq!(pin.trust_basis, expected_basis);
        assert_eq!(report.root_signature, PersonaRootSignatureStatus::Verified);
        assert_eq!(report.card_match, PersonaRootMatchStatus::Matched);
        assert_eq!(report.pin_match, PersonaRootMatchStatus::Matched);
        assert_eq!(
            report.current_signing_authority,
            PersonaRootClaimStatus::NotEstablished
        );
        assert_eq!(
            report.current_recovery_authority,
            PersonaRootClaimStatus::NotEstablished
        );
        assert_eq!(
            report.artifact_truth_or_safety,
            PersonaRootClaimStatus::NotEstablished
        );
        assert!(!report.root_card_possession_grants_authority);
        let report_value = serde_json::to_value(&report).unwrap();
        for (field, expected) in vector["expected_comparison"].as_object().unwrap() {
            assert_eq!(&report_value[field], expected, "comparison field {field}");
        }
        assert_eq!(sha256(bytes), vector["files"][name].as_str().unwrap());
    }

    assert_eq!(
        sha256(PROOF),
        vector["files"]["root-proof.json"].as_str().unwrap()
    );
    assert_eq!(
        sha256(CARD),
        vector["files"]["root-card.json"].as_str().unwrap()
    );
    assert_eq!(
        sha256(render_root_card_text(&card).unwrap().as_bytes()),
        vector["rendered_sha256"]["accessible_text"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        sha256(render_root_card_html(&card).unwrap().as_bytes()),
        vector["rendered_sha256"]["standalone_html"]
            .as_str()
            .unwrap()
    );
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
