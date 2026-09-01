//! Black-box checks against the independently frozen Omarchy risk-record oracle.
//!
//! Expected bytes, hashes, bindings, and the decision rule are established by
//! `fixtures/omarchy-plugin-risk-v1-independent` without A Quo constructors or
//! canonicalization helpers. These tests exercise only public byte parsers and
//! the public joined validator.

use std::fs;
use std::path::PathBuf;

use a_quo_omarchy::risk::{
    LocalPolicyRecord, NativeReportBinding, OperationAction, OperationAssessment,
    PolicyDisposition, PolicyResultRecord, PublisherEvidenceRecord, RiskContractError,
    RiskRecordSet, StructuralRecord, UpdateDeltaRecord, parse_local_policy_record_bytes,
    parse_operation_assessment_bytes, parse_policy_result_record_bytes,
    parse_publisher_evidence_record_bytes, parse_structural_record_bytes,
    parse_update_delta_record_bytes, validate_risk_record_set_shape_and_bindings,
};

fn fixture_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/omarchy-plugin-risk-v1-independent")
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixture_directory().join(name)).unwrap()
}

struct ParsedOracle {
    previous_publisher: PublisherEvidenceRecord,
    previous_structural: StructuralRecord,
    previous_native_reports: Vec<NativeReportBinding>,
    publisher: PublisherEvidenceRecord,
    structural: StructuralRecord,
    delta: UpdateDeltaRecord,
    policy: LocalPolicyRecord,
    result: PolicyResultRecord,
    assessment: OperationAssessment,
}

impl ParsedOracle {
    fn records(&self) -> RiskRecordSet<'_> {
        RiskRecordSet {
            previous_publisher: Some(&self.previous_publisher),
            previous_structural: Some(&self.previous_structural),
            previous_native_reports: &self.previous_native_reports,
            publisher: &self.publisher,
            structural: &self.structural,
            update_delta: Some(&self.delta),
            policy: &self.policy,
            policy_result: &self.result,
            assessment: &self.assessment,
        }
    }
}

fn parse_oracle() -> ParsedOracle {
    ParsedOracle {
        previous_publisher: parse_publisher_evidence_record_bytes(&fixture(
            "publisher-evidence-old.json",
        ))
        .unwrap(),
        previous_structural: parse_structural_record_bytes(&fixture("structural-record-old.json"))
            .unwrap(),
        previous_native_reports: serde_json::from_slice(&fixture("previous-native-reports.json"))
            .unwrap(),
        publisher: parse_publisher_evidence_record_bytes(&fixture("publisher-evidence-new.json"))
            .unwrap(),
        structural: parse_structural_record_bytes(&fixture("structural-record-new.json")).unwrap(),
        delta: parse_update_delta_record_bytes(&fixture("update-delta.json")).unwrap(),
        policy: parse_local_policy_record_bytes(&fixture("local-policy.json")).unwrap(),
        result: parse_policy_result_record_bytes(&fixture("policy-result.json")).unwrap(),
        assessment: parse_operation_assessment_bytes(&fixture("operation-assessment.json"))
            .unwrap(),
    }
}

fn replace_once(bytes: &[u8], needle: &str, replacement: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert_eq!(text.matches(needle).count(), 1);
    text.replacen(needle, replacement, 1).into_bytes()
}

#[test]
fn independent_records_pass_public_parsers_and_joined_validation() {
    let oracle = parse_oracle();
    validate_risk_record_set_shape_and_bindings(&oracle.records()).unwrap();
    assert_eq!(oracle.result.action, OperationAction::Update);
    assert_eq!(oracle.result.decision, PolicyDisposition::Block);
}

#[test]
fn public_parser_rejects_duplicate_keys() {
    let raw = fixture("policy-result.json");
    let mut duplicate = br#"{"action":"update","#.to_vec();
    duplicate.extend_from_slice(&raw[1..]);
    assert!(matches!(
        parse_policy_result_record_bytes(&duplicate),
        Err(RiskContractError::Json { .. })
    ));
}

#[test]
fn public_parser_rejects_noncanonical_bytes() {
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&fixture("publisher-evidence-new.json"));
    assert!(matches!(
        parse_publisher_evidence_record_bytes(&noncanonical),
        Err(RiskContractError::NonCanonical { .. })
    ));
}

#[test]
fn public_parser_rejects_reordered_policy_reasons() {
    let raw = fixture("policy-result.json");
    let first = r#"{"code":"interactive_approval_required","disposition":"require_consent","provider_id":null}"#;
    let second = r#"{"code":"indeterminate_comparison","disposition":"block","provider_id":"oracle.static"}"#;
    let reordered = replace_once(
        &raw,
        &format!(r#""reasons":[{first},{second}]"#),
        &format!(r#""reasons":[{second},{first}]"#),
    );
    assert!(matches!(
        parse_policy_result_record_bytes(&reordered),
        Err(RiskContractError::Invalid { .. })
    ));
}

#[test]
fn public_parser_rejects_reordered_native_report_bindings() {
    let raw = fixture("policy-result.json");
    let binding = r#"{"integration_status":"complete","native_report_schema":"urn:example:oracle-report:v1","native_report_sha256":"c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2","native_report_size":2048,"provider_id":"oracle.static"}"#;
    let later_binding = binding.replace("oracle.static", "zebra.static");
    let reordered = replace_once(
        &raw,
        &format!(r#""native_reports":[{binding}]"#),
        &format!(r#""native_reports":[{later_binding},{binding}]"#),
    );
    assert!(matches!(
        parse_policy_result_record_bytes(&reordered),
        Err(RiskContractError::Invalid { .. })
    ));
}

#[test]
fn public_parser_rejects_decision_that_disagrees_with_reasons() {
    let invalid = replace_once(
        &fixture("policy-result.json"),
        r#""decision":"block""#,
        r#""decision":"require_consent""#,
    );
    assert!(matches!(
        parse_policy_result_record_bytes(&invalid),
        Err(RiskContractError::Invalid { .. })
    ));
}

#[test]
fn joined_validator_rejects_substituted_cross_record_digest() {
    let mut oracle = parse_oracle();
    let substituted = replace_once(
        &fixture("operation-assessment.json"),
        "59807da15580d60660879d6c29e9e6d5b023213649b7be37ba50ce3e3f1c71d1",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    oracle.assessment = parse_operation_assessment_bytes(&substituted).unwrap();
    assert!(matches!(
        validate_risk_record_set_shape_and_bindings(&oracle.records()),
        Err(RiskContractError::Invalid { .. })
    ));
}
