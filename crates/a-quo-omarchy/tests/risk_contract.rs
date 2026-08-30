use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use a_quo_omarchy::risk::*;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

fn digest(byte: &str) -> String {
    byte.repeat(64 / byte.len())
}

fn bytes_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn subject(
    artifact: &str,
    artifact_size: u64,
    version: &str,
    manifest: &str,
    stream: &str,
    stream_size: u64,
) -> RiskSubject {
    RiskSubject {
        artifact_sha256: digest(artifact),
        artifact_size,
        package_format: "omarchy-zstd-tar-v1".to_owned(),
        plugin_id: Nullable(Some("test.risk-contract".to_owned())),
        plugin_version: Nullable(Some(version.to_owned())),
        manifest_sha256: Nullable(Some(digest(manifest))),
        analysis_stream_schema: "a-quo-regular-file-stream-v1".to_owned(),
        analysis_stream_sha256: digest(stream),
        analysis_stream_size: stream_size,
    }
}

fn publisher(subject: RiskSubject, proof: &str) -> PublisherEvidenceRecord {
    PublisherEvidenceRecord {
        schema: PUBLISHER_EVIDENCE_SCHEMA.to_owned(),
        subject,
        proof_sha256: digest(proof),
        artifact_integrity: VerifiedStatus::Verified,
        signature: VerifiedStatus::Verified,
        signed_persona: "JuniperQuill".to_owned(),
        signing_key_fingerprint: format!("SHA256:{}", "A".repeat(43)),
        registry_status: RiskPublisherRegistryStatus::Active,
        local_persona_id: Nullable(Some("01234567-89ab-cdef-0123-456789abcdef".to_owned())),
        local_persona_root_sha256: Nullable(Some(digest("55"))),
        signed_label_agreement: Nullable(Some(true)),
        key_status: Nullable(Some(RiskKeyStatus::Active)),
        continuity: RiskContinuityStatus::Verified,
        installation_authority: InstallationAuthority::Authorized,
    }
}

fn old_structural(subject: RiskSubject) -> StructuralRecord {
    StructuralRecord {
        schema: STRUCTURAL_RECORD_SCHEMA.to_owned(),
        subject,
        archive_validation: VerifiedStatus::Verified,
        entries: 3,
        regular_files: 2,
        directories: 1,
        uncompressed_file_bytes: 15,
        links: 0,
        special_entries: 0,
        files: vec![
            StructuralFile {
                path: "manifest.json".to_owned(),
                mode: 420,
                size: 5,
                sha256: digest("11"),
                manifest_entry_point: false,
            },
            StructuralFile {
                path: "plugin/main.sh".to_owned(),
                mode: 493,
                size: 10,
                sha256: digest("22"),
                manifest_entry_point: true,
            },
        ],
        executable_paths: vec!["plugin/main.sh".to_owned()],
        manifest_entry_point_paths: vec!["plugin/main.sh".to_owned()],
        hidden_executable_paths: vec![],
        executable_not_manifest_entry_point_paths: vec![],
        omarchy_manifest_validation: ManifestValidatorStatus::Passed,
    }
}

fn current_structural(subject: RiskSubject) -> StructuralRecord {
    StructuralRecord {
        schema: STRUCTURAL_RECORD_SCHEMA.to_owned(),
        subject,
        archive_validation: VerifiedStatus::Verified,
        entries: 5,
        regular_files: 3,
        directories: 2,
        uncompressed_file_bytes: 20,
        links: 0,
        special_entries: 0,
        files: vec![
            StructuralFile {
                path: ".hidden/tool".to_owned(),
                mode: 493,
                size: 3,
                sha256: digest("99"),
                manifest_entry_point: false,
            },
            StructuralFile {
                path: "manifest.json".to_owned(),
                mode: 420,
                size: 6,
                sha256: digest("33"),
                manifest_entry_point: false,
            },
            StructuralFile {
                path: "plugin/main.sh".to_owned(),
                mode: 493,
                size: 11,
                sha256: digest("44"),
                manifest_entry_point: true,
            },
        ],
        executable_paths: vec![".hidden/tool".to_owned(), "plugin/main.sh".to_owned()],
        manifest_entry_point_paths: vec!["plugin/main.sh".to_owned()],
        hidden_executable_paths: vec![".hidden/tool".to_owned()],
        executable_not_manifest_entry_point_paths: vec![".hidden/tool".to_owned()],
        omarchy_manifest_validation: ManifestValidatorStatus::Passed,
    }
}

fn policy() -> LocalPolicyRecord {
    LocalPolicyRecord {
        schema: LOCAL_POLICY_SCHEMA.to_owned(),
        policy_id: "default.desktop".to_owned(),
        revision: 1,
        required_provider_ids: vec!["static.analysis".to_owned()],
        provider_handling: ProviderHandlingPolicy {
            missing_required: PolicyDisposition::Block,
            incomplete: PolicyDisposition::RequireConsent,
            error: PolicyDisposition::Block,
            unsupported: PolicyDisposition::Block,
            not_run: PolicyDisposition::Block,
        },
        update_handling: UpdateHandlingPolicy {
            indeterminate_comparison: PolicyDisposition::Block,
        },
        interactive_approval: PolicyDisposition::RequireConsent,
    }
}

fn file_state(sha256: &str, mode: u16) -> FileState {
    FileState {
        sha256: digest(sha256),
        mode,
    }
}

struct Vector {
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

fn build_vector() -> Vector {
    let previous_subject = subject("aa", 100, "1.0.0", "11", "bb", 158);
    let subject = subject("cc", 120, "1.1.0", "33", "dd", 223);
    let previous_publisher = publisher(previous_subject.clone(), "ee");
    let previous_structural = old_structural(previous_subject.clone());
    let publisher = publisher(subject.clone(), "ff");
    let structural = current_structural(subject.clone());
    let policy = policy();
    let previous_native_reports = vec![NativeReportBinding {
        provider_id: "static.analysis".to_owned(),
        native_report_schema: Nullable(Some("urn:plug-prejudice:report:v2".to_owned())),
        native_report_sha256: Nullable(Some(digest("66"))),
        native_report_size: Nullable(Some(1_024)),
        integration_status: AnalysisIntegrationStatus::Complete,
    }];
    let native_reports = vec![NativeReportBinding {
        provider_id: "static.analysis".to_owned(),
        native_report_schema: Nullable(Some("urn:plug-prejudice:report:v2".to_owned())),
        native_report_sha256: Nullable(Some(digest("77"))),
        native_report_size: Nullable(Some(2_048)),
        integration_status: AnalysisIntegrationStatus::Complete,
    }];
    let delta = UpdateDeltaRecord {
        schema: UPDATE_DELTA_SCHEMA.to_owned(),
        previous_subject,
        subject: subject.clone(),
        previous_publisher_evidence_sha256: publisher_evidence_record_sha256(&previous_publisher)
            .unwrap(),
        publisher_evidence_sha256: publisher_evidence_record_sha256(&publisher).unwrap(),
        previous_structural_record_sha256: structural_record_sha256(&previous_structural).unwrap(),
        structural_record_sha256: structural_record_sha256(&structural).unwrap(),
        publisher_continuity: PublisherContinuityDelta::Matched,
        plugin_id: PluginIdDelta::Unchanged,
        version: VersionDelta::Upgrade,
        files: vec![
            FileDelta {
                path: ".hidden/tool".to_owned(),
                change: FileChangeKind::Added,
                previous: Nullable(None),
                current: Nullable(Some(file_state("99", 493))),
            },
            FileDelta {
                path: "manifest.json".to_owned(),
                change: FileChangeKind::ContentChanged,
                previous: Nullable(Some(file_state("11", 420))),
                current: Nullable(Some(file_state("33", 420))),
            },
            FileDelta {
                path: "plugin/main.sh".to_owned(),
                change: FileChangeKind::ContentChanged,
                previous: Nullable(Some(file_state("22", 493))),
                current: Nullable(Some(file_state("44", 493))),
            },
        ],
        providers: vec![ProviderDelta {
            provider_id: "static.analysis".to_owned(),
            previous_native_report_sha256: Nullable(Some(digest("66"))),
            current_native_report_sha256: Nullable(Some(digest("77"))),
        }],
        fresh_consent_required: true,
    };
    let operation_id = digest("ab");
    let result = PolicyResultRecord {
        schema: POLICY_RESULT_SCHEMA.to_owned(),
        operation_id: operation_id.clone(),
        action: OperationAction::Update,
        subject: subject.clone(),
        policy_sha256: local_policy_record_sha256(&policy).unwrap(),
        publisher_evidence_sha256: publisher_evidence_record_sha256(&publisher).unwrap(),
        structural_record_sha256: structural_record_sha256(&structural).unwrap(),
        update_delta_sha256: Nullable(Some(update_delta_record_sha256(&delta).unwrap())),
        native_reports: native_reports.clone(),
        decision: PolicyDisposition::Block,
        reasons: vec![
            PolicyReason {
                code: PolicyReasonCode::InteractiveApprovalRequired,
                disposition: PolicyDisposition::RequireConsent,
                provider_id: Nullable(None),
            },
            PolicyReason {
                code: PolicyReasonCode::IndeterminateComparison,
                disposition: PolicyDisposition::Block,
                provider_id: Nullable(Some("static.analysis".to_owned())),
            },
        ],
    };
    let assessment = OperationAssessment {
        schema: OPERATION_ASSESSMENT_SCHEMA.to_owned(),
        operation_id,
        action: OperationAction::Update,
        subject,
        destination: "/home/test/.config/omarchy/plugins/test.risk-contract".to_owned(),
        destination_parent_device: "1".to_owned(),
        destination_parent_inode: "2".to_owned(),
        registry_sha256: digest("12"),
        publisher_evidence_sha256: publisher_evidence_record_sha256(&publisher).unwrap(),
        structural_record_sha256: structural_record_sha256(&structural).unwrap(),
        update_delta_sha256: Nullable(Some(update_delta_record_sha256(&delta).unwrap())),
        policy_sha256: local_policy_record_sha256(&policy).unwrap(),
        policy_result_sha256: policy_result_record_sha256(&result).unwrap(),
        native_reports,
        issued_at_unix: 1_800_000_000,
        expires_at_unix: 1_800_000_300,
    };
    Vector {
        previous_publisher,
        previous_structural,
        previous_native_reports,
        publisher,
        structural,
        delta,
        policy,
        result,
        assessment,
    }
}

fn rebind_vector(vector: &mut Vector) {
    vector.delta.previous_publisher_evidence_sha256 =
        publisher_evidence_record_sha256(&vector.previous_publisher).unwrap();
    vector.delta.publisher_evidence_sha256 =
        publisher_evidence_record_sha256(&vector.publisher).unwrap();
    vector.delta.previous_structural_record_sha256 =
        structural_record_sha256(&vector.previous_structural).unwrap();
    vector.delta.structural_record_sha256 = structural_record_sha256(&vector.structural).unwrap();

    vector.result.publisher_evidence_sha256 =
        publisher_evidence_record_sha256(&vector.publisher).unwrap();
    vector.result.structural_record_sha256 = structural_record_sha256(&vector.structural).unwrap();
    vector.result.update_delta_sha256 =
        Nullable(Some(update_delta_record_sha256(&vector.delta).unwrap()));

    vector.assessment.publisher_evidence_sha256 =
        publisher_evidence_record_sha256(&vector.publisher).unwrap();
    vector.assessment.structural_record_sha256 =
        structural_record_sha256(&vector.structural).unwrap();
    vector.assessment.update_delta_sha256 =
        Nullable(Some(update_delta_record_sha256(&vector.delta).unwrap()));
    vector.assessment.policy_result_sha256 = policy_result_record_sha256(&vector.result).unwrap();
}

fn validate_vector(vector: &Vector) -> RiskResult<()> {
    validate_risk_record_set_shape_and_bindings(&RiskRecordSet {
        previous_publisher: Some(&vector.previous_publisher),
        previous_structural: Some(&vector.previous_structural),
        previous_native_reports: &vector.previous_native_reports,
        publisher: &vector.publisher,
        structural: &vector.structural,
        update_delta: Some(&vector.delta),
        policy: &vector.policy,
        policy_result: &vector.result,
        assessment: &vector.assessment,
    })
}

#[test]
fn every_record_is_canonical_and_cross_bound() {
    let vector = build_vector();
    let publisher = canonical_publisher_evidence_record_bytes(&vector.publisher).unwrap();
    let structural = canonical_structural_record_bytes(&vector.structural).unwrap();
    let delta = canonical_update_delta_record_bytes(&vector.delta).unwrap();
    let policy = canonical_local_policy_record_bytes(&vector.policy).unwrap();
    let result = canonical_policy_result_record_bytes(&vector.result).unwrap();
    let assessment = canonical_operation_assessment_bytes(&vector.assessment).unwrap();

    assert_eq!(
        parse_publisher_evidence_record_bytes(&publisher).unwrap(),
        vector.publisher
    );
    assert_eq!(
        parse_structural_record_bytes(&structural).unwrap(),
        vector.structural
    );
    assert_eq!(
        parse_update_delta_record_bytes(&delta).unwrap(),
        vector.delta
    );
    assert_eq!(
        parse_local_policy_record_bytes(&policy).unwrap(),
        vector.policy
    );
    assert_eq!(
        parse_policy_result_record_bytes(&result).unwrap(),
        vector.result
    );
    assert_eq!(
        parse_operation_assessment_bytes(&assessment).unwrap(),
        vector.assessment
    );
    validate_risk_record_set_shape_and_bindings(&RiskRecordSet {
        previous_publisher: Some(&vector.previous_publisher),
        previous_structural: Some(&vector.previous_structural),
        previous_native_reports: &vector.previous_native_reports,
        publisher: &vector.publisher,
        structural: &vector.structural,
        update_delta: Some(&vector.delta),
        policy: &vector.policy,
        policy_result: &vector.result,
        assessment: &vector.assessment,
    })
    .unwrap();
}

#[test]
fn required_null_unknown_fields_and_noncanonical_json_are_rejected() {
    let vector = build_vector();
    let canonical = canonical_publisher_evidence_record_bytes(&vector.publisher).unwrap();
    let mut pretty = b" \n".to_vec();
    pretty.extend_from_slice(&canonical);
    assert!(matches!(
        parse_publisher_evidence_record_bytes(&pretty),
        Err(RiskContractError::NonCanonical { .. })
    ));

    let mut value = serde_json::to_value(&vector.publisher).unwrap();
    value.as_object_mut().unwrap().remove("local_persona_id");
    let missing = serde_json_canonicalizer::to_vec(&value).unwrap();
    assert!(matches!(
        parse_publisher_evidence_record_bytes(&missing),
        Err(RiskContractError::Json { .. })
    ));

    let mut value = serde_json::to_value(&vector.publisher).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("trusted".to_owned(), serde_json::Value::Bool(true));
    let unknown = serde_json_canonicalizer::to_vec(&value).unwrap();
    assert!(matches!(
        parse_publisher_evidence_record_bytes(&unknown),
        Err(RiskContractError::Json { .. })
    ));
}

#[test]
fn subject_digest_file_delta_and_reason_tampering_are_rejected() {
    let mut vector = build_vector();
    vector.delta.files[1].current.0.as_mut().unwrap().sha256 = digest("aa");
    assert!(canonical_update_delta_record_bytes(&vector.delta).is_ok());
    assert!(
        validate_risk_record_set_shape_and_bindings(&RiskRecordSet {
            previous_publisher: Some(&vector.previous_publisher),
            previous_structural: Some(&vector.previous_structural),
            previous_native_reports: &vector.previous_native_reports,
            publisher: &vector.publisher,
            structural: &vector.structural,
            update_delta: Some(&vector.delta),
            policy: &vector.policy,
            policy_result: &vector.result,
            assessment: &vector.assessment,
        })
        .is_err()
    );

    let mut vector = build_vector();
    vector.result.reasons.pop();
    assert!(
        validate_risk_record_set_shape_and_bindings(&RiskRecordSet {
            previous_publisher: Some(&vector.previous_publisher),
            previous_structural: Some(&vector.previous_structural),
            previous_native_reports: &vector.previous_native_reports,
            publisher: &vector.publisher,
            structural: &vector.structural,
            update_delta: Some(&vector.delta),
            policy: &vector.policy,
            policy_result: &vector.result,
            assessment: &vector.assessment,
        })
        .is_err()
    );
}

#[test]
fn policy_has_no_silent_allow_or_safe_state() {
    let vector = build_vector();
    let mut value = serde_json::to_value(&vector.result).unwrap();
    value["decision"] = serde_json::Value::String("safe".to_owned());
    let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
    assert!(matches!(
        parse_policy_result_record_bytes(&bytes),
        Err(RiskContractError::Json { .. })
    ));

    let mut policy = vector.policy;
    policy.interactive_approval = PolicyDisposition::Block;
    assert!(canonical_local_policy_record_bytes(&policy).is_err());
}

#[test]
fn hostile_paths_bounds_and_diagnostics_fail_closed() {
    let mut vector = build_vector();
    vector.structural.files[0].path = "bad\u{202e}path".to_owned();
    let error = canonical_structural_record_bytes(&vector.structural).unwrap_err();
    let diagnostic = error.to_string();
    assert!(diagnostic.is_ascii());
    assert!(diagnostic.len() < 256);

    let oversized = vec![b' '; MAX_RISK_RECORD_BYTES + 1];
    assert!(matches!(
        parse_local_policy_record_bytes(&oversized),
        Err(RiskContractError::TooLarge { .. })
    ));

    let mut vector = build_vector();
    vector.assessment.issued_at_unix = 9_007_199_254_740_992;
    assert!(canonical_operation_assessment_bytes(&vector.assessment).is_err());

    let mut vector = build_vector();
    vector.publisher.local_persona_id =
        Nullable(Some("00000000-0000-0000-0000-000000000000".to_owned()));
    assert!(canonical_publisher_evidence_record_bytes(&vector.publisher).is_err());

    let mut vector = build_vector();
    vector.result.operation_id = digest("0");
    assert!(canonical_policy_result_record_bytes(&vector.result).is_err());
    vector.assessment.operation_id = digest("0");
    assert!(canonical_operation_assessment_bytes(&vector.assessment).is_err());
}

#[test]
fn install_requires_explicit_null_delta_and_interactive_consent() {
    let mut vector = build_vector();
    vector.result.action = OperationAction::Install;
    vector.result.update_delta_sha256 = Nullable(None);
    vector.result.decision = PolicyDisposition::RequireConsent;
    vector.result.reasons.truncate(1);
    vector.assessment.action = OperationAction::Install;
    vector.assessment.update_delta_sha256 = Nullable(None);
    vector.assessment.policy_result_sha256 = policy_result_record_sha256(&vector.result).unwrap();
    validate_risk_record_set_shape_and_bindings(&RiskRecordSet {
        previous_publisher: None,
        previous_structural: None,
        previous_native_reports: &[],
        publisher: &vector.publisher,
        structural: &vector.structural,
        update_delta: None,
        policy: &vector.policy,
        policy_result: &vector.result,
        assessment: &vector.assessment,
    })
    .unwrap();

    vector.result.update_delta_sha256 = Nullable(Some(digest("99")));
    assert!(canonical_policy_result_record_bytes(&vector.result).is_err());
}

#[test]
fn missing_required_provider_is_an_explicit_block() {
    let mut vector = build_vector();
    vector.result.action = OperationAction::Install;
    vector.result.update_delta_sha256 = Nullable(None);
    vector.result.native_reports.clear();
    vector.result.decision = PolicyDisposition::Block;
    vector.result.reasons = vec![
        PolicyReason {
            code: PolicyReasonCode::InteractiveApprovalRequired,
            disposition: PolicyDisposition::RequireConsent,
            provider_id: Nullable(None),
        },
        PolicyReason {
            code: PolicyReasonCode::MissingRequiredProvider,
            disposition: PolicyDisposition::Block,
            provider_id: Nullable(Some("static.analysis".to_owned())),
        },
    ];
    vector.assessment.action = OperationAction::Install;
    vector.assessment.update_delta_sha256 = Nullable(None);
    vector.assessment.native_reports.clear();
    vector.assessment.policy_result_sha256 = policy_result_record_sha256(&vector.result).unwrap();

    validate_risk_record_set_shape_and_bindings(&RiskRecordSet {
        previous_publisher: None,
        previous_structural: None,
        previous_native_reports: &[],
        publisher: &vector.publisher,
        structural: &vector.structural,
        update_delta: None,
        policy: &vector.policy,
        policy_result: &vector.result,
        assessment: &vector.assessment,
    })
    .unwrap();
}

#[test]
fn install_without_an_optional_provider_requires_explicit_consent() {
    let mut vector = build_vector();
    vector.policy.required_provider_ids.clear();
    vector.result.action = OperationAction::Install;
    vector.result.policy_sha256 = local_policy_record_sha256(&vector.policy).unwrap();
    vector.result.update_delta_sha256 = Nullable(None);
    vector.result.native_reports.clear();
    vector.result.decision = PolicyDisposition::RequireConsent;
    vector.result.reasons.truncate(1);
    vector.assessment.action = OperationAction::Install;
    vector.assessment.update_delta_sha256 = Nullable(None);
    vector.assessment.policy_sha256 = local_policy_record_sha256(&vector.policy).unwrap();
    vector.assessment.native_reports.clear();
    vector.assessment.policy_result_sha256 = policy_result_record_sha256(&vector.result).unwrap();

    validate_risk_record_set_shape_and_bindings(&RiskRecordSet {
        previous_publisher: None,
        previous_structural: None,
        previous_native_reports: &[],
        publisher: &vector.publisher,
        structural: &vector.structural,
        update_delta: None,
        policy: &vector.policy,
        policy_result: &vector.result,
        assessment: &vector.assessment,
    })
    .unwrap();
}

#[test]
fn not_run_is_explicit_and_cannot_carry_fake_report_bytes() {
    let mut vector = build_vector();
    let binding = &mut vector.result.native_reports[0];
    binding.integration_status = AnalysisIntegrationStatus::NotRun;
    binding.native_report_schema = Nullable(None);
    binding.native_report_sha256 = Nullable(None);
    binding.native_report_size = Nullable(None);
    vector.assessment.native_reports = vector.result.native_reports.clone();
    vector.delta.providers[0].current_native_report_sha256 = Nullable(None);
    vector.result.reasons = vec![
        PolicyReason {
            code: PolicyReasonCode::InteractiveApprovalRequired,
            disposition: PolicyDisposition::RequireConsent,
            provider_id: Nullable(None),
        },
        PolicyReason {
            code: PolicyReasonCode::ProviderNotRun,
            disposition: PolicyDisposition::Block,
            provider_id: Nullable(Some("static.analysis".to_owned())),
        },
        PolicyReason {
            code: PolicyReasonCode::IndeterminateComparison,
            disposition: PolicyDisposition::Block,
            provider_id: Nullable(Some("static.analysis".to_owned())),
        },
    ];
    rebind_vector(&mut vector);
    assert!(validate_vector(&vector).is_ok());

    vector.result.native_reports[0].native_report_sha256 = Nullable(Some(digest("77")));
    vector.result.native_reports[0].native_report_size = Nullable(Some(2_048));
    assert!(canonical_policy_result_record_bytes(&vector.result).is_err());
}

#[test]
fn missing_manifest_validator_result_is_a_hard_block_not_safe() {
    let mut vector = build_vector();
    vector.structural.omarchy_manifest_validation = ManifestValidatorStatus::NotRun;
    vector.result.action = OperationAction::Install;
    vector.result.update_delta_sha256 = Nullable(None);
    vector.result.structural_record_sha256 = structural_record_sha256(&vector.structural).unwrap();
    vector.result.decision = PolicyDisposition::Block;
    vector.result.reasons = vec![
        PolicyReason {
            code: PolicyReasonCode::InteractiveApprovalRequired,
            disposition: PolicyDisposition::RequireConsent,
            provider_id: Nullable(None),
        },
        PolicyReason {
            code: PolicyReasonCode::ManifestValidatorNotPassed,
            disposition: PolicyDisposition::Block,
            provider_id: Nullable(None),
        },
    ];
    vector.assessment.action = OperationAction::Install;
    vector.assessment.update_delta_sha256 = Nullable(None);
    vector.assessment.structural_record_sha256 =
        structural_record_sha256(&vector.structural).unwrap();
    vector.assessment.policy_result_sha256 = policy_result_record_sha256(&vector.result).unwrap();
    validate_risk_record_set_shape_and_bindings(&RiskRecordSet {
        previous_publisher: None,
        previous_structural: None,
        previous_native_reports: &[],
        publisher: &vector.publisher,
        structural: &vector.structural,
        update_delta: None,
        policy: &vector.policy,
        policy_result: &vector.result,
        assessment: &vector.assessment,
    })
    .unwrap();
}

#[test]
fn duplicate_members_invalid_utf8_trailing_bytes_and_array_reordering_fail() {
    let vector = build_vector();
    let canonical = canonical_local_policy_record_bytes(&vector.policy).unwrap();
    let mut duplicate = br#"{"schema":"urn:a-quo:duplicate:test","#.to_vec();
    duplicate.extend_from_slice(&canonical[1..]);
    assert!(matches!(
        parse_local_policy_record_bytes(&duplicate),
        Err(RiskContractError::Json { .. })
    ));

    let mut trailing = canonical.clone();
    trailing.extend_from_slice(b"{}");
    assert!(matches!(
        parse_local_policy_record_bytes(&trailing),
        Err(RiskContractError::Json { .. })
    ));

    let invalid_utf8 = [b'{', 0xff, b'}'];
    assert!(matches!(
        parse_local_policy_record_bytes(&invalid_utf8),
        Err(RiskContractError::Json { .. })
    ));

    let mut policy = vector.policy;
    policy.required_provider_ids = vec!["z.provider".to_owned(), "a.provider".to_owned()];
    assert!(canonical_local_policy_record_bytes(&policy).is_err());
}

#[test]
fn semver_build_metadata_cannot_fake_an_upgrade() {
    let mut vector = build_vector();
    vector.delta.previous_subject.plugin_version = Nullable(Some("1.0.0+aaa".to_owned()));
    vector.delta.subject.plugin_version = Nullable(Some("1.0.0+zzz".to_owned()));
    vector.delta.version = VersionDelta::Upgrade;
    assert!(canonical_update_delta_record_bytes(&vector.delta).is_err());

    vector.delta.version = VersionDelta::Equal;
    assert!(canonical_update_delta_record_bytes(&vector.delta).is_ok());
}

#[test]
fn publisher_continuity_and_native_report_bindings_are_derived() {
    let mut vector = build_vector();
    vector.publisher.local_persona_id =
        Nullable(Some("11234567-89ab-cdef-0123-456789abcdef".to_owned()));
    rebind_vector(&mut vector);
    assert!(validate_vector(&vector).is_err());

    let mut vector = build_vector();
    vector.previous_native_reports[0].native_report_sha256 = Nullable(Some(digest("99")));
    assert!(validate_vector(&vector).is_err());

    let mut vector = build_vector();
    vector.delta.providers[0].previous_native_report_sha256 = Nullable(None);
    vector.delta.providers[0].current_native_report_sha256 = Nullable(None);
    assert!(canonical_update_delta_record_bytes(&vector.delta).is_ok());
    assert!(validate_vector(&vector).is_err());

    let mut vector = build_vector();
    vector.result.reasons[1].provider_id = Nullable(Some("ghost.provider".to_owned()));
    vector.assessment.policy_result_sha256 = policy_result_record_sha256(&vector.result).unwrap();
    assert!(validate_vector(&vector).is_err());
}

#[test]
fn structural_stream_manifest_and_assessment_bounds_are_exact() {
    let mut vector = build_vector();
    vector.structural.subject.analysis_stream_size += 1;
    assert!(canonical_structural_record_bytes(&vector.structural).is_err());

    let mut vector = build_vector();
    let manifest = vector
        .structural
        .files
        .iter_mut()
        .find(|file| file.path == "manifest.json")
        .unwrap();
    let increase = 65_537 - manifest.size;
    manifest.size = 65_537;
    vector.structural.uncompressed_file_bytes += increase;
    vector.structural.subject.analysis_stream_size += increase;
    assert!(canonical_structural_record_bytes(&vector.structural).is_err());

    let mut vector = build_vector();
    vector.assessment.destination = format!("/{}", "a".repeat(MAX_RISK_PATH_BYTES));
    assert!(canonical_operation_assessment_bytes(&vector.assessment).is_err());
    vector.assessment.destination = "/valid".to_owned();
    vector.assessment.destination_parent_inode = "1".repeat(17);
    assert!(canonical_operation_assessment_bytes(&vector.assessment).is_err());
}

#[test]
fn json_depth_and_native_report_nullability_fail_closed() {
    let mut too_deep = vec![b'['; 17];
    too_deep.extend(std::iter::repeat_n(b']', 17));
    assert!(matches!(
        parse_publisher_evidence_record_bytes(&too_deep),
        Err(RiskContractError::Invalid { .. })
    ));

    let mut vector = build_vector();
    vector.result.native_reports[0].native_report_schema = Nullable(None);
    assert!(canonical_policy_result_record_bytes(&vector.result).is_err());

    let mut vector = build_vector();
    vector.result.native_reports[0].native_report_sha256 = Nullable(None);
    assert!(canonical_policy_result_record_bytes(&vector.result).is_err());

    let mut vector = build_vector();
    vector.result.native_reports[0].integration_status = AnalysisIntegrationStatus::Incomplete;
    assert!(canonical_policy_result_record_bytes(&vector.result).is_ok());
    vector.result.native_reports[0].native_report_size = Nullable(None);
    assert!(canonical_policy_result_record_bytes(&vector.result).is_err());

    let mut vector = build_vector();
    let binding = &mut vector.result.native_reports[0];
    binding.integration_status = AnalysisIntegrationStatus::Error;
    binding.native_report_schema = Nullable(None);
    binding.native_report_sha256 = Nullable(None);
    binding.native_report_size = Nullable(None);
    assert!(canonical_policy_result_record_bytes(&vector.result).is_ok());

    let mut vector = build_vector();
    let binding = &mut vector.result.native_reports[0];
    binding.integration_status = AnalysisIntegrationStatus::Unsupported;
    binding.native_report_schema = Nullable(None);
    assert!(canonical_policy_result_record_bytes(&vector.result).is_ok());

    let mut vector = build_vector();
    vector.result.native_reports[0].integration_status = AnalysisIntegrationStatus::NotRun;
    vector.result.native_reports[0].native_report_schema = Nullable(None);
    vector.result.native_reports[0].native_report_sha256 = Nullable(None);
    vector.result.native_reports[0].native_report_size = Nullable(None);
    assert!(canonical_policy_result_record_bytes(&vector.result).is_ok());
    vector.result.native_reports[0].native_report_sha256 = Nullable(Some(digest("77")));
    vector.result.native_reports[0].native_report_size = Nullable(Some(2_048));
    assert!(canonical_policy_result_record_bytes(&vector.result).is_err());
}

#[test]
fn native_report_byte_bound_matches_the_published_schema() {
    const MAX_NATIVE_REPORT_BYTES: u64 = 16 * 1024 * 1024;

    let mut vector = build_vector();
    vector.result.native_reports[0].native_report_size = Nullable(Some(MAX_NATIVE_REPORT_BYTES));
    assert!(canonical_policy_result_record_bytes(&vector.result).is_ok());
    vector.result.native_reports[0].native_report_size =
        Nullable(Some(MAX_NATIVE_REPORT_BYTES + 1));
    assert!(canonical_policy_result_record_bytes(&vector.result).is_err());

    let common: serde_json::Value =
        serde_json::from_slice(&fs::read(schema_directory().join("common.schema.json")).unwrap())
            .unwrap();
    assert_eq!(
        common
            .pointer(
                "/$defs/nativeReportBinding/properties/native_report_size/oneOf/0/allOf/1/maximum"
            )
            .and_then(serde_json::Value::as_u64),
        Some(MAX_NATIVE_REPORT_BYTES)
    );
}

#[test]
fn typed_canonicalization_stops_at_the_record_byte_bound() {
    let mut vector = build_vector();
    for index in 0..300 {
        let path = format!("payload/{index:04}-{}", "a".repeat(3_980));
        vector.structural.subject.analysis_stream_size += 49 + path.len() as u64;
        vector.structural.files.push(StructuralFile {
            path,
            mode: 420,
            size: 1,
            sha256: digest("88"),
            manifest_entry_point: false,
        });
    }
    vector
        .structural
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    vector.structural.entries += 300;
    vector.structural.regular_files += 300;
    vector.structural.uncompressed_file_bytes += 300;
    assert!(matches!(
        canonical_structural_record_bytes(&vector.structural),
        Err(RiskContractError::TooLarge { .. })
    ));
}

#[derive(Serialize)]
struct GoldenFile {
    schema: String,
    size: usize,
    sha256: String,
}

#[derive(Serialize)]
struct GoldenManifest {
    schema: &'static str,
    provenance: &'static str,
    generator_source_sha256: String,
    files: BTreeMap<String, GoldenFile>,
    expected_operation: &'static str,
    expected_decision: &'static str,
    nonclaims: [&'static str; 5],
}

fn fixture_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/omarchy-plugin-risk-v1")
}

fn schema_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("schemas/omarchy-plugin-risk-v1")
}

fn golden_records(vector: &Vector) -> Vec<(&'static str, &'static str, Vec<u8>)> {
    vec![
        (
            "publisher-evidence-old.json",
            PUBLISHER_EVIDENCE_SCHEMA,
            canonical_publisher_evidence_record_bytes(&vector.previous_publisher).unwrap(),
        ),
        (
            "publisher-evidence-new.json",
            PUBLISHER_EVIDENCE_SCHEMA,
            canonical_publisher_evidence_record_bytes(&vector.publisher).unwrap(),
        ),
        (
            "structural-record-old.json",
            STRUCTURAL_RECORD_SCHEMA,
            canonical_structural_record_bytes(&vector.previous_structural).unwrap(),
        ),
        (
            "structural-record-new.json",
            STRUCTURAL_RECORD_SCHEMA,
            canonical_structural_record_bytes(&vector.structural).unwrap(),
        ),
        (
            "update-delta.json",
            UPDATE_DELTA_SCHEMA,
            canonical_update_delta_record_bytes(&vector.delta).unwrap(),
        ),
        (
            "local-policy.json",
            LOCAL_POLICY_SCHEMA,
            canonical_local_policy_record_bytes(&vector.policy).unwrap(),
        ),
        (
            "policy-result.json",
            POLICY_RESULT_SCHEMA,
            canonical_policy_result_record_bytes(&vector.result).unwrap(),
        ),
        (
            "operation-assessment.json",
            OPERATION_ASSESSMENT_SCHEMA,
            canonical_operation_assessment_bytes(&vector.assessment).unwrap(),
        ),
    ]
}

fn golden_manifest(records: &[(&str, &str, Vec<u8>)]) -> Vec<u8> {
    let files = records
        .iter()
        .map(|(name, schema, bytes)| {
            (
                (*name).to_owned(),
                GoldenFile {
                    schema: (*schema).to_owned(),
                    size: bytes.len(),
                    sha256: bytes_sha256(bytes),
                },
            )
        })
        .collect();
    serde_json_canonicalizer::to_vec(&GoldenManifest {
        schema: "urn:a-quo:test-vector:omarchy-plugin-risk:v1",
        provenance: "fictional_synthetic_records_without_private_keys",
        generator_source_sha256: bytes_sha256(include_bytes!("risk_contract.rs")),
        files,
        expected_operation: "update",
        expected_decision: "block",
        nonclaims: [
            "artifact_safety",
            "legal_identity",
            "provider_independence",
            "native_report_semantics",
            "production_readiness",
        ],
    })
    .unwrap()
}

fn fuzz_seed_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fuzz/seeds/omarchy_risk_records_bytes")
}

fn fuzz_seeds(vector: &Vector) -> Vec<(&'static str, Vec<u8>)> {
    [
        (
            "publisher",
            b'0',
            canonical_publisher_evidence_record_bytes(&vector.publisher).unwrap(),
        ),
        (
            "structural",
            b'1',
            canonical_structural_record_bytes(&vector.structural).unwrap(),
        ),
        (
            "delta",
            b'2',
            canonical_update_delta_record_bytes(&vector.delta).unwrap(),
        ),
        (
            "policy",
            b'3',
            canonical_local_policy_record_bytes(&vector.policy).unwrap(),
        ),
        (
            "result",
            b'4',
            canonical_policy_result_record_bytes(&vector.result).unwrap(),
        ),
        (
            "assessment",
            b'5',
            canonical_operation_assessment_bytes(&vector.assessment).unwrap(),
        ),
    ]
    .into_iter()
    .map(|(name, selector, bytes)| {
        let mut seed = Vec::with_capacity(bytes.len() + 1);
        seed.push(selector);
        seed.extend_from_slice(&bytes);
        (name, seed)
    })
    .collect()
}

#[test]
fn committed_golden_vectors_match_exact_canonical_bytes() {
    let vector = build_vector();
    let records = golden_records(&vector);
    let manifest = golden_manifest(&records);
    let directory = fixture_directory();
    let seeds = fuzz_seeds(&vector);
    let seed_directory = fuzz_seed_directory();
    let update = std::env::var_os("A_QUO_UPDATE_RISK_VECTORS").is_some();
    if update {
        fs::create_dir_all(&directory).unwrap();
        fs::create_dir_all(&seed_directory).unwrap();
        for (name, _, bytes) in &records {
            fs::write(directory.join(name), bytes).unwrap();
        }
        fs::write(directory.join("vector.json"), &manifest).unwrap();
        for (name, bytes) in &seeds {
            fs::write(seed_directory.join(name), bytes).unwrap();
        }
    }
    for (name, _, bytes) in &records {
        assert_eq!(fs::read(directory.join(name)).unwrap(), *bytes, "{name}");
    }
    assert_eq!(fs::read(directory.join("vector.json")).unwrap(), manifest);
    for (name, bytes) in &seeds {
        assert_eq!(
            fs::read(seed_directory.join(name)).unwrap(),
            *bytes,
            "{name}"
        );
    }
}

fn assert_schema_nodes_closed_and_bounded(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if object.get("type").and_then(serde_json::Value::as_str) == Some("object") {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&serde_json::Value::Bool(false))
                );
                let properties: std::collections::BTreeSet<_> = object
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect();
                let required: std::collections::BTreeSet<_> = object
                    .get("required")
                    .and_then(serde_json::Value::as_array)
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(properties, required);
            }
            if object.get("type").and_then(serde_json::Value::as_str) == Some("array") {
                assert!(object.contains_key("maxItems"));
            }
            for child in object.values() {
                assert_schema_nodes_closed_and_bounded(child);
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                assert_schema_nodes_closed_and_bounded(child);
            }
        }
        _ => {}
    }
}

fn assert_schema_refs_resolve(
    value: &serde_json::Value,
    current: &serde_json::Value,
    common: &serde_json::Value,
) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str) {
                let resolved = if let Some(pointer) = reference.strip_prefix('#') {
                    current.pointer(pointer)
                } else if let Some(pointer) = reference.strip_prefix("common.schema.json#") {
                    common.pointer(pointer)
                } else {
                    panic!("unexpected non-local schema reference: {reference}");
                };
                assert!(
                    resolved.is_some(),
                    "unresolved schema reference: {reference}"
                );
            }
            for child in object.values() {
                assert_schema_refs_resolve(child, current, common);
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                assert_schema_refs_resolve(child, current, common);
            }
        }
        _ => {}
    }
}

fn serialized_enum_names<T: Serialize>(values: &[T]) -> Vec<String> {
    values
        .iter()
        .map(|value| {
            serde_json::to_value(value)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn schema_string_values(schema: &serde_json::Value, pointer: &str) -> Vec<String> {
    schema
        .pointer(pointer)
        .unwrap_or_else(|| panic!("missing schema enum at {pointer}"))
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_owned)
        .collect()
}

#[test]
fn schema_enum_order_matches_rust_wire_order() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("schemas/omarchy-plugin-risk-v1");
    let read = |name: &str| -> serde_json::Value {
        serde_json::from_slice(&fs::read(directory.join(name)).unwrap()).unwrap()
    };
    let common = read("common.schema.json");
    let publisher = read("publisher-evidence.schema.json");
    let structural = read("structural-record.schema.json");
    let update = read("update-delta.schema.json");
    let result = read("policy-result.schema.json");

    assert_eq!(
        schema_string_values(&common, "/$defs/policyDisposition/enum"),
        serialized_enum_names(&[PolicyDisposition::Block, PolicyDisposition::RequireConsent,])
    );
    assert_eq!(
        schema_string_values(&common, "/$defs/analysisIntegrationStatus/enum"),
        serialized_enum_names(&[
            AnalysisIntegrationStatus::Complete,
            AnalysisIntegrationStatus::Incomplete,
            AnalysisIntegrationStatus::Error,
            AnalysisIntegrationStatus::Unsupported,
            AnalysisIntegrationStatus::NotRun,
        ])
    );
    assert_eq!(
        schema_string_values(&publisher, "/properties/registry_status/enum"),
        serialized_enum_names(&[
            RiskPublisherRegistryStatus::NotChecked,
            RiskPublisherRegistryStatus::Unrecognized,
            RiskPublisherRegistryStatus::EvidenceOnly,
            RiskPublisherRegistryStatus::Archived,
            RiskPublisherRegistryStatus::TerminallyRevoked,
            RiskPublisherRegistryStatus::Active,
            RiskPublisherRegistryStatus::Retired,
            RiskPublisherRegistryStatus::Compromised,
        ])
    );
    assert_eq!(
        schema_string_values(&publisher, "/properties/continuity/enum"),
        serialized_enum_names(&[
            RiskContinuityStatus::NotChecked,
            RiskContinuityStatus::NotManaged,
            RiskContinuityStatus::Verified,
            RiskContinuityStatus::Invalid,
        ])
    );
    assert_eq!(
        schema_string_values(&publisher, "/properties/installation_authority/enum"),
        serialized_enum_names(&[
            InstallationAuthority::Authorized,
            InstallationAuthority::Denied,
        ])
    );
    assert_eq!(
        schema_string_values(&structural, "/properties/omarchy_manifest_validation/enum",),
        serialized_enum_names(&[
            ManifestValidatorStatus::NotRun,
            ManifestValidatorStatus::Passed,
            ManifestValidatorStatus::Failed,
        ])
    );
    assert_eq!(
        schema_string_values(&update, "/properties/publisher_continuity/enum"),
        serialized_enum_names(&[
            PublisherContinuityDelta::Matched,
            PublisherContinuityDelta::Mismatched,
            PublisherContinuityDelta::NotChecked,
        ])
    );
    assert_eq!(
        schema_string_values(&update, "/properties/plugin_id/enum"),
        serialized_enum_names(&[PluginIdDelta::Unchanged, PluginIdDelta::Changed])
    );
    assert_eq!(
        schema_string_values(&update, "/properties/version/enum"),
        serialized_enum_names(&[
            VersionDelta::Upgrade,
            VersionDelta::Equal,
            VersionDelta::Downgrade,
        ])
    );
    assert_eq!(
        schema_string_values(&result, "/properties/action/enum"),
        serialized_enum_names(&[OperationAction::Install, OperationAction::Update])
    );
    assert_eq!(
        schema_string_values(&result, "/$defs/reason/properties/code/enum"),
        serialized_enum_names(&[
            PolicyReasonCode::InteractiveApprovalRequired,
            PolicyReasonCode::PublisherNotAuthorized,
            PolicyReasonCode::PublisherContinuityNotMatched,
            PolicyReasonCode::ManifestValidatorNotPassed,
            PolicyReasonCode::MissingRequiredProvider,
            PolicyReasonCode::ProviderIncomplete,
            PolicyReasonCode::ProviderError,
            PolicyReasonCode::ProviderUnsupported,
            PolicyReasonCode::ProviderNotRun,
            PolicyReasonCode::PluginIdChanged,
            PolicyReasonCode::VersionNotUpgrade,
            PolicyReasonCode::IndeterminateComparison,
        ])
    );
}

#[test]
fn machine_readable_schemas_are_closed_bounded_and_locally_resolvable() {
    let schema_directory = schema_directory();
    let common: serde_json::Value =
        serde_json::from_slice(&fs::read(schema_directory.join("common.schema.json")).unwrap())
            .unwrap();
    let mappings = [
        (
            "publisher-evidence.schema.json",
            "publisher-evidence-new.json",
            PUBLISHER_EVIDENCE_SCHEMA,
        ),
        (
            "structural-record.schema.json",
            "structural-record-new.json",
            STRUCTURAL_RECORD_SCHEMA,
        ),
        (
            "update-delta.schema.json",
            "update-delta.json",
            UPDATE_DELTA_SCHEMA,
        ),
        (
            "local-policy.schema.json",
            "local-policy.json",
            LOCAL_POLICY_SCHEMA,
        ),
        (
            "policy-result.schema.json",
            "policy-result.json",
            POLICY_RESULT_SCHEMA,
        ),
        (
            "operation-assessment.schema.json",
            "operation-assessment.json",
            OPERATION_ASSESSMENT_SCHEMA,
        ),
    ];
    assert_schema_nodes_closed_and_bounded(&common);
    assert_schema_refs_resolve(&common, &common, &common);
    for (schema_name, fixture_name, urn) in mappings {
        let schema: serde_json::Value =
            serde_json::from_slice(&fs::read(schema_directory.join(schema_name)).unwrap()).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["properties"]["schema"]["const"], urn);
        assert_schema_nodes_closed_and_bounded(&schema);
        assert_schema_refs_resolve(&schema, &schema, &common);

        let fixture: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture_directory().join(fixture_name)).unwrap())
                .unwrap();
        assert_eq!(fixture["schema"], urn);
        let schema_keys: std::collections::BTreeSet<_> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        let fixture_keys: std::collections::BTreeSet<_> = fixture
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(schema_keys, fixture_keys, "{schema_name}");
    }
}
