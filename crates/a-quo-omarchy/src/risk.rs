//! Candidate v1 canonical records for Omarchy plugin risk evidence.
//!
//! These records close the previously undefined descriptors referenced by the
//! operation-assessment design. They are a parser and interoperability
//! prototype, not a scanner, policy service, consent prompt, or safety verdict.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;

use a_quo_display::contains_unsafe_display_characters;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

pub use crate::model::{PluginReferenceState, ShellConfigSource};

pub const PUBLISHER_EVIDENCE_SCHEMA: &str = "urn:a-quo:omarchy-plugin-publisher-evidence:v1";
pub const STRUCTURAL_RECORD_SCHEMA: &str = "urn:a-quo:omarchy-plugin-structural-evidence:v1";
pub const UPDATE_DELTA_SCHEMA: &str = "urn:a-quo:omarchy-plugin-update-delta:v1";
pub const LOCAL_POLICY_SCHEMA: &str = "urn:a-quo:omarchy-plugin-local-policy:v1";
pub const POLICY_RESULT_SCHEMA: &str = "urn:a-quo:omarchy-plugin-policy-result:v1";
pub const OPERATION_ASSESSMENT_SCHEMA: &str = "urn:a-quo:omarchy-plugin-risk-assessment:v1";

pub const MAX_RISK_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_RISK_PATH_BYTES: usize = 4_096;
pub const MAX_RISK_ITEMS: usize = 4_096;
pub const MAX_PROVIDER_BINDINGS: usize = 16;
pub const MAX_PROVIDER_DELTAS: usize = MAX_PROVIDER_BINDINGS * 2;

const MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ANALYSIS_STREAM_BYTES: u64 = 600 * 1024 * 1024;
const MAX_UNCOMPRESSED_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SINGLE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_NATIVE_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 16;
const SHA256_HEX_BYTES: usize = 64;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RiskContractError {
    #[error("{record} exceeds the {maximum}-byte limit")]
    TooLarge {
        record: &'static str,
        maximum: usize,
    },

    #[error("invalid {record} JSON ({category}) at line {line}, column {column}")]
    Json {
        record: &'static str,
        category: &'static str,
        line: usize,
        column: usize,
    },

    #[error("invalid {record}: {reason}")]
    Invalid {
        record: &'static str,
        reason: &'static str,
    },

    #[error("{record} is not canonical RFC 8785 JSON")]
    NonCanonical { record: &'static str },

    #[error("cannot canonicalize {record}")]
    Canonicalization { record: &'static str },
}

pub type RiskResult<T> = std::result::Result<T, RiskContractError>;

/// A required JSON member whose value may be `null`.
///
/// Unlike `Option<T>` as a struct field, this wrapper does not silently treat a
/// missing member as `None`.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Nullable<T>(pub Option<T>);

fn deserialize_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Nullable<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Nullable)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskSubject {
    pub artifact_sha256: String,
    pub artifact_size: u64,
    pub package_format: String,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub plugin_id: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub plugin_version: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub manifest_sha256: Nullable<String>,
    pub analysis_stream_schema: String,
    pub analysis_stream_sha256: String,
    pub analysis_stream_size: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedStatus {
    Verified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskPublisherRegistryStatus {
    NotChecked,
    Unrecognized,
    EvidenceOnly,
    Archived,
    TerminallyRevoked,
    Active,
    Retired,
    Compromised,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskKeyStatus {
    Active,
    Retired,
    Compromised,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskContinuityStatus {
    NotChecked,
    NotManaged,
    Verified,
    Invalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationAuthority {
    Authorized,
    Denied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherEvidenceRecord {
    pub schema: String,
    pub subject: RiskSubject,
    pub proof_sha256: String,
    pub artifact_integrity: VerifiedStatus,
    pub signature: VerifiedStatus,
    pub signed_persona: String,
    pub signing_key_fingerprint: String,
    pub registry_status: RiskPublisherRegistryStatus,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub local_persona_id: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub local_persona_root_sha256: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub signed_label_agreement: Nullable<bool>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub key_status: Nullable<RiskKeyStatus>,
    pub continuity: RiskContinuityStatus,
    pub installation_authority: InstallationAuthority,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestValidatorStatus {
    NotRun,
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralRecord {
    pub schema: String,
    pub subject: RiskSubject,
    pub archive_validation: VerifiedStatus,
    pub entries: u64,
    pub regular_files: u64,
    pub directories: u64,
    pub uncompressed_file_bytes: u64,
    pub links: u64,
    pub special_entries: u64,
    pub files: Vec<StructuralFile>,
    pub executable_paths: Vec<String>,
    pub manifest_entry_point_paths: Vec<String>,
    pub hidden_executable_paths: Vec<String>,
    pub executable_not_manifest_entry_point_paths: Vec<String>,
    pub omarchy_manifest_validation: ManifestValidatorStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralFile {
    pub path: String,
    pub mode: u16,
    pub size: u64,
    pub sha256: String,
    pub manifest_entry_point: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherContinuityDelta {
    Matched,
    Mismatched,
    NotChecked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginIdDelta {
    Unchanged,
    Changed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionDelta {
    Upgrade,
    Equal,
    Downgrade,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Added,
    Removed,
    ContentChanged,
    ModeChanged,
    ContentAndModeChanged,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileState {
    pub sha256: String,
    pub mode: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileDelta {
    pub path: String,
    pub change: FileChangeKind,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub previous: Nullable<FileState>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub current: Nullable<FileState>,
}

/// Exact retained native-report digests, not a behavioural comparison.
///
/// A digest change may be caused by metadata such as scan timestamps.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDelta {
    pub provider_id: String,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub previous_native_report_sha256: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub current_native_report_sha256: Nullable<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDeltaRecord {
    pub schema: String,
    pub previous_subject: RiskSubject,
    pub subject: RiskSubject,
    pub previous_publisher_evidence_sha256: String,
    pub publisher_evidence_sha256: String,
    pub previous_structural_record_sha256: String,
    pub structural_record_sha256: String,
    pub publisher_continuity: PublisherContinuityDelta,
    pub plugin_id: PluginIdDelta,
    pub version: VersionDelta,
    pub files: Vec<FileDelta>,
    pub providers: Vec<ProviderDelta>,
    pub fresh_consent_required: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDisposition {
    Block,
    RequireConsent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderHandlingPolicy {
    pub missing_required: PolicyDisposition,
    pub incomplete: PolicyDisposition,
    pub error: PolicyDisposition,
    pub unsupported: PolicyDisposition,
    pub not_run: PolicyDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateHandlingPolicy {
    pub indeterminate_comparison: PolicyDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPolicyRecord {
    pub schema: String,
    pub policy_id: String,
    pub revision: u64,
    pub required_provider_ids: Vec<String>,
    pub provider_handling: ProviderHandlingPolicy,
    pub update_handling: UpdateHandlingPolicy,
    pub interactive_approval: PolicyDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationAction {
    Install,
    Update,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnablementIntent {
    LeaveUnreferenced,
    PreserveReferenceState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnablementContext {
    pub pre_operation: PluginReferenceState,
    pub intent: EnablementIntent,
    pub shell_config_source: ShellConfigSource,
    pub shell_config_sha256: String,
}

/// Coordinator-derived integration state, not a scanner safety verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisIntegrationStatus {
    Complete,
    Incomplete,
    Error,
    Unsupported,
    NotRun,
}

/// Opaque attachment of an unchanged provider-native report.
///
/// This binding does not interpret report semantics or prove that the report
/// describes the enclosing [`RiskSubject`]. That equivalence remains gated on
/// the Plug & Prejudice pre-install subject-binding contract.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReportBinding {
    pub provider_id: String,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub native_report_schema: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub native_report_sha256: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub native_report_size: Nullable<u64>,
    pub integration_status: AnalysisIntegrationStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReasonCode {
    InteractiveApprovalRequired,
    PublisherNotAuthorized,
    PublisherContinuityNotMatched,
    ManifestValidatorNotPassed,
    MissingRequiredProvider,
    ProviderIncomplete,
    ProviderError,
    ProviderUnsupported,
    ProviderNotRun,
    PluginIdChanged,
    VersionNotUpgrade,
    IndeterminateComparison,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReason {
    pub code: PolicyReasonCode,
    pub disposition: PolicyDisposition,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub provider_id: Nullable<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResultRecord {
    pub schema: String,
    pub operation_id: String,
    pub action: OperationAction,
    pub enablement: EnablementContext,
    pub subject: RiskSubject,
    pub policy_sha256: String,
    pub publisher_evidence_sha256: String,
    pub structural_record_sha256: String,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub update_delta_sha256: Nullable<String>,
    pub native_reports: Vec<NativeReportBinding>,
    pub decision: PolicyDisposition,
    pub reasons: Vec<PolicyReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAssessment {
    pub schema: String,
    pub operation_id: String,
    pub action: OperationAction,
    pub enablement: EnablementContext,
    pub subject: RiskSubject,
    pub destination: String,
    pub destination_parent_device: String,
    pub destination_parent_inode: String,
    pub registry_sha256: String,
    pub publisher_evidence_sha256: String,
    pub structural_record_sha256: String,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub update_delta_sha256: Nullable<String>,
    pub policy_sha256: String,
    pub policy_result_sha256: String,
    pub native_reports: Vec<NativeReportBinding>,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

/// The closed records needed to verify assessment bindings.
///
/// Native scanner reports are represented only by their opaque bindings in
/// this Stage-0 prototype. Plug & Prejudice remains authoritative for report
/// semantics; A Quo does not translate its behavioural evidence here.
pub struct RiskRecordSet<'a> {
    pub previous_publisher: Option<&'a PublisherEvidenceRecord>,
    pub previous_structural: Option<&'a StructuralRecord>,
    pub previous_native_reports: &'a [NativeReportBinding],
    pub publisher: &'a PublisherEvidenceRecord,
    pub structural: &'a StructuralRecord,
    pub update_delta: Option<&'a UpdateDeltaRecord>,
    pub policy: &'a LocalPolicyRecord,
    pub policy_result: &'a PolicyResultRecord,
    pub assessment: &'a OperationAssessment,
}

trait ValidateRiskRecord {
    const DESCRIPTION: &'static str;

    fn validate(&self) -> RiskResult<()>;
}

fn invalid<T>(record: &'static str, reason: &'static str) -> RiskResult<T> {
    Err(RiskContractError::Invalid { record, reason })
}

fn require_schema(actual: &str, expected: &str, record: &'static str) -> RiskResult<()> {
    if actual == expected {
        Ok(())
    } else {
        invalid(record, "unsupported schema identifier")
    }
}

fn validate_jcs_integer(value: u64, record: &'static str) -> RiskResult<()> {
    if value <= MAX_JCS_SAFE_INTEGER {
        Ok(())
    } else {
        invalid(record, "integer exceeds the RFC 8785 exact-integer range")
    }
}

fn validate_sha256(value: &str, record: &'static str) -> RiskResult<()> {
    if value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        invalid(
            record,
            "SHA-256 must be 64 lowercase hexadecimal characters",
        )
    }
}

fn validate_operation_id(value: &str, record: &'static str) -> RiskResult<()> {
    validate_sha256(value, record)?;
    if value.bytes().all(|byte| byte == b'0') {
        invalid(record, "operation ID is the reserved all-zero value")
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str, record: &'static str) -> RiskResult<()> {
    let mut bytes = value.bytes();
    if value.len() > 64
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        invalid(record, "identifier does not use the closed 64-byte grammar")
    } else {
        Ok(())
    }
}

fn validate_sorted_unique_identifiers(
    values: &[String],
    maximum: usize,
    record: &'static str,
) -> RiskResult<()> {
    if values.len() > maximum {
        return invalid(record, "identifier list exceeds its item bound");
    }
    for value in values {
        validate_identifier(value, record)?;
    }
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        invalid(record, "identifier list must be strictly bytewise sorted")
    }
}

fn validate_nfc_text(
    value: &str,
    minimum: usize,
    maximum: usize,
    record: &'static str,
) -> RiskResult<()> {
    if value.len() < minimum || value.len() > maximum {
        return invalid(record, "text exceeds its UTF-8 byte bounds");
    }
    if contains_unsafe_display_characters(value) {
        return invalid(record, "text contains a security-unsafe display character");
    }
    if !value.nfc().eq(value.chars()) {
        return invalid(record, "text is not Unicode NFC");
    }
    Ok(())
}

fn validate_relative_path(value: &str, record: &'static str) -> RiskResult<()> {
    validate_nfc_text(value, 1, MAX_RISK_PATH_BYTES, record)?;
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return invalid(record, "path is not a normalized relative POSIX path");
    }
    Ok(())
}

fn validate_absolute_path(value: &str, record: &'static str) -> RiskResult<()> {
    validate_nfc_text(value, 2, MAX_RISK_PATH_BYTES, record)?;
    if !value.starts_with('/') || value == "/" {
        return invalid(record, "path is not a non-root absolute POSIX path");
    }
    validate_relative_path(&value[1..], record)
}

fn validate_sorted_unique_paths(values: &[String], record: &'static str) -> RiskResult<()> {
    if values.len() > MAX_RISK_ITEMS {
        return invalid(record, "path list exceeds its item bound");
    }
    for value in values {
        validate_relative_path(value, record)?;
    }
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        invalid(record, "path list must be strictly bytewise sorted")
    }
}

fn validate_plugin_id(value: &str, record: &'static str) -> RiskResult<()> {
    crate::archive::validate_plugin_id(value).map_err(|_| RiskContractError::Invalid {
        record,
        reason: "plugin ID is invalid or reserved",
    })
}

fn validate_subject(
    subject: &RiskSubject,
    require_manifest: bool,
    record: &'static str,
) -> RiskResult<()> {
    validate_sha256(&subject.artifact_sha256, record)?;
    validate_jcs_integer(subject.artifact_size, record)?;
    if subject.artifact_size == 0 || subject.artifact_size > MAX_PACKAGE_BYTES {
        return invalid(record, "artifact size is outside the package bound");
    }
    if subject.package_format != "omarchy-zstd-tar-v1" {
        return invalid(record, "unsupported package format");
    }
    match (
        &subject.plugin_id.0,
        &subject.plugin_version.0,
        &subject.manifest_sha256.0,
    ) {
        (Some(plugin_id), Some(plugin_version), Some(manifest_sha256)) => {
            validate_plugin_id(plugin_id, record)?;
            validate_nfc_text(plugin_version, 1, 128, record)?;
            Version::parse(plugin_version).map_err(|_| RiskContractError::Invalid {
                record,
                reason: "plugin version is not semantic versioning",
            })?;
            validate_sha256(manifest_sha256, record)?;
        }
        (None, None, None) if !require_manifest => {}
        _ => {
            return invalid(
                record,
                "manifest subject fields must be all present or all null",
            );
        }
    }
    if require_manifest && subject.plugin_id.0.is_none() {
        return invalid(record, "this record requires a valid manifest subject");
    }
    if subject.analysis_stream_schema != "a-quo-regular-file-stream-v1" {
        return invalid(record, "unsupported analysis-stream schema");
    }
    validate_sha256(&subject.analysis_stream_sha256, record)?;
    validate_jcs_integer(subject.analysis_stream_size, record)?;
    if subject.analysis_stream_size < 20 || subject.analysis_stream_size > MAX_ANALYSIS_STREAM_BYTES
    {
        return invalid(record, "analysis stream size is outside its bound");
    }
    Ok(())
}

fn validate_key_fingerprint(value: &str, record: &'static str) -> RiskResult<()> {
    let Some(encoded) = value.strip_prefix("SHA256:") else {
        return invalid(record, "key fingerprint is not OpenSSH SHA256 form");
    };
    let decoded = STANDARD_NO_PAD.decode(encoded).ok();
    if decoded.as_deref().is_none_or(|bytes| bytes.len() != 32)
        || decoded
            .as_deref()
            .is_none_or(|bytes| STANDARD_NO_PAD.encode(bytes) != encoded)
    {
        invalid(
            record,
            "key fingerprint is not canonical unpadded SHA256 Base64",
        )
    } else {
        Ok(())
    }
}

fn validate_local_persona_id(value: &str, record: &'static str) -> RiskResult<()> {
    let bytes = value.as_bytes();
    if bytes.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
    {
        Ok(())
    } else {
        invalid(
            record,
            "local persona ID is not canonical lowercase UUID text",
        )
    }
}

impl ValidateRiskRecord for PublisherEvidenceRecord {
    const DESCRIPTION: &'static str = "publisher evidence";

    fn validate(&self) -> RiskResult<()> {
        let record = Self::DESCRIPTION;
        require_schema(&self.schema, PUBLISHER_EVIDENCE_SCHEMA, record)?;
        validate_subject(&self.subject, true, record)?;
        validate_sha256(&self.proof_sha256, record)?;
        validate_nfc_text(&self.signed_persona, 1, 256, record)?;
        validate_key_fingerprint(&self.signing_key_fingerprint, record)?;

        if let Some(persona_id) = &self.local_persona_id.0 {
            validate_local_persona_id(persona_id, record)?;
        }
        if let Some(root) = &self.local_persona_root_sha256.0 {
            validate_sha256(root, record)?;
        }

        let recognized = !matches!(
            self.registry_status,
            RiskPublisherRegistryStatus::NotChecked | RiskPublisherRegistryStatus::Unrecognized
        );
        if recognized
            != (self.local_persona_id.0.is_some()
                && self.signed_label_agreement.0.is_some()
                && self.key_status.0.is_some())
        {
            return invalid(
                record,
                "local recognition fields do not match registry status",
            );
        }
        if !recognized
            && (self.local_persona_root_sha256.0.is_some()
                || self.continuity != RiskContinuityStatus::NotChecked)
        {
            return invalid(
                record,
                "unrecognized publisher carries local continuity evidence",
            );
        }
        if recognized && self.continuity == RiskContinuityStatus::NotChecked {
            return invalid(
                record,
                "recognized publisher continuity must be verified, invalid, or not_managed",
            );
        }
        match self.continuity {
            RiskContinuityStatus::Verified | RiskContinuityStatus::Invalid
                if self.local_persona_root_sha256.0.is_none() =>
            {
                return invalid(record, "continuity result is not bound to a persona root");
            }
            RiskContinuityStatus::NotManaged if self.local_persona_root_sha256.0.is_some() => {
                return invalid(record, "unmanaged continuity carries a persona root");
            }
            _ => {}
        }
        match (self.registry_status, self.key_status.0) {
            (RiskPublisherRegistryStatus::Active, Some(RiskKeyStatus::Active))
            | (RiskPublisherRegistryStatus::Retired, Some(RiskKeyStatus::Retired))
            | (RiskPublisherRegistryStatus::Compromised, Some(RiskKeyStatus::Compromised))
            | (RiskPublisherRegistryStatus::EvidenceOnly, Some(_))
            | (RiskPublisherRegistryStatus::Archived, Some(_))
            | (RiskPublisherRegistryStatus::TerminallyRevoked, Some(_))
            | (RiskPublisherRegistryStatus::NotChecked, None)
            | (RiskPublisherRegistryStatus::Unrecognized, None) => {}
            _ => return invalid(record, "key status contradicts publisher registry status"),
        }

        let authorized = self.registry_status == RiskPublisherRegistryStatus::Active
            && self.key_status.0 == Some(RiskKeyStatus::Active)
            && self.signed_label_agreement.0 == Some(true)
            && matches!(
                self.continuity,
                RiskContinuityStatus::Verified | RiskContinuityStatus::NotManaged
            );
        if authorized != (self.installation_authority == InstallationAuthority::Authorized) {
            return invalid(
                record,
                "installation authority is not derived from publisher evidence",
            );
        }
        Ok(())
    }
}

fn hidden_path(path: &str) -> bool {
    path.split('/').any(|component| component.starts_with('.'))
}

impl ValidateRiskRecord for StructuralRecord {
    const DESCRIPTION: &'static str = "structural record";

    fn validate(&self) -> RiskResult<()> {
        let record = Self::DESCRIPTION;
        require_schema(&self.schema, STRUCTURAL_RECORD_SCHEMA, record)?;
        validate_subject(&self.subject, true, record)?;
        for value in [
            self.entries,
            self.regular_files,
            self.directories,
            self.uncompressed_file_bytes,
            self.links,
            self.special_entries,
        ] {
            validate_jcs_integer(value, record)?;
        }
        if self.links != 0 || self.special_entries != 0 {
            return invalid(
                record,
                "accepted structural record contains a non-regular entry",
            );
        }
        if self.entries > MAX_RISK_ITEMS as u64
            || self.regular_files > MAX_RISK_ITEMS as u64
            || self.directories > MAX_RISK_ITEMS as u64
            || self.uncompressed_file_bytes > MAX_UNCOMPRESSED_FILE_BYTES
        {
            return invalid(record, "archive facts exceed the candidate v1 bounds");
        }
        if self.entries != self.regular_files.saturating_add(self.directories) {
            return invalid(record, "archive entry counts do not add up");
        }
        if self.files.len() > MAX_RISK_ITEMS
            || u64::try_from(self.files.len()).ok() != Some(self.regular_files)
        {
            return invalid(record, "file facts do not match the regular-file count");
        }
        if !self
            .files
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        {
            return invalid(record, "file facts must be strictly path-sorted");
        }
        let mut total = 0_u64;
        for file in &self.files {
            validate_relative_path(&file.path, record)?;
            if !matches!(file.mode, 420 | 493) {
                return invalid(record, "file mode is not normalized to 0644 or 0755");
            }
            validate_jcs_integer(file.size, record)?;
            if file.size > MAX_SINGLE_FILE_BYTES {
                return invalid(record, "one structural file exceeds the size bound");
            }
            validate_sha256(&file.sha256, record)?;
            total = total
                .checked_add(file.size)
                .ok_or(RiskContractError::Invalid {
                    record,
                    reason: "file-size sum overflowed",
                })?;
        }
        if total != self.uncompressed_file_bytes {
            return invalid(record, "file facts do not match the content-byte total");
        }
        let analysis_stream_size =
            20_u64
                .checked_add(self.regular_files.checked_mul(48).ok_or(
                    RiskContractError::Invalid {
                        record,
                        reason: "analysis-stream framing size overflowed",
                    },
                )?)
                .and_then(|size| {
                    self.files.iter().try_fold(size, |size, file| {
                        size.checked_add(u64::try_from(file.path.len()).ok()?)
                            .and_then(|size| size.checked_add(file.size))
                    })
                })
                .ok_or(RiskContractError::Invalid {
                    record,
                    reason: "analysis-stream framing size overflowed",
                })?;
        if self.subject.analysis_stream_size != analysis_stream_size {
            return invalid(
                record,
                "analysis-stream size does not match exact file framing",
            );
        }

        for paths in [
            &self.executable_paths,
            &self.manifest_entry_point_paths,
            &self.hidden_executable_paths,
            &self.executable_not_manifest_entry_point_paths,
        ] {
            validate_sorted_unique_paths(paths, record)?;
        }
        let executable: Vec<_> = self
            .files
            .iter()
            .filter(|file| file.mode == 493)
            .map(|file| file.path.clone())
            .collect();
        let entry_points: Vec<_> = self
            .files
            .iter()
            .filter(|file| file.manifest_entry_point)
            .map(|file| file.path.clone())
            .collect();
        let hidden_executable: Vec<_> = self
            .files
            .iter()
            .filter(|file| file.mode == 493 && hidden_path(&file.path))
            .map(|file| file.path.clone())
            .collect();
        let undeclared_executable: Vec<_> = self
            .files
            .iter()
            .filter(|file| file.mode == 493 && !file.manifest_entry_point)
            .map(|file| file.path.clone())
            .collect();
        if self.executable_paths != executable
            || self.manifest_entry_point_paths != entry_points
            || self.hidden_executable_paths != hidden_executable
            || self.executable_not_manifest_entry_point_paths != undeclared_executable
        {
            return invalid(
                record,
                "derived executable path lists do not match file facts",
            );
        }
        let manifest = self
            .files
            .iter()
            .find(|file| file.path == "manifest.json")
            .ok_or(RiskContractError::Invalid {
                record,
                reason: "structural record omits manifest.json",
            })?;
        if manifest.size > crate::archive::MAX_MANIFEST_BYTES {
            return invalid(record, "manifest.json exceeds the archive validator bound");
        }
        if self.subject.manifest_sha256.0.as_deref() != Some(manifest.sha256.as_str()) {
            return invalid(record, "manifest file digest differs from the subject");
        }
        Ok(())
    }
}

fn validate_file_state(state: &FileState, record: &'static str) -> RiskResult<()> {
    validate_sha256(&state.sha256, record)?;
    if matches!(state.mode, 420 | 493) {
        Ok(())
    } else {
        invalid(record, "file delta mode is not normalized to 0644 or 0755")
    }
}

fn validate_file_delta(delta: &FileDelta, record: &'static str) -> RiskResult<()> {
    validate_relative_path(&delta.path, record)?;
    if let Some(previous) = &delta.previous.0 {
        validate_file_state(previous, record)?;
    }
    if let Some(current) = &delta.current.0 {
        validate_file_state(current, record)?;
    }
    let valid = match (&delta.change, &delta.previous.0, &delta.current.0) {
        (FileChangeKind::Added, None, Some(_)) | (FileChangeKind::Removed, Some(_), None) => true,
        (FileChangeKind::ContentChanged, Some(previous), Some(current)) => {
            previous.sha256 != current.sha256 && previous.mode == current.mode
        }
        (FileChangeKind::ModeChanged, Some(previous), Some(current)) => {
            previous.sha256 == current.sha256 && previous.mode != current.mode
        }
        (FileChangeKind::ContentAndModeChanged, Some(previous), Some(current)) => {
            previous.sha256 != current.sha256 && previous.mode != current.mode
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        invalid(
            record,
            "file change tag does not match its previous/current states",
        )
    }
}

fn validate_optional_sha256(value: &Nullable<String>, record: &'static str) -> RiskResult<()> {
    if let Some(value) = &value.0 {
        validate_sha256(value, record)?;
    }
    Ok(())
}

fn validate_provider_delta(delta: &ProviderDelta, record: &'static str) -> RiskResult<()> {
    validate_identifier(&delta.provider_id, record)?;
    for digest in [
        &delta.previous_native_report_sha256,
        &delta.current_native_report_sha256,
    ] {
        validate_optional_sha256(digest, record)?;
    }
    Ok(())
}

impl ValidateRiskRecord for UpdateDeltaRecord {
    const DESCRIPTION: &'static str = "update delta";

    fn validate(&self) -> RiskResult<()> {
        let record = Self::DESCRIPTION;
        require_schema(&self.schema, UPDATE_DELTA_SCHEMA, record)?;
        validate_subject(&self.previous_subject, true, record)?;
        validate_subject(&self.subject, true, record)?;
        for digest in [
            &self.previous_publisher_evidence_sha256,
            &self.publisher_evidence_sha256,
            &self.previous_structural_record_sha256,
            &self.structural_record_sha256,
        ] {
            validate_sha256(digest, record)?;
        }

        let plugin_id = if self.previous_subject.plugin_id == self.subject.plugin_id {
            PluginIdDelta::Unchanged
        } else {
            PluginIdDelta::Changed
        };
        if self.plugin_id != plugin_id {
            return invalid(record, "plugin-ID delta does not match the two subjects");
        }
        let previous_version = Version::parse(
            self.previous_subject
                .plugin_version
                .0
                .as_deref()
                .expect("validated manifest subject has a version"),
        )
        .expect("validated manifest subject has a semantic version");
        let current_version = Version::parse(
            self.subject
                .plugin_version
                .0
                .as_deref()
                .expect("validated manifest subject has a version"),
        )
        .expect("validated manifest subject has a semantic version");
        let version = match current_version.cmp_precedence(&previous_version) {
            Ordering::Greater => VersionDelta::Upgrade,
            Ordering::Equal => VersionDelta::Equal,
            Ordering::Less => VersionDelta::Downgrade,
        };
        if self.version != version {
            return invalid(record, "version delta does not match the two subjects");
        }

        if self.files.len() > MAX_RISK_ITEMS
            || !self
                .files
                .windows(2)
                .all(|pair| pair[0].path < pair[1].path)
        {
            return invalid(record, "file deltas are not strictly path-sorted");
        }
        for delta in &self.files {
            validate_file_delta(delta, record)?;
        }
        if self.providers.len() > MAX_PROVIDER_DELTAS
            || !self
                .providers
                .windows(2)
                .all(|pair| pair[0].provider_id < pair[1].provider_id)
        {
            return invalid(
                record,
                "provider deltas are not strictly provider-ID sorted",
            );
        }
        for provider in &self.providers {
            validate_provider_delta(provider, record)?;
        }
        let material = !self.files.is_empty()
            || self.publisher_continuity != PublisherContinuityDelta::Matched
            || self.plugin_id != PluginIdDelta::Unchanged
            || self.version != VersionDelta::Upgrade
            || !self.providers.is_empty();
        if self.fresh_consent_required != material {
            return invalid(
                record,
                "fresh-consent flag does not match material update changes",
            );
        }
        Ok(())
    }
}

impl ValidateRiskRecord for LocalPolicyRecord {
    const DESCRIPTION: &'static str = "local policy";

    fn validate(&self) -> RiskResult<()> {
        let record = Self::DESCRIPTION;
        require_schema(&self.schema, LOCAL_POLICY_SCHEMA, record)?;
        validate_identifier(&self.policy_id, record)?;
        validate_jcs_integer(self.revision, record)?;
        if self.revision == 0 {
            return invalid(record, "policy revision must be positive");
        }
        validate_sorted_unique_identifiers(
            &self.required_provider_ids,
            MAX_PROVIDER_BINDINGS,
            record,
        )?;
        if self.interactive_approval != PolicyDisposition::RequireConsent {
            return invalid(
                record,
                "interactive approval cannot be disabled or called safe",
            );
        }
        Ok(())
    }
}

fn validate_native_report_schema(value: &str, record: &'static str) -> RiskResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
    {
        invalid(record, "native-report schema is not bounded visible ASCII")
    } else {
        Ok(())
    }
}

fn validate_native_report_bindings(
    bindings: &[NativeReportBinding],
    record: &'static str,
) -> RiskResult<()> {
    if bindings.len() > MAX_PROVIDER_BINDINGS
        || !bindings
            .windows(2)
            .all(|pair| pair[0].provider_id < pair[1].provider_id)
    {
        return invalid(record, "native reports are not strictly provider-ID sorted");
    }
    for binding in bindings {
        validate_identifier(&binding.provider_id, record)?;
        if let Some(schema) = &binding.native_report_schema.0 {
            validate_native_report_schema(schema, record)?;
        }
        validate_optional_sha256(&binding.native_report_sha256, record)?;
        if let Some(size) = binding.native_report_size.0 {
            validate_jcs_integer(size, record)?;
            if size == 0 || size > MAX_NATIVE_REPORT_BYTES {
                return invalid(record, "native report size is outside its bound");
            }
        }

        let has_digest = binding.native_report_sha256.0.is_some();
        let has_size = binding.native_report_size.0.is_some();
        if has_digest != has_size {
            return invalid(record, "native report digest and size presence differ");
        }
        if binding.native_report_schema.0.is_some() && !has_digest {
            return invalid(record, "native report schema exists without report bytes");
        }
        match binding.integration_status {
            AnalysisIntegrationStatus::Complete | AnalysisIntegrationStatus::Incomplete
                if binding.native_report_schema.0.is_none() || !has_digest =>
            {
                return invalid(
                    record,
                    "successful native report integration lacks schema or report bytes",
                );
            }
            AnalysisIntegrationStatus::NotRun
                if binding.native_report_schema.0.is_some() || has_digest =>
            {
                return invalid(record, "not-run integration carries a native report");
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_policy_reason(reason: &PolicyReason, record: &'static str) -> RiskResult<()> {
    if let Some(provider_id) = &reason.provider_id.0 {
        validate_identifier(provider_id, record)?;
    }
    let provider_required = matches!(
        reason.code,
        PolicyReasonCode::MissingRequiredProvider
            | PolicyReasonCode::ProviderIncomplete
            | PolicyReasonCode::ProviderError
            | PolicyReasonCode::ProviderUnsupported
            | PolicyReasonCode::ProviderNotRun
            | PolicyReasonCode::IndeterminateComparison
    );
    if provider_required != reason.provider_id.0.is_some() {
        return invalid(
            record,
            "policy reason has the wrong provider-ID nullability",
        );
    }
    match reason.code {
        PolicyReasonCode::InteractiveApprovalRequired
            if reason.disposition != PolicyDisposition::RequireConsent =>
        {
            invalid(record, "interactive approval reason is not require_consent")
        }
        PolicyReasonCode::PublisherNotAuthorized
        | PolicyReasonCode::PublisherContinuityNotMatched
        | PolicyReasonCode::ManifestValidatorNotPassed
        | PolicyReasonCode::PluginIdChanged
        | PolicyReasonCode::VersionNotUpgrade
            if reason.disposition != PolicyDisposition::Block =>
        {
            invalid(record, "hard policy failure is not block")
        }
        _ => Ok(()),
    }
}

impl ValidateRiskRecord for PolicyResultRecord {
    const DESCRIPTION: &'static str = "policy result";

    fn validate(&self) -> RiskResult<()> {
        let record = Self::DESCRIPTION;
        require_schema(&self.schema, POLICY_RESULT_SCHEMA, record)?;
        validate_operation_id(&self.operation_id, record)?;
        validate_subject(&self.subject, true, record)?;
        for digest in [
            &self.policy_sha256,
            &self.publisher_evidence_sha256,
            &self.structural_record_sha256,
        ] {
            validate_sha256(digest, record)?;
        }
        validate_optional_sha256(&self.update_delta_sha256, record)?;
        if (self.action == OperationAction::Install) != self.update_delta_sha256.0.is_none() {
            return invalid(record, "action does not match update-delta nullability");
        }
        validate_enablement_context(self.action, &self.enablement, record)?;
        validate_native_report_bindings(&self.native_reports, record)?;
        if self.reasons.is_empty()
            || self.reasons.len() > MAX_RISK_ITEMS
            || !self.reasons.windows(2).all(|pair| pair[0] < pair[1])
        {
            return invalid(record, "policy reasons are empty, duplicate, or unsorted");
        }
        for reason in &self.reasons {
            validate_policy_reason(reason, record)?;
        }
        if !self.reasons.iter().any(|reason| {
            reason.code == PolicyReasonCode::InteractiveApprovalRequired
                && reason.disposition == PolicyDisposition::RequireConsent
        }) {
            return invalid(record, "policy result omits mandatory interactive approval");
        }
        let decision = if self
            .reasons
            .iter()
            .any(|reason| reason.disposition == PolicyDisposition::Block)
        {
            PolicyDisposition::Block
        } else {
            PolicyDisposition::RequireConsent
        };
        if self.decision != decision {
            return invalid(record, "policy decision does not match its reasons");
        }
        Ok(())
    }
}

fn validate_lower_hex_integer(value: &str, record: &'static str) -> RiskResult<()> {
    if value.is_empty()
        || value.len() > 16
        || (value.len() > 1 && value.starts_with('0'))
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        invalid(
            record,
            "filesystem identity is not canonical lowercase hexadecimal",
        )
    } else {
        Ok(())
    }
}

fn validate_enablement_context(
    action: OperationAction,
    enablement: &EnablementContext,
    record: &'static str,
) -> RiskResult<()> {
    validate_sha256(&enablement.shell_config_sha256, record)?;
    match (action, enablement.pre_operation, enablement.intent) {
        (
            OperationAction::Install,
            PluginReferenceState::NotReferenced,
            EnablementIntent::LeaveUnreferenced,
        )
        | (
            OperationAction::Update,
            PluginReferenceState::NotReferenced | PluginReferenceState::Referenced,
            EnablementIntent::PreserveReferenceState,
        ) => Ok(()),
        (OperationAction::Install, _, _) => invalid(
            record,
            "install enablement context is not unreferenced with leave-unreferenced intent",
        ),
        (OperationAction::Update, _, _) => invalid(
            record,
            "update enablement context does not preserve the observed reference state",
        ),
    }
}

fn validate_json_depth(bytes: &[u8], record: &'static str) -> RiskResult<()> {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return invalid(record, "JSON nesting exceeds the depth bound");
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

impl ValidateRiskRecord for OperationAssessment {
    const DESCRIPTION: &'static str = "operation assessment";

    fn validate(&self) -> RiskResult<()> {
        let record = Self::DESCRIPTION;
        require_schema(&self.schema, OPERATION_ASSESSMENT_SCHEMA, record)?;
        validate_operation_id(&self.operation_id, record)?;
        validate_subject(&self.subject, true, record)?;
        validate_absolute_path(&self.destination, record)?;
        validate_lower_hex_integer(&self.destination_parent_device, record)?;
        validate_lower_hex_integer(&self.destination_parent_inode, record)?;
        for digest in [
            &self.registry_sha256,
            &self.publisher_evidence_sha256,
            &self.structural_record_sha256,
            &self.policy_sha256,
            &self.policy_result_sha256,
        ] {
            validate_sha256(digest, record)?;
        }
        validate_optional_sha256(&self.update_delta_sha256, record)?;
        if (self.action == OperationAction::Install) != self.update_delta_sha256.0.is_none() {
            return invalid(record, "action does not match update-delta nullability");
        }
        validate_enablement_context(self.action, &self.enablement, record)?;
        validate_native_report_bindings(&self.native_reports, record)?;
        validate_jcs_integer(self.issued_at_unix, record)?;
        validate_jcs_integer(self.expires_at_unix, record)?;
        if self.expires_at_unix <= self.issued_at_unix
            || self.expires_at_unix - self.issued_at_unix > 600
        {
            return invalid(
                record,
                "assessment validity is not within 1 through 600 seconds",
            );
        }
        Ok(())
    }
}

fn parse_record<T>(bytes: &[u8]) -> RiskResult<T>
where
    T: DeserializeOwned + Serialize + ValidateRiskRecord,
{
    if bytes.len() > MAX_RISK_RECORD_BYTES {
        return Err(RiskContractError::TooLarge {
            record: T::DESCRIPTION,
            maximum: MAX_RISK_RECORD_BYTES,
        });
    }
    validate_json_depth(bytes, T::DESCRIPTION)?;
    let value: T = serde_json::from_slice(bytes).map_err(|error| RiskContractError::Json {
        record: T::DESCRIPTION,
        category: match error.classify() {
            serde_json::error::Category::Io => "I/O",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "end-of-input",
        },
        line: error.line(),
        column: error.column(),
    })?;
    value.validate()?;
    let canonical = canonical_record(&value)?;
    if canonical != bytes {
        return Err(RiskContractError::NonCanonical {
            record: T::DESCRIPTION,
        });
    }
    Ok(value)
}

struct CappedCanonicalWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl CappedCanonicalWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(8 * 1024),
            exceeded: false,
        }
    }
}

impl io::Write for CappedCanonicalWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(new_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("canonical record exceeds byte limit"));
        };
        if new_len > MAX_RISK_RECORD_BYTES {
            self.exceeded = true;
            return Err(io::Error::other("canonical record exceeds byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_record<T>(value: &T) -> RiskResult<Vec<u8>>
where
    T: Serialize + ValidateRiskRecord,
{
    value.validate()?;
    let mut writer = CappedCanonicalWriter::new();
    let result = serde_json_canonicalizer::to_writer(value, &mut writer);
    if writer.exceeded {
        return Err(RiskContractError::TooLarge {
            record: T::DESCRIPTION,
            maximum: MAX_RISK_RECORD_BYTES,
        });
    }
    result.map_err(|_| RiskContractError::Canonicalization {
        record: T::DESCRIPTION,
    })?;
    Ok(writer.bytes)
}

fn record_sha256<T>(value: &T) -> RiskResult<String>
where
    T: Serialize + ValidateRiskRecord,
{
    Ok(hex_sha256(&canonical_record(value)?))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(SHA256_HEX_BYTES);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

macro_rules! risk_record_api {
    ($parse:ident, $canonical:ident, $digest:ident, $type:ty) => {
        pub fn $parse(bytes: &[u8]) -> RiskResult<$type> {
            parse_record(bytes)
        }

        pub fn $canonical(value: &$type) -> RiskResult<Vec<u8>> {
            canonical_record(value)
        }

        pub fn $digest(value: &$type) -> RiskResult<String> {
            record_sha256(value)
        }
    };
}

risk_record_api!(
    parse_publisher_evidence_record_bytes,
    canonical_publisher_evidence_record_bytes,
    publisher_evidence_record_sha256,
    PublisherEvidenceRecord
);
risk_record_api!(
    parse_structural_record_bytes,
    canonical_structural_record_bytes,
    structural_record_sha256,
    StructuralRecord
);
risk_record_api!(
    parse_update_delta_record_bytes,
    canonical_update_delta_record_bytes,
    update_delta_record_sha256,
    UpdateDeltaRecord
);
risk_record_api!(
    parse_local_policy_record_bytes,
    canonical_local_policy_record_bytes,
    local_policy_record_sha256,
    LocalPolicyRecord
);
risk_record_api!(
    parse_policy_result_record_bytes,
    canonical_policy_result_record_bytes,
    policy_result_record_sha256,
    PolicyResultRecord
);
risk_record_api!(
    parse_operation_assessment_bytes,
    canonical_operation_assessment_bytes,
    operation_assessment_sha256,
    OperationAssessment
);

fn policy_reason(
    code: PolicyReasonCode,
    disposition: PolicyDisposition,
    provider_id: Option<&str>,
) -> PolicyReason {
    PolicyReason {
        code,
        disposition,
        provider_id: Nullable(provider_id.map(str::to_owned)),
    }
}

fn provider_status_reason(
    status: AnalysisIntegrationStatus,
    policy: &ProviderHandlingPolicy,
) -> Option<(PolicyReasonCode, PolicyDisposition)> {
    match status {
        AnalysisIntegrationStatus::Complete => None,
        AnalysisIntegrationStatus::Incomplete => {
            Some((PolicyReasonCode::ProviderIncomplete, policy.incomplete))
        }
        AnalysisIntegrationStatus::Error => Some((PolicyReasonCode::ProviderError, policy.error)),
        AnalysisIntegrationStatus::Unsupported => {
            Some((PolicyReasonCode::ProviderUnsupported, policy.unsupported))
        }
        AnalysisIntegrationStatus::NotRun => {
            Some((PolicyReasonCode::ProviderNotRun, policy.not_run))
        }
    }
}

fn require_digest(actual: &str, expected: String, record: &'static str) -> RiskResult<()> {
    if actual == expected {
        Ok(())
    } else {
        invalid(
            record,
            "record digest binding does not match canonical bytes",
        )
    }
}

fn structural_file_state(file: &StructuralFile) -> FileState {
    FileState {
        sha256: file.sha256.clone(),
        mode: file.mode,
    }
}

fn derive_file_deltas(previous: &StructuralRecord, current: &StructuralRecord) -> Vec<FileDelta> {
    let previous: BTreeMap<_, _> = previous
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let current: BTreeMap<_, _> = current
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let paths: BTreeSet<_> = previous.keys().chain(current.keys()).copied().collect();
    paths
        .into_iter()
        .filter_map(|path| match (previous.get(path), current.get(path)) {
            (None, Some(current)) => Some(FileDelta {
                path: path.to_owned(),
                change: FileChangeKind::Added,
                previous: Nullable(None),
                current: Nullable(Some(structural_file_state(current))),
            }),
            (Some(previous), None) => Some(FileDelta {
                path: path.to_owned(),
                change: FileChangeKind::Removed,
                previous: Nullable(Some(structural_file_state(previous))),
                current: Nullable(None),
            }),
            (Some(previous), Some(current)) => {
                let content_changed = previous.sha256 != current.sha256;
                let mode_changed = previous.mode != current.mode;
                let change = match (content_changed, mode_changed) {
                    (true, true) => FileChangeKind::ContentAndModeChanged,
                    (true, false) => FileChangeKind::ContentChanged,
                    (false, true) => FileChangeKind::ModeChanged,
                    (false, false) => return None,
                };
                Some(FileDelta {
                    path: path.to_owned(),
                    change,
                    previous: Nullable(Some(structural_file_state(previous))),
                    current: Nullable(Some(structural_file_state(current))),
                })
            }
            (None, None) => unreachable!("path came from one of the maps"),
        })
        .collect()
}

fn derive_publisher_continuity(
    previous: &PublisherEvidenceRecord,
    current: &PublisherEvidenceRecord,
) -> PublisherContinuityDelta {
    match (&previous.local_persona_id.0, &current.local_persona_id.0) {
        (Some(previous_id), Some(current_id)) if previous_id != current_id => {
            PublisherContinuityDelta::Mismatched
        }
        (Some(_), Some(_)) => match (previous.continuity, current.continuity) {
            (RiskContinuityStatus::Verified, RiskContinuityStatus::Verified)
                if previous.local_persona_root_sha256.0.is_some()
                    && previous.local_persona_root_sha256 == current.local_persona_root_sha256 =>
            {
                PublisherContinuityDelta::Matched
            }
            (RiskContinuityStatus::Invalid, _) | (_, RiskContinuityStatus::Invalid) => {
                PublisherContinuityDelta::Mismatched
            }
            (RiskContinuityStatus::Verified, RiskContinuityStatus::Verified) => {
                PublisherContinuityDelta::Mismatched
            }
            _ => PublisherContinuityDelta::NotChecked,
        },
        _ => PublisherContinuityDelta::NotChecked,
    }
}

/// Validate Stage-0 shapes, non-circular bindings, and policy reasons.
///
/// Native reports are opaque here. Plug & Prejudice owns their behavioural
/// semantics, and a digest difference is never treated as evidence of a
/// capability change. Until the pre-install subject-binding contract exists,
/// every old/new report comparison remains indeterminate.
pub fn validate_risk_record_set_shape_and_bindings(records: &RiskRecordSet<'_>) -> RiskResult<()> {
    const RECORD: &str = "risk record set";

    records.publisher.validate()?;
    records.structural.validate()?;
    records.policy.validate()?;
    records.policy_result.validate()?;
    records.assessment.validate()?;
    if let Some(previous) = records.previous_publisher {
        previous.validate()?;
    }
    if let Some(previous) = records.previous_structural {
        previous.validate()?;
    }
    if let Some(delta) = records.update_delta {
        delta.validate()?;
    }
    validate_native_report_bindings(records.previous_native_reports, RECORD)?;

    let subject = &records.publisher.subject;
    if &records.structural.subject != subject
        || &records.policy_result.subject != subject
        || &records.assessment.subject != subject
    {
        return invalid(RECORD, "current subjects differ across records");
    }
    if records.policy_result.operation_id != records.assessment.operation_id
        || records.policy_result.action != records.assessment.action
    {
        return invalid(
            RECORD,
            "policy result and assessment operation bindings differ",
        );
    }
    if records.policy_result.enablement != records.assessment.enablement {
        return invalid(
            RECORD,
            "policy result and assessment enablement contexts differ",
        );
    }
    if records.policy_result.native_reports != records.assessment.native_reports {
        return invalid(
            RECORD,
            "policy result and assessment native-report bindings differ",
        );
    }

    require_digest(
        &records.policy_result.publisher_evidence_sha256,
        publisher_evidence_record_sha256(records.publisher)?,
        RECORD,
    )?;
    require_digest(
        &records.assessment.publisher_evidence_sha256,
        publisher_evidence_record_sha256(records.publisher)?,
        RECORD,
    )?;
    require_digest(
        &records.policy_result.structural_record_sha256,
        structural_record_sha256(records.structural)?,
        RECORD,
    )?;
    require_digest(
        &records.assessment.structural_record_sha256,
        structural_record_sha256(records.structural)?,
        RECORD,
    )?;
    require_digest(
        &records.policy_result.policy_sha256,
        local_policy_record_sha256(records.policy)?,
        RECORD,
    )?;
    require_digest(
        &records.assessment.policy_sha256,
        local_policy_record_sha256(records.policy)?,
        RECORD,
    )?;
    require_digest(
        &records.assessment.policy_result_sha256,
        policy_result_record_sha256(records.policy_result)?,
        RECORD,
    )?;

    match (
        records.assessment.action,
        records.previous_publisher,
        records.previous_structural,
        records.update_delta,
    ) {
        (OperationAction::Install, None, None, None) => {
            if !records.previous_native_reports.is_empty() {
                return invalid(RECORD, "install operation carries prior native reports");
            }
            if records.policy_result.update_delta_sha256.0.is_some()
                || records.assessment.update_delta_sha256.0.is_some()
            {
                return invalid(RECORD, "install operation carries an update delta");
            }
        }
        (
            OperationAction::Update,
            Some(previous_publisher),
            Some(previous_structural),
            Some(delta),
        ) => {
            if delta.subject != *subject
                || delta.previous_subject != previous_publisher.subject
                || delta.previous_subject != previous_structural.subject
            {
                return invalid(RECORD, "update-delta subjects differ from evidence records");
            }
            require_digest(
                &delta.previous_publisher_evidence_sha256,
                publisher_evidence_record_sha256(previous_publisher)?,
                RECORD,
            )?;
            require_digest(
                &delta.publisher_evidence_sha256,
                publisher_evidence_record_sha256(records.publisher)?,
                RECORD,
            )?;
            require_digest(
                &delta.previous_structural_record_sha256,
                structural_record_sha256(previous_structural)?,
                RECORD,
            )?;
            require_digest(
                &delta.structural_record_sha256,
                structural_record_sha256(records.structural)?,
                RECORD,
            )?;
            if delta.files != derive_file_deltas(previous_structural, records.structural) {
                return invalid(
                    RECORD,
                    "file deltas do not match old and new structural facts",
                );
            }
            if delta.publisher_continuity
                != derive_publisher_continuity(previous_publisher, records.publisher)
            {
                return invalid(
                    RECORD,
                    "publisher continuity does not match old and new publisher evidence",
                );
            }
            let delta_sha256 = update_delta_record_sha256(delta)?;
            if records.policy_result.update_delta_sha256.0.as_deref() != Some(delta_sha256.as_str())
                || records.assessment.update_delta_sha256.0.as_deref()
                    != Some(delta_sha256.as_str())
            {
                return invalid(
                    RECORD,
                    "update-delta digest differs across operation records",
                );
            }

            for provider in &delta.providers {
                let previous = records
                    .previous_native_reports
                    .iter()
                    .find(|binding| binding.provider_id == provider.provider_id);
                let previous_digest =
                    previous.and_then(|binding| binding.native_report_sha256.0.as_deref());
                if provider.previous_native_report_sha256.0.as_deref() != previous_digest {
                    return invalid(
                        RECORD,
                        "update provider binding does not match the previous native report",
                    );
                }
                let current = records
                    .policy_result
                    .native_reports
                    .iter()
                    .find(|binding| binding.provider_id == provider.provider_id);
                let current_digest =
                    current.and_then(|binding| binding.native_report_sha256.0.as_deref());
                if provider.current_native_report_sha256.0.as_deref() != current_digest {
                    return invalid(
                        RECORD,
                        "update provider binding does not match the current native report",
                    );
                }
                if previous.is_none() && current.is_none() {
                    return invalid(RECORD, "update delta contains a ghost provider");
                }
            }
            if records.previous_native_reports.iter().any(|binding| {
                !delta
                    .providers
                    .iter()
                    .any(|provider| provider.provider_id == binding.provider_id)
            }) {
                return invalid(RECORD, "previous native report is absent from update delta");
            }
            if records.policy_result.native_reports.iter().any(|binding| {
                !delta
                    .providers
                    .iter()
                    .any(|provider| provider.provider_id == binding.provider_id)
            }) {
                return invalid(RECORD, "current native report is absent from update delta");
            }
        }
        _ => {
            return invalid(
                RECORD,
                "action does not match prior-record and delta presence",
            );
        }
    }

    let mut expected_reasons = BTreeSet::new();
    expected_reasons.insert(policy_reason(
        PolicyReasonCode::InteractiveApprovalRequired,
        PolicyDisposition::RequireConsent,
        None,
    ));
    if records.publisher.installation_authority != InstallationAuthority::Authorized {
        expected_reasons.insert(policy_reason(
            PolicyReasonCode::PublisherNotAuthorized,
            PolicyDisposition::Block,
            None,
        ));
    }
    if records.structural.omarchy_manifest_validation != ManifestValidatorStatus::Passed {
        expected_reasons.insert(policy_reason(
            PolicyReasonCode::ManifestValidatorNotPassed,
            PolicyDisposition::Block,
            None,
        ));
    }

    let bindings = &records.policy_result.native_reports;
    for provider_id in &records.policy.required_provider_ids {
        if !bindings
            .iter()
            .any(|binding| &binding.provider_id == provider_id)
        {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::MissingRequiredProvider,
                records.policy.provider_handling.missing_required,
                Some(provider_id),
            ));
        }
    }
    for binding in bindings {
        if let Some((code, disposition)) = provider_status_reason(
            binding.integration_status,
            &records.policy.provider_handling,
        ) {
            expected_reasons.insert(policy_reason(code, disposition, Some(&binding.provider_id)));
        }
    }

    if let Some(delta) = records.update_delta {
        if delta.publisher_continuity != PublisherContinuityDelta::Matched {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::PublisherContinuityNotMatched,
                PolicyDisposition::Block,
                None,
            ));
        }
        if delta.plugin_id != PluginIdDelta::Unchanged {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::PluginIdChanged,
                PolicyDisposition::Block,
                None,
            ));
        }
        if delta.version != VersionDelta::Upgrade {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::VersionNotUpgrade,
                PolicyDisposition::Block,
                None,
            ));
        }
        for provider in &delta.providers {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::IndeterminateComparison,
                records.policy.update_handling.indeterminate_comparison,
                Some(&provider.provider_id),
            ));
        }
    }

    let actual_reasons: BTreeSet<_> = records.policy_result.reasons.iter().cloned().collect();
    if actual_reasons != expected_reasons {
        return invalid(
            RECORD,
            "policy reasons do not deterministically match bound evidence",
        );
    }
    Ok(())
}
