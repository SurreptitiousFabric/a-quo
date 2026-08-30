//! Candidate v1 canonical records for Omarchy plugin risk evidence.
//!
//! These records close the previously undefined descriptors referenced by the
//! operation-assessment design. They are a parser and interoperability
//! prototype, not a scanner, policy service, consent prompt, or safety verdict.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use a_quo_display::contains_unsafe_display_characters;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

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
pub const MAX_POLICY_RULES: usize = 4_096;

const MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ANALYSIS_STREAM_BYTES: u64 = 600 * 1024 * 1024;
const MAX_UNCOMPRESSED_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SINGLE_FILE_BYTES: u64 = 128 * 1024 * 1024;
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Filesystem,
    Network,
    Process,
    Privilege,
    DesktopSession,
    UpdateAndInstall,
    Persistence,
    NativeOrDynamicCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskScope {
    Package,
    PluginState,
    Home,
    System,
    Session,
    Lan,
    Internet,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    PathExact,
    PathPrefix,
    HostExact,
    DomainSuffix,
    Cidr,
    PortRange,
    CommandExact,
    IpcName,
    ServiceName,
    ConfigKey,
    CapabilityName,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityKey {
    pub category: RiskCategory,
    pub operation: String,
    pub scope: RiskScope,
    pub resource_kind: ResourceKind,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub resource_value: Nullable<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityChangeKind {
    Added,
    Expanded,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDelta {
    pub change: CapabilityChangeKind,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub previous: Nullable<CapabilityKey>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub current: Nullable<CapabilityKey>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderComparability {
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDelta {
    pub provider_id: String,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub previous_envelope_sha256: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub current_envelope_sha256: Nullable<String>,
    pub comparability: ProviderComparability,
    pub coverage_regressions: Vec<RiskCategory>,
    pub capability_changes: Vec<CapabilityDelta>,
    pub new_limitation_ids: Vec<String>,
    pub new_error_ids: Vec<String>,
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
    pub permission_expansion: bool,
    pub fresh_consent_required: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDisposition {
    Block,
    RequireConsent,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicyRule {
    pub rule_id: String,
    pub disposition: PolicyDisposition,
    pub capability: CapabilityKey,
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
    pub permission_expansion: PolicyDisposition,
    pub coverage_regression: PolicyDisposition,
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
    pub unknown_capability: PolicyDisposition,
    pub capability_rules: Vec<CapabilityPolicyRule>,
    pub default_capability: PolicyDisposition,
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
pub enum ProviderRunStatus {
    Complete,
    Incomplete,
    Error,
    Unsupported,
    NotRun,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEnvelopeBinding {
    pub provider_id: String,
    pub envelope_sha256: String,
    pub run_status: ProviderRunStatus,
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
    NewProviderLimitation,
    NewProviderError,
    PluginIdChanged,
    VersionNotUpgrade,
    PermissionExpansion,
    CoverageRegression,
    IndeterminateComparison,
    UnknownCapability,
    DefaultCapability,
    CapabilityRule,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReason {
    pub code: PolicyReasonCode,
    pub disposition: PolicyDisposition,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub provider_id: Nullable<String>,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub rule_id: Nullable<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResultRecord {
    pub schema: String,
    pub operation_id: String,
    pub action: OperationAction,
    pub subject: RiskSubject,
    pub policy_sha256: String,
    pub publisher_evidence_sha256: String,
    pub structural_record_sha256: String,
    #[serde(deserialize_with = "deserialize_nullable")]
    pub update_delta_sha256: Nullable<String>,
    pub provider_envelopes: Vec<ProviderEnvelopeBinding>,
    pub decision: PolicyDisposition,
    pub reasons: Vec<PolicyReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAssessment {
    pub schema: String,
    pub operation_id: String,
    pub action: OperationAction,
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
    pub provider_envelopes: Vec<ProviderEnvelopeBinding>,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

/// The closed records needed to verify assessment bindings.
///
/// Provider envelopes are represented only by their already parsed bindings in
/// this Stage-0 prototype. Provider-envelope semantic conformance remains a
/// separate, explicitly open gate.
pub struct RiskRecordSet<'a> {
    pub previous_publisher: Option<&'a PublisherEvidenceRecord>,
    pub previous_structural: Option<&'a StructuralRecord>,
    pub previous_provider_envelopes: &'a [ProviderEnvelopeBinding],
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

fn validate_operation(
    category: RiskCategory,
    operation: &str,
    record: &'static str,
) -> RiskResult<()> {
    let allowed = match category {
        RiskCategory::Filesystem => &[
            "unknown",
            "read",
            "enumerate",
            "create",
            "write",
            "delete",
            "execute",
        ][..],
        RiskCategory::Network => &["unknown", "resolve", "connect", "listen"],
        RiskCategory::Process => &["unknown", "spawn_exact", "spawn_dynamic", "signal"],
        RiskCategory::Privilege => &["unknown", "elevate", "change_identity", "use_capability"],
        RiskCategory::DesktopSession => &[
            "unknown",
            "read_ipc",
            "write_ipc",
            "observe_input",
            "inject_input",
            "overlay",
            "modify_config",
        ],
        RiskCategory::UpdateAndInstall => &[
            "unknown",
            "download",
            "install",
            "migrate",
            "self_update",
            "uninstall",
        ],
        RiskCategory::Persistence => &["unknown", "autostart", "service", "timer"],
        RiskCategory::NativeOrDynamicCode => &[
            "unknown",
            "load_native",
            "dynamic_import",
            "evaluate",
            "download_execute",
        ],
    };
    if allowed.contains(&operation) {
        Ok(())
    } else {
        invalid(record, "operation is outside its category vocabulary")
    }
}

fn validate_domain_ascii(value: &str, record: &'static str) -> RiskResult<()> {
    if value.len() > 253
        || value.is_empty()
        || !value.is_ascii()
        || value != value.to_ascii_lowercase()
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || idna::domain_to_ascii_strict(value).ok().as_deref() != Some(value)
    {
        invalid(record, "host is not canonical lower-case IDNA ASCII")
    } else {
        Ok(())
    }
}

fn canonical_network(address: IpAddr, prefix: u8) -> Option<IpAddr> {
    match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask)))
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Some(IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask)))
        }
        _ => None,
    }
}

fn parse_cidr(value: &str, record: &'static str) -> RiskResult<(IpAddr, u8)> {
    let Some((address_text, prefix_text)) = value.split_once('/') else {
        return invalid(record, "CIDR lacks one prefix separator");
    };
    if prefix_text.is_empty()
        || (prefix_text.len() > 1 && prefix_text.starts_with('0'))
        || !prefix_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return invalid(record, "CIDR prefix is not canonical decimal");
    }
    let address: IpAddr = address_text
        .parse()
        .map_err(|_| RiskContractError::Invalid {
            record,
            reason: "CIDR address is invalid",
        })?;
    let prefix: u8 = prefix_text
        .parse()
        .map_err(|_| RiskContractError::Invalid {
            record,
            reason: "CIDR prefix is invalid",
        })?;
    let Some(network) = canonical_network(address, prefix) else {
        return invalid(record, "CIDR prefix exceeds its address width");
    };
    if network != address || address.to_string() != address_text {
        return invalid(record, "CIDR is not in canonical network form");
    }
    Ok((address, prefix))
}

fn parse_port_range<'a>(value: &'a str, record: &'static str) -> RiskResult<(&'a str, u16, u16)> {
    let Some((transport, range)) = value.split_once(':') else {
        return invalid(record, "port range lacks a transport separator");
    };
    if !matches!(transport, "tcp" | "udp") {
        return invalid(record, "port range has an unsupported transport");
    }
    let Some((start_text, end_text)) = range.split_once('-') else {
        return invalid(record, "port range lacks an end");
    };
    let canonical_decimal = |text: &str| {
        !text.is_empty()
            && !(text.len() > 1 && text.starts_with('0'))
            && text.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !canonical_decimal(start_text) || !canonical_decimal(end_text) {
        return invalid(record, "port range is not canonical decimal");
    }
    let start: u16 = start_text.parse().map_err(|_| RiskContractError::Invalid {
        record,
        reason: "port range start is invalid",
    })?;
    let end: u16 = end_text.parse().map_err(|_| RiskContractError::Invalid {
        record,
        reason: "port range end is invalid",
    })?;
    if start == 0 || start > end {
        return invalid(record, "port range is empty or includes port zero");
    }
    Ok((transport, start, end))
}

fn validate_resource_path(value: &str, prefix: bool, record: &'static str) -> RiskResult<()> {
    validate_nfc_text(value, 1, MAX_RISK_PATH_BYTES, record)?;
    if !value.starts_with('/') || value.contains("//") || value.contains('\\') {
        return invalid(
            record,
            "resource path is not normalized absolute-within-scope POSIX",
        );
    }
    if value != "/" {
        let body = if prefix {
            value.strip_suffix('/').ok_or(RiskContractError::Invalid {
                record,
                reason: "path prefix does not end in a slash",
            })?
        } else {
            if value.ends_with('/') {
                return invalid(record, "exact path ends in a slash");
            }
            value
        };
        validate_relative_path(&body[1..], record)?;
    }
    Ok(())
}

fn validate_capability_key(key: &CapabilityKey, record: &'static str) -> RiskResult<()> {
    validate_operation(key.category, &key.operation, record)?;
    if key.operation == "unknown"
        || key.scope == RiskScope::Unknown
        || key.resource_kind == ResourceKind::Unknown
    {
        if key.operation == "unknown"
            && key.scope == RiskScope::Unknown
            && key.resource_kind == ResourceKind::Unknown
            && key.resource_value.0.is_none()
        {
            return Ok(());
        }
        return invalid(
            record,
            "unknown capability is not the closed all-unknown form",
        );
    }
    let value = key
        .resource_value
        .0
        .as_deref()
        .ok_or(RiskContractError::Invalid {
            record,
            reason: "non-unknown capability has a null resource value",
        })?;
    match key.resource_kind {
        ResourceKind::PathExact => validate_resource_path(value, false, record)?,
        ResourceKind::PathPrefix => validate_resource_path(value, true, record)?,
        ResourceKind::CommandExact => {
            if key.scope != RiskScope::System {
                return invalid(record, "command resource is not in system scope");
            }
            validate_resource_path(value, false, record)?;
        }
        ResourceKind::HostExact | ResourceKind::DomainSuffix => {
            validate_domain_ascii(value, record)?;
        }
        ResourceKind::Cidr => {
            parse_cidr(value, record)?;
        }
        ResourceKind::PortRange => {
            parse_port_range(value, record)?;
        }
        ResourceKind::IpcName
        | ResourceKind::ServiceName
        | ResourceKind::ConfigKey
        | ResourceKind::CapabilityName => validate_identifier(value, record)?,
        ResourceKind::Unknown => unreachable!("unknown resource returned above"),
    }
    let path = matches!(
        key.resource_kind,
        ResourceKind::PathExact | ResourceKind::PathPrefix
    );
    let network = matches!(
        key.resource_kind,
        ResourceKind::HostExact
            | ResourceKind::DomainSuffix
            | ResourceKind::Cidr
            | ResourceKind::PortRange
    );
    let compatible = match (key.category, key.operation.as_str()) {
        (RiskCategory::Filesystem, _) => {
            path && matches!(
                key.scope,
                RiskScope::Package | RiskScope::PluginState | RiskScope::Home | RiskScope::System
            )
        }
        (RiskCategory::Network, "resolve") => {
            matches!(key.scope, RiskScope::Lan | RiskScope::Internet)
                && matches!(
                    key.resource_kind,
                    ResourceKind::HostExact | ResourceKind::DomainSuffix
                )
        }
        (RiskCategory::Network, "connect") => {
            matches!(key.scope, RiskScope::Lan | RiskScope::Internet) && network
        }
        (RiskCategory::Network, "listen") => {
            matches!(key.scope, RiskScope::Lan | RiskScope::Internet)
                && matches!(
                    key.resource_kind,
                    ResourceKind::Cidr | ResourceKind::PortRange
                )
        }
        (RiskCategory::Process, "spawn_exact") => {
            key.scope == RiskScope::System && key.resource_kind == ResourceKind::CommandExact
        }
        (RiskCategory::Process, "spawn_dynamic" | "signal") => {
            key.scope == RiskScope::Session && key.resource_kind == ResourceKind::CapabilityName
        }
        (RiskCategory::Privilege, _) => {
            key.scope == RiskScope::System && key.resource_kind == ResourceKind::CapabilityName
        }
        (RiskCategory::DesktopSession, "read_ipc" | "write_ipc") => {
            key.scope == RiskScope::Session && key.resource_kind == ResourceKind::IpcName
        }
        (RiskCategory::DesktopSession, "observe_input" | "inject_input" | "overlay") => {
            key.scope == RiskScope::Session && key.resource_kind == ResourceKind::CapabilityName
        }
        (RiskCategory::DesktopSession, "modify_config") => {
            matches!(key.scope, RiskScope::Home | RiskScope::Session)
                && (path || key.resource_kind == ResourceKind::ConfigKey)
        }
        (RiskCategory::UpdateAndInstall, "download") => key.scope == RiskScope::Internet && network,
        (RiskCategory::UpdateAndInstall, _) => {
            path && matches!(
                key.scope,
                RiskScope::PluginState | RiskScope::Home | RiskScope::System
            )
        }
        (RiskCategory::Persistence, "autostart") => {
            matches!(key.scope, RiskScope::Home | RiskScope::Session)
                && (path || key.resource_kind == ResourceKind::ConfigKey)
        }
        (RiskCategory::Persistence, "service" | "timer") => {
            matches!(key.scope, RiskScope::Session | RiskScope::System)
                && key.resource_kind == ResourceKind::ServiceName
        }
        (RiskCategory::NativeOrDynamicCode, "load_native" | "dynamic_import" | "evaluate") => {
            path && matches!(
                key.scope,
                RiskScope::Package | RiskScope::PluginState | RiskScope::Home | RiskScope::System
            )
        }
        (RiskCategory::NativeOrDynamicCode, "download_execute") => {
            key.scope == RiskScope::Internet && network
        }
        _ => false,
    };
    if !compatible {
        return invalid(
            record,
            "capability category, operation, scope, and resource kind are incompatible",
        );
    }
    Ok(())
}

fn cidr_contains(container: &str, contained: &str, record: &'static str) -> RiskResult<bool> {
    let (container_address, container_prefix) = parse_cidr(container, record)?;
    let (contained_address, contained_prefix) = parse_cidr(contained, record)?;
    if std::mem::discriminant(&container_address) != std::mem::discriminant(&contained_address)
        || container_prefix > contained_prefix
    {
        return Ok(false);
    }
    Ok(canonical_network(contained_address, container_prefix) == Some(container_address))
}

fn resource_covers(
    container: &CapabilityKey,
    contained: &CapabilityKey,
    record: &'static str,
) -> RiskResult<bool> {
    if container.category != contained.category
        || container.operation != contained.operation
        || container.scope != contained.scope
    {
        return Ok(false);
    }
    if container == contained {
        return Ok(true);
    }
    let Some(container_value) = container.resource_value.0.as_deref() else {
        return Ok(false);
    };
    let Some(contained_value) = contained.resource_value.0.as_deref() else {
        return Ok(false);
    };
    match (container.resource_kind, contained.resource_kind) {
        (ResourceKind::PathPrefix, ResourceKind::PathExact | ResourceKind::PathPrefix) => {
            Ok(container_value == "/" || contained_value.starts_with(container_value))
        }
        (ResourceKind::DomainSuffix, ResourceKind::HostExact | ResourceKind::DomainSuffix) => {
            Ok(contained_value == container_value
                || contained_value
                    .strip_suffix(container_value)
                    .is_some_and(|prefix| prefix.ends_with('.')))
        }
        (ResourceKind::Cidr, ResourceKind::Cidr) => {
            cidr_contains(container_value, contained_value, record)
        }
        (ResourceKind::PortRange, ResourceKind::PortRange) => {
            let (container_transport, container_start, container_end) =
                parse_port_range(container_value, record)?;
            let (contained_transport, contained_start, contained_end) =
                parse_port_range(contained_value, record)?;
            Ok(container_transport == contained_transport
                && container_start <= contained_start
                && container_end >= contained_end)
        }
        _ => Ok(false),
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

fn validate_capability_delta(delta: &CapabilityDelta, record: &'static str) -> RiskResult<()> {
    if let Some(previous) = &delta.previous.0 {
        validate_capability_key(previous, record)?;
    }
    if let Some(current) = &delta.current.0 {
        validate_capability_key(current, record)?;
    }
    match (&delta.change, &delta.previous.0, &delta.current.0) {
        (CapabilityChangeKind::Added, None, Some(_))
        | (CapabilityChangeKind::Removed, Some(_), None) => Ok(()),
        (CapabilityChangeKind::Expanded, Some(previous), Some(current))
            if previous != current
                && resource_covers(current, previous, record)?
                && !resource_covers(previous, current, record)? =>
        {
            Ok(())
        }
        _ => invalid(record, "capability change tag does not match its keys"),
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
        &delta.previous_envelope_sha256,
        &delta.current_envelope_sha256,
    ] {
        validate_optional_sha256(digest, record)?;
    }
    if delta.previous_envelope_sha256.0.is_none() && delta.current_envelope_sha256.0.is_none() {
        return invalid(record, "provider delta is not bound to either snapshot");
    }
    if delta.coverage_regressions.len() > 8
        || !delta
            .coverage_regressions
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return invalid(
            record,
            "coverage regressions are not strictly category-sorted",
        );
    }
    if delta.capability_changes.len() > MAX_RISK_ITEMS
        || !delta
            .capability_changes
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return invalid(record, "capability changes are not strictly sorted");
    }
    for capability in &delta.capability_changes {
        validate_capability_delta(capability, record)?;
    }
    validate_sorted_unique_identifiers(&delta.new_limitation_ids, 1_024, record)?;
    validate_sorted_unique_identifiers(&delta.new_error_ids, 1_024, record)?;

    if delta.current_envelope_sha256.0.is_none()
        && (!delta.new_limitation_ids.is_empty() || !delta.new_error_ids.is_empty())
    {
        return invalid(
            record,
            "provider findings exist without a current envelope binding",
        );
    }

    if !delta.coverage_regressions.is_empty() || !delta.capability_changes.is_empty() {
        return invalid(
            record,
            "provider comparison claims require the unopened Stage-2 envelope parser",
        );
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
        let permission_expansion = self.providers.iter().any(|provider| {
            provider.capability_changes.iter().any(|delta| {
                matches!(
                    delta.change,
                    CapabilityChangeKind::Added | CapabilityChangeKind::Expanded
                )
            })
        });
        if self.permission_expansion != permission_expansion {
            return invalid(
                record,
                "permission-expansion flag does not match capability deltas",
            );
        }
        let material = !self.files.is_empty()
            || permission_expansion
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
        if self.capability_rules.len() > MAX_POLICY_RULES
            || !self
                .capability_rules
                .windows(2)
                .all(|pair| pair[0].rule_id < pair[1].rule_id)
        {
            return invalid(record, "capability rules are not strictly rule-ID sorted");
        }
        let mut capabilities = BTreeSet::new();
        for rule in &self.capability_rules {
            validate_identifier(&rule.rule_id, record)?;
            validate_capability_key(&rule.capability, record)?;
            if !capabilities.insert(&rule.capability) {
                return invalid(record, "two policy rules select the same capability key");
            }
        }
        Ok(())
    }
}

fn validate_provider_bindings(
    bindings: &[ProviderEnvelopeBinding],
    record: &'static str,
) -> RiskResult<()> {
    if bindings.len() > MAX_PROVIDER_BINDINGS
        || !bindings
            .windows(2)
            .all(|pair| pair[0].provider_id < pair[1].provider_id)
    {
        return invalid(
            record,
            "provider envelopes are not strictly provider-ID sorted",
        );
    }
    for binding in bindings {
        validate_identifier(&binding.provider_id, record)?;
        validate_sha256(&binding.envelope_sha256, record)?;
    }
    Ok(())
}

fn validate_policy_reason(reason: &PolicyReason, record: &'static str) -> RiskResult<()> {
    if let Some(provider_id) = &reason.provider_id.0 {
        validate_identifier(provider_id, record)?;
    }
    if let Some(rule_id) = &reason.rule_id.0 {
        validate_identifier(rule_id, record)?;
    }
    let provider_required = matches!(
        reason.code,
        PolicyReasonCode::MissingRequiredProvider
            | PolicyReasonCode::ProviderIncomplete
            | PolicyReasonCode::ProviderError
            | PolicyReasonCode::ProviderUnsupported
            | PolicyReasonCode::ProviderNotRun
            | PolicyReasonCode::NewProviderLimitation
            | PolicyReasonCode::NewProviderError
            | PolicyReasonCode::PermissionExpansion
            | PolicyReasonCode::CoverageRegression
            | PolicyReasonCode::IndeterminateComparison
            | PolicyReasonCode::UnknownCapability
            | PolicyReasonCode::DefaultCapability
            | PolicyReasonCode::CapabilityRule
    );
    if provider_required != reason.provider_id.0.is_some() {
        return invalid(
            record,
            "policy reason has the wrong provider-ID nullability",
        );
    }
    if (reason.code == PolicyReasonCode::CapabilityRule) != reason.rule_id.0.is_some() {
        return invalid(record, "policy reason has the wrong rule-ID nullability");
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
        validate_provider_bindings(&self.provider_envelopes, record)?;
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
        validate_provider_bindings(&self.provider_envelopes, record)?;
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
    rule_id: Option<&str>,
) -> PolicyReason {
    PolicyReason {
        code,
        disposition,
        provider_id: Nullable(provider_id.map(str::to_owned)),
        rule_id: Nullable(rule_id.map(str::to_owned)),
    }
}

fn provider_status_reason(
    status: ProviderRunStatus,
    policy: &ProviderHandlingPolicy,
) -> Option<(PolicyReasonCode, PolicyDisposition)> {
    match status {
        ProviderRunStatus::Complete => None,
        ProviderRunStatus::Incomplete => {
            Some((PolicyReasonCode::ProviderIncomplete, policy.incomplete))
        }
        ProviderRunStatus::Error => Some((PolicyReasonCode::ProviderError, policy.error)),
        ProviderRunStatus::Unsupported => {
            Some((PolicyReasonCode::ProviderUnsupported, policy.unsupported))
        }
        ProviderRunStatus::NotRun => Some((PolicyReasonCode::ProviderNotRun, policy.not_run)),
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

/// Validate Stage-0 shapes, non-circular bindings, and the policy reasons that
/// are derivable without interpreting provider envelopes.
///
/// This function intentionally does not authenticate or re-interpret provider
/// envelopes. Until the provider-envelope parser exists, `unknown_capability`
/// `unknown_capability`, `default_capability`, and `capability_rule` reasons
/// are shape-checked and digest-bound but cannot be independently recomputed.
/// That remaining gate is documented in `docs/PLUGIN-RISK.md`.
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
    validate_provider_bindings(records.previous_provider_envelopes, RECORD)?;

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
    if records.policy_result.provider_envelopes != records.assessment.provider_envelopes {
        return invalid(
            RECORD,
            "policy result and assessment provider bindings differ",
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
            if !records.previous_provider_envelopes.is_empty() {
                return invalid(RECORD, "install operation carries prior provider evidence");
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
                    .previous_provider_envelopes
                    .iter()
                    .find(|binding| binding.provider_id == provider.provider_id);
                match (&provider.previous_envelope_sha256.0, previous) {
                    (Some(digest), Some(binding)) if digest == &binding.envelope_sha256 => {}
                    (None, None) => {}
                    _ => {
                        return invalid(
                            RECORD,
                            "update provider binding does not match the previous envelope",
                        );
                    }
                }
                let current = records
                    .policy_result
                    .provider_envelopes
                    .iter()
                    .find(|binding| binding.provider_id == provider.provider_id);
                match (&provider.current_envelope_sha256.0, current) {
                    (Some(digest), Some(binding)) if digest == &binding.envelope_sha256 => {}
                    (None, None) => {}
                    _ => {
                        return invalid(
                            RECORD,
                            "update provider binding does not match the current envelope",
                        );
                    }
                }
            }
            if records.previous_provider_envelopes.iter().any(|binding| {
                !delta
                    .providers
                    .iter()
                    .any(|provider| provider.provider_id == binding.provider_id)
            }) {
                return invalid(
                    RECORD,
                    "previous provider envelope is absent from update delta",
                );
            }
            if records
                .policy_result
                .provider_envelopes
                .iter()
                .any(|binding| {
                    !delta
                        .providers
                        .iter()
                        .any(|provider| provider.provider_id == binding.provider_id)
                })
            {
                return invalid(
                    RECORD,
                    "current provider envelope is absent from update delta",
                );
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
        None,
    ));
    if records.publisher.installation_authority != InstallationAuthority::Authorized {
        expected_reasons.insert(policy_reason(
            PolicyReasonCode::PublisherNotAuthorized,
            PolicyDisposition::Block,
            None,
            None,
        ));
    }
    if records.structural.omarchy_manifest_validation != ManifestValidatorStatus::Passed {
        expected_reasons.insert(policy_reason(
            PolicyReasonCode::ManifestValidatorNotPassed,
            PolicyDisposition::Block,
            None,
            None,
        ));
    }

    let bindings = &records.policy_result.provider_envelopes;
    for provider_id in &records.policy.required_provider_ids {
        if !bindings
            .iter()
            .any(|binding| &binding.provider_id == provider_id)
        {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::MissingRequiredProvider,
                records.policy.provider_handling.missing_required,
                Some(provider_id),
                None,
            ));
        }
    }
    for binding in bindings {
        if let Some((code, disposition)) =
            provider_status_reason(binding.run_status, &records.policy.provider_handling)
        {
            expected_reasons.insert(policy_reason(
                code,
                disposition,
                Some(&binding.provider_id),
                None,
            ));
        }
    }

    if let Some(delta) = records.update_delta {
        if delta.publisher_continuity != PublisherContinuityDelta::Matched {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::PublisherContinuityNotMatched,
                PolicyDisposition::Block,
                None,
                None,
            ));
        }
        if delta.plugin_id != PluginIdDelta::Unchanged {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::PluginIdChanged,
                PolicyDisposition::Block,
                None,
                None,
            ));
        }
        if delta.version != VersionDelta::Upgrade {
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::VersionNotUpgrade,
                PolicyDisposition::Block,
                None,
                None,
            ));
        }
        for provider in &delta.providers {
            if provider.capability_changes.iter().any(|change| {
                matches!(
                    change.change,
                    CapabilityChangeKind::Added | CapabilityChangeKind::Expanded
                )
            }) {
                expected_reasons.insert(policy_reason(
                    PolicyReasonCode::PermissionExpansion,
                    records.policy.update_handling.permission_expansion,
                    Some(&provider.provider_id),
                    None,
                ));
            }
            if !provider.coverage_regressions.is_empty() {
                expected_reasons.insert(policy_reason(
                    PolicyReasonCode::CoverageRegression,
                    records.policy.update_handling.coverage_regression,
                    Some(&provider.provider_id),
                    None,
                ));
            }
            expected_reasons.insert(policy_reason(
                PolicyReasonCode::IndeterminateComparison,
                records.policy.update_handling.indeterminate_comparison,
                Some(&provider.provider_id),
                None,
            ));
            if !provider.new_limitation_ids.is_empty() {
                expected_reasons.insert(policy_reason(
                    PolicyReasonCode::NewProviderLimitation,
                    records.policy.provider_handling.incomplete,
                    Some(&provider.provider_id),
                    None,
                ));
            }
            if !provider.new_error_ids.is_empty() {
                expected_reasons.insert(policy_reason(
                    PolicyReasonCode::NewProviderError,
                    records.policy.provider_handling.error,
                    Some(&provider.provider_id),
                    None,
                ));
            }
        }
    }

    for reason in &records.policy_result.reasons {
        match reason.code {
            PolicyReasonCode::UnknownCapability => {
                let provider_id = reason
                    .provider_id
                    .0
                    .as_deref()
                    .expect("validated provider-scoped reason has an ID");
                if !bindings
                    .iter()
                    .any(|binding| binding.provider_id == provider_id)
                {
                    return invalid(RECORD, "capability reason names an unbound provider");
                }
                if reason.disposition != records.policy.unknown_capability {
                    return invalid(RECORD, "unknown-capability reason contradicts policy");
                }
                expected_reasons.insert(reason.clone());
            }
            PolicyReasonCode::DefaultCapability => {
                let provider_id = reason
                    .provider_id
                    .0
                    .as_deref()
                    .expect("validated provider-scoped reason has an ID");
                if !bindings
                    .iter()
                    .any(|binding| binding.provider_id == provider_id)
                {
                    return invalid(RECORD, "capability reason names an unbound provider");
                }
                if reason.disposition != records.policy.default_capability {
                    return invalid(RECORD, "default-capability reason contradicts policy");
                }
                expected_reasons.insert(reason.clone());
            }
            PolicyReasonCode::CapabilityRule => {
                let provider_id = reason
                    .provider_id
                    .0
                    .as_deref()
                    .expect("validated provider-scoped reason has an ID");
                if !bindings
                    .iter()
                    .any(|binding| binding.provider_id == provider_id)
                {
                    return invalid(RECORD, "capability reason names an unbound provider");
                }
                let Some(rule_id) = &reason.rule_id.0 else {
                    return invalid(RECORD, "capability-rule reason lacks a rule ID");
                };
                let Some(rule) = records
                    .policy
                    .capability_rules
                    .iter()
                    .find(|rule| &rule.rule_id == rule_id)
                else {
                    return invalid(
                        RECORD,
                        "policy result references an unknown capability rule",
                    );
                };
                if reason.disposition != rule.disposition {
                    return invalid(RECORD, "capability-rule reason contradicts policy");
                }
                expected_reasons.insert(reason.clone());
            }
            _ => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(
        category: RiskCategory,
        operation: &str,
        scope: RiskScope,
        resource_kind: ResourceKind,
        resource_value: &str,
    ) -> CapabilityKey {
        CapabilityKey {
            category,
            operation: operation.to_owned(),
            scope,
            resource_kind,
            resource_value: Nullable(Some(resource_value.to_owned())),
        }
    }

    #[test]
    fn containment_is_component_label_network_and_transport_aware() {
        let record = "test capability";
        let path_prefix = capability(
            RiskCategory::Filesystem,
            "read",
            RiskScope::Home,
            ResourceKind::PathPrefix,
            "/Documents/",
        );
        let path = capability(
            RiskCategory::Filesystem,
            "read",
            RiskScope::Home,
            ResourceKind::PathExact,
            "/Documents/report.txt",
        );
        let sibling = capability(
            RiskCategory::Filesystem,
            "read",
            RiskScope::Home,
            ResourceKind::PathExact,
            "/Documents-old/report.txt",
        );
        assert!(resource_covers(&path_prefix, &path, record).unwrap());
        assert!(!resource_covers(&path_prefix, &sibling, record).unwrap());

        let suffix = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Internet,
            ResourceKind::DomainSuffix,
            "example.com",
        );
        let host = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Internet,
            ResourceKind::HostExact,
            "api.example.com",
        );
        let deceptive_host = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Internet,
            ResourceKind::HostExact,
            "notexample.com",
        );
        assert!(resource_covers(&suffix, &host, record).unwrap());
        assert!(!resource_covers(&suffix, &deceptive_host, record).unwrap());

        let network = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Lan,
            ResourceKind::Cidr,
            "10.0.0.0/8",
        );
        let subnet = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Lan,
            ResourceKind::Cidr,
            "10.2.0.0/16",
        );
        let other_network = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Lan,
            ResourceKind::Cidr,
            "11.0.0.0/8",
        );
        assert!(resource_covers(&network, &subnet, record).unwrap());
        assert!(!resource_covers(&network, &other_network, record).unwrap());

        let ports = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Internet,
            ResourceKind::PortRange,
            "tcp:100-200",
        );
        let contained_ports = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Internet,
            ResourceKind::PortRange,
            "tcp:120-130",
        );
        let udp_ports = capability(
            RiskCategory::Network,
            "connect",
            RiskScope::Internet,
            ResourceKind::PortRange,
            "udp:120-130",
        );
        assert!(resource_covers(&ports, &contained_ports, record).unwrap());
        assert!(!resource_covers(&ports, &udp_ports, record).unwrap());
    }

    #[test]
    fn expansion_requires_the_current_resource_to_be_strictly_broader() {
        let old = capability(
            RiskCategory::Filesystem,
            "read",
            RiskScope::Home,
            ResourceKind::PathExact,
            "/Documents/report.txt",
        );
        let broader = capability(
            RiskCategory::Filesystem,
            "read",
            RiskScope::Home,
            ResourceKind::PathPrefix,
            "/Documents/",
        );
        assert!(
            validate_capability_delta(
                &CapabilityDelta {
                    change: CapabilityChangeKind::Expanded,
                    previous: Nullable(Some(old.clone())),
                    current: Nullable(Some(broader.clone())),
                },
                "test delta",
            )
            .is_ok()
        );
        assert!(
            validate_capability_delta(
                &CapabilityDelta {
                    change: CapabilityChangeKind::Expanded,
                    previous: Nullable(Some(broader)),
                    current: Nullable(Some(old)),
                },
                "test delta",
            )
            .is_err()
        );
    }
}
