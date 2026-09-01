use std::collections::BTreeMap;
use std::path::PathBuf;

use a_quo_core::VerificationReport;
use a_quo_store::{KeyStatus, PersonaPurpose};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginReferenceState {
    NotReferenced,
    Referenced,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellConfigSource {
    User,
    SystemDefault,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OmarchyManifestValidationStatus {
    #[serde(rename = "not_run")]
    NotRun,
    #[serde(rename = "passed")]
    Passed,
    #[serde(rename = "passed_path_observation_not_continuous")]
    PassedPathObservationNotContinuous,
    #[serde(rename = "passed_pinned_root_observation_not_content_continuous")]
    PassedPinnedRootObservationNotContentContinuous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RuntimeSafetyStatus {
    #[serde(rename = "not_evaluated")]
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AQuoEnablementAction {
    #[serde(rename = "not_performed")]
    NotPerformed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ShellRescanStatus {
    #[serde(rename = "passed")]
    Passed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiskPurgeStatus {
    #[serde(rename = "not_performed")]
    NotPerformed,
    #[serde(rename = "automatic_temporary_cleanup")]
    AutomaticTemporaryCleanup,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BehavioralAnalysisStatus {
    #[serde(rename = "not_run")]
    NotRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustedConsentStatus {
    #[serde(rename = "not_run")]
    NotRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PublisherContinuityStatus {
    #[serde(rename = "same_local_persona")]
    SameLocalPersona,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReferenceObservationBoundary {
    #[serde(rename = "before_atomic_quarantine")]
    BeforeAtomicQuarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UninstallReferenceObservationWire")]
pub struct UninstallReferenceObservation {
    state: PluginReferenceState,
    boundary: ReferenceObservationBoundary,
}

impl UninstallReferenceObservation {
    pub const fn not_referenced_before_atomic_quarantine() -> Self {
        Self {
            state: PluginReferenceState::NotReferenced,
            boundary: ReferenceObservationBoundary::BeforeAtomicQuarantine,
        }
    }

    pub const fn state(self) -> PluginReferenceState {
        self.state
    }

    pub const fn boundary(self) -> ReferenceObservationBoundary {
        self.boundary
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UninstallReferenceObservationWire {
    state: PluginReferenceState,
    boundary: ReferenceObservationBoundary,
}

impl TryFrom<UninstallReferenceObservationWire> for UninstallReferenceObservation {
    type Error = &'static str;

    fn try_from(value: UninstallReferenceObservationWire) -> Result<Self, Self::Error> {
        if value.state != PluginReferenceState::NotReferenced {
            return Err("successful uninstall observation must be not_referenced");
        }
        Ok(Self {
            state: value.state,
            boundary: value.boundary,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UninstallOutcomeSchema {
    #[serde(rename = "urn:a-quo:omarchy-uninstall-outcome:v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OmarchyManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    pub id: String,
    pub name: String,
    pub version: String,
    pub kinds: Vec<String>,
    #[serde(rename = "entryPoints")]
    pub entry_points: BTreeMap<String, String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArchiveReport {
    pub compressed_bytes: u64,
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    pub uncompressed_file_bytes: u64,
    pub executable_files: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherRegistryStatus {
    NotChecked,
    Unrecognized,
    EvidenceOnly,
    Archived,
    TerminallyRevoked,
    Active,
    Retired,
    Compromised,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherEvidence {
    pub registry_status: PublisherRegistryStatus,
    pub local_label: Option<String>,
    pub local_purpose: Option<PersonaPurpose>,
    pub signed_label_agreement: Option<bool>,
    pub key_status: Option<KeyStatus>,
    pub meaning: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginInspection {
    pub artifact_evidence: VerificationReport,
    pub publisher_evidence: PublisherEvidence,
    pub manifest: OmarchyManifest,
    pub archive: ArchiveReport,
    pub omarchy_manifest_validation: OmarchyManifestValidationStatus,
    pub runtime_safety: RuntimeSafetyStatus,
    pub a_quo_enablement_action: AQuoEnablementAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallOutcome {
    pub plugin_id: String,
    pub version: String,
    pub a_quo_enablement_action: AQuoEnablementAction,
    pub omarchy_manifest_validation: OmarchyManifestValidationStatus,
    pub shell_rescan: ShellRescanStatus,
    pub retained_staging: PathBuf,
    pub staging_retained: bool,
    pub disk_purge: DiskPurgeStatus,
    pub behavioral_analysis: BehavioralAnalysisStatus,
    pub trusted_consent: TrustedConsentStatus,
    pub runtime_safety: RuntimeSafetyStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateOutcome {
    pub plugin_id: String,
    pub previous_version: String,
    pub version: String,
    pub publisher_continuity: PublisherContinuityStatus,
    pub omarchy_manifest_validation: OmarchyManifestValidationStatus,
    pub atomic_exchange: bool,
    pub shell_rescan: ShellRescanStatus,
    pub previous_release_recovery: PathBuf,
    pub recovery_retained: bool,
    pub disk_purge: DiskPurgeStatus,
    pub a_quo_enablement_action: AQuoEnablementAction,
    pub behavioral_analysis: BehavioralAnalysisStatus,
    pub trusted_consent: TrustedConsentStatus,
    pub runtime_safety: RuntimeSafetyStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallOutcome {
    pub schema: UninstallOutcomeSchema,
    pub plugin_id: String,
    pub version: String,
    pub reference_observation: UninstallReferenceObservation,
    pub atomic_quarantine: bool,
    pub shell_rescan: ShellRescanStatus,
    pub recovery_quarantine: PathBuf,
    pub disk_purge: DiskPurgeStatus,
    pub a_quo_enablement_action: AQuoEnablementAction,
    pub behavioral_analysis: BehavioralAnalysisStatus,
    pub trusted_consent: TrustedConsentStatus,
    pub runtime_safety: RuntimeSafetyStatus,
}

/// One fail-closed, point-in-time observation of persisted Omarchy
/// configuration.
///
/// This does not establish that a running shell applied the configuration,
/// loaded a plugin, or kept the same state after the bytes were read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OmarchyReferenceObservation {
    pub plugin_id: String,
    pub state: PluginReferenceState,
    pub shell_config_source: ShellConfigSource,
    pub shell_config_sha256: String,
}
