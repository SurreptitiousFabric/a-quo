use std::collections::BTreeMap;
use std::path::PathBuf;

use a_quo_core::VerificationReport;
use a_quo_store::{KeyStatus, PersonaPurpose};
use serde::{Deserialize, Serialize};

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
pub struct PluginInspection {
    pub artifact_evidence: VerificationReport,
    pub publisher_evidence: PublisherEvidence,
    pub manifest: OmarchyManifest,
    pub archive: ArchiveReport,
    pub omarchy_manifest_validation: String,
    pub runtime_safety: String,
    pub a_quo_enablement_action: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstallOutcome {
    pub plugin_id: String,
    pub version: String,
    pub a_quo_enablement_action: String,
    pub omarchy_manifest_validation: String,
    pub shell_rescan: String,
    pub runtime_safety: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateOutcome {
    pub plugin_id: String,
    pub previous_version: String,
    pub version: String,
    pub publisher_continuity: String,
    pub omarchy_manifest_validation: String,
    pub atomic_exchange: bool,
    pub shell_rescan: String,
    pub a_quo_enablement_action: String,
    pub runtime_safety: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UninstallOutcome {
    pub plugin_id: String,
    pub version: String,
    pub observed_reference_state: String,
    pub atomic_quarantine: bool,
    pub shell_rescan: String,
    pub recovery_quarantine: PathBuf,
    pub disk_purge: String,
    pub a_quo_enablement_action: String,
    pub runtime_safety: String,
}
