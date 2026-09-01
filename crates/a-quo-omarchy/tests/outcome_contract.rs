use std::fmt::Debug;

use a_quo_omarchy::{
    AQuoEnablementAction, BehavioralAnalysisStatus, DiskPurgeStatus, InstallOutcome,
    OmarchyManifestValidationStatus, PluginInspection, PluginReferenceState,
    PublisherContinuityStatus, ReferenceObservationBoundary, RuntimeSafetyStatus,
    ShellRescanStatus, TrustedConsentStatus, UninstallOutcome, UninstallOutcomeSchema,
    UpdateOutcome,
};
use serde::{Serialize, de::DeserializeOwned};

const INSPECTION: &[u8] = include_bytes!("../../../fixtures/omarchy-outcomes-v1/inspection.json");
const INSTALL: &[u8] = include_bytes!("../../../fixtures/omarchy-outcomes-v1/install.json");
const UPDATE: &[u8] = include_bytes!("../../../fixtures/omarchy-outcomes-v1/update.json");
const UNINSTALL: &[u8] = include_bytes!("../../../fixtures/omarchy-outcomes-v1/uninstall.json");
const INSTALL_UNKNOWN_STATUS: &[u8] =
    include_bytes!("../../../fixtures/omarchy-outcomes-v1/install-unknown-status.json");
const INSTALL_UNKNOWN_FIELD: &[u8] =
    include_bytes!("../../../fixtures/omarchy-outcomes-v1/install-unknown-field.json");
const UNINSTALL_LEGACY_UNVERSIONED: &[u8] =
    include_bytes!("../../../fixtures/omarchy-outcomes-v1/uninstall-legacy-unversioned.json");
const UNINSTALL_CONTRADICTORY_REFERENCE: &[u8] =
    include_bytes!("../../../fixtures/omarchy-outcomes-v1/uninstall-contradictory-reference.json");

fn exact_fixture<T>(bytes: &[u8]) -> T
where
    T: Debug + DeserializeOwned + Serialize,
{
    let expected = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let parsed = serde_json::from_slice::<T>(expected).expect("fixture must deserialize");
    assert_eq!(
        serde_json::to_vec(&parsed).expect("fixture must reserialize"),
        expected,
        "the typed model changed the reviewed wire bytes"
    );
    parsed
}

fn rejects<T: DeserializeOwned>(bytes: &[u8]) {
    assert!(
        serde_json::from_slice::<T>(bytes).is_err(),
        "hostile or incompatible JSON unexpectedly deserialized"
    );
}

#[test]
fn inspection_preserves_the_existing_wire_vocabulary() {
    let outcome = exact_fixture::<PluginInspection>(INSPECTION);
    assert_eq!(
        outcome.omarchy_manifest_validation,
        OmarchyManifestValidationStatus::NotRun
    );
    assert_eq!(outcome.runtime_safety, RuntimeSafetyStatus::NotEvaluated);
    assert_eq!(
        outcome.a_quo_enablement_action,
        AQuoEnablementAction::NotPerformed
    );
}

#[test]
fn install_preserves_the_existing_wire_vocabulary() {
    let outcome = exact_fixture::<InstallOutcome>(INSTALL);
    assert_eq!(
        outcome.omarchy_manifest_validation,
        OmarchyManifestValidationStatus::PassedPinnedRootObservationNotContentContinuous
    );
    assert_eq!(outcome.shell_rescan, ShellRescanStatus::Passed);
    assert_eq!(outcome.disk_purge, DiskPurgeStatus::NotPerformed);
    assert_eq!(
        outcome.behavioral_analysis,
        BehavioralAnalysisStatus::NotRun
    );
    assert_eq!(outcome.trusted_consent, TrustedConsentStatus::NotRun);
}

#[test]
fn update_preserves_the_existing_wire_vocabulary() {
    let outcome = exact_fixture::<UpdateOutcome>(UPDATE);
    assert_eq!(
        outcome.publisher_continuity,
        PublisherContinuityStatus::SameLocalPersona
    );
    assert_eq!(
        outcome.omarchy_manifest_validation,
        OmarchyManifestValidationStatus::PassedPathObservationNotContinuous
    );
}

#[test]
fn uninstall_v1_separates_reference_state_from_observation_boundary() {
    let outcome = exact_fixture::<UninstallOutcome>(UNINSTALL);
    assert_eq!(outcome.schema, UninstallOutcomeSchema::V1);
    assert_eq!(
        outcome.reference_observation.state(),
        PluginReferenceState::NotReferenced
    );
    assert_eq!(
        outcome.reference_observation.boundary(),
        ReferenceObservationBoundary::BeforeAtomicQuarantine
    );
}

#[test]
fn every_closed_status_rejects_an_unknown_variant() {
    let unknown = br#""unexpected""#;
    rejects::<OmarchyManifestValidationStatus>(unknown);
    rejects::<RuntimeSafetyStatus>(unknown);
    rejects::<AQuoEnablementAction>(unknown);
    rejects::<ShellRescanStatus>(unknown);
    rejects::<DiskPurgeStatus>(unknown);
    rejects::<BehavioralAnalysisStatus>(unknown);
    rejects::<TrustedConsentStatus>(unknown);
    rejects::<PublisherContinuityStatus>(unknown);
    rejects::<ReferenceObservationBoundary>(unknown);
    rejects::<UninstallOutcomeSchema>(unknown);
}

#[test]
fn outcome_receipts_reject_unknown_fields_and_statuses() {
    rejects::<InstallOutcome>(INSTALL_UNKNOWN_STATUS);
    rejects::<InstallOutcome>(INSTALL_UNKNOWN_FIELD);
}

#[test]
fn uninstall_rejects_legacy_and_contradictory_evidence() {
    rejects::<UninstallOutcome>(UNINSTALL_LEGACY_UNVERSIONED);
    rejects::<UninstallOutcome>(UNINSTALL_CONTRADICTORY_REFERENCE);
}
