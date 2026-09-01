use std::path::Path;

use a_quo_core::load_proof;
use a_quo_store::PersonaStore;

use super::super::authorization::publisher_persona_id;
#[cfg(target_os = "linux")]
use super::super::authorization::{FinalAuthorization, with_final_publisher_operation};
use super::super::command::{run_validator, validate_system_command};
use super::super::lifecycle::UpdateLifecycle;
use super::super::package::copy_package_once;
#[cfg(target_os = "linux")]
use super::super::package::snapshot_staged_package;
use super::super::receipt::{build_receipt_for_artifact, write_install_receipt};
#[cfg(target_os = "linux")]
use super::super::receipt::{
    read_update_snapshot_manifest, read_update_snapshot_receipt, require_newer_version,
    validate_installed_state,
};
use super::super::staging::prepare_plugins_directory;
#[cfg(target_os = "linux")]
use super::super::staging::retained_update_staging_directory;
#[cfg(target_os = "linux")]
use super::super::tree::{
    reject_git_managed_target, reject_git_managed_update_snapshot, snapshot_update_tree_path,
    target_identity, verify_candidate_matches_extracted_manifest, verify_update_tree_path,
};
#[cfg(test)]
use super::super::update_test_seam::UpdateTestHooks;
#[cfg(target_os = "linux")]
use super::update_transaction::{
    UpdateBaselines, describe_retained_update_staging, describe_update_recovery_state,
    pinned_update_recovery_path, retain_and_exchange_update, rollback_pinned_update,
    verify_update_layout,
};
#[cfg(target_os = "linux")]
use crate::archive::extract_archive_file;
#[cfg(target_os = "linux")]
use crate::inspect_file_with_proof;
use crate::{
    AQuoEnablementAction, BehavioralAnalysisStatus, DiskPurgeStatus, OmarchyError,
    OmarchyManifestValidationStatus, PublisherContinuityStatus, Result, RuntimeSafetyStatus,
    ShellRescanStatus, TrustedConsentStatus, UpdateOutcome, require_installable_publisher,
};

#[derive(Clone, Copy)]
pub(crate) struct UpdateRequest<'a> {
    package_path: &'a Path,
    proof_path: &'a Path,
    plugins_directory: &'a Path,
    validator: &'a Path,
    omarchy_shell: &'a Path,
}

impl<'a> UpdateRequest<'a> {
    pub(crate) const fn new(
        package_path: &'a Path,
        proof_path: &'a Path,
        plugins_directory: &'a Path,
        validator: &'a Path,
        omarchy_shell: &'a Path,
    ) -> Self {
        Self {
            package_path,
            proof_path,
            plugins_directory,
            validator,
            omarchy_shell,
        }
    }

    #[cfg(test)]
    pub(crate) fn simulated_success(
        package_path: &'a Path,
        proof_path: &'a Path,
        plugins_directory: &'a Path,
    ) -> Self {
        Self::new(
            package_path,
            proof_path,
            plugins_directory,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
    }
}

struct NoopUpdateLifecycle;

impl UpdateLifecycle for NoopUpdateLifecycle {}

pub(crate) fn update_with_commands(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
) -> Result<UpdateOutcome> {
    let mut lifecycle = NoopUpdateLifecycle;
    update_with_lifecycle(
        UpdateRequest::new(
            package_path,
            proof_path,
            plugins_directory,
            validator,
            omarchy_shell,
        ),
        store,
        &mut lifecycle,
    )
}

#[cfg(test)]
pub(crate) fn update_with_test_hooks(
    request: UpdateRequest<'_>,
    store: &mut PersonaStore,
    mut hooks: UpdateTestHooks<'_>,
) -> Result<UpdateOutcome> {
    update_with_lifecycle(request, store, &mut hooks)
}

#[cfg(target_os = "linux")]
fn update_with_lifecycle(
    request: UpdateRequest<'_>,
    store: &mut PersonaStore,
    lifecycle: &mut impl UpdateLifecycle,
) -> Result<UpdateOutcome> {
    let UpdateRequest {
        package_path,
        proof_path,
        plugins_directory,
        validator,
        omarchy_shell,
    } = request;
    validate_system_command(validator)?;
    validate_system_command(omarchy_shell)?;
    prepare_plugins_directory(plugins_directory)?;
    let expected_plugins_identity = target_identity(plugins_directory)?;

    let proof = load_proof(proof_path)?;
    let recovery_path = retained_update_staging_directory(plugins_directory)?;
    let staged_package = recovery_path.join("package.tar.zst");
    copy_package_once(package_path, &staged_package)?;
    let sealed_package = snapshot_staged_package(&staged_package)?;

    let inspection = inspect_file_with_proof(sealed_package.file(), &proof, Some(store))?;
    require_installable_publisher(&inspection)?;
    lifecycle.after_package_inspection(&staged_package)?;
    let expected_publisher_persona_id = publisher_persona_id(store, &inspection)?;
    let target = plugins_directory.join(&inspection.manifest.id);
    let installed_identity = target_identity(&target)?;
    reject_git_managed_target(&target)?;
    let installed_snapshot = snapshot_update_tree_path(&target, installed_identity)
        .map_err(OmarchyError::UpdateStateIndeterminate)?;
    reject_git_managed_update_snapshot(&target, &installed_snapshot)?;
    run_validator(validator, &target)?;
    verify_update_tree_path(
        &target,
        installed_identity,
        &installed_snapshot,
        "installed release changed during manifest validation",
    )
    .map_err(OmarchyError::UpdateStateIndeterminate)?;

    let installed_manifest = read_update_snapshot_manifest(&target, &installed_snapshot)?;
    let installed_receipt = read_update_snapshot_receipt(&target, &installed_snapshot)?;
    validate_installed_state(&target, &installed_manifest, &installed_receipt)?;
    if installed_manifest.id != inspection.manifest.id {
        return Err(OmarchyError::InvalidInstallReceipt(format!(
            "candidate id {} does not match installed id {}",
            inspection.manifest.id, installed_manifest.id
        )));
    }
    if installed_receipt.publisher_persona_id != expected_publisher_persona_id {
        return Err(OmarchyError::PublisherContinuityMismatch);
    }
    require_newer_version(&installed_manifest.version, &inspection.manifest.version)?;

    let extracted = recovery_path.join("plugin");
    let (extracted_manifest, extracted_archive, extracted_tree) =
        extract_archive_file(sealed_package.file(), &extracted)?;
    if extracted_manifest != inspection.manifest || extracted_archive != inspection.archive {
        return Err(OmarchyError::InvalidPackage(
            "archive inspection changed between verification and extraction".to_owned(),
        ));
    }
    let receipt = build_receipt_for_artifact(
        sealed_package.descriptor(),
        &inspection,
        expected_publisher_persona_id.clone(),
    )?;
    let (receipt_size, receipt_sha256) = write_install_receipt(&extracted, &receipt)?;
    let candidate_identity = target_identity(&extracted)?;
    let candidate_snapshot = snapshot_update_tree_path(&extracted, candidate_identity)
        .map_err(OmarchyError::UpdateStateIndeterminate)?;
    verify_candidate_matches_extracted_manifest(
        &candidate_snapshot,
        extracted_tree,
        receipt_size,
        receipt_sha256,
    )
    .map_err(OmarchyError::UpdateStateIndeterminate)?;
    run_validator(validator, &extracted)?;
    verify_update_tree_path(
        &extracted,
        candidate_identity,
        &candidate_snapshot,
        "staged candidate changed during manifest validation",
    )
    .map_err(OmarchyError::UpdateStateIndeterminate)?;
    let expected_recovery_identity = target_identity(&recovery_path)?;
    let baselines = UpdateBaselines {
        plugins_identity: expected_plugins_identity,
        recovery_identity: expected_recovery_identity,
        installed_identity,
        candidate_identity,
        installed_snapshot,
        candidate_snapshot,
    };
    if let Err(cause) = lifecycle.before_final_authorization() {
        return Err(OmarchyError::UpdateAuthorizationRefused {
            cause: Box::new(cause),
            retained_state: describe_retained_update_staging(
                &recovery_path,
                plugins_directory,
                expected_plugins_identity,
                expected_recovery_identity,
            ),
        });
    }
    let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
    let signed_label = &inspection.artifact_evidence.signer.persona;
    let authorization = with_final_publisher_operation(
        store,
        fingerprint,
        signed_label,
        &expected_publisher_persona_id,
        || {
            retain_and_exchange_update(
                &recovery_path,
                plugins_directory,
                &inspection.manifest.id,
                baselines,
            )
        },
        || lifecycle.after_exchange_authorization(),
    );
    let pinned = match authorization {
        FinalAuthorization::Authorized(pinned) => pinned,
        FinalAuthorization::Refused(cause) => {
            return Err(OmarchyError::UpdateAuthorizationRefused {
                cause: Box::new(cause),
                retained_state: describe_retained_update_staging(
                    &recovery_path,
                    plugins_directory,
                    expected_plugins_identity,
                    expected_recovery_identity,
                ),
            });
        }
        FinalAuthorization::OperationFailed(error) => return Err(error),
        FinalAuthorization::FinalizationFailed {
            completed: pinned,
            cause,
        } => {
            if let Err(rollback_error) = rollback_pinned_update(&pinned, &inspection.manifest.id) {
                let recovery_state = describe_update_recovery_state(
                    &pinned,
                    plugins_directory,
                    &inspection.manifest.id,
                    installed_identity,
                );
                return Err(OmarchyError::UpdateRollbackFailed(format!(
                    "publisher authorization finalization failed after exchange ({cause}); exact rollback failed ({rollback_error}); no recursive deletion ran; {recovery_state}"
                )));
            }
            let restore_rescan = lifecycle.rescan(omarchy_shell);
            verify_update_layout(
                &pinned,
                plugins_directory,
                &inspection.manifest.id,
                installed_identity,
                candidate_identity,
            )
            .map_err(|error| {
                let recovery_state = describe_update_recovery_state(
                    &pinned,
                    plugins_directory,
                    &inspection.manifest.id,
                    installed_identity,
                );
                OmarchyError::UpdateStateIndeterminate(format!(
                    "publisher authorization finalization failed after exchange ({cause}) and the prior release was exchanged back, but post-rescan layout verification failed ({error}); no recursive deletion ran; {recovery_state}"
                ))
            })?;
            if let Err(rescan_error) = restore_rescan {
                return Err(OmarchyError::UpdateRollbackFailed(format!(
                    "publisher authorization finalization failed after exchange ({cause}); the exact prior release was restored, but its shell rescan failed ({rescan_error}); the rejected candidate remains at {}",
                    pinned_update_recovery_path(&pinned).display()
                )));
            }
            return Err(OmarchyError::UpdateAuthorizationFinalizationFailed(
                format!(
                    "{cause}; the exact prior release was restored and revalidated; the rejected candidate remains at {}",
                    pinned_update_recovery_path(&pinned).display()
                ),
            ));
        }
        FinalAuthorization::CompletedWithoutValue => {
            return Err(OmarchyError::UpdateStateIndeterminate(
                "publisher authorization completed without an update result".to_owned(),
            ));
        }
    };

    if let Err(rescan_error) = lifecycle.rescan(omarchy_shell) {
        if let Err(rollback_error) = rollback_pinned_update(&pinned, &inspection.manifest.id) {
            let recovery_state = describe_update_recovery_state(
                &pinned,
                plugins_directory,
                &inspection.manifest.id,
                installed_identity,
            );
            return Err(OmarchyError::UpdateRollbackFailed(format!(
                "shell rescan failed ({rescan_error}); exact rollback failed ({rollback_error}); no recursive deletion ran; {recovery_state}"
            )));
        }
        let rollback_rescan = lifecycle.rescan(omarchy_shell);
        verify_update_layout(
            &pinned,
            plugins_directory,
            &inspection.manifest.id,
            installed_identity,
            candidate_identity,
        )
        .map_err(|error| {
            let recovery_state = describe_update_recovery_state(
                &pinned,
                plugins_directory,
                &inspection.manifest.id,
                installed_identity,
            );
            OmarchyError::UpdateStateIndeterminate(format!(
                "the prior release was exchanged back after shell rescan failed ({rescan_error}), but post-rescan layout verification failed ({error}); no recursive deletion ran; {recovery_state}"
            ))
        })?;
        if let Err(rollback_rescan_error) = rollback_rescan {
            return Err(OmarchyError::UpdateRollbackFailed(format!(
                "the exact prior release was restored and revalidated after shell rescan failed ({rescan_error}), but the restore rescan also failed ({rollback_rescan_error}); the rejected candidate remains at {}",
                pinned_update_recovery_path(&pinned).display()
            )));
        }
        return Err(OmarchyError::UpdateRolledBack(format!(
            "{rescan_error}; the exact prior release was restored and the rejected candidate remains at {}",
            pinned_update_recovery_path(&pinned).display()
        )));
    }

    verify_update_layout(
        &pinned,
        plugins_directory,
        &inspection.manifest.id,
        candidate_identity,
        installed_identity,
    )
    .map_err(|error| {
        let recovery_state = describe_update_recovery_state(
            &pinned,
            plugins_directory,
            &inspection.manifest.id,
            installed_identity,
        );
        OmarchyError::UpdateStateIndeterminate(format!(
            "final update layout verification failed ({error}); no recursive deletion ran; {recovery_state}"
        ))
    })?;

    Ok(UpdateOutcome {
        plugin_id: inspection.manifest.id,
        previous_version: installed_manifest.version,
        version: inspection.manifest.version,
        publisher_continuity: PublisherContinuityStatus::SameLocalPersona,
        omarchy_manifest_validation:
            OmarchyManifestValidationStatus::PassedPathObservationNotContinuous,
        atomic_exchange: true,
        shell_rescan: ShellRescanStatus::Passed,
        previous_release_recovery: pinned_update_recovery_path(&pinned),
        recovery_retained: true,
        disk_purge: DiskPurgeStatus::NotPerformed,
        a_quo_enablement_action: AQuoEnablementAction::NotPerformed,
        behavioral_analysis: BehavioralAnalysisStatus::NotRun,
        trusted_consent: TrustedConsentStatus::NotRun,
        runtime_safety: RuntimeSafetyStatus::NotEvaluated,
    })
}

#[cfg(not(target_os = "linux"))]
fn update_with_lifecycle(
    request: UpdateRequest<'_>,
    store: &mut PersonaStore,
    lifecycle: &mut impl UpdateLifecycle,
) -> Result<UpdateOutcome> {
    let _ = (request, store, lifecycle);
    Err(OmarchyError::AtomicUpdate(
        "guarded Omarchy updates require Linux descriptor-relative renameat2".to_owned(),
    ))
}
