use std::path::Path;

#[cfg(not(target_os = "linux"))]
use a_quo_core::describe_artifact;
use a_quo_core::load_proof;
use a_quo_store::PersonaStore;

use super::super::authorization::publisher_persona_id;
#[cfg(not(target_os = "linux"))]
use super::super::authorization::with_final_publisher_authorization;
#[cfg(target_os = "linux")]
use super::super::authorization::{FinalInstallAuthorization, with_final_install_authorization};
#[cfg(not(target_os = "linux"))]
use super::super::command::run_validator;
#[cfg(target_os = "linux")]
use super::super::command::run_validator_for_descriptor;
use super::super::command::validate_system_command;
#[cfg(target_os = "linux")]
use super::super::install_transaction::{
    InstallBaselines, describe_install_recovery_state, describe_pinned_install_root,
    describe_retained_install_staging, expose_pinned_install_no_replace,
    fail_after_install_and_rollback, install_failed_retained, install_failed_with_pinned_state,
    prepare_pinned_install, verify_install_layout,
};
use super::super::lifecycle::{InstallLifecycle, InstallRescanPhase};
use super::super::package::copy_package_once;
#[cfg(target_os = "linux")]
use super::super::package::snapshot_staged_package;
#[cfg(not(target_os = "linux"))]
use super::super::receipt::build_receipt;
use super::super::receipt::{build_receipt_for_artifact, write_install_receipt};
use super::super::reference::reject_stale_enabled_configuration;
#[cfg(target_os = "linux")]
use super::super::staging::retained_install_staging_directory;
#[cfg(not(target_os = "linux"))]
use super::super::staging::{atomic_install_no_replace, private_staging_directory};
use super::super::staging::{prepare_plugins_directory, reject_existing_target};
#[cfg(test)]
use super::super::test_seam::InstallTestHooks;
#[cfg(target_os = "linux")]
use super::super::tree::{
    TargetIdentity, snapshot_update_tree_path, target_identity,
    verify_candidate_matches_extracted_manifest, verify_update_tree_descriptor,
};
#[cfg(not(target_os = "linux"))]
use crate::PublisherContinuityStatus;
#[cfg(not(target_os = "linux"))]
use crate::archive::extract_archive;
#[cfg(target_os = "linux")]
use crate::archive::extract_archive_file;
#[cfg(not(target_os = "linux"))]
use crate::archive::validate_plugin_id;
#[cfg(target_os = "linux")]
use crate::inspect_file_with_proof;
#[cfg(not(target_os = "linux"))]
use crate::inspect_with_proof;
use crate::{
    AQuoEnablementAction, BehavioralAnalysisStatus, DiskPurgeStatus, InstallOutcome, OmarchyError,
    OmarchyManifestValidationStatus, Result, RuntimeSafetyStatus, ShellRescanStatus,
    TrustedConsentStatus, require_installable_publisher,
};

#[derive(Clone, Copy)]
pub(crate) struct InstallRequest<'a> {
    package_path: &'a Path,
    proof_path: &'a Path,
    plugins_directory: &'a Path,
    validator: &'a Path,
    omarchy_shell: &'a Path,
}

impl<'a> InstallRequest<'a> {
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

struct NoopInstallLifecycle;

impl InstallLifecycle for NoopInstallLifecycle {}

pub(crate) fn install_with_commands(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
) -> Result<InstallOutcome> {
    install_with_lifecycle(
        InstallRequest::new(
            package_path,
            proof_path,
            plugins_directory,
            validator,
            omarchy_shell,
        ),
        store,
        &NoopInstallLifecycle,
    )
}

#[cfg(test)]
pub(crate) fn install_with_test_hooks(
    request: InstallRequest<'_>,
    store: &mut PersonaStore,
    hooks: InstallTestHooks<'_>,
) -> Result<InstallOutcome> {
    install_with_lifecycle(request, store, &hooks)
}

fn install_with_lifecycle(
    request: InstallRequest<'_>,
    store: &mut PersonaStore,
    lifecycle: &impl InstallLifecycle,
) -> Result<InstallOutcome> {
    validate_system_command(request.validator)?;
    validate_system_command(request.omarchy_shell)?;
    prepare_plugins_directory(request.plugins_directory)?;

    #[cfg(target_os = "linux")]
    {
        let expected_plugins_identity = target_identity(request.plugins_directory)?;
        let staging_path = retained_install_staging_directory(request.plugins_directory)?;
        let expected_staging_identity = target_identity(&staging_path).map_err(|error| {
            OmarchyError::InstallStateIndeterminate(format!(
                "install staging was created with automatic cleanup disabled, but its identity could not be established ({error}); the recorded path {} is not safe to purge without manual filesystem inspection",
                staging_path.display()
            ))
        })?;
        install_on_linux(
            request,
            store,
            &staging_path,
            expected_plugins_identity,
            expected_staging_identity,
            lifecycle,
        )
    }

    #[cfg(not(target_os = "linux"))]
    {
        let InstallRequest {
            package_path,
            proof_path,
            plugins_directory,
            validator,
            omarchy_shell,
        } = request;
        let proof = load_proof(proof_path)?;
        let staging = private_staging_directory(plugins_directory, ".a-quo-install-")?;
        let staged_package = staging.path().join("package.tar.zst");
        copy_package_once(package_path, &staged_package)?;

        let inspection = inspect_with_proof(&staged_package, &proof, Some(store))?;
        require_installable_publisher(&inspection)?;
        lifecycle.after_package_inspection(&staged_package)?;
        let expected_publisher_persona_id = publisher_persona_id(store, &inspection)?;
        reject_stale_enabled_configuration(plugins_directory, &inspection.manifest.id)?;

        let target = plugins_directory.join(&inspection.manifest.id);
        reject_existing_target(&target)?;

        let extracted = staging.path().join("plugin");
        let (extracted_manifest, extracted_archive, _) =
            extract_archive(&staged_package, &extracted)?;
        if extracted_manifest != inspection.manifest || extracted_archive != inspection.archive {
            return Err(OmarchyError::InvalidPackage(
                "archive inspection changed between verification and extraction".to_owned(),
            ));
        }
        let receipt = build_receipt(
            &staged_package,
            &inspection,
            expected_publisher_persona_id.clone(),
        )?;
        let _ = write_install_receipt(&extracted, &receipt)?;
        run_validator(validator, &extracted)?;

        lifecycle.before_final_authorization()?;
        reject_stale_enabled_configuration(plugins_directory, &inspection.manifest.id)?;
        reject_existing_target(&target)?;
        let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
        let signed_label = &inspection.artifact_evidence.signer.persona;
        with_final_publisher_authorization(
            store,
            fingerprint,
            signed_label,
            &expected_publisher_persona_id,
            || {
                lifecycle.before_exposure()?;
                atomic_install_no_replace(&extracted, &target)?;
                lifecycle.after_exposure()
            },
        )?;

        lifecycle
            .rescan(omarchy_shell, InstallRescanPhase::Initial)
            .map_err(|error| {
                OmarchyError::InstallStateIndeterminate(format!(
                    "shell rescan failed after installation ({error}); this platform has no automatic fresh-install rollback"
                ))
            })?;
        Ok(InstallOutcome {
            plugin_id: inspection.manifest.id,
            version: inspection.manifest.version,
            a_quo_enablement_action: AQuoEnablementAction::NotPerformed,
            omarchy_manifest_validation: OmarchyManifestValidationStatus::Passed,
            shell_rescan: ShellRescanStatus::Passed,
            retained_staging: staging.path().to_path_buf(),
            staging_retained: false,
            disk_purge: DiskPurgeStatus::AutomaticTemporaryCleanup,
            behavioral_analysis: BehavioralAnalysisStatus::NotRun,
            trusted_consent: TrustedConsentStatus::NotRun,
            runtime_safety: RuntimeSafetyStatus::NotEvaluated,
        })
    }
}

#[cfg(target_os = "linux")]
fn install_on_linux(
    request: InstallRequest<'_>,
    store: &mut PersonaStore,
    staging_path: &Path,
    expected_plugins_identity: TargetIdentity,
    expected_staging_identity: TargetIdentity,
    lifecycle: &impl InstallLifecycle,
) -> Result<InstallOutcome> {
    let InstallRequest {
        package_path,
        proof_path,
        plugins_directory,
        validator,
        omarchy_shell,
    } = request;
    let retained_error = |cause| {
        install_failed_retained(
            cause,
            staging_path,
            plugins_directory,
            expected_plugins_identity,
            expected_staging_identity,
        )
    };

    let proof = load_proof(proof_path)
        .map_err(OmarchyError::from)
        .map_err(&retained_error)?;
    let staged_package = staging_path.join("package.tar.zst");
    copy_package_once(package_path, &staged_package).map_err(&retained_error)?;
    let sealed_package = snapshot_staged_package(&staged_package).map_err(&retained_error)?;
    let inspection = inspect_file_with_proof(sealed_package.file(), &proof, Some(store))
        .map_err(&retained_error)?;
    require_installable_publisher(&inspection).map_err(&retained_error)?;
    lifecycle
        .after_package_inspection(&staged_package)
        .map_err(&retained_error)?;
    let expected_publisher_persona_id =
        publisher_persona_id(store, &inspection).map_err(&retained_error)?;
    reject_stale_enabled_configuration(plugins_directory, &inspection.manifest.id)
        .map_err(&retained_error)?;

    let target = plugins_directory.join(&inspection.manifest.id);
    reject_existing_target(&target).map_err(&retained_error)?;

    let extracted = staging_path.join("plugin");
    let (extracted_manifest, extracted_archive, extracted_tree) =
        extract_archive_file(sealed_package.file(), &extracted).map_err(&retained_error)?;
    if extracted_manifest != inspection.manifest || extracted_archive != inspection.archive {
        return Err(retained_error(OmarchyError::InvalidPackage(
            "archive inspection changed between verification and extraction".to_owned(),
        )));
    }
    let receipt = build_receipt_for_artifact(
        sealed_package.descriptor(),
        &inspection,
        expected_publisher_persona_id.clone(),
    )
    .map_err(&retained_error)?;
    let (receipt_size, receipt_sha256) =
        write_install_receipt(&extracted, &receipt).map_err(&retained_error)?;
    let candidate_identity = target_identity(&extracted).map_err(&retained_error)?;
    let candidate_snapshot = snapshot_update_tree_path(&extracted, candidate_identity)
        .map_err(|error| retained_error(OmarchyError::InstallStateIndeterminate(error)))?;
    verify_candidate_matches_extracted_manifest(
        &candidate_snapshot,
        extracted_tree,
        receipt_size,
        receipt_sha256,
    )
    .map_err(|error| retained_error(OmarchyError::InstallStateIndeterminate(error)))?;

    let baselines = InstallBaselines {
        plugins_identity: expected_plugins_identity,
        staging_identity: expected_staging_identity,
        candidate_identity,
        candidate_snapshot,
    };
    let pinned = prepare_pinned_install(
        plugins_directory,
        staging_path,
        &inspection.manifest.id,
        baselines,
    )
    .map_err(|error| {
        OmarchyError::InstallStateIndeterminate(format!(
            "{error}; automatic cleanup was disabled; {}",
            describe_retained_install_staging(
                staging_path,
                plugins_directory,
                expected_plugins_identity,
                expected_staging_identity,
            )
        ))
    })?;

    run_validator_for_descriptor(validator, &pinned.candidate)
        .map_err(|cause| install_failed_with_pinned_state(cause, &pinned))?;
    verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "staged install candidate changed during pinned-root manifest validation",
    )
    .map_err(|error| {
        OmarchyError::InstallStateIndeterminate(format!(
            "{error}; {}",
            describe_pinned_install_root(&pinned)
        ))
    })?;

    if let Err(cause) = lifecycle.before_final_authorization() {
        return Err(OmarchyError::InstallAuthorizationRefused {
            cause: Box::new(cause),
            retained_state: describe_pinned_install_root(&pinned),
        });
    }
    reject_stale_enabled_configuration(plugins_directory, &inspection.manifest.id)
        .map_err(|cause| install_failed_with_pinned_state(cause, &pinned))?;
    reject_existing_target(&target)
        .map_err(|cause| install_failed_with_pinned_state(cause, &pinned))?;

    let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
    let signed_label = &inspection.artifact_evidence.signer.persona;
    let authorization = with_final_install_authorization(
        store,
        fingerprint,
        signed_label,
        &expected_publisher_persona_id,
        pinned,
        |pinned, rename_completed| {
            expose_pinned_install_no_replace(
                pinned,
                plugins_directory,
                &inspection.manifest.id,
                || lifecycle.before_exposure(),
                rename_completed,
            )
        },
        || lifecycle.after_exposure(),
    );
    let pinned = match authorization {
        FinalInstallAuthorization::Authorized(pinned) => pinned,
        FinalInstallAuthorization::Refused { pinned, cause } => {
            return Err(OmarchyError::InstallAuthorizationRefused {
                cause: Box::new(cause),
                retained_state: describe_pinned_install_root(&pinned),
            });
        }
        FinalInstallAuthorization::OperationFailed {
            pinned,
            cause,
            rename_completed,
        } => {
            let exposure_state = if rename_completed {
                "the descriptor-relative exposure rename completed, but its postcheck failed"
            } else {
                "the descriptor-relative exposure rename did not complete"
            };
            return Err(OmarchyError::InstallStateIndeterminate(format!(
                "{cause}; {exposure_state}; {}",
                describe_install_recovery_state(
                    &pinned,
                    plugins_directory,
                    &inspection.manifest.id,
                )
            )));
        }
        FinalInstallAuthorization::FinalizationFailed { pinned, cause } => {
            let mut recovery_rescan =
                || lifecycle.rescan(omarchy_shell, InstallRescanPhase::Recovery);
            return Err(fail_after_install_and_rollback(
                &pinned,
                plugins_directory,
                &inspection.manifest.id,
                &format!("publisher authorization finalization failed after exposure ({cause})"),
                &mut recovery_rescan,
                OmarchyError::InstallAuthorizationFinalizationFailed,
            ));
        }
    };

    if let Err(rescan_error) = lifecycle.rescan(omarchy_shell, InstallRescanPhase::Initial) {
        let mut recovery_rescan = || lifecycle.rescan(omarchy_shell, InstallRescanPhase::Recovery);
        return Err(fail_after_install_and_rollback(
            &pinned,
            plugins_directory,
            &inspection.manifest.id,
            &format!("shell rescan failed after installation ({rescan_error})"),
            &mut recovery_rescan,
            OmarchyError::InstallRolledBack,
        ));
    }
    verify_install_layout(&pinned, plugins_directory, &inspection.manifest.id).map_err(
        |error| {
            OmarchyError::InstallStateIndeterminate(format!(
                "final install layout verification failed ({error}); no recursive deletion ran; {}",
                describe_install_recovery_state(
                    &pinned,
                    plugins_directory,
                    &inspection.manifest.id,
                )
            ))
        },
    )?;

    Ok(InstallOutcome {
        plugin_id: inspection.manifest.id,
        version: inspection.manifest.version,
        a_quo_enablement_action: AQuoEnablementAction::NotPerformed,
        omarchy_manifest_validation:
            OmarchyManifestValidationStatus::PassedPinnedRootObservationNotContentContinuous,
        shell_rescan: ShellRescanStatus::Passed,
        retained_staging: pinned.staging_path.clone(),
        staging_retained: true,
        disk_purge: DiskPurgeStatus::NotPerformed,
        behavioral_analysis: BehavioralAnalysisStatus::NotRun,
        trusted_consent: TrustedConsentStatus::NotRun,
        runtime_safety: RuntimeSafetyStatus::NotEvaluated,
    })
}
