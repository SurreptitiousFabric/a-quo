use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(target_os = "linux"))]
use a_quo_core::describe_artifact;
use a_quo_core::{ArtifactDescriptor, load_proof};
#[cfg(target_os = "linux")]
use a_quo_ipc::{SealedArtifact, snapshot_artifact};
use a_quo_store::{PersonaAuthorityDisposition, PersonaStore, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::Builder;

#[cfg(test)]
mod test_seam;
#[cfg(test)]
pub(crate) use test_seam::InstallTestHooks;

#[cfg(target_os = "linux")]
use crate::OmarchyManifest;
#[cfg(not(target_os = "linux"))]
use crate::archive::extract_archive;
#[cfg(target_os = "linux")]
use crate::archive::{
    ExtractedTreeEntry, ExtractedTreeManifest, MAX_MANIFEST_BYTES, MAX_SINGLE_FILE_BYTES,
    MAX_UNCOMPRESSED_FILE_BYTES, extract_archive_file, parse_semantic_version,
};
use crate::archive::{MAX_COMPRESSED_BYTES, validate_plugin_id};
#[cfg(target_os = "linux")]
use crate::inspect_file_with_proof;
#[cfg(not(target_os = "linux"))]
use crate::inspect_with_proof;
use crate::{
    AQuoEnablementAction, BehavioralAnalysisStatus, DiskPurgeStatus, InstallOutcome, OmarchyError,
    OmarchyManifestValidationStatus, OmarchyReferenceObservation, PluginInspection,
    PluginReferenceState, PublisherContinuityStatus, Result, RuntimeSafetyStatus,
    ShellConfigSource, ShellRescanStatus, TrustedConsentStatus, UninstallOutcome,
    UninstallOutcomeSchema, UninstallReferenceObservation, UpdateOutcome,
    require_installable_publisher,
};

const VALIDATOR: &str = "/usr/bin/omarchy-plugin-validate";
const OMARCHY_SHELL: &str = "/usr/bin/omarchy-shell";
const DEFAULT_SHELL_CONFIG: &str = "/usr/share/omarchy/config/omarchy/shell.json";
const MAX_SHELL_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const MAX_UPDATE_TREE_BYTES: u64 = MAX_UNCOMPRESSED_FILE_BYTES + MAX_RECEIPT_BYTES;
#[cfg(target_os = "linux")]
const MAX_UPDATE_TREE_ENTRIES: u64 = 8_192;
#[cfg(target_os = "linux")]
const MAX_UPDATE_TREE_DEPTH: usize = 64;
#[cfg(target_os = "linux")]
const MAX_UPDATE_TREE_PATH_BYTES: u64 = 32 * 1024 * 1024;
const RECEIPT_SCHEMA_VERSION: u64 = 1;
pub(crate) const INSTALL_RECEIPT_NAME: &str = ".a-quo-install.json";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallReceipt {
    schema_version: u64,
    plugin_id: String,
    version: String,
    package_sha256: String,
    publisher_key_fingerprint: String,
    publisher_persona_id: String,
    installed_at_unix_seconds: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TargetIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
struct PinnedInstall {
    plugins: OwnedFd,
    staging: OwnedFd,
    candidate: OwnedFd,
    plugins_identity: TargetIdentity,
    staging_identity: TargetIdentity,
    candidate_identity: TargetIdentity,
    candidate_snapshot: UpdateTreeSnapshot,
    staging_name: std::ffi::OsString,
    staging_path: PathBuf,
}

#[cfg(target_os = "linux")]
enum FinalInstallAuthorization {
    Authorized(PinnedInstall),
    Refused {
        pinned: PinnedInstall,
        cause: OmarchyError,
    },
    OperationFailed {
        pinned: PinnedInstall,
        cause: OmarchyError,
        rename_completed: bool,
    },
    FinalizationFailed {
        pinned: PinnedInstall,
        cause: OmarchyError,
    },
}

#[cfg(target_os = "linux")]
struct PinnedRemoval {
    plugins: OwnedFd,
    target: OwnedFd,
    quarantine: OwnedFd,
    plugins_identity: TargetIdentity,
    target_identity: TargetIdentity,
    quarantine_identity: TargetIdentity,
    quarantine_name: std::ffi::OsString,
    quarantine_path: PathBuf,
}

#[cfg(target_os = "linux")]
struct PinnedUpdate {
    plugins: OwnedFd,
    recovery: OwnedFd,
    installed: OwnedFd,
    candidate: OwnedFd,
    plugins_identity: TargetIdentity,
    recovery_identity: TargetIdentity,
    installed_identity: TargetIdentity,
    candidate_identity: TargetIdentity,
    installed_snapshot: UpdateTreeSnapshot,
    candidate_snapshot: UpdateTreeSnapshot,
    recovery_name: std::ffi::OsString,
    recovery_path: PathBuf,
}

#[cfg(target_os = "linux")]
enum FinalUpdateAuthorization {
    Authorized(PinnedUpdate),
    Refused(OmarchyError),
    OperationFailed(OmarchyError),
    FinalizationFailed {
        pinned: PinnedUpdate,
        cause: OmarchyError,
    },
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct UpdateTreeSnapshot {
    entries: Vec<UpdateTreeEntry>,
    total_file_bytes: u64,
    total_path_bytes: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct UpdateTreeEntry {
    path: Vec<Vec<u8>>,
    kind: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: u64,
    sha256: Option<[u8; 32]>,
}

#[cfg(target_os = "linux")]
struct UpdateBaselines {
    plugins_identity: TargetIdentity,
    recovery_identity: TargetIdentity,
    installed_identity: TargetIdentity,
    candidate_identity: TargetIdentity,
    installed_snapshot: UpdateTreeSnapshot,
    candidate_snapshot: UpdateTreeSnapshot,
}

#[cfg(target_os = "linux")]
struct InstallBaselines {
    plugins_identity: TargetIdentity,
    staging_identity: TargetIdentity,
    candidate_identity: TargetIdentity,
    candidate_snapshot: UpdateTreeSnapshot,
}

pub fn install_signed_package(
    package_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
    store: &mut PersonaStore,
    plugins_directory: impl AsRef<Path>,
) -> Result<InstallOutcome> {
    install_with_commands(
        package_path.as_ref(),
        proof_path.as_ref(),
        store,
        plugins_directory.as_ref(),
        Path::new(VALIDATOR),
        Path::new(OMARCHY_SHELL),
    )
}

/// Updates one managed plugin while retaining the displaced tree on Linux.
///
/// The bounded prototype performs no automatic recovery purge. Callers must
/// surface [`UpdateOutcome::previous_release_recovery`] after success and the
/// retained-state detail carried by update errors. Retained trees are
/// reverified at the operation boundary, not made permanently immutable.
pub fn update_signed_package(
    package_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
    store: &mut PersonaStore,
    plugins_directory: impl AsRef<Path>,
) -> Result<UpdateOutcome> {
    update_with_commands(
        package_path.as_ref(),
        proof_path.as_ref(),
        store,
        plugins_directory.as_ref(),
        Path::new(VALIDATOR),
        Path::new(OMARCHY_SHELL),
    )
}

/// Removes a managed plugin from its live Omarchy plugin-ID path.
///
/// This bounded operation never purges the plugin from disk. Callers must
/// surface [`UninstallOutcome::recovery_quarantine`] and `disk_purge` so users
/// know where the moved directory remains.
pub fn uninstall_managed_plugin(
    plugin_id: &str,
    plugins_directory: impl AsRef<Path>,
) -> Result<UninstallOutcome> {
    uninstall_with_commands(
        plugin_id,
        plugins_directory.as_ref(),
        Path::new(OMARCHY_SHELL),
    )
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallRescanPhase {
    Initial,
    Recovery,
}

/// Private install control-flow seam.
///
/// Its callbacks can only observe a boundary or return an error. They cannot
/// supply an authorization result, replace a verified identity, or construct
/// a successful outcome. Production can instantiate only the no-op
/// implementation below; configurable callbacks exist only under `cfg(test)`.
///
/// The complete injection-point inventory is:
///
/// - `after_package_inspection`: challenge the sealed-package/path-substitution
///   invariant after signature and publisher inspection;
/// - `before_final_authorization`: challenge publisher, configuration,
///   candidate-tree, and pinned-parent revalidation before authority is used;
/// - `before_exposure`: challenge the last descriptor-relative source and
///   no-replace destination checks immediately before rename;
/// - `after_exposure`: challenge authorization finalization and final-layout
///   verification after the candidate becomes live; and
/// - `rescan`: inject the initial or recovery rescan result while retaining the
///   existing rollback and recovery-observation behavior.
trait InstallLifecycle {
    fn after_package_inspection(&self, _staged_package: &Path) -> Result<()> {
        Ok(())
    }

    fn before_final_authorization(&self) -> Result<()> {
        Ok(())
    }

    fn before_exposure(&self) -> Result<()> {
        Ok(())
    }

    fn after_exposure(&self) -> Result<()> {
        Ok(())
    }

    fn rescan(
        &self,
        omarchy_shell: &Path,
        _phase: InstallRescanPhase,
    ) -> std::result::Result<(), String> {
        run_rescan(omarchy_shell)
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

pub(crate) fn update_with_commands(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
) -> Result<UpdateOutcome> {
    update_with_rescan(
        package_path,
        proof_path,
        store,
        plugins_directory,
        validator,
        omarchy_shell,
        || run_rescan(omarchy_shell),
    )
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn update_with_commands_and_authorization_hook<F>(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
    before_final_authorization: F,
) -> Result<UpdateOutcome>
where
    F: FnOnce() -> Result<()>,
{
    update_with_rescan_and_authorization_hook(
        package_path,
        proof_path,
        store,
        plugins_directory,
        validator,
        omarchy_shell,
        |_| Ok(()),
        before_final_authorization,
        || Ok(()),
        || run_rescan(omarchy_shell),
    )
}

pub(crate) fn update_with_rescan<F>(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
    rescan: F,
) -> Result<UpdateOutcome>
where
    F: FnMut() -> std::result::Result<(), String>,
{
    update_with_rescan_and_authorization_hook(
        package_path,
        proof_path,
        store,
        plugins_directory,
        validator,
        omarchy_shell,
        |_| Ok(()),
        || Ok(()),
        || Ok(()),
        rescan,
    )
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn update_with_rescan_and_authorization_finalization_hook<C, F>(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
    after_exchange_authorization: C,
    rescan: F,
) -> Result<UpdateOutcome>
where
    C: FnOnce() -> Result<()>,
    F: FnMut() -> std::result::Result<(), String>,
{
    update_with_rescan_and_authorization_hook(
        package_path,
        proof_path,
        store,
        plugins_directory,
        validator,
        omarchy_shell,
        |_| Ok(()),
        || Ok(()),
        after_exchange_authorization,
        rescan,
    )
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn update_with_rescan_and_staged_package_hook<H, F>(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
    after_package_inspection: H,
    rescan: F,
) -> Result<UpdateOutcome>
where
    H: FnOnce(&Path) -> Result<()>,
    F: FnMut() -> std::result::Result<(), String>,
{
    update_with_rescan_and_authorization_hook(
        package_path,
        proof_path,
        store,
        plugins_directory,
        validator,
        omarchy_shell,
        after_package_inspection,
        || Ok(()),
        || Ok(()),
        rescan,
    )
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn update_with_rescan_and_authorization_hook<H, A, C, F>(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
    after_package_inspection: H,
    before_final_authorization: A,
    after_exchange_authorization: C,
    mut rescan: F,
) -> Result<UpdateOutcome>
where
    H: FnOnce(&Path) -> Result<()>,
    A: FnOnce() -> Result<()>,
    C: FnOnce() -> Result<()>,
    F: FnMut() -> std::result::Result<(), String>,
{
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
    after_package_inspection(&staged_package)?;
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
    if let Err(cause) = before_final_authorization() {
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
    let authorization = with_final_update_authorization(
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
        after_exchange_authorization,
    );
    let pinned = match authorization {
        FinalUpdateAuthorization::Authorized(pinned) => pinned,
        FinalUpdateAuthorization::Refused(cause) => {
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
        FinalUpdateAuthorization::OperationFailed(error) => return Err(error),
        FinalUpdateAuthorization::FinalizationFailed { pinned, cause } => {
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
            let restore_rescan = rescan();
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
    };

    if let Err(rescan_error) = rescan() {
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
        let rollback_rescan = rescan();
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
#[allow(clippy::too_many_arguments)]
fn update_with_rescan_and_authorization_hook<H, A, C, F>(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
    after_package_inspection: H,
    before_final_authorization: A,
    after_exchange_authorization: C,
    rescan: F,
) -> Result<UpdateOutcome>
where
    H: FnOnce(&Path) -> Result<()>,
    A: FnOnce() -> Result<()>,
    C: FnOnce() -> Result<()>,
    F: FnMut() -> std::result::Result<(), String>,
{
    let _ = (
        package_path,
        proof_path,
        store,
        plugins_directory,
        validator,
        omarchy_shell,
        after_package_inspection,
        before_final_authorization,
        after_exchange_authorization,
        rescan,
    );
    Err(OmarchyError::AtomicUpdate(
        "guarded Omarchy updates require Linux descriptor-relative renameat2".to_owned(),
    ))
}

pub(crate) fn uninstall_with_commands(
    plugin_id: &str,
    plugins_directory: &Path,
    omarchy_shell: &Path,
) -> Result<UninstallOutcome> {
    uninstall_with_rescan_and_quarantine_hook(
        plugin_id,
        plugins_directory,
        omarchy_shell,
        || Ok(()),
        || run_rescan(omarchy_shell),
    )
}

#[cfg(test)]
pub(crate) fn uninstall_with_rescan<F>(
    plugin_id: &str,
    plugins_directory: &Path,
    omarchy_shell: &Path,
    rescan: F,
) -> Result<UninstallOutcome>
where
    F: FnMut() -> std::result::Result<(), String>,
{
    uninstall_with_rescan_and_quarantine_hook(
        plugin_id,
        plugins_directory,
        omarchy_shell,
        || Ok(()),
        rescan,
    )
}

#[cfg(test)]
pub(crate) fn uninstall_with_commands_and_quarantine_hook<F>(
    plugin_id: &str,
    plugins_directory: &Path,
    omarchy_shell: &Path,
    before_atomic_quarantine: F,
) -> Result<UninstallOutcome>
where
    F: FnOnce() -> Result<()>,
{
    uninstall_with_rescan_and_quarantine_hook(
        plugin_id,
        plugins_directory,
        omarchy_shell,
        before_atomic_quarantine,
        || run_rescan(omarchy_shell),
    )
}

#[cfg(target_os = "linux")]
fn uninstall_with_rescan_and_quarantine_hook<A, F>(
    plugin_id: &str,
    plugins_directory: &Path,
    omarchy_shell: &Path,
    before_atomic_quarantine: A,
    mut rescan: F,
) -> Result<UninstallOutcome>
where
    A: FnOnce() -> Result<()>,
    F: FnMut() -> std::result::Result<(), String>,
{
    validate_system_command(omarchy_shell)?;
    validate_plugin_id(plugin_id)?;
    require_existing_plugins_directory(plugins_directory)?;

    let target = plugins_directory.join(plugin_id);
    let expected_identity = target_identity(&target)?;
    reject_git_managed_target(&target)?;
    let installed_manifest = read_installed_manifest(&target)?;
    let installed_receipt = read_install_receipt(&target)?;
    validate_installed_state(&target, &installed_manifest, &installed_receipt)?;
    if installed_manifest.id != plugin_id {
        return Err(OmarchyError::InvalidInstallReceipt(format!(
            "{} names plugin {}, not requested plugin {plugin_id}",
            target.join(INSTALL_RECEIPT_NAME).display(),
            installed_manifest.id
        )));
    }
    reject_referenced_removal(plugins_directory, plugin_id)?;

    let pinned = prepare_pinned_removal(plugins_directory, plugin_id, &target, expected_identity)?;
    before_atomic_quarantine()?;
    reject_referenced_removal(plugins_directory, plugin_id)?;
    reject_git_managed_target(&target)?;
    let moved = quarantine_pinned_target(&pinned, plugin_id)?;

    if let Err(rescan_error) = rescan() {
        if let Err(rollback_error) = restore_pinned_target(&pinned, plugin_id) {
            let recovery_state = describe_pinned_recovery_state(&pinned, plugins_directory);
            return Err(OmarchyError::RemovalRollbackFailed(format!(
                "shell rescan failed ({rescan_error}); exact plugin restore failed ({rollback_error}); no recursive deletion ran; {recovery_state}"
            )));
        }
        let rollback_rescan = rescan();
        if let Err(post_restore_error) =
            verify_restored_target(&pinned, plugins_directory, plugin_id)
        {
            return Err(OmarchyError::RemovalStateIndeterminate(format!(
                "the exact plugin directory was restored after shell rescan failed ({rescan_error}), but post-rescan identity verification failed ({post_restore_error}); no recursive deletion ran and no quarantine cleanup ran"
            )));
        }
        if let Err(rollback_rescan_error) = rollback_rescan {
            return Err(OmarchyError::RemovalRollbackFailed(format!(
                "the exact plugin directory was restored and revalidated after shell rescan failed ({rescan_error}), but the restore rescan also failed ({rollback_rescan_error}); no quarantine cleanup ran"
            )));
        }
        return Err(OmarchyError::RemovalRolledBack(format!(
            "{rescan_error}; the exact managed directory was restored and revalidated; no quarantine cleanup ran"
        )));
    }

    verify_retained_quarantine(&pinned, &moved, plugins_directory, plugin_id)?;

    Ok(UninstallOutcome {
        schema: UninstallOutcomeSchema::V1,
        plugin_id: installed_manifest.id,
        version: installed_manifest.version,
        reference_observation:
            UninstallReferenceObservation::not_referenced_before_atomic_quarantine(),
        atomic_quarantine: true,
        shell_rescan: ShellRescanStatus::Passed,
        recovery_quarantine: pinned.quarantine_path,
        disk_purge: DiskPurgeStatus::NotPerformed,
        a_quo_enablement_action: AQuoEnablementAction::NotPerformed,
        behavioral_analysis: BehavioralAnalysisStatus::NotRun,
        trusted_consent: TrustedConsentStatus::NotRun,
        runtime_safety: RuntimeSafetyStatus::NotEvaluated,
    })
}

#[cfg(not(target_os = "linux"))]
fn uninstall_with_rescan_and_quarantine_hook<A, F>(
    plugin_id: &str,
    plugins_directory: &Path,
    omarchy_shell: &Path,
    _before_atomic_quarantine: A,
    _rescan: F,
) -> Result<UninstallOutcome>
where
    A: FnOnce() -> Result<()>,
    F: FnMut() -> std::result::Result<(), String>,
{
    let _ = (plugins_directory, omarchy_shell);
    validate_plugin_id(plugin_id)?;
    Err(OmarchyError::AtomicRemoval(
        "guarded Omarchy removal requires Linux descriptor-relative renameat2".to_owned(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn private_staging_directory(plugins_directory: &Path, prefix: &str) -> Result<tempfile::TempDir> {
    let directory = Builder::new()
        .prefix(prefix)
        .tempdir_in(plugins_directory)
        .map_err(|source| OmarchyError::Io {
            path: plugins_directory.to_path_buf(),
            source,
        })?;
    secure_private_directory(directory.path())?;
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn retained_install_staging_directory(plugins_directory: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let directory = Builder::new()
        .prefix(".a-quo-install-")
        .permissions(fs::Permissions::from_mode(0o700))
        .disable_cleanup(true)
        .tempdir_in(plugins_directory)
        .map_err(|source| OmarchyError::Io {
            path: plugins_directory.to_path_buf(),
            source,
        })?;
    let staging_path = directory.path().to_path_buf();
    let retained_path = directory.keep();
    if retained_path != staging_path {
        return Err(OmarchyError::InstallStateIndeterminate(
            "install staging path changed while automatic cleanup was disabled".to_owned(),
        ));
    }
    Ok(staging_path)
}

#[cfg(target_os = "linux")]
fn retained_update_staging_directory(plugins_directory: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let directory = Builder::new()
        .prefix(".a-quo-update-")
        .permissions(fs::Permissions::from_mode(0o700))
        .disable_cleanup(true)
        .tempdir_in(plugins_directory)
        .map_err(|source| OmarchyError::Io {
            path: plugins_directory.to_path_buf(),
            source,
        })?;
    let recovery_path = directory.path().to_path_buf();
    let retained_path = directory.keep();
    if retained_path != recovery_path {
        return Err(OmarchyError::UpdateStateIndeterminate(
            "update staging path changed while automatic cleanup was disabled".to_owned(),
        ));
    }
    Ok(recovery_path)
}

#[cfg(target_os = "linux")]
fn retained_removal_quarantine(plugins_directory: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let directory = Builder::new()
        .prefix(".a-quo-remove-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(plugins_directory)
        .map_err(|source| OmarchyError::Io {
            path: plugins_directory.to_path_buf(),
            source,
        })?;
    let quarantine_path = directory.path().to_path_buf();
    let retained_path = directory.keep();
    if retained_path != quarantine_path {
        return Err(OmarchyError::AtomicRemoval(
            "recovery quarantine path changed while automatic cleanup was disabled".to_owned(),
        ));
    }
    Ok(quarantine_path)
}

#[cfg(not(target_os = "linux"))]
fn with_final_publisher_authorization<T>(
    store: &mut PersonaStore,
    fingerprint: &str,
    signed_label: &str,
    expected_publisher_persona_id: &str,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let result = store.with_active_key_authorization(fingerprint, signed_label, |recognized| {
        if recognized.persona.id != expected_publisher_persona_id {
            return Err(OmarchyError::PublisherContinuityMismatch);
        }
        operation()
    });
    result.map_err(|error| normalize_final_authorization_error(error, fingerprint))
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn with_final_install_authorization(
    store: &mut PersonaStore,
    fingerprint: &str,
    signed_label: &str,
    expected_publisher_persona_id: &str,
    pinned: PinnedInstall,
    operation: impl FnOnce(&PinnedInstall, &mut bool) -> Result<()>,
    after_exposure: impl FnOnce() -> Result<()>,
) -> FinalInstallAuthorization {
    let mut operation_started = false;
    let mut operation_completed = false;
    let mut rename_completed = false;
    let result = store.with_active_key_authorization(fingerprint, signed_label, |recognized| {
        if recognized.persona.id != expected_publisher_persona_id {
            return Err(OmarchyError::PublisherContinuityMismatch);
        }
        operation_started = true;
        operation(&pinned, &mut rename_completed)?;
        operation_completed = true;
        after_exposure()?;
        Ok(())
    });
    let normalized =
        result.map_err(|error| normalize_final_authorization_error(error, fingerprint));
    match (normalized, operation_started, operation_completed) {
        (Ok(()), _, true) => FinalInstallAuthorization::Authorized(pinned),
        (Ok(()), _, false) => FinalInstallAuthorization::OperationFailed {
            pinned,
            cause: OmarchyError::InstallStateIndeterminate(
                "publisher authorization completed without exposing an install".to_owned(),
            ),
            rename_completed,
        },
        (Err(cause), _, true) => FinalInstallAuthorization::FinalizationFailed { pinned, cause },
        (Err(cause), true, false) => FinalInstallAuthorization::OperationFailed {
            pinned,
            cause,
            rename_completed,
        },
        (Err(cause), false, false) => FinalInstallAuthorization::Refused { pinned, cause },
    }
}

#[cfg(target_os = "linux")]
fn with_final_update_authorization(
    store: &mut PersonaStore,
    fingerprint: &str,
    signed_label: &str,
    expected_publisher_persona_id: &str,
    operation: impl FnOnce() -> Result<PinnedUpdate>,
    after_exchange: impl FnOnce() -> Result<()>,
) -> FinalUpdateAuthorization {
    let mut completed = None;
    let mut operation_started = false;
    let result = store.with_active_key_authorization(fingerprint, signed_label, |recognized| {
        if recognized.persona.id != expected_publisher_persona_id {
            return Err(OmarchyError::PublisherContinuityMismatch);
        }
        operation_started = true;
        let pinned = operation()?;
        completed = Some(pinned);
        after_exchange()?;
        Ok(())
    });
    let normalized =
        result.map_err(|error| normalize_final_authorization_error(error, fingerprint));
    match (normalized, completed, operation_started) {
        (Ok(()), Some(pinned), _) => FinalUpdateAuthorization::Authorized(pinned),
        (Ok(()), None, _) => {
            FinalUpdateAuthorization::OperationFailed(OmarchyError::UpdateStateIndeterminate(
                "publisher authorization completed without an update result".to_owned(),
            ))
        }
        (Err(cause), Some(pinned), _) => {
            FinalUpdateAuthorization::FinalizationFailed { pinned, cause }
        }
        (Err(cause), None, true) => FinalUpdateAuthorization::OperationFailed(cause),
        (Err(cause), None, false) => FinalUpdateAuthorization::Refused(cause),
    }
}

fn normalize_final_authorization_error(error: OmarchyError, fingerprint: &str) -> OmarchyError {
    match error {
        OmarchyError::Store(StoreError::PersonaTerminallyRevoked(_)) => {
            OmarchyError::TerminalPublisher(fingerprint.to_owned())
        }
        OmarchyError::Store(StoreError::PersonaArchived(_)) => {
            OmarchyError::ArchivedPublisher(fingerprint.to_owned())
        }
        OmarchyError::Store(StoreError::ContinuityEvidenceOnly(_)) => {
            OmarchyError::EvidenceOnlyPublisher(fingerprint.to_owned())
        }
        OmarchyError::Store(StoreError::PersonaLabelMismatch(_)) => {
            OmarchyError::PublisherLabelMismatch
        }
        OmarchyError::Store(StoreError::InactiveSigningKey(rejected)) => {
            if rejected != fingerprint {
                return OmarchyError::Store(StoreError::InactiveSigningKey(rejected));
            }
            OmarchyError::InactivePublisher {
                fingerprint: rejected,
                status: "inactive",
            }
        }
        error => error,
    }
}

pub(crate) fn publisher_persona_id(
    store: &PersonaStore,
    inspection: &PluginInspection,
) -> Result<String> {
    let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
    let recognized = store
        .lookup_key(fingerprint)?
        .ok_or_else(|| OmarchyError::UnrecognizedPublisher(fingerprint.clone()))?;
    match recognized.authority_disposition {
        PersonaAuthorityDisposition::Operational => {}
        PersonaAuthorityDisposition::EvidenceOnly => {
            return Err(OmarchyError::EvidenceOnlyPublisher(fingerprint.clone()));
        }
        PersonaAuthorityDisposition::TerminallyRevoked => {
            return Err(OmarchyError::TerminalPublisher(fingerprint.clone()));
        }
        PersonaAuthorityDisposition::Archived => {
            return Err(OmarchyError::ArchivedPublisher(fingerprint.clone()));
        }
    }
    if recognized.persona.archived_at.is_some() {
        return Err(OmarchyError::ArchivedPublisher(fingerprint.clone()));
    }
    match recognized.key.status {
        a_quo_store::KeyStatus::Active => {}
        a_quo_store::KeyStatus::Retired => {
            return Err(OmarchyError::InactivePublisher {
                fingerprint: fingerprint.clone(),
                status: "retired",
            });
        }
        a_quo_store::KeyStatus::Compromised => {
            return Err(OmarchyError::InactivePublisher {
                fingerprint: fingerprint.clone(),
                status: "compromised",
            });
        }
    }
    if recognized.persona.label != inspection.artifact_evidence.signer.persona {
        return Err(OmarchyError::PublisherLabelMismatch);
    }
    Ok(recognized.persona.id)
}

#[cfg(not(target_os = "linux"))]
fn build_receipt(
    package: &Path,
    inspection: &PluginInspection,
    publisher_persona_id: String,
) -> Result<InstallReceipt> {
    let artifact = describe_artifact(package)?;
    build_receipt_for_artifact(&artifact, inspection, publisher_persona_id)
}

fn build_receipt_for_artifact(
    artifact: &ArtifactDescriptor,
    inspection: &PluginInspection,
    publisher_persona_id: String,
) -> Result<InstallReceipt> {
    Ok(InstallReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        plugin_id: inspection.manifest.id.clone(),
        version: inspection.manifest.version.clone(),
        package_sha256: artifact.digest.value.clone(),
        publisher_key_fingerprint: inspection.artifact_evidence.signer.key_fingerprint.clone(),
        publisher_persona_id,
        installed_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                OmarchyError::InvalidInstallReceipt(format!(
                    "system clock predates the Unix epoch: {error}"
                ))
            })?
            .as_secs(),
    })
}

fn write_install_receipt(
    plugin_directory: &Path,
    receipt: &InstallReceipt,
) -> Result<(u64, [u8; 32])> {
    let path = plugin_directory.join(INSTALL_RECEIPT_NAME);
    let mut bytes = serde_json::to_vec_pretty(receipt)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(OmarchyError::InvalidInstallReceipt(
            "serialized receipt exceeds its size limit".to_owned(),
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| OmarchyError::Io {
            path: path.clone(),
            source,
        })?;
    secure_receipt(&path)?;
    output
        .write_all(&bytes)
        .map_err(|source| OmarchyError::Io {
            path: path.clone(),
            source,
        })?;
    output.sync_all().map_err(|source| OmarchyError::Io {
        path: path.clone(),
        source,
    })?;
    Ok((bytes.len() as u64, Sha256::digest(&bytes).into()))
}

#[cfg(target_os = "linux")]
fn read_install_receipt(plugin_directory: &Path) -> Result<InstallReceipt> {
    let path = plugin_directory.join(INSTALL_RECEIPT_NAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(OmarchyError::NotManagedInstall(
                plugin_directory.to_path_buf(),
            ));
        }
        Err(source) => return Err(OmarchyError::Io { path, source }),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::InvalidInstallReceipt(format!(
            "{} must be a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() > MAX_RECEIPT_BYTES {
        return Err(OmarchyError::InvalidInstallReceipt(format!(
            "{} exceeds {MAX_RECEIPT_BYTES} bytes",
            path.display()
        )));
    }
    let bytes = fs::read(&path).map_err(|source| OmarchyError::Io {
        path: path.clone(),
        source,
    })?;
    let receipt: InstallReceipt = serde_json::from_slice(&bytes).map_err(|error| {
        OmarchyError::InvalidInstallReceipt(format!("{}: {error}", path.display()))
    })?;
    validate_receipt(&receipt)?;
    Ok(receipt)
}

#[cfg(target_os = "linux")]
fn validate_receipt(receipt: &InstallReceipt) -> Result<()> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err(OmarchyError::InvalidInstallReceipt(format!(
            "unsupported schema version {}",
            receipt.schema_version
        )));
    }
    validate_plugin_id(&receipt.plugin_id)?;
    parse_semantic_version(&receipt.version)?;
    if receipt.package_sha256.len() != 64
        || !receipt
            .package_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(OmarchyError::InvalidInstallReceipt(
            "package_sha256 must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    if receipt.publisher_key_fingerprint.trim().is_empty()
        || receipt.publisher_key_fingerprint.len() > 256
        || receipt.publisher_persona_id.trim().is_empty()
        || receipt.publisher_persona_id.len() > 256
    {
        return Err(OmarchyError::InvalidInstallReceipt(
            "publisher identifiers are empty or too long".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_installed_state(
    target: &Path,
    manifest: &OmarchyManifest,
    receipt: &InstallReceipt,
) -> Result<()> {
    if receipt.plugin_id != manifest.id || receipt.version != manifest.version {
        return Err(OmarchyError::InvalidInstallReceipt(format!(
            "{} does not match the installed manifest",
            target.join(INSTALL_RECEIPT_NAME).display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_installed_manifest(plugin_directory: &Path) -> Result<OmarchyManifest> {
    let path = plugin_directory.join("manifest.json");
    let metadata = fs::symlink_metadata(&path).map_err(|source| OmarchyError::Io {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::SymlinkBoundary(path));
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(OmarchyError::InvalidPackage(format!(
            "installed manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let bytes = fs::read(&path).map_err(|source| OmarchyError::Io {
        path: path.clone(),
        source,
    })?;
    let manifest: OmarchyManifest = serde_json::from_slice(&bytes)?;
    validate_plugin_id(&manifest.id)?;
    parse_semantic_version(&manifest.version)?;
    Ok(manifest)
}

#[cfg(target_os = "linux")]
fn read_update_snapshot_manifest(
    plugin_directory: &Path,
    snapshot: &UpdateTreeSnapshot,
) -> Result<OmarchyManifest> {
    let bytes = read_update_snapshot_file(
        plugin_directory,
        snapshot,
        "manifest.json",
        MAX_MANIFEST_BYTES,
    )?;
    let manifest: OmarchyManifest = serde_json::from_slice(&bytes)?;
    validate_plugin_id(&manifest.id)?;
    parse_semantic_version(&manifest.version)?;
    Ok(manifest)
}

#[cfg(target_os = "linux")]
fn read_update_snapshot_receipt(
    plugin_directory: &Path,
    snapshot: &UpdateTreeSnapshot,
) -> Result<InstallReceipt> {
    let path = plugin_directory.join(INSTALL_RECEIPT_NAME);
    let bytes = read_update_snapshot_file(
        plugin_directory,
        snapshot,
        INSTALL_RECEIPT_NAME,
        MAX_RECEIPT_BYTES,
    )?;
    let receipt: InstallReceipt = serde_json::from_slice(&bytes).map_err(|error| {
        OmarchyError::InvalidInstallReceipt(format!("{}: {error}", path.display()))
    })?;
    validate_receipt(&receipt)?;
    Ok(receipt)
}

#[cfg(target_os = "linux")]
fn read_update_snapshot_file(
    plugin_directory: &Path,
    snapshot: &UpdateTreeSnapshot,
    relative_name: &str,
    maximum: u64,
) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, open};

    let expected_path = vec![relative_name.as_bytes().to_vec()];
    let expected = snapshot
        .entries
        .iter()
        .find(|entry| entry.path == expected_path && entry.kind == b'f')
        .ok_or_else(|| {
            OmarchyError::UpdateStateIndeterminate(format!(
                "installed {relative_name} is absent from the pinned update baseline"
            ))
        })?;
    if expected.size > maximum || expected.sha256.is_none() {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "installed {relative_name} baseline is not a bounded regular file"
        )));
    }

    let path = plugin_directory.join(relative_name);
    let descriptor = open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "cannot open installed {relative_name} without following links: {error}"
        ))
    })?;
    let mut file = File::from(descriptor);
    let before = file.metadata().map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "cannot inspect installed {relative_name}: {error}"
        ))
    })?;
    if !before.is_file() || before.len() > maximum {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "installed {relative_name} is not a bounded regular file"
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            OmarchyError::UpdateStateIndeterminate(format!(
                "cannot read installed {relative_name}: {error}"
            ))
        })?;
    if bytes.len() as u64 > maximum {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "installed {relative_name} exceeded its read limit"
        )));
    }
    let after = file.metadata().map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "cannot recheck installed {relative_name}: {error}"
        ))
    })?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if !after.is_file()
        || before.len() != after.len()
        || expected.size != bytes.len() as u64
        || expected.sha256 != Some(digest)
    {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "installed {relative_name} bytes did not match the pinned update baseline"
        )));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn require_newer_version(installed: &str, candidate: &str) -> Result<()> {
    let installed_version = parse_semantic_version(installed)?;
    let candidate_version = parse_semantic_version(candidate)?;
    if !candidate_version.cmp_precedence(&installed_version).is_gt() {
        return Err(OmarchyError::VersionNotNewer {
            installed: installed.to_owned(),
            candidate: candidate.to_owned(),
        });
    }
    Ok(())
}

fn copy_package_once(source: &Path, destination: &Path) -> Result<()> {
    let mut input = open_package_source(source)?;
    let metadata = input.metadata().map_err(|source_error| OmarchyError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if !metadata.is_file() {
        return Err(OmarchyError::InvalidPackage(
            "package source must be a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_COMPRESSED_BYTES {
        return Err(OmarchyError::PackageTooLarge {
            actual: metadata.len(),
            maximum: MAX_COMPRESSED_BYTES,
        });
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|source_error| OmarchyError::Io {
            path: destination.to_path_buf(),
            source: source_error,
        })?;
    let copied =
        copy_at_most(&mut input, &mut output, MAX_COMPRESSED_BYTES).map_err(|source_error| {
            OmarchyError::Io {
                path: destination.to_path_buf(),
                source: source_error,
            }
        })?;
    if copied > MAX_COMPRESSED_BYTES {
        return Err(OmarchyError::PackageTooLarge {
            actual: copied,
            maximum: MAX_COMPRESSED_BYTES,
        });
    }
    if copied != metadata.len() {
        return Err(OmarchyError::InvalidPackage(
            "package changed while it was copied into staging".to_owned(),
        ));
    }
    output.flush().map_err(|source_error| OmarchyError::Io {
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    secure_staged_package(destination)?;
    output.sync_all().map_err(|source_error| OmarchyError::Io {
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_package_source(source: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        source,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            OmarchyError::SymlinkBoundary(source.to_path_buf())
        } else {
            OmarchyError::Io {
                path: source.to_path_buf(),
                source: std::io::Error::from_raw_os_error(error.raw_os_error()),
            }
        }
    })?;
    Ok(File::from(descriptor))
}

#[cfg(not(target_os = "linux"))]
fn open_package_source(source: &Path) -> Result<File> {
    let link_metadata = fs::symlink_metadata(source).map_err(|source_error| OmarchyError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(OmarchyError::SymlinkBoundary(source.to_path_buf()));
    }
    File::open(source).map_err(|source_error| OmarchyError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })
}

fn copy_at_most(
    input: &mut impl Read,
    output: &mut impl Write,
    maximum: u64,
) -> std::io::Result<u64> {
    std::io::copy(&mut input.take(maximum.saturating_add(1)), output)
}

#[cfg(target_os = "linux")]
fn snapshot_staged_package(path: &Path) -> Result<SealedArtifact> {
    use rustix::fs::{Mode, OFlags, open};

    let metadata = fs::symlink_metadata(path).map_err(|source| OmarchyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::InvalidPackage(
            "staged package must be a regular, non-symlink file".to_owned(),
        ));
    }
    let source = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| OmarchyError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::from_raw_os_error(error.raw_os_error()),
    })?;
    snapshot_artifact(source, MAX_COMPRESSED_BYTES).map_err(Into::into)
}

fn prepare_plugins_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|source| OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| OmarchyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(OmarchyError::SymlinkBoundary(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(OmarchyError::InvalidPackage(format!(
            "plugins path is not a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_existing_plugins_directory(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(OmarchyError::PluginsDirectoryMissing(path.to_path_buf()));
        }
        Err(source) => {
            return Err(OmarchyError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(OmarchyError::SymlinkBoundary(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(OmarchyError::InvalidPackage(format!(
            "plugins path is not a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn reject_existing_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(OmarchyError::TargetExists(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(target_os = "linux")]
fn target_identity(path: &Path) -> Result<TargetIdentity> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(OmarchyError::TargetMissing(path.to_path_buf()));
        }
        Err(source) => {
            return Err(OmarchyError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(OmarchyError::SymlinkBoundary(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(OmarchyError::NotManagedInstall(path.to_path_buf()));
    }
    Ok(target_identity_from_metadata(&metadata))
}

#[cfg(target_os = "linux")]
fn target_identity_from_metadata(metadata: &fs::Metadata) -> TargetIdentity {
    use std::os::unix::fs::MetadataExt;

    TargetIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(target_os = "linux")]
fn snapshot_update_tree_path(
    path: &Path,
    expected_identity: TargetIdentity,
) -> std::result::Result<UpdateTreeSnapshot, String> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        path,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot pin update tree {}: {error}", path.display()))?;
    if removal_descriptor_identity_raw(&descriptor, "update tree")? != expected_identity {
        return Err(format!(
            "update tree identity changed before it could be snapshotted: {}",
            path.display()
        ));
    }
    let snapshot = snapshot_update_tree_descriptor(&descriptor)?;
    if target_identity(path)
        .map_err(|error| format!("cannot revalidate update-tree path: {error}"))?
        != expected_identity
    {
        return Err(format!(
            "update tree path changed while it was snapshotted: {}",
            path.display()
        ));
    }
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
fn verify_update_tree_path(
    path: &Path,
    expected_identity: TargetIdentity,
    expected_snapshot: &UpdateTreeSnapshot,
    phase: &str,
) -> std::result::Result<(), String> {
    let actual = snapshot_update_tree_path(path, expected_identity)?;
    if &actual != expected_snapshot {
        return Err(phase.to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_candidate_matches_extracted_manifest(
    snapshot: &UpdateTreeSnapshot,
    mut expected: ExtractedTreeManifest,
    receipt_size: u64,
    receipt_sha256: [u8; 32],
) -> std::result::Result<(), String> {
    expected.entries.push(ExtractedTreeEntry {
        path: vec![INSTALL_RECEIPT_NAME.as_bytes().to_vec()],
        kind: b'f',
        mode: 0o600,
        size: receipt_size,
        sha256: Some(receipt_sha256),
    });
    expected.entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    let actual = snapshot
        .entries
        .iter()
        .map(|entry| ExtractedTreeEntry {
            path: entry.path.clone(),
            kind: entry.kind,
            mode: entry.mode,
            size: entry.size,
            sha256: entry.sha256,
        })
        .collect::<Vec<_>>();
    if actual != expected.entries {
        return Err(
            "extracted candidate tree does not match the verified package and local receipt"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_update_tree_descriptor(
    descriptor: &OwnedFd,
    expected_snapshot: &UpdateTreeSnapshot,
    phase: &str,
) -> std::result::Result<(), String> {
    let actual = snapshot_update_tree_descriptor(descriptor)?;
    if &actual != expected_snapshot {
        return Err(phase.to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn snapshot_update_tree_descriptor(
    descriptor: &OwnedFd,
) -> std::result::Result<UpdateTreeSnapshot, String> {
    let mut snapshot = UpdateTreeSnapshot {
        entries: Vec::new(),
        total_file_bytes: 0,
        total_path_bytes: 0,
    };
    let mut path = Vec::new();
    snapshot_update_directory(descriptor, &mut path, 0, &mut snapshot)?;
    snapshot
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
fn snapshot_update_directory(
    descriptor: &OwnedFd,
    path: &mut Vec<Vec<u8>>,
    depth: usize,
    snapshot: &mut UpdateTreeSnapshot,
) -> std::result::Result<(), String> {
    use rustix::fs::{Dir, FileType, Mode, OFlags, fstat, openat};

    if depth > MAX_UPDATE_TREE_DEPTH {
        return Err(format!(
            "update tree exceeds the maximum depth of {MAX_UPDATE_TREE_DEPTH}"
        ));
    }
    let before = fstat(descriptor)
        .map_err(|error| format!("cannot inspect update-tree directory: {error}"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::Directory {
        return Err("update-tree directory descriptor changed type".to_owned());
    }
    push_update_tree_entry(
        snapshot,
        UpdateTreeEntry {
            path: path.clone(),
            kind: b'd',
            mode: before.st_mode & 0o7777,
            uid: before.st_uid,
            gid: before.st_gid,
            links: before.st_nlink as u64,
            size: 0,
            sha256: None,
        },
    )?;

    let readable = openat(
        descriptor,
        ".",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open pinned update-tree directory: {error}"))?;
    let directory = Dir::new(readable)
        .map_err(|error| format!("cannot enumerate pinned update-tree directory: {error}"))?;
    for entry in directory {
        let entry = entry.map_err(|error| format!("cannot read update-tree entry: {error}"))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name = name.to_owned();
        let child = openat(
            descriptor,
            name.as_c_str(),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| format!("cannot pin update-tree entry: {error}"))?;
        let stat = fstat(&child)
            .map_err(|error| format!("cannot inspect pinned update-tree entry: {error}"))?;
        path.push(name.as_bytes().to_vec());
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                snapshot_update_directory(&child, path, depth + 1, snapshot)?;
            }
            FileType::RegularFile => {
                snapshot_update_file(descriptor, name.as_c_str(), &child, path, snapshot)?;
            }
            _ => {
                return Err(
                    "update tree contains a symlink or unsupported special entry".to_owned(),
                );
            }
        }
        path.pop();
    }

    let after = fstat(descriptor)
        .map_err(|error| format!("cannot re-inspect update-tree directory: {error}"))?;
    if !update_scan_stat_is_stable(&before, &after) {
        return Err("update-tree directory changed while it was snapshotted".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn snapshot_update_file(
    parent: &OwnedFd,
    name: &std::ffi::CStr,
    pinned: &OwnedFd,
    path: &[Vec<u8>],
    snapshot: &mut UpdateTreeSnapshot,
) -> std::result::Result<(), String> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, openat};

    let pinned_stat = fstat(pinned)
        .map_err(|error| format!("cannot inspect pinned update-tree file: {error}"))?;
    if pinned_stat.st_nlink != 1 {
        return Err("update tree contains a multiply linked regular file".to_owned());
    }
    if pinned_stat.st_size < 0 || pinned_stat.st_size as u64 > MAX_SINGLE_FILE_BYTES {
        return Err(format!(
            "update-tree file exceeds the maximum size of {MAX_SINGLE_FILE_BYTES} bytes"
        ));
    }
    let readable = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open pinned update-tree file: {error}"))?;
    let before = fstat(&readable)
        .map_err(|error| format!("cannot inspect readable update-tree file: {error}"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_dev != pinned_stat.st_dev
        || before.st_ino != pinned_stat.st_ino
    {
        return Err("update-tree file changed before it could be read".to_owned());
    }

    let mut file = File::from(readable);
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash update-tree file: {error}"))?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| "update-tree byte count overflowed".to_owned())?;
        if bytes_read > MAX_SINGLE_FILE_BYTES {
            return Err(format!(
                "update-tree file exceeds the maximum size of {MAX_SINGLE_FILE_BYTES} bytes"
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let after =
        fstat(&file).map_err(|error| format!("cannot re-inspect update-tree file: {error}"))?;
    if !update_scan_stat_is_stable(&before, &after) || bytes_read != before.st_size as u64 {
        return Err("update-tree file changed while it was snapshotted".to_owned());
    }
    snapshot.total_file_bytes = snapshot
        .total_file_bytes
        .checked_add(bytes_read)
        .ok_or_else(|| "update-tree total byte count overflowed".to_owned())?;
    if snapshot.total_file_bytes > MAX_UPDATE_TREE_BYTES {
        return Err(format!(
            "update tree exceeds the maximum total file size of {MAX_UPDATE_TREE_BYTES} bytes"
        ));
    }
    push_update_tree_entry(
        snapshot,
        UpdateTreeEntry {
            path: path.to_vec(),
            kind: b'f',
            mode: before.st_mode & 0o7777,
            uid: before.st_uid,
            gid: before.st_gid,
            links: before.st_nlink as u64,
            size: bytes_read,
            sha256: Some(hasher.finalize().into()),
        },
    )
}

#[cfg(target_os = "linux")]
fn push_update_tree_entry(
    snapshot: &mut UpdateTreeSnapshot,
    entry: UpdateTreeEntry,
) -> std::result::Result<(), String> {
    if snapshot.entries.len() as u64 >= MAX_UPDATE_TREE_ENTRIES {
        return Err(format!(
            "update tree exceeds the maximum entry count of {MAX_UPDATE_TREE_ENTRIES}"
        ));
    }
    let entry_path_bytes = entry.path.iter().try_fold(0_u64, |total, component| {
        total.checked_add(component.len() as u64 + 1)
    });
    snapshot.total_path_bytes = snapshot
        .total_path_bytes
        .checked_add(entry_path_bytes.ok_or_else(|| "update-tree path size overflowed".to_owned())?)
        .ok_or_else(|| "update-tree total path size overflowed".to_owned())?;
    if snapshot.total_path_bytes > MAX_UPDATE_TREE_PATH_BYTES {
        return Err(format!(
            "update tree exceeds the maximum stored path size of {MAX_UPDATE_TREE_PATH_BYTES} bytes"
        ));
    }
    snapshot.entries.push(entry);
    Ok(())
}

#[cfg(target_os = "linux")]
fn update_scan_stat_is_stable(before: &rustix::fs::Stat, after: &rustix::fs::Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_nlink == after.st_nlink
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

#[cfg(target_os = "linux")]
fn install_failed_retained(
    cause: OmarchyError,
    staging_path: &Path,
    plugins_directory: &Path,
    expected_plugins_identity: TargetIdentity,
    expected_staging_identity: TargetIdentity,
) -> OmarchyError {
    OmarchyError::InstallFailedRetained {
        cause: Box::new(cause),
        retained_state: describe_retained_install_staging(
            staging_path,
            plugins_directory,
            expected_plugins_identity,
            expected_staging_identity,
        ),
    }
}

#[cfg(target_os = "linux")]
fn install_failed_with_pinned_state(cause: OmarchyError, pinned: &PinnedInstall) -> OmarchyError {
    OmarchyError::InstallFailedRetained {
        cause: Box::new(cause),
        retained_state: describe_pinned_install_root(pinned),
    }
}

#[cfg(target_os = "linux")]
fn describe_retained_install_staging(
    staging_path: &Path,
    plugins_directory: &Path,
    expected_plugins_identity: TargetIdentity,
    expected_staging_identity: TargetIdentity,
) -> String {
    let plugins_path_matches = target_identity(plugins_directory)
        .map(|identity| identity == expected_plugins_identity)
        .unwrap_or(false);
    let staging_path_matches = target_identity(staging_path)
        .map(|identity| identity == expected_staging_identity)
        .unwrap_or(false);
    if plugins_path_matches && staging_path_matches {
        return format!(
            "retained install staging was revalidated at {}",
            staging_path.display()
        );
    }
    format!(
        "retained install staging was identified as device {} inode {} beneath the original plugins root device {} inode {}, but its pathname is indeterminate",
        expected_staging_identity.device,
        expected_staging_identity.inode,
        expected_plugins_identity.device,
        expected_plugins_identity.inode
    )
}

#[cfg(target_os = "linux")]
fn describe_pinned_install_root(pinned: &PinnedInstall) -> String {
    let staging_descriptor_matches =
        removal_descriptor_identity_raw(&pinned.staging, "install staging root")
            .map(|identity| identity == pinned.staging_identity)
            .unwrap_or(false);
    let candidate_descriptor_matches =
        removal_descriptor_identity_raw(&pinned.candidate, "install candidate")
            .map(|identity| identity == pinned.candidate_identity)
            .unwrap_or(false);
    let candidate_tree_matches = verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "install candidate tree changed",
    )
    .is_ok();
    let external_path_matches = target_identity(&pinned.staging_path)
        .map(|identity| identity == pinned.staging_identity)
        .unwrap_or(false);
    let parent_mapping_matches = open_removal_directory_at(
        &pinned.plugins,
        &pinned.staging_name,
        "reported install staging root",
    )
    .map(|(_, identity)| identity == pinned.staging_identity)
    .unwrap_or(false);
    let candidate_mapping_matches = open_removal_directory_at(
        &pinned.staging,
        std::ffi::OsStr::new("plugin"),
        "staged install candidate",
    )
    .map(|(_, identity)| identity == pinned.candidate_identity)
    .unwrap_or(false);
    if staging_descriptor_matches
        && candidate_descriptor_matches
        && candidate_tree_matches
        && external_path_matches
        && parent_mapping_matches
        && candidate_mapping_matches
    {
        return format!(
            "the exact install candidate was revalidated at {}/plugin",
            pinned.staging_path.display()
        );
    }
    if staging_descriptor_matches && candidate_descriptor_matches && candidate_tree_matches {
        return format!(
            "the install staging was last revalidated through its pinned descriptor as device {} inode {} and the candidate as device {} inode {}, but their pathnames are indeterminate and no descriptor remains open after this operation returns",
            pinned.staging_identity.device,
            pinned.staging_identity.inode,
            pinned.candidate_identity.device,
            pinned.candidate_identity.inode
        );
    }
    "the retained install staging or candidate could not be revalidated and requires manual filesystem inspection"
        .to_owned()
}

#[cfg(target_os = "linux")]
fn prepare_pinned_install(
    plugins_directory: &Path,
    staging_path: &Path,
    plugin_id: &str,
    baselines: InstallBaselines,
) -> Result<PinnedInstall> {
    use rustix::fs::{Mode, OFlags, open};

    let InstallBaselines {
        plugins_identity: expected_plugins_identity,
        staging_identity: expected_staging_identity,
        candidate_identity: expected_candidate_identity,
        candidate_snapshot,
    } = baselines;
    let plugins = open(
        plugins_directory,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::InstallStateIndeterminate(format!(
            "cannot pin plugins directory {}: {error}",
            plugins_directory.display()
        ))
    })?;
    let plugins_identity = removal_descriptor_identity_raw(&plugins, "plugins directory")
        .map_err(OmarchyError::InstallStateIndeterminate)?;
    if plugins_identity != expected_plugins_identity
        || target_identity(plugins_directory)? != expected_plugins_identity
    {
        return Err(OmarchyError::InstallStateIndeterminate(format!(
            "plugins directory changed after install staging began: {}",
            plugins_directory.display()
        )));
    }

    let staging_name = staging_path
        .file_name()
        .ok_or_else(|| {
            OmarchyError::InstallStateIndeterminate(
                "install staging directory has no basename".to_owned(),
            )
        })?
        .to_os_string();
    let (staging, staging_identity) =
        open_removal_directory_at(&plugins, &staging_name, "install staging directory")
            .map_err(OmarchyError::InstallStateIndeterminate)?;
    if staging_identity != expected_staging_identity
        || target_identity(staging_path)? != expected_staging_identity
    {
        return Err(OmarchyError::InstallStateIndeterminate(format!(
            "install staging directory changed while it was pinned: {}",
            staging_path.display()
        )));
    }
    let staging_stat = rustix::fs::fstat(&staging).map_err(|error| {
        OmarchyError::InstallStateIndeterminate(format!(
            "cannot inspect pinned install staging directory: {error}"
        ))
    })?;
    if staging_stat.st_mode & 0o7777 != 0o700 {
        return Err(OmarchyError::InstallStateIndeterminate(format!(
            "pinned install staging directory is not mode 0700: {}",
            staging_path.display()
        )));
    }

    let (candidate, candidate_identity) = open_removal_directory_at(
        &staging,
        std::ffi::OsStr::new("plugin"),
        "staged install candidate",
    )
    .map_err(OmarchyError::InstallStateIndeterminate)?;
    if candidate_identity != expected_candidate_identity {
        return Err(OmarchyError::InstallStateIndeterminate(
            "staged install candidate changed while it was pinned".to_owned(),
        ));
    }
    verify_update_tree_descriptor(
        &candidate,
        &candidate_snapshot,
        "staged install candidate changed before validation",
    )
    .map_err(OmarchyError::InstallStateIndeterminate)?;
    match removal_entry_exists(&plugins, std::ffi::OsStr::new(plugin_id)) {
        Ok(false) => {}
        Ok(true) => {
            return Err(OmarchyError::TargetExists(
                plugins_directory.join(plugin_id),
            ));
        }
        Err(error) => {
            return Err(OmarchyError::InstallStateIndeterminate(format!(
                "cannot prove the live install target is absent: {error}"
            )));
        }
    }

    Ok(PinnedInstall {
        plugins,
        staging,
        candidate,
        plugins_identity,
        staging_identity,
        candidate_identity,
        candidate_snapshot,
        staging_name,
        staging_path: staging_path.to_path_buf(),
    })
}

#[cfg(target_os = "linux")]
fn verify_install_source_before_rename(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
) -> std::result::Result<(), String> {
    if removal_descriptor_identity_raw(&pinned.plugins, "plugins directory")?
        != pinned.plugins_identity
        || removal_descriptor_identity_raw(&pinned.staging, "install staging root")?
            != pinned.staging_identity
        || removal_descriptor_identity_raw(&pinned.candidate, "install candidate")?
            != pinned.candidate_identity
    {
        return Err("a pinned install descriptor changed before exposure".to_owned());
    }
    verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "install candidate tree changed before exposure",
    )?;
    let (_, staging_identity) = open_removal_directory_at(
        &pinned.plugins,
        &pinned.staging_name,
        "install staging root before exposure",
    )?;
    if staging_identity != pinned.staging_identity {
        return Err("install staging mapping changed before exposure".to_owned());
    }
    let (_, candidate_identity) = open_removal_directory_at(
        &pinned.staging,
        std::ffi::OsStr::new("plugin"),
        "install candidate before exposure",
    )?;
    if candidate_identity != pinned.candidate_identity {
        return Err("install candidate mapping changed before exposure".to_owned());
    }
    let staging_stat = rustix::fs::fstat(&pinned.staging)
        .map_err(|error| format!("cannot inspect pinned install staging: {error}"))?;
    if staging_stat.st_mode & 0o7777 != 0o700 {
        return Err("install staging is no longer mode 0700".to_owned());
    }
    if target_identity(plugins_directory)
        .map_err(|error| format!("cannot revalidate plugins-directory path: {error}"))?
        != pinned.plugins_identity
        || target_identity(&pinned.staging_path)
            .map_err(|error| format!("cannot revalidate install-staging path: {error}"))?
            != pinned.staging_identity
    {
        return Err("an external install parent path changed before exposure".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn expose_pinned_install_no_replace<B>(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
    immediately_before_rename: B,
    rename_completed: &mut bool,
) -> Result<()>
where
    B: FnOnce() -> Result<()>,
{
    immediately_before_rename()?;
    // The hook models mutations after the ordinary configuration and target
    // checks. Revalidate every source-side binding once, immediately before the
    // syscall. Target absence is deliberately left to RENAME_NOREPLACE so a
    // concurrent target cannot be overwritten between a userspace check and
    // the rename.
    verify_install_source_before_rename(pinned, plugins_directory)
        .map_err(OmarchyError::InstallStateIndeterminate)?;
    rustix::fs::renameat_with(
        &pinned.staging,
        "plugin",
        &pinned.plugins,
        plugin_id,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        OmarchyError::AtomicInstall(format!(
            "descriptor-relative no-replace exposure failed: {error}"
        ))
    })?;
    *rename_completed = true;
    verify_install_layout(pinned, plugins_directory, plugin_id)
        .map_err(OmarchyError::InstallStateIndeterminate)
}

#[cfg(target_os = "linux")]
fn verify_install_layout(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    if removal_descriptor_identity_raw(&pinned.plugins, "plugins directory")?
        != pinned.plugins_identity
        || removal_descriptor_identity_raw(&pinned.staging, "install staging root")?
            != pinned.staging_identity
        || removal_descriptor_identity_raw(&pinned.candidate, "install candidate")?
            != pinned.candidate_identity
    {
        return Err("a pinned install descriptor changed during exposure".to_owned());
    }
    verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "installed candidate tree changed during exposure or rescan",
    )?;
    let (_, live_identity) = open_removal_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "live install target",
    )?;
    if live_identity != pinned.candidate_identity {
        return Err("live install target is not the pinned candidate".to_owned());
    }
    match removal_entry_exists(&pinned.staging, std::ffi::OsStr::new("plugin")) {
        Ok(false) => {}
        Ok(true) => return Err("install staging still contains a plugin entry".to_owned()),
        Err(error) => {
            return Err(format!(
                "cannot verify that install staging no longer contains the candidate: {error}"
            ));
        }
    }
    let (_, staging_identity) = open_removal_directory_at(
        &pinned.plugins,
        &pinned.staging_name,
        "reported install staging root",
    )?;
    if staging_identity != pinned.staging_identity {
        return Err("reported install staging path changed during rescan".to_owned());
    }
    let staging_stat = rustix::fs::fstat(&pinned.staging)
        .map_err(|error| format!("cannot inspect pinned install staging: {error}"))?;
    if staging_stat.st_mode & 0o7777 != 0o700 {
        return Err("install staging is no longer mode 0700".to_owned());
    }
    if target_identity(plugins_directory)
        .map_err(|error| format!("cannot revalidate plugins-directory path: {error}"))?
        != pinned.plugins_identity
        || target_identity(&pinned.staging_path)
            .map_err(|error| format!("cannot revalidate install-staging path: {error}"))?
            != pinned.staging_identity
        || target_identity(&plugins_directory.join(plugin_id))
            .map_err(|error| format!("cannot revalidate live install target: {error}"))?
            != pinned.candidate_identity
    {
        return Err("an external install path no longer names the pinned layout".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rollback_pinned_install(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    rollback_pinned_install_with_hook(pinned, plugins_directory, plugin_id, || Ok(()))
}

#[cfg(target_os = "linux")]
fn rollback_pinned_install_with_hook<B>(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
    immediately_before_rename: B,
) -> std::result::Result<(), String>
where
    B: FnOnce() -> std::result::Result<(), String>,
{
    verify_install_layout(pinned, plugins_directory, plugin_id)?;
    // Parent descriptors stay pinned, but Linux still resolves both child
    // names at the syscall. The test hook exercises that unavoidable final
    // name-resolution window; postchecks must reject a moved wrong child.
    immediately_before_rename()?;
    rustix::fs::renameat_with(
        &pinned.plugins,
        plugin_id,
        &pinned.staging,
        "plugin",
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| format!("descriptor-relative no-replace rollback failed: {error}"))?;
    verify_rolled_back_install_layout(pinned, plugins_directory, plugin_id)
}

#[cfg(target_os = "linux")]
fn verify_rolled_back_install_layout(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    if removal_descriptor_identity_raw(&pinned.plugins, "plugins directory")?
        != pinned.plugins_identity
        || removal_descriptor_identity_raw(&pinned.staging, "install staging root")?
            != pinned.staging_identity
        || removal_descriptor_identity_raw(&pinned.candidate, "install candidate")?
            != pinned.candidate_identity
    {
        return Err("a pinned install descriptor changed during rollback".to_owned());
    }
    verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "rolled-back install candidate tree changed",
    )?;
    match removal_entry_exists(&pinned.plugins, std::ffi::OsStr::new(plugin_id)) {
        Ok(false) => {}
        Ok(true) => return Err("live install target still exists after rollback".to_owned()),
        Err(error) => {
            return Err(format!(
                "cannot prove the live install target is absent after rollback: {error}"
            ));
        }
    }
    let (_, staged_identity) = open_removal_directory_at(
        &pinned.staging,
        std::ffi::OsStr::new("plugin"),
        "rolled-back install candidate",
    )?;
    if staged_identity != pinned.candidate_identity {
        return Err(
            "install staging does not contain the pinned candidate after rollback".to_owned(),
        );
    }
    let (_, staging_identity) = open_removal_directory_at(
        &pinned.plugins,
        &pinned.staging_name,
        "reported install staging root after rollback",
    )?;
    if staging_identity != pinned.staging_identity {
        return Err("reported install staging path changed during rollback".to_owned());
    }
    let staging_stat = rustix::fs::fstat(&pinned.staging)
        .map_err(|error| format!("cannot inspect pinned install staging: {error}"))?;
    if staging_stat.st_mode & 0o7777 != 0o700 {
        return Err("install staging is no longer mode 0700".to_owned());
    }
    if target_identity(plugins_directory)
        .map_err(|error| format!("cannot revalidate plugins-directory path: {error}"))?
        != pinned.plugins_identity
        || target_identity(&pinned.staging_path)
            .map_err(|error| format!("cannot revalidate install-staging path: {error}"))?
            != pinned.staging_identity
        || target_identity(&pinned.staging_path.join("plugin"))
            .map_err(|error| format!("cannot revalidate rolled-back candidate path: {error}"))?
            != pinned.candidate_identity
    {
        return Err("an external install path no longer names the rolled-back layout".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn fail_after_install_and_rollback<F>(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
    original_failure: &str,
    rescan: &mut F,
    successful_rollback_error: fn(String) -> OmarchyError,
) -> OmarchyError
where
    F: FnMut() -> std::result::Result<(), String>,
{
    if let Err(rollback_error) = rollback_pinned_install(pinned, plugins_directory, plugin_id) {
        return OmarchyError::InstallRollbackFailed(format!(
            "{original_failure}; exact rollback failed ({rollback_error}); no recursive deletion ran; {}",
            describe_install_recovery_state(pinned, plugins_directory, plugin_id)
        ));
    }

    let rollback_rescan = rescan();
    let reference_observation = reject_stale_enabled_configuration(plugins_directory, plugin_id);
    let layout_observation =
        verify_rolled_back_install_layout(pinned, plugins_directory, plugin_id);
    if let Err(error) = layout_observation {
        let rescan_context = match &rollback_rescan {
            Ok(()) => "the restoration rescan returned success".to_owned(),
            Err(rescan_error) => format!("the restoration rescan also failed ({rescan_error})"),
        };
        let reference_context = match &reference_observation {
            Ok(()) => "the post-rescan configuration observation was unreferenced".to_owned(),
            Err(reference_error) => {
                format!("the post-rescan configuration observation also failed ({reference_error})")
            }
        };
        return OmarchyError::InstallStateIndeterminate(format!(
            "{original_failure}; the candidate was moved back into retained staging, but post-rescan layout verification failed ({error}); {rescan_context}; {reference_context}; no recursive deletion ran; {}",
            describe_install_recovery_state(pinned, plugins_directory, plugin_id)
        ));
    }
    if let Err(reference_error) = reference_observation {
        let rescan_context = match &rollback_rescan {
            Ok(()) => "the restoration rescan returned success".to_owned(),
            Err(rescan_error) => format!("the restoration rescan also failed ({rescan_error})"),
        };
        return OmarchyError::InstallStateIndeterminate(format!(
            "{original_failure}; the exact candidate was restored to retained staging, but Omarchy configuration no longer proves it is unreferenced ({reference_error}); {rescan_context}; no recursive deletion ran; {}",
            describe_install_recovery_state(pinned, plugins_directory, plugin_id)
        ));
    }
    if let Err(rollback_rescan_error) = rollback_rescan {
        return OmarchyError::InstallRollbackFailed(format!(
            "{original_failure}; the exact candidate was restored to retained staging and revalidated, but the restoration rescan also failed ({rollback_rescan_error}); no recursive deletion ran; {}",
            describe_install_recovery_state(pinned, plugins_directory, plugin_id)
        ));
    }
    successful_rollback_error(format!(
        "{original_failure}; the exact candidate was restored and revalidated at {}/plugin, and the live target was revalidated absent; no recursive deletion ran",
        pinned.staging_path.display()
    ))
}

#[cfg(target_os = "linux")]
fn describe_install_recovery_state(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
) -> String {
    let candidate_descriptor_matches =
        removal_descriptor_identity_raw(&pinned.candidate, "install candidate")
            .map(|identity| identity == pinned.candidate_identity)
            .unwrap_or(false);
    let candidate_tree_matches = verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "install candidate tree changed",
    )
    .is_ok();
    let live_matches = open_removal_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "live install target",
    )
    .map(|(_, identity)| identity == pinned.candidate_identity)
    .unwrap_or(false);
    let staged_matches = open_removal_directory_at(
        &pinned.staging,
        std::ffi::OsStr::new("plugin"),
        "staged install candidate",
    )
    .map(|(_, identity)| identity == pinned.candidate_identity)
    .unwrap_or(false);
    let plugins_path_matches = target_identity(plugins_directory)
        .map(|identity| identity == pinned.plugins_identity)
        .unwrap_or(false);
    let staging_path_matches = target_identity(&pinned.staging_path)
        .map(|identity| identity == pinned.staging_identity)
        .unwrap_or(false);
    let staging_parent_mapping_matches = open_removal_directory_at(
        &pinned.plugins,
        &pinned.staging_name,
        "reported install staging root",
    )
    .map(|(_, identity)| identity == pinned.staging_identity)
    .unwrap_or(false);
    let staging_mode_is_private = rustix::fs::fstat(&pinned.staging)
        .map(|stat| stat.st_mode & 0o7777 == 0o700)
        .unwrap_or(false);

    if candidate_descriptor_matches
        && candidate_tree_matches
        && live_matches
        && plugins_path_matches
    {
        if staging_path_matches && staging_parent_mapping_matches && staging_mode_is_private {
            return format!(
                "the exact candidate was revalidated at the live plugin path {}; retained private staging was revalidated at {}",
                plugins_directory.join(plugin_id).display(),
                pinned.staging_path.display()
            );
        }
        return format!(
            "the exact candidate was revalidated at the live plugin path {}; install staging was last recorded as device {} inode {}, but its pathname or private mode is indeterminate and no staging path is safe to purge without manual filesystem inspection",
            plugins_directory.join(plugin_id).display(),
            pinned.staging_identity.device,
            pinned.staging_identity.inode
        );
    }
    if candidate_descriptor_matches
        && candidate_tree_matches
        && staged_matches
        && staging_path_matches
    {
        return format!(
            "the exact candidate was revalidated at {}/plugin",
            pinned.staging_path.display()
        );
    }
    if candidate_descriptor_matches && candidate_tree_matches {
        return format!(
            "the exact candidate was last revalidated through its pinned descriptor as device {} inode {}, but its pathname is indeterminate and no descriptor remains open after this operation returns",
            pinned.candidate_identity.device, pinned.candidate_identity.inode
        );
    }
    "the install candidate could not be revalidated and requires manual filesystem inspection"
        .to_owned()
}

#[cfg(target_os = "linux")]
fn describe_retained_update_staging(
    recovery_path: &Path,
    plugins_directory: &Path,
    expected_plugins_identity: TargetIdentity,
    expected_recovery_identity: TargetIdentity,
) -> String {
    let plugins_path_matches = target_identity(plugins_directory)
        .map(|identity| identity == expected_plugins_identity)
        .unwrap_or(false);
    let recovery_path_matches = target_identity(recovery_path)
        .map(|identity| identity == expected_recovery_identity)
        .unwrap_or(false);
    if plugins_path_matches && recovery_path_matches {
        return format!(
            "retained update staging was revalidated at {}",
            recovery_path.display()
        );
    }
    format!(
        "retained update staging was identified as device {} inode {} beneath the original plugins root device {} inode {}, but its pathname is indeterminate",
        expected_recovery_identity.device,
        expected_recovery_identity.inode,
        expected_plugins_identity.device,
        expected_plugins_identity.inode
    )
}

#[cfg(target_os = "linux")]
fn describe_pinned_update_root(pinned: &PinnedUpdate) -> String {
    let descriptor_matches =
        removal_descriptor_identity_raw(&pinned.recovery, "update recovery root")
            .map(|identity| identity == pinned.recovery_identity)
            .unwrap_or(false);
    let external_path_matches = target_identity(&pinned.recovery_path)
        .map(|identity| identity == pinned.recovery_identity)
        .unwrap_or(false);
    let parent_mapping_matches = open_removal_directory_at(
        &pinned.plugins,
        &pinned.recovery_name,
        "reported update recovery root",
    )
    .map(|(_, identity)| identity == pinned.recovery_identity)
    .unwrap_or(false);
    if descriptor_matches && external_path_matches && parent_mapping_matches {
        return format!(
            "the retained update root was revalidated at {}",
            pinned.recovery_path.display()
        );
    }
    format!(
        "the retained update root descriptor names device {} inode {}, but its pathname is indeterminate",
        pinned.recovery_identity.device, pinned.recovery_identity.inode
    )
}

#[cfg(target_os = "linux")]
fn retain_and_exchange_update(
    recovery_path: &Path,
    plugins_directory: &Path,
    plugin_id: &str,
    baselines: UpdateBaselines,
) -> Result<PinnedUpdate> {
    let expected_plugins_identity = baselines.plugins_identity;
    let expected_recovery_identity = baselines.recovery_identity;
    let expected_installed_identity = baselines.installed_identity;
    let expected_candidate_identity = baselines.candidate_identity;
    let pinned = prepare_pinned_update(plugins_directory, recovery_path, plugin_id, baselines)
        .map_err(|error| {
            let retained_state = describe_retained_update_staging(
                recovery_path,
                plugins_directory,
                expected_plugins_identity,
                expected_recovery_identity,
            );
            OmarchyError::UpdateStateIndeterminate(format!(
                "{error}; automatic cleanup was disabled; {retained_state}"
            ))
        })?;
    verify_update_pair(
        &pinned,
        plugin_id,
        expected_installed_identity,
        expected_candidate_identity,
        "before initial exchange",
    )
    .map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "{error}; {}",
            describe_pinned_update_root(&pinned)
        ))
    })?;

    rustix::fs::renameat_with(
        &pinned.recovery,
        "plugin",
        &pinned.plugins,
        plugin_id,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        OmarchyError::AtomicUpdate(format!(
            "descriptor-relative update exchange failed ({error}); no recursive deletion ran; {}",
            describe_pinned_update_root(&pinned)
        ))
    })?;

    verify_update_pair(
        &pinned,
        plugin_id,
        expected_candidate_identity,
        expected_installed_identity,
        "after initial exchange",
    )
    .map_err(|error| {
        let recovery_state = describe_update_recovery_state(
            &pinned,
            plugins_directory,
            plugin_id,
            expected_installed_identity,
        );
        OmarchyError::UpdateStateIndeterminate(format!(
            "initial exchange completed but exact-directory verification failed ({error}); no recursive deletion ran; {recovery_state}"
        ))
    })?;
    Ok(pinned)
}

#[cfg(target_os = "linux")]
fn prepare_pinned_update(
    plugins_directory: &Path,
    recovery_path: &Path,
    plugin_id: &str,
    baselines: UpdateBaselines,
) -> Result<PinnedUpdate> {
    use rustix::fs::{Mode, OFlags, open};

    let UpdateBaselines {
        plugins_identity: expected_plugins_identity,
        recovery_identity: expected_recovery_identity,
        installed_identity: expected_installed_identity,
        candidate_identity: expected_candidate_identity,
        installed_snapshot,
        candidate_snapshot,
    } = baselines;

    let plugins = open(
        plugins_directory,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "cannot pin plugins directory {}: {error}",
            plugins_directory.display()
        ))
    })?;
    let plugins_identity = removal_descriptor_identity_raw(&plugins, "plugins directory")
        .map_err(OmarchyError::UpdateStateIndeterminate)?;
    if plugins_identity != expected_plugins_identity
        || target_identity(plugins_directory)? != expected_plugins_identity
    {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "plugins directory changed after update staging began: {}",
            plugins_directory.display()
        )));
    }

    let recovery_name = recovery_path
        .file_name()
        .ok_or_else(|| {
            OmarchyError::UpdateStateIndeterminate(
                "update recovery directory has no basename".to_owned(),
            )
        })?
        .to_os_string();
    let (recovery, recovery_identity) =
        open_removal_directory_at(&plugins, &recovery_name, "update recovery directory")
            .map_err(OmarchyError::UpdateStateIndeterminate)?;
    if recovery_identity != expected_recovery_identity
        || target_identity(recovery_path)? != expected_recovery_identity
    {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "update recovery directory changed while it was pinned: {}",
            recovery_path.display()
        )));
    }
    let recovery_stat = rustix::fs::fstat(&recovery).map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "cannot inspect pinned update recovery directory: {error}"
        ))
    })?;
    if recovery_stat.st_mode & 0o7777 != 0o700 {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "pinned update recovery directory is not mode 0700: {}",
            recovery_path.display()
        )));
    }

    let (installed, installed_identity) = open_removal_directory_at(
        &plugins,
        std::ffi::OsStr::new(plugin_id),
        "installed update target",
    )
    .map_err(OmarchyError::UpdateStateIndeterminate)?;
    if installed_identity != expected_installed_identity {
        return Err(OmarchyError::UpdateStateIndeterminate(
            "installed target changed before descriptor-relative exchange".to_owned(),
        ));
    }

    let (candidate, candidate_identity) = open_removal_directory_at(
        &recovery,
        std::ffi::OsStr::new("plugin"),
        "staged update candidate",
    )
    .map_err(OmarchyError::UpdateStateIndeterminate)?;
    if candidate_identity != expected_candidate_identity {
        return Err(OmarchyError::UpdateStateIndeterminate(
            "staged candidate changed before descriptor-relative exchange".to_owned(),
        ));
    }

    verify_update_tree_descriptor(
        &installed,
        &installed_snapshot,
        "installed release changed before descriptor-relative exchange",
    )
    .map_err(OmarchyError::UpdateStateIndeterminate)?;
    verify_update_tree_descriptor(
        &candidate,
        &candidate_snapshot,
        "staged candidate changed before descriptor-relative exchange",
    )
    .map_err(OmarchyError::UpdateStateIndeterminate)?;

    Ok(PinnedUpdate {
        plugins,
        recovery,
        installed,
        candidate,
        plugins_identity,
        recovery_identity,
        installed_identity,
        candidate_identity,
        installed_snapshot,
        candidate_snapshot,
        recovery_name,
        recovery_path: recovery_path.to_path_buf(),
    })
}

#[cfg(target_os = "linux")]
fn rollback_pinned_update(
    pinned: &PinnedUpdate,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    verify_update_pair(
        pinned,
        plugin_id,
        pinned.candidate_identity,
        pinned.installed_identity,
        "before rollback exchange",
    )?;
    verify_update_tree_descriptor(
        &pinned.installed,
        &pinned.installed_snapshot,
        "the prior release tree changed before rollback",
    )?;
    rustix::fs::renameat_with(
        &pinned.recovery,
        "plugin",
        &pinned.plugins,
        plugin_id,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| format!("descriptor-relative rollback exchange failed: {error}"))?;
    verify_update_pair(
        pinned,
        plugin_id,
        pinned.installed_identity,
        pinned.candidate_identity,
        "after rollback exchange",
    )
}

#[cfg(target_os = "linux")]
fn verify_update_pair(
    pinned: &PinnedUpdate,
    plugin_id: &str,
    expected_live_identity: TargetIdentity,
    expected_recovery_identity: TargetIdentity,
    phase: &str,
) -> std::result::Result<(), String> {
    if removal_descriptor_identity_raw(&pinned.installed, "original installed release")?
        != pinned.installed_identity
        || removal_descriptor_identity_raw(&pinned.candidate, "update candidate")?
            != pinned.candidate_identity
    {
        return Err(format!("pinned release descriptor changed {phase}"));
    }
    let (_, live_identity) = open_removal_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "live update target",
    )?;
    if live_identity != expected_live_identity {
        return Err(format!("live target identity mismatch {phase}"));
    }
    let (_, recovery_child_identity) = open_removal_directory_at(
        &pinned.recovery,
        std::ffi::OsStr::new("plugin"),
        "update recovery child",
    )?;
    if recovery_child_identity != expected_recovery_identity {
        return Err(format!("recovery-child identity mismatch {phase}"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_update_layout(
    pinned: &PinnedUpdate,
    plugins_directory: &Path,
    plugin_id: &str,
    expected_live_identity: TargetIdentity,
    expected_recovery_identity: TargetIdentity,
) -> std::result::Result<(), String> {
    verify_update_pair(
        pinned,
        plugin_id,
        expected_live_identity,
        expected_recovery_identity,
        "during final layout verification",
    )?;
    verify_update_tree_descriptor(
        &pinned.installed,
        &pinned.installed_snapshot,
        "the prior release tree changed during the update operation",
    )?;
    verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "the candidate tree changed during the update operation",
    )?;

    let recovery_stat = rustix::fs::fstat(&pinned.recovery)
        .map_err(|error| format!("cannot inspect pinned update recovery directory: {error}"))?;
    if recovery_stat.st_mode & 0o7777 != 0o700 {
        return Err("update recovery directory is no longer mode 0700".to_owned());
    }
    let (_, current_recovery_identity) = open_removal_directory_at(
        &pinned.plugins,
        &pinned.recovery_name,
        "reported update recovery directory",
    )?;
    if current_recovery_identity != pinned.recovery_identity {
        return Err("reported update recovery path changed during rescan".to_owned());
    }
    let current_plugins_identity = target_identity(plugins_directory)
        .map_err(|error| format!("cannot revalidate plugins-directory path: {error}"))?;
    if current_plugins_identity != pinned.plugins_identity {
        return Err("plugins-directory path changed during rescan".to_owned());
    }
    let external_recovery_identity = target_identity(&pinned.recovery_path)
        .map_err(|error| format!("cannot revalidate update recovery path: {error}"))?;
    if external_recovery_identity != pinned.recovery_identity {
        return Err(
            "external update recovery path no longer names the pinned directory".to_owned(),
        );
    }
    let external_live_identity = target_identity(&plugins_directory.join(plugin_id))
        .map_err(|error| format!("cannot revalidate live update target: {error}"))?;
    if external_live_identity != expected_live_identity {
        return Err("external live path no longer names the expected release".to_owned());
    }
    let external_recovery_child = target_identity(&pinned.recovery_path.join("plugin"))
        .map_err(|error| format!("cannot revalidate recovery child: {error}"))?;
    if external_recovery_child != expected_recovery_identity {
        return Err("external recovery path no longer names the expected release".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn describe_update_recovery_state(
    pinned: &PinnedUpdate,
    plugins_directory: &Path,
    plugin_id: &str,
    expected_prior_identity: TargetIdentity,
) -> String {
    let descriptor_matches =
        removal_descriptor_identity_raw(&pinned.installed, "original installed release")
            .map(|identity| identity == expected_prior_identity)
            .unwrap_or(false);
    let tree_matches = verify_update_tree_descriptor(
        &pinned.installed,
        &pinned.installed_snapshot,
        "prior release tree changed",
    )
    .is_ok();
    let recovery_child_matches = open_removal_directory_at(
        &pinned.recovery,
        std::ffi::OsStr::new("plugin"),
        "update recovery child",
    )
    .map(|(_, identity)| identity == expected_prior_identity)
    .unwrap_or(false);
    let live_child_matches = open_removal_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "live update target",
    )
    .map(|(_, identity)| identity == expected_prior_identity)
    .unwrap_or(false);
    let plugins_path_matches = target_identity(plugins_directory)
        .map(|identity| identity == pinned.plugins_identity)
        .unwrap_or(false);
    let recovery_path_matches = target_identity(&pinned.recovery_path)
        .map(|identity| identity == pinned.recovery_identity)
        .unwrap_or(false);
    let recovery_mode_matches = rustix::fs::fstat(&pinned.recovery)
        .map(|stat| stat.st_mode & 0o7777 == 0o700)
        .unwrap_or(false);

    if descriptor_matches
        && tree_matches
        && recovery_child_matches
        && plugins_path_matches
        && recovery_path_matches
        && recovery_mode_matches
    {
        return format!(
            "the exact prior release was revalidated at {}",
            pinned_update_recovery_path(pinned).display()
        );
    }
    if descriptor_matches && tree_matches && live_child_matches && plugins_path_matches {
        return format!(
            "the exact prior release was revalidated at the live plugin path, but the overall update layout is indeterminate: {}",
            plugins_directory.join(plugin_id).display()
        );
    }
    if descriptor_matches && tree_matches {
        return format!(
            "the prior release descriptor remained pinned, but its pathname is indeterminate; locate device {} inode {} manually",
            pinned.installed_identity.device, pinned.installed_identity.inode
        );
    }
    if descriptor_matches {
        return "the prior release directory remained pinned, but its file tree changed and requires manual inspection"
            .to_owned();
    }
    "the prior release could not be revalidated and requires manual filesystem inspection"
        .to_owned()
}

#[cfg(target_os = "linux")]
fn pinned_update_recovery_path(pinned: &PinnedUpdate) -> PathBuf {
    pinned.recovery_path.join("plugin")
}

#[cfg(target_os = "linux")]
fn prepare_pinned_removal(
    plugins_directory: &Path,
    plugin_id: &str,
    target: &Path,
    expected_target_identity: TargetIdentity,
) -> Result<PinnedRemoval> {
    use rustix::fs::{Mode, OFlags, open};

    let plugins = open(
        plugins_directory,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::AtomicRemoval(format!(
            "cannot pin plugins directory {}: {error}",
            plugins_directory.display()
        ))
    })?;
    let plugins_identity = removal_descriptor_identity(&plugins, "plugins directory")?;
    if target_identity(plugins_directory)? != plugins_identity {
        return Err(OmarchyError::AtomicRemoval(format!(
            "plugins directory changed while removal was prepared: {}",
            plugins_directory.display()
        )));
    }

    let (target_descriptor, target_descriptor_identity) =
        open_removal_directory_at(&plugins, std::ffi::OsStr::new(plugin_id), "managed target")
            .map_err(OmarchyError::AtomicRemoval)?;
    if target_descriptor_identity != expected_target_identity {
        return Err(OmarchyError::AtomicRemoval(format!(
            "managed target changed while removal was prepared: {}",
            target.display()
        )));
    }

    let quarantine_path = retained_removal_quarantine(plugins_directory)?;
    let quarantine_path_identity = target_identity(&quarantine_path).map_err(|error| {
        OmarchyError::AtomicRemoval(format!(
            "cannot identify retained recovery quarantine {}: {error}",
            quarantine_path.display()
        ))
    })?;
    let quarantine_name = quarantine_path
        .file_name()
        .ok_or_else(|| {
            OmarchyError::AtomicRemoval("recovery quarantine has no basename".to_owned())
        })?
        .to_os_string();
    let (quarantine_descriptor, quarantine_identity) =
        open_removal_directory_at(&plugins, &quarantine_name, "recovery quarantine")
            .map_err(OmarchyError::AtomicRemoval)?;
    if quarantine_identity != quarantine_path_identity {
        return Err(OmarchyError::AtomicRemoval(format!(
            "recovery quarantine changed while its descriptor was pinned: {}",
            quarantine_path.display()
        )));
    }
    let quarantine_stat = rustix::fs::fstat(&quarantine_descriptor).map_err(|error| {
        OmarchyError::AtomicRemoval(format!(
            "cannot inspect pinned recovery quarantine {}: {error}",
            quarantine_path.display()
        ))
    })?;
    if quarantine_stat.st_mode & 0o7777 != 0o700 {
        return Err(OmarchyError::AtomicRemoval(format!(
            "pinned recovery quarantine is not mode 0700: {}",
            quarantine_path.display()
        )));
    }

    let (_, final_target_identity) =
        open_removal_directory_at(&plugins, std::ffi::OsStr::new(plugin_id), "managed target")
            .map_err(OmarchyError::AtomicRemoval)?;
    if final_target_identity != target_descriptor_identity {
        return Err(OmarchyError::AtomicRemoval(format!(
            "managed target changed before atomic quarantine: {}",
            target.display()
        )));
    }

    Ok(PinnedRemoval {
        plugins,
        target: target_descriptor,
        quarantine: quarantine_descriptor,
        plugins_identity,
        target_identity: target_descriptor_identity,
        quarantine_identity,
        quarantine_name,
        quarantine_path,
    })
}

#[cfg(target_os = "linux")]
fn quarantine_pinned_target(pinned: &PinnedRemoval, plugin_id: &str) -> Result<OwnedFd> {
    rustix::fs::renameat_with(
        &pinned.plugins,
        plugin_id,
        &pinned.quarantine,
        "plugin",
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        OmarchyError::AtomicRemoval(format!(
            "cannot move the managed target into pinned recovery quarantine {}: {error}",
            pinned.quarantine_path.display()
        ))
    })?;

    let (moved, moved_identity) = open_removal_directory_at(
        &pinned.quarantine,
        std::ffi::OsStr::new("plugin"),
        "quarantined plugin",
    )
    .map_err(|error| {
        OmarchyError::AtomicRemoval(format!(
            "the moved entry could not be verified ({error}); no recursive deletion ran and the intended recovery path is {}",
            pinned.quarantine_path.display()
        ))
    })?;
    if moved_identity != pinned.target_identity {
        let restore = restore_quarantined_identity(pinned, plugin_id, moved_identity);
        return Err(OmarchyError::AtomicRemoval(format!(
            "the entry moved into recovery quarantine is not the pinned managed target; no recursive deletion ran; mismatched-entry restore result: {}; recovery path: {}",
            restore
                .as_ref()
                .map(|()| "restored".to_owned())
                .unwrap_or_else(|error| format!("manual attention required ({error})")),
            pinned.quarantine_path.display()
        )));
    }
    Ok(moved)
}

#[cfg(target_os = "linux")]
fn verify_restored_target(
    pinned: &PinnedRemoval,
    plugins_directory: &Path,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    let (_, restored_identity) = open_removal_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "restored managed target after rescan",
    )?;
    if restored_identity != pinned.target_identity {
        return Err("the live plugin path no longer names the restored managed target".to_owned());
    }

    match removal_entry_exists(&pinned.quarantine, std::ffi::OsStr::new("plugin")) {
        Ok(false) => {}
        Ok(true) => {
            return Err(
                "the pinned quarantine unexpectedly contains a plugin entry after restore"
                    .to_owned(),
            );
        }
        Err(error) => {
            return Err(format!(
                "cannot verify the pinned quarantine after restore: {error}"
            ));
        }
    }

    let (_, quarantine_path_identity) = open_removal_directory_at(
        &pinned.plugins,
        &pinned.quarantine_name,
        "recovery quarantine after restore",
    )?;
    if quarantine_path_identity != pinned.quarantine_identity {
        return Err("the reported recovery-quarantine path changed during rollback".to_owned());
    }

    let plugins_path_identity = target_identity(plugins_directory)
        .map_err(|error| format!("cannot revalidate plugins-directory path: {error}"))?;
    if plugins_path_identity != pinned.plugins_identity {
        return Err("the plugins-directory path changed during rollback rescan".to_owned());
    }

    let external_target_identity = target_identity(&plugins_directory.join(plugin_id))
        .map_err(|error| format!("cannot revalidate restored plugin path: {error}"))?;
    if external_target_identity != pinned.target_identity {
        return Err("the external plugin path no longer names the restored target".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn describe_pinned_recovery_state(pinned: &PinnedRemoval, plugins_directory: &Path) -> String {
    let child_matches = open_removal_directory_at(
        &pinned.quarantine,
        std::ffi::OsStr::new("plugin"),
        "quarantined plugin",
    )
    .map(|(_, identity)| identity == pinned.target_identity)
    .unwrap_or(false);
    let plugins_path_matches = target_identity(plugins_directory)
        .map(|identity| identity == pinned.plugins_identity)
        .unwrap_or(false);
    let quarantine_mode_matches = rustix::fs::fstat(&pinned.quarantine)
        .map(|stat| stat.st_mode & 0o7777 == 0o700)
        .unwrap_or(false);
    let path_matches = plugins_path_matches
        && quarantine_mode_matches
        && open_removal_directory_at(
            &pinned.plugins,
            &pinned.quarantine_name,
            "recovery quarantine",
        )
        .map(|(_, identity)| identity == pinned.quarantine_identity)
        .unwrap_or(false);

    match (child_matches, path_matches) {
        (true, true) => format!(
            "the exact managed directory was revalidated at {}/plugin",
            pinned.quarantine_path.display()
        ),
        (true, false) => format!(
            "the exact managed directory remained in the pinned recovery directory, but its reported pathname changed; locate the directory with device {} and inode {} manually",
            pinned.quarantine_identity.device, pinned.quarantine_identity.inode
        ),
        (false, _) => {
            "the recovery entry could not be revalidated and requires manual filesystem inspection"
                .to_owned()
        }
    }
}

#[cfg(target_os = "linux")]
fn restore_quarantined_identity(
    pinned: &PinnedRemoval,
    plugin_id: &str,
    expected_identity: TargetIdentity,
) -> std::result::Result<(), String> {
    let (_, current_identity) = open_removal_directory_at(
        &pinned.quarantine,
        std::ffi::OsStr::new("plugin"),
        "quarantined entry",
    )?;
    if current_identity != expected_identity {
        return Err("quarantined entry changed before defensive restore".to_owned());
    }
    rustix::fs::renameat_with(
        &pinned.quarantine,
        "plugin",
        &pinned.plugins,
        plugin_id,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| format!("defensive descriptor-relative restore failed: {error}"))?;
    let (_, restored_identity) = open_removal_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "defensively restored entry",
    )?;
    if restored_identity != expected_identity {
        return Err("defensively restored path changed before verification".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_pinned_target(
    pinned: &PinnedRemoval,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    let (_, quarantined_identity) = open_removal_directory_at(
        &pinned.quarantine,
        std::ffi::OsStr::new("plugin"),
        "quarantined plugin",
    )?;
    if quarantined_identity != pinned.target_identity {
        return Err("the quarantine entry no longer names the pinned managed target".to_owned());
    }

    rustix::fs::renameat_with(
        &pinned.quarantine,
        "plugin",
        &pinned.plugins,
        plugin_id,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| format!("descriptor-relative exact restore failed: {error}"))?;

    let (_, restored_identity) = open_removal_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "restored managed target",
    )?;
    if restored_identity != pinned.target_identity {
        return Err("the restored path does not name the pinned managed target".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_retained_quarantine(
    pinned: &PinnedRemoval,
    moved: &OwnedFd,
    plugins_directory: &Path,
    plugin_id: &str,
) -> Result<()> {
    let quarantine_stat = rustix::fs::fstat(&pinned.quarantine).map_err(|error| {
        OmarchyError::RemovalStateIndeterminate(format!(
            "cannot revalidate recovery-quarantine mode after rescan: {error}"
        ))
    })?;
    if quarantine_stat.st_mode & 0o7777 != 0o700 {
        return Err(OmarchyError::RemovalStateIndeterminate(format!(
            "the recovery quarantine is no longer mode 0700; no recursive deletion ran; inspect {}",
            pinned.quarantine_path.display()
        )));
    }

    if removal_descriptor_identity_raw(moved, "quarantined plugin")
        .map_err(OmarchyError::RemovalStateIndeterminate)?
        != pinned.target_identity
        || removal_descriptor_identity_raw(&pinned.target, "original managed target")
            .map_err(OmarchyError::RemovalStateIndeterminate)?
            != pinned.target_identity
    {
        return Err(OmarchyError::RemovalStateIndeterminate(
            "the pinned target descriptor identity changed unexpectedly; no recursive deletion ran"
                .to_owned(),
        ));
    }

    let (_, current_quarantined_identity) = open_removal_directory_at(
        &pinned.quarantine,
        std::ffi::OsStr::new("plugin"),
        "quarantined plugin",
    )
    .map_err(OmarchyError::RemovalStateIndeterminate)?;
    if current_quarantined_identity != pinned.target_identity {
        return Err(OmarchyError::RemovalStateIndeterminate(format!(
            "the recovery quarantine no longer names the pinned plugin; no recursive deletion ran; inspect {}",
            pinned.quarantine_path.display()
        )));
    }

    let (_, current_quarantine_identity) = open_removal_directory_at(
        &pinned.plugins,
        &pinned.quarantine_name,
        "recovery quarantine",
    )
    .map_err(OmarchyError::RemovalStateIndeterminate)?;
    if current_quarantine_identity != pinned.quarantine_identity {
        return Err(OmarchyError::RemovalStateIndeterminate(format!(
            "the reported recovery-quarantine path changed during rescan; no recursive deletion ran; inspect {}",
            pinned.quarantine_path.display()
        )));
    }

    if target_identity(plugins_directory).map_err(|error| {
        OmarchyError::RemovalStateIndeterminate(format!(
            "cannot revalidate the plugins-directory path after rescan: {error}"
        ))
    })? != pinned.plugins_identity
    {
        return Err(OmarchyError::RemovalStateIndeterminate(
            "the plugins-directory path changed during rescan; no recursive deletion ran"
                .to_owned(),
        ));
    }

    match removal_entry_exists(&pinned.plugins, std::ffi::OsStr::new(plugin_id)) {
        Ok(false) => {}
        Ok(true) => {
            return Err(OmarchyError::RemovalStateIndeterminate(format!(
                "a new live entry appeared at plugin ID {plugin_id}; the pinned original remains at {}",
                pinned.quarantine_path.display()
            )));
        }
        Err(error) => {
            return Err(OmarchyError::RemovalStateIndeterminate(format!(
                "cannot verify that the live plugin target is absent: {error}"
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_removal_directory_at(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    label: &str,
) -> std::result::Result<(OwnedFd, TargetIdentity), String> {
    use rustix::fs::{Mode, OFlags, openat};

    let descriptor = openat(
        parent,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("{label} is unavailable: {error}"))?;
    let identity = removal_descriptor_identity_raw(&descriptor, label)?;
    Ok((descriptor, identity))
}

#[cfg(target_os = "linux")]
fn removal_descriptor_identity(descriptor: &OwnedFd, label: &str) -> Result<TargetIdentity> {
    removal_descriptor_identity_raw(descriptor, label).map_err(OmarchyError::AtomicRemoval)
}

#[cfg(target_os = "linux")]
fn removal_descriptor_identity_raw(
    descriptor: &OwnedFd,
    label: &str,
) -> std::result::Result<TargetIdentity, String> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|error| format!("cannot inspect pinned {label}: {error}"))?;
    Ok(TargetIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

#[cfg(target_os = "linux")]
fn removal_entry_exists(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
) -> std::result::Result<bool, rustix::io::Errno> {
    use rustix::fs::{Mode, OFlags, openat};

    match openat(
        parent,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn reject_git_managed_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path.join(".git")) {
        Ok(_) => Err(OmarchyError::NotManagedInstall(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(OmarchyError::Io {
            path: path.join(".git"),
            source,
        }),
    }
}

#[cfg(target_os = "linux")]
fn reject_git_managed_update_snapshot(path: &Path, snapshot: &UpdateTreeSnapshot) -> Result<()> {
    if snapshot
        .entries
        .iter()
        .any(|entry| entry.path.as_slice() == [b".git".to_vec()])
    {
        return Err(OmarchyError::NotManagedInstall(path.to_path_buf()));
    }
    Ok(())
}

/// Observes whether the exact plugin ID is referenced by the accepted
/// persisted Omarchy configuration.
///
/// The returned digest covers the exact raw bytes parsed. This is a
/// point-in-time file observation, not evidence that the running shell applied
/// the configuration or that the plugin was loaded or unloaded.
pub fn observe_plugin_reference(
    plugins_directory: &Path,
    plugin_id: &str,
) -> Result<OmarchyReferenceObservation> {
    validate_plugin_id(plugin_id)?;
    let Some(omarchy_directory) = plugins_directory.parent() else {
        return Err(OmarchyError::InvalidShellConfiguration(
            "plugins directory has no parent".to_owned(),
        ));
    };
    let config_path = omarchy_directory.join("shell.json");
    let (bytes, observed_config_path, shell_config_source) =
        match read_shell_configuration(omarchy_directory, &config_path)? {
            Some(bytes) => (bytes, config_path, ShellConfigSource::User),
            None => {
                let default_path = Path::new(DEFAULT_SHELL_CONFIG);
                (
                    read_default_shell_configuration(default_path)?,
                    default_path.to_path_buf(),
                    ShellConfigSource::SystemDefault,
                )
            }
        };
    parse_reference_observation(
        plugin_id,
        &bytes,
        &observed_config_path,
        shell_config_source,
    )
}

fn parse_reference_observation(
    plugin_id: &str,
    bytes: &[u8],
    observed_config_path: &Path,
    shell_config_source: ShellConfigSource,
) -> Result<OmarchyReferenceObservation> {
    let config: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        OmarchyError::InvalidShellConfiguration(format!(
            "{} is not valid JSON: {error}",
            observed_config_path.display()
        ))
    })?;
    if !config.is_object() || config.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "{} must be an object with version 1",
            observed_config_path.display()
        )));
    }
    let state = if shell_configuration_references_plugin(&config, plugin_id)? {
        PluginReferenceState::Referenced
    } else {
        PluginReferenceState::NotReferenced
    };
    Ok(OmarchyReferenceObservation {
        plugin_id: plugin_id.to_owned(),
        state,
        shell_config_source,
        shell_config_sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

fn reject_stale_enabled_configuration(plugins_directory: &Path, plugin_id: &str) -> Result<()> {
    if observe_plugin_reference(plugins_directory, plugin_id)?.state
        == PluginReferenceState::Referenced
    {
        return Err(OmarchyError::StaleEnabledConfiguration(
            plugin_id.to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_referenced_removal(plugins_directory: &Path, plugin_id: &str) -> Result<()> {
    match reject_stale_enabled_configuration(plugins_directory, plugin_id) {
        Err(OmarchyError::StaleEnabledConfiguration(referenced)) => {
            Err(OmarchyError::ReferencedPluginRemoval(referenced))
        }
        result => result,
    }
}

#[cfg(target_os = "linux")]
fn read_shell_configuration(
    omarchy_directory: &Path,
    config_path: &Path,
) -> Result<Option<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use rustix::fs::{Mode, OFlags, open, openat};

    let directory = open(
        omarchy_directory,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::InvalidShellConfiguration(format!(
            "cannot safely open {}: {error}",
            omarchy_directory.display()
        ))
    })?;
    let descriptor = match openat(
        &directory,
        "shell.json",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(OmarchyError::InvalidShellConfiguration(format!(
                "cannot safely open {}: {error}",
                config_path.display()
            )));
        }
    };
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "{} must be a regular current-user-owned file that is not group/world writable",
            config_path.display()
        )));
    }
    read_shell_configuration_bytes(file, config_path)
}

#[cfg(not(target_os = "linux"))]
fn read_shell_configuration(
    _omarchy_directory: &Path,
    config_path: &Path,
) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(OmarchyError::Io {
                path: config_path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::SymlinkBoundary(config_path.to_path_buf()));
    }
    let file = File::open(config_path).map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    read_shell_configuration_bytes(file, config_path)
}

fn read_shell_configuration_bytes(file: File, config_path: &Path) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    file.take(MAX_SHELL_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| OmarchyError::Io {
            path: config_path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_SHELL_CONFIG_BYTES {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "{} exceeds {MAX_SHELL_CONFIG_BYTES} bytes",
            config_path.display()
        )));
    }
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn read_default_shell_configuration(config_path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        config_path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::InvalidShellConfiguration(format!(
            "cannot safely open effective default {}: {error}",
            config_path.display()
        ))
    })?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "effective default {} must be a regular root-owned file that is not group/world writable",
            config_path.display()
        )));
    }
    read_shell_configuration_bytes(file, config_path)?.ok_or_else(|| {
        OmarchyError::InvalidShellConfiguration(format!(
            "effective default {} is unavailable",
            config_path.display()
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn read_default_shell_configuration(config_path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(config_path).map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::SymlinkBoundary(config_path.to_path_buf()));
    }
    let file = File::open(config_path).map_err(|source| OmarchyError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;
    read_shell_configuration_bytes(file, config_path)?.ok_or_else(|| {
        OmarchyError::InvalidShellConfiguration(format!(
            "effective default {} is unavailable",
            config_path.display()
        ))
    })
}

fn shell_configuration_references_plugin(
    config: &serde_json::Value,
    plugin_id: &str,
) -> Result<bool> {
    let Some(root) = config.as_object() else {
        return Err(OmarchyError::InvalidShellConfiguration(
            "shell configuration root must be an object".to_owned(),
        ));
    };
    if let Some(bar) = optional_shell_object(root.get("bar"), "bar")? {
        if shell_id_value(bar.get("id"), "bar.id")? == Some(plugin_id) {
            return Ok(true);
        }
        if let Some(layout) = optional_shell_object(bar.get("layout"), "bar.layout")? {
            for section in ["left", "center", "right"] {
                let Some(entries) = optional_shell_array(
                    layout.get(section),
                    match section {
                        "left" => "bar.layout.left",
                        "center" => "bar.layout.center",
                        "right" => "bar.layout.right",
                        _ => unreachable!(),
                    },
                )?
                else {
                    continue;
                };
                for entry in entries {
                    if shell_entry_plugin_id(entry, true, "bar.layout entry")? == Some(plugin_id) {
                        return Ok(true);
                    }
                }
            }
        }
    }
    if let Some(entries) = optional_shell_array(root.get("plugins"), "plugins")? {
        for entry in entries {
            if shell_entry_plugin_id(entry, false, "plugins entry")? == Some(plugin_id) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn optional_shell_object<'a>(
    value: Option<&'a serde_json::Value>,
    location: &'static str,
) -> Result<Option<&'a serde_json::Map<String, serde_json::Value>>> {
    match value {
        None => Ok(None),
        Some(serde_json::Value::Object(value)) => Ok(Some(value)),
        Some(_) => Err(OmarchyError::InvalidShellConfiguration(format!(
            "{location} must be an object when present"
        ))),
    }
}

fn optional_shell_array<'a>(
    value: Option<&'a serde_json::Value>,
    location: &'static str,
) -> Result<Option<&'a Vec<serde_json::Value>>> {
    match value {
        None => Ok(None),
        Some(serde_json::Value::Array(value)) => Ok(Some(value)),
        Some(_) => Err(OmarchyError::InvalidShellConfiguration(format!(
            "{location} must be an array when present"
        ))),
    }
}

fn shell_id_value<'a>(
    value: Option<&'a serde_json::Value>,
    location: &'static str,
) -> Result<Option<&'a str>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(OmarchyError::InvalidShellConfiguration(format!(
            "{location} must be a string when present"
        ))),
    }
}

fn shell_entry_plugin_id<'a>(
    entry: &'a serde_json::Value,
    allow_string: bool,
    location: &'static str,
) -> Result<Option<&'a str>> {
    match entry {
        serde_json::Value::String(value) if allow_string => Ok(Some(value)),
        serde_json::Value::Object(values) => {
            let Some(value) = shell_id_value(values.get("id"), location)? else {
                return Err(OmarchyError::InvalidShellConfiguration(format!(
                    "{location} must contain a string plugin id"
                )));
            };
            Ok(Some(value))
        }
        _ => Err(OmarchyError::InvalidShellConfiguration(format!(
            "{location} must contain a string plugin id"
        ))),
    }
}

fn validate_system_command(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| OmarchyError::UnsafeSystemCommand(path.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::UnsafeSystemCommand(path.to_path_buf()));
    }
    validate_system_command_permissions(path, &metadata)
}

#[cfg(unix)]
fn validate_system_command_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode();
    let owner = metadata.uid();
    if mode & 0o111 == 0 || mode & 0o022 != 0 || !matches!(owner, 0 | 65_534) {
        Err(OmarchyError::UnsafeSystemCommand(path.to_path_buf()))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn validate_system_command_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

fn run_validator(validator: &Path, plugin_directory: &Path) -> Result<()> {
    let mut command = clean_system_command(validator);
    let status = command
        .arg(plugin_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|source| OmarchyError::Io {
            path: validator.to_path_buf(),
            source,
        })?;
    if !status.success() {
        return Err(OmarchyError::ManifestValidationFailed(status.to_string()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_validator_for_descriptor(validator: &Path, plugin_directory: &OwnedFd) -> Result<()> {
    use rustix::io::{FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd};

    let child_descriptor = fcntl_dupfd_cloexec(plugin_directory, 3).map_err(|error| {
        OmarchyError::ManifestValidationFailed(format!(
            "cannot duplicate the pinned plugin root for validation: {error}"
        ))
    })?;
    let parent_flags = fcntl_getfd(&child_descriptor).map_err(|error| {
        OmarchyError::ManifestValidationFailed(format!(
            "cannot inspect the validator descriptor flags: {error}"
        ))
    })?;
    if !parent_flags.contains(FdFlags::CLOEXEC) {
        return Err(OmarchyError::ManifestValidationFailed(
            "the validator descriptor was not created close-on-exec".to_owned(),
        ));
    }
    let raw_descriptor = child_descriptor.as_raw_fd();
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{raw_descriptor}/."));
    let child_flags = parent_flags.difference(FdFlags::CLOEXEC);

    let mut command = clean_system_command(validator);
    command
        .arg(&descriptor_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // SAFETY: `raw_descriptor` remains owned by `child_descriptor` until the
    // synchronous child exits. The hook runs after fork and performs only one
    // `fcntl(F_SETFD)` syscall on that already-open descriptor. All allocation,
    // path formatting, and command configuration happened before `pre_exec`.
    unsafe {
        command.pre_exec(move || {
            let descriptor = BorrowedFd::borrow_raw(raw_descriptor);
            fcntl_setfd(descriptor, child_flags).map_err(std::io::Error::from)
        });
    }
    let status = command.status().map_err(|source| OmarchyError::Io {
        path: validator.to_path_buf(),
        source,
    })?;
    let final_parent_flags = fcntl_getfd(&child_descriptor).map_err(|error| {
        OmarchyError::ManifestValidationFailed(format!(
            "cannot recheck the validator descriptor flags: {error}"
        ))
    })?;
    if !final_parent_flags.contains(FdFlags::CLOEXEC) {
        return Err(OmarchyError::ManifestValidationFailed(
            "the validator descriptor lost close-on-exec in the parent".to_owned(),
        ));
    }
    if !status.success() {
        return Err(OmarchyError::ManifestValidationFailed(status.to_string()));
    }
    Ok(())
}

fn run_rescan(omarchy_shell: &Path) -> std::result::Result<(), String> {
    let mut command = rescan_command(omarchy_shell);
    match command
        .args(["shell", "rescanPlugins"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(status.to_string()),
        Err(error) => Err(error.to_string()),
    }
}

fn rescan_command(omarchy_shell: &Path) -> Command {
    let mut command = clean_system_command(omarchy_shell);
    for name in [
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
    ] {
        copy_environment_if_present(&mut command, name);
    }
    command
        .env("OMARCHY_PATH", "/usr/share/omarchy")
        .env("OMARCHY_SHELL_IPC_TIMEOUT", "2s");
    command
}

fn clean_system_command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    command
}

fn copy_environment_if_present(command: &mut Command, name: &str) {
    if let Some(value) = std::env::var_os(name) {
        command.env(name, value);
    }
}

#[cfg(not(target_os = "linux"))]
fn atomic_install_no_replace(_source: &Path, _target: &Path) -> Result<()> {
    Err(OmarchyError::AtomicInstall(
        "guarded Omarchy installation requires Linux renameat2".to_owned(),
    ))
}

#[cfg(unix)]
fn secure_staged_package(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_staged_package(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_receipt(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn secure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_receipt(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn secure_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::io::Cursor;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    #[cfg(target_os = "linux")]
    use std::sync::mpsc;
    #[cfg(target_os = "linux")]
    use std::thread;
    #[cfg(target_os = "linux")]
    use std::time::Duration;

    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;

    #[cfg(target_os = "linux")]
    use super::{
        MAX_COMPRESSED_BYTES, UpdateTreeEntry, UpdateTreeSnapshot, copy_at_most, copy_package_once,
        read_update_snapshot_file, reject_git_managed_target, reject_git_managed_update_snapshot,
        run_validator_for_descriptor, snapshot_update_tree_path, target_identity,
        verify_update_tree_descriptor,
    };
    use super::{
        MAX_SHELL_CONFIG_BYTES, observe_plugin_reference, parse_reference_observation,
        read_shell_configuration, reject_stale_enabled_configuration, rescan_command,
        shell_configuration_references_plugin,
    };
    use crate::{
        OmarchyError, OmarchyReferenceObservation, PluginReferenceState, ShellConfigSource,
    };

    #[test]
    fn plugin_rescan_does_not_inherit_the_session_bus() {
        let command = rescan_command(Path::new("/usr/bin/omarchy-shell"));
        assert!(
            command
                .get_envs()
                .all(|(name, _)| name != "DBUS_SESSION_BUS_ADDRESS")
        );
    }

    #[cfg(target_os = "linux")]
    fn exposed_pinned_install_fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        super::PinnedInstall,
    ) {
        let directory = tempdir().unwrap();
        let omarchy = directory.path().join("omarchy");
        let plugins = omarchy.join("plugins");
        let staging = plugins.join(".a-quo-install-test");
        let candidate = staging.join("plugin");
        fs::create_dir_all(&candidate).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(omarchy.join("shell.json"), br#"{"version":1,"plugins":[]}"#).unwrap();
        fs::write(candidate.join("marker"), b"signed candidate\n").unwrap();

        let plugins_identity = super::target_identity(&plugins).unwrap();
        let staging_identity = super::target_identity(&staging).unwrap();
        let candidate_identity = super::target_identity(&candidate).unwrap();
        let candidate_snapshot =
            super::snapshot_update_tree_path(&candidate, candidate_identity).unwrap();
        let pinned = super::prepare_pinned_install(
            &plugins,
            &staging,
            "example.signed-plugin",
            super::InstallBaselines {
                plugins_identity,
                staging_identity,
                candidate_identity,
                candidate_snapshot,
            },
        )
        .unwrap();
        let mut rename_completed = false;
        super::expose_pinned_install_no_replace(
            &pinned,
            &plugins,
            "example.signed-plugin",
            || Ok(()),
            &mut rename_completed,
        )
        .unwrap();
        assert!(rename_completed);
        (directory, plugins, staging, pinned)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn install_rollback_syscall_never_overwrites_a_last_moment_staging_entry() {
        let (_directory, plugins, staging, pinned) = exposed_pinned_install_fixture();
        let live = plugins.join("example.signed-plugin");

        let error = super::rollback_pinned_install_with_hook(
            &pinned,
            &plugins,
            "example.signed-plugin",
            || {
                fs::create_dir(staging.join("plugin")).unwrap();
                fs::write(staging.join("plugin/conflict"), b"do not overwrite\n").unwrap();
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("descriptor-relative no-replace rollback failed"));
        assert_eq!(
            fs::read(live.join("marker")).unwrap(),
            b"signed candidate\n"
        );
        assert_eq!(
            fs::read(staging.join("plugin/conflict")).unwrap(),
            b"do not overwrite\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn install_rollback_postcheck_detects_a_wrong_child_moved_in_name_race() {
        let (directory, plugins, staging, pinned) = exposed_pinned_install_fixture();
        let live = plugins.join("example.signed-plugin");
        let displaced = directory.path().join("displaced-signed-candidate");

        let error = super::rollback_pinned_install_with_hook(
            &pinned,
            &plugins,
            "example.signed-plugin",
            || {
                fs::rename(&live, &displaced).unwrap();
                fs::create_dir(&live).unwrap();
                fs::write(live.join("replacement"), b"wrong child\n").unwrap();
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("does not contain the pinned candidate after rollback"));
        assert!(!live.exists());
        assert_eq!(
            fs::read(displaced.join("marker")).unwrap(),
            b"signed candidate\n"
        );
        assert_eq!(
            fs::read(staging.join("plugin/replacement")).unwrap(),
            b"wrong child\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validator_descriptor_root_survives_candidate_path_replacement() {
        use rustix::fs::{Mode, OFlags, open};

        let directory = tempdir().unwrap();
        let candidate = directory.path().join("candidate");
        let displaced = directory.path().join("displaced");
        fs::create_dir(&candidate).unwrap();
        fs::write(candidate.join("marker"), b"signed\n").unwrap();
        let descriptor = open(
            &candidate,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        fs::rename(&candidate, &displaced).unwrap();
        fs::create_dir(&candidate).unwrap();
        fs::write(candidate.join("marker"), b"replacement\n").unwrap();

        let validator = directory.path().join("validator.sh");
        fs::write(
            &validator,
            b"#!/bin/sh\nset -eu\ntest \"$(cat \"$1/marker\")\" = signed\n",
        )
        .unwrap();
        fs::set_permissions(&validator, fs::Permissions::from_mode(0o755)).unwrap();

        run_validator_for_descriptor(&validator, &descriptor).unwrap();
        assert_eq!(fs::read(displaced.join("marker")).unwrap(), b"signed\n");
        assert_eq!(
            fs::read(candidate.join("marker")).unwrap(),
            b"replacement\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn persistent_validator_mutation_fails_the_pinned_candidate_snapshot() {
        use rustix::fs::{Mode, OFlags, open};

        let directory = tempdir().unwrap();
        let candidate = directory.path().join("candidate");
        fs::create_dir(&candidate).unwrap();
        fs::write(candidate.join("marker"), b"signed\n").unwrap();
        let identity = target_identity(&candidate).unwrap();
        let snapshot = snapshot_update_tree_path(&candidate, identity).unwrap();
        let descriptor = open(
            &candidate,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();

        let validator = directory.path().join("mutating-validator.sh");
        fs::write(
            &validator,
            b"#!/bin/sh\nset -eu\nprintf 'mutated\\n' > \"$1/marker\"\n",
        )
        .unwrap();
        fs::set_permissions(&validator, fs::Permissions::from_mode(0o755)).unwrap();

        run_validator_for_descriptor(&validator, &descriptor).unwrap();
        let error = verify_update_tree_descriptor(
            &descriptor,
            &snapshot,
            "candidate changed during validation",
        )
        .unwrap_err();
        assert_eq!(error, "candidate changed during validation");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_semantic_reads_must_match_the_pinned_tree_digest() {
        let directory = tempdir().unwrap();
        let original = b"baseline manifest bytes\n";
        let path = directory.path().join("manifest.json");
        fs::write(&path, original).unwrap();
        let snapshot = UpdateTreeSnapshot {
            entries: vec![UpdateTreeEntry {
                path: vec![b"manifest.json".to_vec()],
                kind: b'f',
                mode: 0o644,
                uid: 0,
                gid: 0,
                links: 1,
                size: original.len() as u64,
                sha256: Some(Sha256::digest(original).into()),
            }],
            total_file_bytes: original.len() as u64,
            total_path_bytes: b"manifest.json".len() as u64,
        };

        assert_eq!(
            read_update_snapshot_file(directory.path(), &snapshot, "manifest.json", 1_024).unwrap(),
            original
        );
        fs::write(&path, b"forged!! manifest bytes\n").unwrap();
        let error = read_update_snapshot_file(directory.path(), &snapshot, "manifest.json", 1_024)
            .unwrap_err();
        assert!(matches!(error, OmarchyError::UpdateStateIndeterminate(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_snapshot_rejects_git_metadata_restored_after_path_check() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("example.plugin");
        let hidden_git = directory.path().join("hidden-git");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join(".git")).unwrap();

        fs::rename(target.join(".git"), &hidden_git).unwrap();
        reject_git_managed_target(&target).unwrap();
        fs::rename(&hidden_git, target.join(".git")).unwrap();

        let identity = target_identity(&target).unwrap();
        let snapshot = snapshot_update_tree_path(&target, identity).unwrap();
        assert!(matches!(
            reject_git_managed_update_snapshot(&target, &snapshot),
            Err(OmarchyError::NotManagedInstall(path)) if path == target
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_copy_rejects_fifo_without_blocking() {
        use rustix::fs::{CWD, FileType, Mode, OFlags, mknodat, open};

        let directory = tempdir().unwrap();
        let source = directory.path().join("package.fifo");
        let destination = directory.path().join("copied.tar.zst");
        mknodat(CWD, &source, FileType::Fifo, Mode::RWXU, 0).unwrap();

        let (sender, receiver) = mpsc::channel();
        let worker_source = source.clone();
        let worker_destination = destination.clone();
        let worker = thread::spawn(move || {
            sender
                .send(copy_package_once(&worker_source, &worker_destination))
                .unwrap();
        });

        let result = match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => result,
            Err(timeout) => {
                let _writer = open(
                    &source,
                    OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .unwrap();
                let _ = receiver.recv_timeout(Duration::from_secs(1));
                worker.join().unwrap();
                panic!("package FIFO open blocked: {timeout}");
            }
        };
        worker.join().unwrap();
        assert!(matches!(result, Err(OmarchyError::InvalidPackage(_))));
        assert!(!destination.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_copy_rejects_sparse_input_over_compressed_limit() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("oversized.tar.zst");
        let destination = directory.path().join("copied.tar.zst");
        fs::File::create(&source)
            .unwrap()
            .set_len(MAX_COMPRESSED_BYTES + 1)
            .unwrap();

        let error = copy_package_once(&source, &destination).unwrap_err();
        assert!(matches!(
            error,
            OmarchyError::PackageTooLarge {
                actual,
                maximum: MAX_COMPRESSED_BYTES
            } if actual == MAX_COMPRESSED_BYTES + 1
        ));
        assert!(!destination.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_copy_reads_at_most_one_byte_beyond_its_limit() {
        let mut input = Cursor::new(b"abcdef".as_slice());
        let mut output = Vec::new();
        let copied = copy_at_most(&mut input, &mut output, 4).unwrap();

        assert_eq!(copied, 5);
        assert_eq!(output, b"abcde");
        assert_eq!(input.position(), 5);
    }

    #[test]
    fn shell_reference_detection_matches_only_omarchy_enablement_locations() {
        let plugin_id = "example.signed-plugin";
        for config in [
            json!({"version": 1, "bar": {"id": plugin_id}}),
            json!({"version": 1, "bar": {"layout": {"left": [plugin_id]}}}),
            json!({"version": 1, "bar": {"layout": {"center": [{"id": plugin_id}]}}}),
            json!({"version": 1, "bar": {"layout": {"right": [{"id": plugin_id}]}}}),
            json!({"version": 1, "plugins": [{"id": plugin_id}]}),
        ] {
            assert!(shell_configuration_references_plugin(&config, plugin_id).unwrap());
        }

        let unrelated = json!({
            "version": 1,
            "bar": {
                "id": "omarchy.bar",
                "layout": {
                    "left": [{"id": "other.plugin", "label": plugin_id}],
                    "center": [],
                    "right": []
                },
                "note": plugin_id
            },
            "plugins": [{"id": "other.plugin", "setting": plugin_id}],
            "unrelated": {"id": plugin_id}
        });
        assert!(!shell_configuration_references_plugin(&unrelated, plugin_id).unwrap());

        let disabled_only = json!({
            "version": 1,
            "plugins": [],
            "disabledPlugins": [plugin_id]
        });
        assert!(!shell_configuration_references_plugin(&disabled_only, plugin_id).unwrap());
        let referenced_and_disabled = json!({
            "version": 1,
            "plugins": [{"id": plugin_id}],
            "disabledPlugins": [plugin_id]
        });
        assert!(
            shell_configuration_references_plugin(&referenced_and_disabled, plugin_id).unwrap()
        );

        for malformed in [
            json!([]),
            json!({"version": 1, "bar": []}),
            json!({"version": 1, "bar": {"id": 123}}),
            json!({"version": 1, "bar": {"layout": []}}),
            json!({"version": 1, "bar": {"layout": {"left": {}}}}),
            json!({"version": 1, "bar": {"layout": {"left": [true]}}}),
            json!({"version": 1, "bar": {"layout": {"center": [{"id": 123}]}}}),
            json!({"version": 1, "bar": {"layout": {"right": [{}]}}}),
            json!({"version": 1, "plugins": {}}),
            json!({"version": 1, "plugins": [{"id": true}]}),
            json!({"version": 1, "plugins": [plugin_id]}),
        ] {
            assert!(shell_configuration_references_plugin(&malformed, plugin_id).is_err());
        }
    }

    #[test]
    fn reference_observation_binds_state_source_and_exact_raw_bytes() {
        let plugin_id = "example.signed-plugin";
        let path = Path::new("accepted-shell.json");
        let referenced = br#"{"version":1,"plugins":[{"id":"example.signed-plugin"}]}"#;
        let observation =
            parse_reference_observation(plugin_id, referenced, path, ShellConfigSource::User)
                .unwrap();
        assert_eq!(
            observation,
            OmarchyReferenceObservation {
                plugin_id: plugin_id.to_owned(),
                state: PluginReferenceState::Referenced,
                shell_config_source: ShellConfigSource::User,
                shell_config_sha256: format!("{:x}", Sha256::digest(referenced)),
            }
        );

        let same_meaning_different_bytes =
            br#"{ "version": 1, "plugins": [ { "id": "example.signed-plugin" } ] }"#;
        let reformatted = parse_reference_observation(
            plugin_id,
            same_meaning_different_bytes,
            path,
            ShellConfigSource::SystemDefault,
        )
        .unwrap();
        assert_eq!(reformatted.state, PluginReferenceState::Referenced);
        assert_eq!(
            reformatted.shell_config_source,
            ShellConfigSource::SystemDefault
        );
        assert_ne!(
            observation.shell_config_sha256,
            reformatted.shell_config_sha256
        );

        let serialized = serde_json::to_value(&observation).unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), 4);
        assert!(serialized.get("config_bytes").is_none());
        assert!(serialized.get("config_path").is_none());
    }

    #[test]
    fn reference_observation_rejects_unmodelled_configuration() {
        let path = Path::new("accepted-shell.json");
        for malformed in [
            br#"not json"#.as_slice(),
            br#"[]"#.as_slice(),
            br#"{"version":2,"plugins":[]}"#.as_slice(),
            br#"{"version":1,"plugins":["example.signed-plugin"]}"#.as_slice(),
        ] {
            assert!(matches!(
                parse_reference_observation(
                    "example.signed-plugin",
                    malformed,
                    path,
                    ShellConfigSource::User,
                ),
                Err(OmarchyError::InvalidShellConfiguration(_))
            ));
        }
    }

    #[test]
    fn public_reference_observer_reuses_the_safe_user_configuration_reader() {
        let (_directory, omarchy) = shell_fixture();
        let plugins = omarchy.join("plugins");
        let bytes = br#"{"version":1,"plugins":[]}"#;
        fs::write(omarchy.join("shell.json"), bytes).unwrap();

        let observation = observe_plugin_reference(&plugins, "example.signed-plugin").unwrap();
        assert_eq!(observation.state, PluginReferenceState::NotReferenced);
        assert_eq!(observation.shell_config_source, ShellConfigSource::User);
        assert_eq!(
            observation.shell_config_sha256,
            format!("{:x}", Sha256::digest(bytes))
        );
        assert!(observe_plugin_reference(&plugins, "../not-a-plugin").is_err());
    }

    fn shell_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempdir().unwrap();
        let omarchy = directory.path().join("omarchy");
        fs::create_dir_all(omarchy.join("plugins")).unwrap();
        (directory, omarchy)
    }

    #[test]
    fn shell_config_read_is_bounded_versioned_and_missing_user_requests_default_fallback() {
        let (_directory, omarchy) = shell_fixture();
        let plugins = omarchy.join("plugins");
        assert!(
            read_shell_configuration(&omarchy, &omarchy.join("shell.json"))
                .unwrap()
                .is_none()
        );

        fs::write(omarchy.join("shell.json"), br#"{"plugins":[]}"#).unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));

        fs::write(
            omarchy.join("shell.json"),
            vec![b' '; usize::try_from(MAX_SHELL_CONFIG_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::write(omarchy.join("shell.json"), br#"{"version":1,"plugins":[]}"#).unwrap();
            fs::set_permissions(
                omarchy.join("shell.json"),
                fs::Permissions::from_mode(0o666),
            )
            .unwrap();
            assert!(matches!(
                reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
                Err(OmarchyError::InvalidShellConfiguration(_))
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shell_config_special_files_fail_closed_without_blocking() {
        use std::os::unix::fs::symlink;

        use rustix::fs::{CWD, Mode, mkfifoat};

        let (_directory, omarchy) = shell_fixture();
        let plugins = omarchy.join("plugins");
        let config = omarchy.join("shell.json");

        fs::create_dir(&config).unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));
        fs::remove_dir(&config).unwrap();

        let target = omarchy.join("target.json");
        fs::write(&target, br#"{"version":1,"plugins":[]}"#).unwrap();
        symlink(&target, &config).unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));
        fs::remove_file(&config).unwrap();

        mkfifoat(CWD, &config, Mode::from_bits_truncate(0o600)).unwrap();
        assert!(matches!(
            reject_stale_enabled_configuration(&plugins, "example.signed-plugin"),
            Err(OmarchyError::InvalidShellConfiguration(_))
        ));
    }
}
