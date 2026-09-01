use std::path::Path;

use super::super::command::{run_rescan, validate_system_command};
#[cfg(target_os = "linux")]
use super::super::limits::INSTALL_RECEIPT_NAME;
#[cfg(target_os = "linux")]
use super::super::receipt::{
    read_install_receipt, read_installed_manifest, validate_installed_state,
};
#[cfg(target_os = "linux")]
use super::super::reference::reject_referenced_removal;
#[cfg(target_os = "linux")]
use super::super::remove_transaction::{
    describe_pinned_recovery_state, prepare_pinned_removal, quarantine_pinned_target,
    restore_pinned_target, retained_quarantine_path, verify_restored_target,
    verify_retained_quarantine,
};
#[cfg(target_os = "linux")]
use super::super::staging::require_existing_plugins_directory;
#[cfg(target_os = "linux")]
use super::super::tree::{reject_git_managed_target, target_identity};
use crate::archive::validate_plugin_id;
use crate::{
    AQuoEnablementAction, BehavioralAnalysisStatus, DiskPurgeStatus, OmarchyError, Result,
    RuntimeSafetyStatus, ShellRescanStatus, TrustedConsentStatus, UninstallOutcome,
    UninstallOutcomeSchema, UninstallReferenceObservation,
};

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
        recovery_quarantine: retained_quarantine_path(&pinned),
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
