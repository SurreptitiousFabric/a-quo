use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use super::reference::reject_stale_enabled_configuration;
#[cfg(test)]
use super::tree::snapshot_update_tree_path;
use super::tree::{
    TargetIdentity, UpdateTreeSnapshot, descriptor_identity, open_pinned_directory_at,
    pinned_entry_exists, target_identity, verify_update_tree_descriptor,
};
use crate::{OmarchyError, Result};

#[cfg(target_os = "linux")]
pub(super) struct PinnedInstall {
    pub(super) plugins: OwnedFd,
    pub(super) staging: OwnedFd,
    pub(super) candidate: OwnedFd,
    pub(super) plugins_identity: TargetIdentity,
    pub(super) staging_identity: TargetIdentity,
    pub(super) candidate_identity: TargetIdentity,
    pub(super) candidate_snapshot: UpdateTreeSnapshot,
    pub(super) staging_name: std::ffi::OsString,
    pub(super) staging_path: PathBuf,
}

#[cfg(target_os = "linux")]
pub(super) struct InstallBaselines {
    pub(super) plugins_identity: TargetIdentity,
    pub(super) staging_identity: TargetIdentity,
    pub(super) candidate_identity: TargetIdentity,
    pub(super) candidate_snapshot: UpdateTreeSnapshot,
}

#[cfg(target_os = "linux")]
pub(super) fn install_failed_retained(
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
pub(super) fn install_failed_with_pinned_state(
    cause: OmarchyError,
    pinned: &PinnedInstall,
) -> OmarchyError {
    OmarchyError::InstallFailedRetained {
        cause: Box::new(cause),
        retained_state: describe_pinned_install_root(pinned),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn describe_retained_install_staging(
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
pub(super) fn describe_pinned_install_root(pinned: &PinnedInstall) -> String {
    let staging_descriptor_matches = descriptor_identity(&pinned.staging, "install staging root")
        .map(|identity| identity == pinned.staging_identity)
        .unwrap_or(false);
    let candidate_descriptor_matches = descriptor_identity(&pinned.candidate, "install candidate")
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
    let parent_mapping_matches = open_pinned_directory_at(
        &pinned.plugins,
        &pinned.staging_name,
        "reported install staging root",
    )
    .map(|(_, identity)| identity == pinned.staging_identity)
    .unwrap_or(false);
    let candidate_mapping_matches = open_pinned_directory_at(
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
pub(super) fn prepare_pinned_install(
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
    let plugins_identity = descriptor_identity(&plugins, "plugins directory")
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
        open_pinned_directory_at(&plugins, &staging_name, "install staging directory")
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

    let (candidate, candidate_identity) = open_pinned_directory_at(
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
    match pinned_entry_exists(&plugins, std::ffi::OsStr::new(plugin_id)) {
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
    if descriptor_identity(&pinned.plugins, "plugins directory")? != pinned.plugins_identity
        || descriptor_identity(&pinned.staging, "install staging root")? != pinned.staging_identity
        || descriptor_identity(&pinned.candidate, "install candidate")? != pinned.candidate_identity
    {
        return Err("a pinned install descriptor changed before exposure".to_owned());
    }
    verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "install candidate tree changed before exposure",
    )?;
    let (_, staging_identity) = open_pinned_directory_at(
        &pinned.plugins,
        &pinned.staging_name,
        "install staging root before exposure",
    )?;
    if staging_identity != pinned.staging_identity {
        return Err("install staging mapping changed before exposure".to_owned());
    }
    let (_, candidate_identity) = open_pinned_directory_at(
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
pub(super) fn expose_pinned_install_no_replace<B>(
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
pub(super) fn verify_install_layout(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    if descriptor_identity(&pinned.plugins, "plugins directory")? != pinned.plugins_identity
        || descriptor_identity(&pinned.staging, "install staging root")? != pinned.staging_identity
        || descriptor_identity(&pinned.candidate, "install candidate")? != pinned.candidate_identity
    {
        return Err("a pinned install descriptor changed during exposure".to_owned());
    }
    verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "installed candidate tree changed during exposure or rescan",
    )?;
    let (_, live_identity) = open_pinned_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "live install target",
    )?;
    if live_identity != pinned.candidate_identity {
        return Err("live install target is not the pinned candidate".to_owned());
    }
    match pinned_entry_exists(&pinned.staging, std::ffi::OsStr::new("plugin")) {
        Ok(false) => {}
        Ok(true) => return Err("install staging still contains a plugin entry".to_owned()),
        Err(error) => {
            return Err(format!(
                "cannot verify that install staging no longer contains the candidate: {error}"
            ));
        }
    }
    let (_, staging_identity) = open_pinned_directory_at(
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
    if descriptor_identity(&pinned.plugins, "plugins directory")? != pinned.plugins_identity
        || descriptor_identity(&pinned.staging, "install staging root")? != pinned.staging_identity
        || descriptor_identity(&pinned.candidate, "install candidate")? != pinned.candidate_identity
    {
        return Err("a pinned install descriptor changed during rollback".to_owned());
    }
    verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "rolled-back install candidate tree changed",
    )?;
    match pinned_entry_exists(&pinned.plugins, std::ffi::OsStr::new(plugin_id)) {
        Ok(false) => {}
        Ok(true) => return Err("live install target still exists after rollback".to_owned()),
        Err(error) => {
            return Err(format!(
                "cannot prove the live install target is absent after rollback: {error}"
            ));
        }
    }
    let (_, staged_identity) = open_pinned_directory_at(
        &pinned.staging,
        std::ffi::OsStr::new("plugin"),
        "rolled-back install candidate",
    )?;
    if staged_identity != pinned.candidate_identity {
        return Err(
            "install staging does not contain the pinned candidate after rollback".to_owned(),
        );
    }
    let (_, staging_identity) = open_pinned_directory_at(
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
pub(super) fn fail_after_install_and_rollback<F>(
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
pub(super) fn describe_install_recovery_state(
    pinned: &PinnedInstall,
    plugins_directory: &Path,
    plugin_id: &str,
) -> String {
    let candidate_descriptor_matches = descriptor_identity(&pinned.candidate, "install candidate")
        .map(|identity| identity == pinned.candidate_identity)
        .unwrap_or(false);
    let candidate_tree_matches = verify_update_tree_descriptor(
        &pinned.candidate,
        &pinned.candidate_snapshot,
        "install candidate tree changed",
    )
    .is_ok();
    let live_matches = open_pinned_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "live install target",
    )
    .map(|(_, identity)| identity == pinned.candidate_identity)
    .unwrap_or(false);
    let staged_matches = open_pinned_directory_at(
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
    let staging_parent_mapping_matches = open_pinned_directory_at(
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

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

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
}
