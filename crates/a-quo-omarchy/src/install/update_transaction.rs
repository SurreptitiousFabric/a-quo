use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use super::tree::{
    TargetIdentity, UpdateTreeSnapshot, descriptor_identity, open_pinned_directory_at,
    target_identity, verify_update_tree_descriptor,
};
use crate::{OmarchyError, Result};

pub(super) struct PinnedUpdate {
    pub(super) plugins: OwnedFd,
    pub(super) recovery: OwnedFd,
    pub(super) installed: OwnedFd,
    pub(super) candidate: OwnedFd,
    pub(super) plugins_identity: TargetIdentity,
    pub(super) recovery_identity: TargetIdentity,
    pub(super) installed_identity: TargetIdentity,
    pub(super) candidate_identity: TargetIdentity,
    pub(super) installed_snapshot: UpdateTreeSnapshot,
    pub(super) candidate_snapshot: UpdateTreeSnapshot,
    pub(super) recovery_name: std::ffi::OsString,
    pub(super) recovery_path: PathBuf,
}

#[cfg(target_os = "linux")]
pub(super) struct UpdateBaselines {
    pub(super) plugins_identity: TargetIdentity,
    pub(super) recovery_identity: TargetIdentity,
    pub(super) installed_identity: TargetIdentity,
    pub(super) candidate_identity: TargetIdentity,
    pub(super) installed_snapshot: UpdateTreeSnapshot,
    pub(super) candidate_snapshot: UpdateTreeSnapshot,
}

#[cfg(target_os = "linux")]
pub(super) fn describe_retained_update_staging(
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
    let descriptor_matches = descriptor_identity(&pinned.recovery, "update recovery root")
        .map(|identity| identity == pinned.recovery_identity)
        .unwrap_or(false);
    let external_path_matches = target_identity(&pinned.recovery_path)
        .map(|identity| identity == pinned.recovery_identity)
        .unwrap_or(false);
    let parent_mapping_matches = open_pinned_directory_at(
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
pub(super) fn retain_and_exchange_update(
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
    let plugins_identity = descriptor_identity(&plugins, "plugins directory")
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
        open_pinned_directory_at(&plugins, &recovery_name, "update recovery directory")
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

    let (installed, installed_identity) = open_pinned_directory_at(
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

    let (candidate, candidate_identity) = open_pinned_directory_at(
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
pub(super) fn rollback_pinned_update(
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
    if descriptor_identity(&pinned.installed, "original installed release")?
        != pinned.installed_identity
        || descriptor_identity(&pinned.candidate, "update candidate")? != pinned.candidate_identity
    {
        return Err(format!("pinned release descriptor changed {phase}"));
    }
    let (_, live_identity) = open_pinned_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "live update target",
    )?;
    if live_identity != expected_live_identity {
        return Err(format!("live target identity mismatch {phase}"));
    }
    let (_, recovery_child_identity) = open_pinned_directory_at(
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
pub(super) fn verify_update_layout(
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
    let (_, current_recovery_identity) = open_pinned_directory_at(
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
pub(super) fn describe_update_recovery_state(
    pinned: &PinnedUpdate,
    plugins_directory: &Path,
    plugin_id: &str,
    expected_prior_identity: TargetIdentity,
) -> String {
    let descriptor_matches = descriptor_identity(&pinned.installed, "original installed release")
        .map(|identity| identity == expected_prior_identity)
        .unwrap_or(false);
    let tree_matches = verify_update_tree_descriptor(
        &pinned.installed,
        &pinned.installed_snapshot,
        "prior release tree changed",
    )
    .is_ok();
    let recovery_child_matches = open_pinned_directory_at(
        &pinned.recovery,
        std::ffi::OsStr::new("plugin"),
        "update recovery child",
    )
    .map(|(_, identity)| identity == expected_prior_identity)
    .unwrap_or(false);
    let live_child_matches = open_pinned_directory_at(
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
pub(super) fn pinned_update_recovery_path(pinned: &PinnedUpdate) -> PathBuf {
    pinned.recovery_path.join("plugin")
}
