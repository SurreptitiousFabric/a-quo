use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use tempfile::Builder;

use super::tree::{
    TargetIdentity, descriptor_identity, open_pinned_directory_at, pinned_entry_exists,
    target_identity,
};
use crate::{OmarchyError, Result};

#[cfg(target_os = "linux")]
pub(super) struct PinnedRemoval {
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
#[cfg(target_os = "linux")]
pub(super) fn prepare_pinned_removal(
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
        open_pinned_directory_at(&plugins, std::ffi::OsStr::new(plugin_id), "managed target")
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
        open_pinned_directory_at(&plugins, &quarantine_name, "recovery quarantine")
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
        open_pinned_directory_at(&plugins, std::ffi::OsStr::new(plugin_id), "managed target")
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
pub(super) fn quarantine_pinned_target(pinned: &PinnedRemoval, plugin_id: &str) -> Result<OwnedFd> {
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

    let (moved, moved_identity) = open_pinned_directory_at(
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
pub(super) fn verify_restored_target(
    pinned: &PinnedRemoval,
    plugins_directory: &Path,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    let (_, restored_identity) = open_pinned_directory_at(
        &pinned.plugins,
        std::ffi::OsStr::new(plugin_id),
        "restored managed target after rescan",
    )?;
    if restored_identity != pinned.target_identity {
        return Err("the live plugin path no longer names the restored managed target".to_owned());
    }

    match pinned_entry_exists(&pinned.quarantine, std::ffi::OsStr::new("plugin")) {
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

    let (_, quarantine_path_identity) = open_pinned_directory_at(
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
pub(super) fn describe_pinned_recovery_state(
    pinned: &PinnedRemoval,
    plugins_directory: &Path,
) -> String {
    let child_matches = open_pinned_directory_at(
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
        && open_pinned_directory_at(
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
    let (_, current_identity) = open_pinned_directory_at(
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
    let (_, restored_identity) = open_pinned_directory_at(
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
pub(super) fn restore_pinned_target(
    pinned: &PinnedRemoval,
    plugin_id: &str,
) -> std::result::Result<(), String> {
    let (_, quarantined_identity) = open_pinned_directory_at(
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

    let (_, restored_identity) = open_pinned_directory_at(
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
pub(super) fn verify_retained_quarantine(
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

    if descriptor_identity(moved, "quarantined plugin")
        .map_err(OmarchyError::RemovalStateIndeterminate)?
        != pinned.target_identity
        || descriptor_identity(&pinned.target, "original managed target")
            .map_err(OmarchyError::RemovalStateIndeterminate)?
            != pinned.target_identity
    {
        return Err(OmarchyError::RemovalStateIndeterminate(
            "the pinned target descriptor identity changed unexpectedly; no recursive deletion ran"
                .to_owned(),
        ));
    }

    let (_, current_quarantined_identity) = open_pinned_directory_at(
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

    let (_, current_quarantine_identity) = open_pinned_directory_at(
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

    match pinned_entry_exists(&pinned.plugins, std::ffi::OsStr::new(plugin_id)) {
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
fn removal_descriptor_identity(descriptor: &OwnedFd, label: &str) -> Result<TargetIdentity> {
    descriptor_identity(descriptor, label).map_err(OmarchyError::AtomicRemoval)
}

pub(super) fn retained_quarantine_path(pinned: &PinnedRemoval) -> PathBuf {
    pinned.quarantine_path.clone()
}
