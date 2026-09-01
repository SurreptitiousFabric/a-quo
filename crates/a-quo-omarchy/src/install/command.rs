use std::fs;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::{OmarchyError, Result};

pub(super) fn validate_system_command(path: &Path) -> Result<()> {
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

pub(super) fn run_validator(validator: &Path, plugin_directory: &Path) -> Result<()> {
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
pub(super) fn run_validator_for_descriptor(
    validator: &Path,
    plugin_directory: &OwnedFd,
) -> Result<()> {
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

pub(super) fn run_rescan(omarchy_shell: &Path) -> std::result::Result<(), String> {
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::rescan_command;

    #[test]
    fn plugin_rescan_does_not_inherit_the_session_bus() {
        let command = rescan_command(Path::new("/usr/bin/omarchy-shell"));
        assert!(
            command
                .get_envs()
                .all(|(name, _)| name != "DBUS_SESSION_BUS_ADDRESS")
        );
    }
}
