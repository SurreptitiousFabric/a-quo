use std::fs;
use std::path::{Path, PathBuf};

use tempfile::Builder;

use crate::{OmarchyError, Result};

#[cfg(not(target_os = "linux"))]
pub(super) fn private_staging_directory(
    plugins_directory: &Path,
    prefix: &str,
) -> Result<tempfile::TempDir> {
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
pub(super) fn retained_install_staging_directory(plugins_directory: &Path) -> Result<PathBuf> {
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
pub(super) fn retained_update_staging_directory(plugins_directory: &Path) -> Result<PathBuf> {
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

pub(super) fn prepare_plugins_directory(path: &Path) -> Result<()> {
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
pub(super) fn require_existing_plugins_directory(path: &Path) -> Result<()> {
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

pub(super) fn reject_existing_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(OmarchyError::TargetExists(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn atomic_install_no_replace(_source: &Path, _target: &Path) -> Result<()> {
    Err(OmarchyError::AtomicInstall(
        "guarded Omarchy installation requires Linux renameat2".to_owned(),
    ))
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(super) fn secure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
pub(super) fn secure_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}
