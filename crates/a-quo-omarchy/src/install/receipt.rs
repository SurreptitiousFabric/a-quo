use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use a_quo_core::ArtifactDescriptor;
#[cfg(not(target_os = "linux"))]
use a_quo_core::describe_artifact;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::limits::{INSTALL_RECEIPT_NAME, MAX_RECEIPT_BYTES, RECEIPT_SCHEMA_VERSION};
#[cfg(target_os = "linux")]
use super::tree::{UpdateTreeSnapshot, read_update_snapshot_file};
#[cfg(target_os = "linux")]
use crate::OmarchyManifest;
#[cfg(target_os = "linux")]
use crate::archive::{MAX_MANIFEST_BYTES, parse_semantic_version, validate_plugin_id};
use crate::{OmarchyError, PluginInspection, Result};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstallReceipt {
    pub(super) schema_version: u64,
    pub(super) plugin_id: String,
    pub(super) version: String,
    pub(super) package_sha256: String,
    pub(super) publisher_key_fingerprint: String,
    pub(super) publisher_persona_id: String,
    pub(super) installed_at_unix_seconds: u64,
}

#[cfg(not(target_os = "linux"))]
pub(super) fn build_receipt(
    package: &Path,
    inspection: &PluginInspection,
    publisher_persona_id: String,
) -> Result<InstallReceipt> {
    let artifact = describe_artifact(package)?;
    build_receipt_for_artifact(&artifact, inspection, publisher_persona_id)
}

pub(super) fn build_receipt_for_artifact(
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

pub(super) fn write_install_receipt(
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
pub(super) fn read_install_receipt(plugin_directory: &Path) -> Result<InstallReceipt> {
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
pub(super) fn validate_installed_state(
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
pub(super) fn read_installed_manifest(plugin_directory: &Path) -> Result<OmarchyManifest> {
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
pub(super) fn read_update_snapshot_manifest(
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
pub(super) fn read_update_snapshot_receipt(
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
pub(super) fn require_newer_version(installed: &str, candidate: &str) -> Result<()> {
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

#[cfg(not(unix))]
fn secure_receipt(_path: &Path) -> Result<()> {
    Ok(())
}
