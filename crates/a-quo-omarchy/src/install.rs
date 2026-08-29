use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use a_quo_core::{describe_artifact, load_proof};
use a_quo_store::{PersonaAuthorityDisposition, PersonaStore, StoreError};
use serde::{Deserialize, Serialize};
use tempfile::Builder;

use crate::archive::{
    MAX_COMPRESSED_BYTES, MAX_MANIFEST_BYTES, extract_archive, parse_semantic_version,
    validate_plugin_id,
};
use crate::{
    InstallOutcome, OmarchyError, OmarchyManifest, PluginInspection, Result, UpdateOutcome,
    inspect_with_proof, require_installable_publisher,
};

const VALIDATOR: &str = "/usr/bin/omarchy-plugin-validate";
const OMARCHY_SHELL: &str = "/usr/bin/omarchy-shell";
const MAX_SHELL_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TargetIdentity {
    device: u64,
    inode: u64,
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

pub(crate) fn install_with_commands(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
) -> Result<InstallOutcome> {
    install_with_commands_and_authorization_hook(
        package_path,
        proof_path,
        store,
        plugins_directory,
        validator,
        omarchy_shell,
        || Ok(()),
    )
}

pub(crate) fn install_with_commands_and_authorization_hook<F>(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
    before_final_authorization: F,
) -> Result<InstallOutcome>
where
    F: FnOnce() -> Result<()>,
{
    validate_system_command(validator)?;
    validate_system_command(omarchy_shell)?;
    prepare_plugins_directory(plugins_directory)?;

    let proof = load_proof(proof_path)?;
    let staging = private_staging_directory(plugins_directory, ".a-quo-install-")?;
    let staged_package = staging.path().join("package.tar.zst");
    copy_package_once(package_path, &staged_package)?;

    let inspection = inspect_with_proof(&staged_package, &proof, Some(store))?;
    require_installable_publisher(&inspection)?;
    let expected_publisher_persona_id = publisher_persona_id(store, &inspection)?;
    reject_stale_enabled_configuration(plugins_directory, &inspection.manifest.id)?;

    let target = plugins_directory.join(&inspection.manifest.id);
    reject_existing_target(&target)?;

    let extracted = staging.path().join("plugin");
    let (extracted_manifest, extracted_archive) = extract_archive(&staged_package, &extracted)?;
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
    write_install_receipt(&extracted, &receipt)?;
    run_validator(validator, &extracted)?;

    before_final_authorization()?;
    reject_stale_enabled_configuration(plugins_directory, &inspection.manifest.id)?;
    reject_existing_target(&target)?;
    let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
    let signed_label = &inspection.artifact_evidence.signer.persona;
    with_final_publisher_authorization(
        store,
        fingerprint,
        signed_label,
        &expected_publisher_persona_id,
        || atomic_install_no_replace(&extracted, &target),
    )?;

    let shell_rescan = match run_rescan(omarchy_shell) {
        Ok(()) => "passed".to_owned(),
        Err(error) => format!("failed_after_install:{error}"),
    };
    Ok(InstallOutcome {
        plugin_id: inspection.manifest.id,
        version: inspection.manifest.version,
        installed_disabled: true,
        omarchy_manifest_validation: "passed".to_owned(),
        shell_rescan,
        runtime_safety: "not_evaluated".to_owned(),
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

#[cfg(test)]
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
        before_final_authorization,
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
        || Ok(()),
        rescan,
    )
}

#[allow(clippy::too_many_arguments)]
fn update_with_rescan_and_authorization_hook<A, F>(
    package_path: &Path,
    proof_path: &Path,
    store: &mut PersonaStore,
    plugins_directory: &Path,
    validator: &Path,
    omarchy_shell: &Path,
    before_final_authorization: A,
    mut rescan: F,
) -> Result<UpdateOutcome>
where
    A: FnOnce() -> Result<()>,
    F: FnMut() -> std::result::Result<(), String>,
{
    validate_system_command(validator)?;
    validate_system_command(omarchy_shell)?;
    prepare_plugins_directory(plugins_directory)?;

    let proof = load_proof(proof_path)?;
    let staging = private_staging_directory(plugins_directory, ".a-quo-update-")?;
    let staged_package = staging.path().join("package.tar.zst");
    copy_package_once(package_path, &staged_package)?;

    let inspection = inspect_with_proof(&staged_package, &proof, Some(store))?;
    require_installable_publisher(&inspection)?;
    let expected_publisher_persona_id = publisher_persona_id(store, &inspection)?;
    let target = plugins_directory.join(&inspection.manifest.id);
    let target_identity = target_identity(&target)?;
    reject_git_managed_target(&target)?;
    run_validator(validator, &target)?;

    let installed_manifest = read_installed_manifest(&target)?;
    let installed_receipt = read_install_receipt(&target)?;
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

    let extracted = staging.path().join("plugin");
    let (extracted_manifest, extracted_archive) = extract_archive(&staged_package, &extracted)?;
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
    write_install_receipt(&extracted, &receipt)?;
    run_validator(validator, &extracted)?;

    before_final_authorization()?;
    ensure_target_identity(&target, target_identity)?;
    let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
    let signed_label = &inspection.artifact_evidence.signer.persona;
    with_final_publisher_authorization(
        store,
        fingerprint,
        signed_label,
        &expected_publisher_persona_id,
        || atomic_exchange(&extracted, &target),
    )?;

    if let Err(rescan_error) = rescan() {
        if let Err(rollback_error) = atomic_exchange(&extracted, &target) {
            return Err(OmarchyError::UpdateRollbackFailed(format!(
                "shell rescan failed ({rescan_error}); atomic restore failed ({rollback_error})"
            )));
        }
        if let Err(rollback_rescan_error) = rescan() {
            return Err(OmarchyError::UpdateRollbackFailed(format!(
                "previous files were restored after shell rescan failed ({rescan_error}), but the restore rescan also failed ({rollback_rescan_error})"
            )));
        }
        return Err(OmarchyError::UpdateRolledBack(rescan_error));
    }

    Ok(UpdateOutcome {
        plugin_id: inspection.manifest.id,
        previous_version: installed_manifest.version,
        version: inspection.manifest.version,
        publisher_continuity: "same_local_persona".to_owned(),
        omarchy_manifest_validation: "passed".to_owned(),
        atomic_exchange: true,
        shell_rescan: "passed".to_owned(),
        enablement: "preserved_from_omarchy_configuration".to_owned(),
        runtime_safety: "not_evaluated".to_owned(),
    })
}

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

fn build_receipt(
    package: &Path,
    inspection: &PluginInspection,
    publisher_persona_id: String,
) -> Result<InstallReceipt> {
    let artifact = describe_artifact(package)?;
    Ok(InstallReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        plugin_id: inspection.manifest.id.clone(),
        version: inspection.manifest.version.clone(),
        package_sha256: artifact.digest.value,
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

fn write_install_receipt(plugin_directory: &Path, receipt: &InstallReceipt) -> Result<()> {
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
    })
}

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
    let link_metadata = fs::symlink_metadata(source).map_err(|source_error| OmarchyError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(OmarchyError::SymlinkBoundary(source.to_path_buf()));
    }
    let mut input = File::open(source).map_err(|source_error| OmarchyError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
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
        std::io::copy(&mut input, &mut output).map_err(|source_error| OmarchyError::Io {
            path: destination.to_path_buf(),
            source: source_error,
        })?;
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

#[cfg(unix)]
fn target_identity_from_metadata(metadata: &fs::Metadata) -> TargetIdentity {
    use std::os::unix::fs::MetadataExt;

    TargetIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn target_identity_from_metadata(_metadata: &fs::Metadata) -> TargetIdentity {
    TargetIdentity {
        device: 0,
        inode: 0,
    }
}

fn ensure_target_identity(path: &Path, expected: TargetIdentity) -> Result<()> {
    let actual = target_identity(path)?;
    if actual != expected {
        return Err(OmarchyError::AtomicUpdate(format!(
            "installed target changed while candidate was staged: {}",
            path.display()
        )));
    }
    Ok(())
}

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

fn reject_stale_enabled_configuration(plugins_directory: &Path, plugin_id: &str) -> Result<()> {
    let Some(omarchy_directory) = plugins_directory.parent() else {
        return Err(OmarchyError::InvalidShellConfiguration(
            "plugins directory has no parent".to_owned(),
        ));
    };
    let config_path = omarchy_directory.join("shell.json");
    let metadata = match fs::symlink_metadata(&config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(OmarchyError::Io {
                path: config_path,
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::SymlinkBoundary(config_path));
    }
    if metadata.len() > MAX_SHELL_CONFIG_BYTES {
        return Err(OmarchyError::InvalidShellConfiguration(format!(
            "{} exceeds {MAX_SHELL_CONFIG_BYTES} bytes",
            config_path.display()
        )));
    }

    let bytes = fs::read(&config_path).map_err(|source| OmarchyError::Io {
        path: config_path.clone(),
        source,
    })?;
    let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        OmarchyError::InvalidShellConfiguration(format!(
            "{} is not valid JSON: {error}",
            config_path.display()
        ))
    })?;
    if config
        .get("bar")
        .is_some_and(|bar| contains_plugin_id(bar, plugin_id))
        || config
            .get("plugins")
            .is_some_and(|plugins| contains_plugin_id(plugins, plugin_id))
    {
        return Err(OmarchyError::StaleEnabledConfiguration(
            plugin_id.to_owned(),
        ));
    }
    Ok(())
}

fn contains_plugin_id(value: &serde_json::Value, plugin_id: &str) -> bool {
    match value {
        serde_json::Value::String(value) => value == plugin_id,
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| contains_plugin_id(value, plugin_id)),
        serde_json::Value::Object(values) => {
            values.get("id").and_then(serde_json::Value::as_str) == Some(plugin_id)
                || values
                    .values()
                    .any(|value| contains_plugin_id(value, plugin_id))
        }
        _ => false,
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

#[cfg(target_os = "linux")]
fn atomic_install_no_replace(source: &Path, target: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        target,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        OmarchyError::AtomicInstall(format!(
            "cannot move {} to {} without replacement: {error}",
            source.display(),
            target.display()
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn atomic_install_no_replace(_source: &Path, _target: &Path) -> Result<()> {
    Err(OmarchyError::AtomicInstall(
        "guarded Omarchy installation requires Linux renameat2".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn atomic_exchange(staged: &Path, installed: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staged,
        rustix::fs::CWD,
        installed,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| {
        OmarchyError::AtomicUpdate(format!(
            "cannot exchange {} with {}: {error}",
            staged.display(),
            installed.display()
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn atomic_exchange(_staged: &Path, _installed: &Path) -> Result<()> {
    Err(OmarchyError::AtomicUpdate(
        "guarded Omarchy updates require Linux renameat2".to_owned(),
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

#[cfg(unix)]
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
