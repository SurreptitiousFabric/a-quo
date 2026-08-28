//! Guarded inspection and installation of signed Omarchy plugin packages.
//!
//! A valid package signature is publisher evidence, not a safety verdict.

mod archive;
mod install;
mod model;

use std::path::{Path, PathBuf};

use a_quo_core::{ProofBundle, ProofError, load_proof, verify_sshsig_proof};
use a_quo_store::{KeyStatus, PersonaStore, StoreError};
use thiserror::Error;

pub use install::{install_signed_package, update_signed_package};
pub use model::{
    ArchiveReport, InstallOutcome, OmarchyManifest, PluginInspection, PublisherEvidence,
    PublisherRegistryStatus, UpdateOutcome,
};

#[derive(Debug, Error)]
pub enum OmarchyError {
    #[error("proof verification failed: {0}")]
    Proof(#[from] ProofError),

    #[error("persona registry failed: {0}")]
    Store(#[from] StoreError),

    #[error("cannot access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("archive processing failed: {0}")]
    ArchiveIo(#[source] std::io::Error),

    #[error("package exceeds the {maximum} byte compressed-size limit: {actual} bytes")]
    PackageTooLarge { actual: u64, maximum: u64 },

    #[error("invalid package: {0}")]
    InvalidPackage(String),

    #[error("unsafe archive entry '{path}': {reason}")]
    UnsafeArchiveEntry { path: String, reason: String },

    #[error("archive exceeds the {limit_name} limit of {maximum}")]
    ArchiveLimit {
        limit_name: &'static str,
        maximum: u64,
    },

    #[error("archive contains duplicate path: {0}")]
    DuplicateArchivePath(String),

    #[error("archive is missing a root manifest.json")]
    MissingManifest,

    #[error("manifest JSON is invalid: {0}")]
    ManifestJson(#[from] serde_json::Error),

    #[error("invalid Omarchy manifest: {0}")]
    InvalidManifest(String),

    #[error("publisher key is not locally recognized: {0}")]
    UnrecognizedPublisher(String),

    #[error("publisher key is {status}: {fingerprint}")]
    InactivePublisher {
        fingerprint: String,
        status: &'static str,
    },

    #[error("signed persona label does not match the local publisher label")]
    PublisherLabelMismatch,

    #[error("refusing symbolic link at installation boundary: {0}")]
    SymlinkBoundary(PathBuf),

    #[error("plugin is already installed: {0}")]
    TargetExists(PathBuf),

    #[error("plugin is not installed: {0}")]
    TargetMissing(PathBuf),

    #[error("installed plugin is not managed by A Quo: {0}")]
    NotManagedInstall(PathBuf),

    #[error("invalid A Quo installation receipt: {0}")]
    InvalidInstallReceipt(String),

    #[error("update publisher is not the same locally recognized persona as the installer")]
    PublisherContinuityMismatch,

    #[error("plugin version must be semantic versioning: {version}: {reason}")]
    InvalidSemanticVersion { version: String, reason: String },

    #[error("candidate version {candidate} is not newer than installed version {installed}")]
    VersionNotNewer {
        installed: String,
        candidate: String,
    },

    #[error(
        "plugin id is already referenced by Omarchy configuration and could load immediately: {0}"
    )]
    StaleEnabledConfiguration(String),

    #[error("cannot safely inspect Omarchy shell configuration: {0}")]
    InvalidShellConfiguration(String),

    #[error("trusted Omarchy command is unavailable or unsafe: {0}")]
    UnsafeSystemCommand(PathBuf),

    #[error("Omarchy manifest validation failed with exit status {0}")]
    ManifestValidationFailed(String),

    #[error("atomic plugin installation failed: {0}")]
    AtomicInstall(String),

    #[error("atomic plugin update failed: {0}")]
    AtomicUpdate(String),

    #[error("Omarchy shell rescan failed; the previous plugin was restored: {0}")]
    UpdateRolledBack(String),

    #[error("plugin update rollback needs manual attention: {0}")]
    UpdateRollbackFailed(String),
}

pub type Result<T> = std::result::Result<T, OmarchyError>;

pub fn inspect_signed_package(
    package_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
    store: Option<&PersonaStore>,
) -> Result<PluginInspection> {
    let proof = load_proof(proof_path)?;
    inspect_with_proof(package_path.as_ref(), &proof, store)
}

pub(crate) fn inspect_with_proof(
    package_path: &Path,
    proof: &ProofBundle,
    store: Option<&PersonaStore>,
) -> Result<PluginInspection> {
    let artifact_evidence = verify_sshsig_proof(package_path, proof)?;
    let (manifest, archive) = archive::inspect_archive(package_path)?;
    let publisher_evidence = publisher_evidence(
        store,
        &artifact_evidence.signer.key_fingerprint,
        &artifact_evidence.signer.persona,
    )?;

    Ok(PluginInspection {
        artifact_evidence,
        publisher_evidence,
        manifest,
        archive,
        omarchy_manifest_validation: "not_run".to_owned(),
        runtime_safety: "not_evaluated".to_owned(),
        automatic_enablement: "forbidden".to_owned(),
    })
}

pub(crate) fn require_installable_publisher(inspection: &PluginInspection) -> Result<()> {
    let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
    match inspection.publisher_evidence.registry_status {
        PublisherRegistryStatus::Active => {}
        PublisherRegistryStatus::NotChecked | PublisherRegistryStatus::Unrecognized => {
            return Err(OmarchyError::UnrecognizedPublisher(fingerprint.clone()));
        }
        PublisherRegistryStatus::Retired => {
            return Err(OmarchyError::InactivePublisher {
                fingerprint: fingerprint.clone(),
                status: "retired",
            });
        }
        PublisherRegistryStatus::Compromised => {
            return Err(OmarchyError::InactivePublisher {
                fingerprint: fingerprint.clone(),
                status: "compromised",
            });
        }
    }
    if inspection.publisher_evidence.signed_label_agreement != Some(true) {
        return Err(OmarchyError::PublisherLabelMismatch);
    }
    Ok(())
}

fn publisher_evidence(
    store: Option<&PersonaStore>,
    fingerprint: &str,
    signed_label: &str,
) -> Result<PublisherEvidence> {
    let Some(store) = store else {
        return Ok(PublisherEvidence {
            registry_status: PublisherRegistryStatus::NotChecked,
            local_label: None,
            local_purpose: None,
            signed_label_agreement: None,
            key_status: None,
            meaning: "local publisher registry was not checked".to_owned(),
        });
    };
    let Some(recognized) = store.lookup_key(fingerprint)? else {
        return Ok(PublisherEvidence {
            registry_status: PublisherRegistryStatus::Unrecognized,
            local_label: None,
            local_purpose: None,
            signed_label_agreement: None,
            key_status: None,
            meaning: "signature is valid, but this key has no local publisher binding".to_owned(),
        });
    };

    let registry_status = match recognized.key.status {
        KeyStatus::Active => PublisherRegistryStatus::Active,
        KeyStatus::Retired => PublisherRegistryStatus::Retired,
        KeyStatus::Compromised => PublisherRegistryStatus::Compromised,
    };
    Ok(PublisherEvidence {
        registry_status,
        local_label: Some(recognized.persona.label.clone()),
        local_purpose: Some(recognized.persona.purpose),
        signed_label_agreement: Some(recognized.persona.label == signed_label),
        key_status: Some(recognized.key.status),
        meaning:
            "local metadata only; legal identity, review, and runtime safety are not established"
                .to_owned(),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::io::{self, Cursor};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use a_quo_core::{create_sshsig_proof, write_proof_new};
    use a_quo_store::{KeyProvider, PersonaPurpose, PersonaStore, RotationReason};
    use serde_json::json;
    use tar::{Builder as TarBuilder, EntryType, Header};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn inspects_and_installs_valid_package_disabled() {
        let fixture = Fixture::new();
        let inspection =
            inspect_signed_package(&fixture.package, &fixture.proof, Some(&fixture.store)).unwrap();

        assert_eq!(inspection.manifest.id, "example.signed-plugin");
        assert_eq!(
            inspection.publisher_evidence.registry_status,
            PublisherRegistryStatus::Active
        );
        assert_eq!(inspection.runtime_safety, "not_evaluated");
        assert_eq!(inspection.automatic_enablement, "forbidden");
        assert_eq!(
            inspection.archive.executable_files,
            vec!["scripts/helper.sh".to_owned()]
        );

        let outcome = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap();
        assert!(outcome.installed_disabled);
        assert_eq!(outcome.omarchy_manifest_validation, "passed");
        assert_eq!(outcome.shell_rescan, "passed");
        let target = fixture.plugins.join("example.signed-plugin");
        assert!(target.join("Panel.qml").is_file());
        assert!(target.join("scripts/helper.sh").is_file());
        assert!(target.join(install::INSTALL_RECEIPT_NAME).is_file());
        assert!(!target.join(".git").exists());
        assert_eq!(
            fs::read_dir(&fixture.plugins).unwrap().count(),
            1,
            "staging directory should be removed"
        );
    }

    #[test]
    fn install_refuses_unrecognized_publisher() {
        let fixture = Fixture::new();
        let empty_store = PersonaStore::open_in_memory().unwrap();

        let error = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &empty_store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UnrecognizedPublisher(_)));
        assert!(!fixture.plugins.join("example.signed-plugin").exists());
    }

    #[test]
    fn installed_omarchy_validator_accepts_fixture_when_available() {
        let validator = Path::new("/usr/bin/omarchy-plugin-validate");
        if !validator.is_file() {
            return;
        }
        let fixture = Fixture::new();

        let outcome = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &fixture.store,
            &fixture.plugins,
            validator,
            Path::new("/usr/bin/true"),
        )
        .unwrap();

        assert!(outcome.installed_disabled);
        assert_eq!(outcome.omarchy_manifest_validation, "passed");
    }

    #[test]
    fn install_refuses_retired_publisher_but_inspection_remains_valid() {
        let mut fixture = Fixture::new();
        let replacement = fixture.directory.path().join("replacement_key");
        generate_key(&replacement);
        let replacement_public = fs::read_to_string(replacement.with_extension("pub")).unwrap();
        fixture
            .store
            .rotate_key(
                &fixture.persona_id,
                &replacement_public,
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                None,
            )
            .unwrap();

        let inspection =
            inspect_signed_package(&fixture.package, &fixture.proof, Some(&fixture.store)).unwrap();
        assert_eq!(
            inspection.artifact_evidence.signature,
            a_quo_core::EvidenceStatus::Verified
        );
        assert_eq!(
            inspection.publisher_evidence.registry_status,
            PublisherRegistryStatus::Retired
        );

        let error = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            OmarchyError::InactivePublisher {
                status: "retired",
                ..
            }
        ));
    }

    #[test]
    fn install_refuses_stale_enabled_configuration() {
        let fixture = Fixture::new();
        fs::write(
            fixture.directory.path().join("omarchy/shell.json"),
            br#"{"plugins":[{"id":"example.signed-plugin"}]}"#,
        )
        .unwrap();

        let error = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            OmarchyError::StaleEnabledConfiguration(ref id) if id == "example.signed-plugin"
        ));
    }

    #[test]
    fn update_requires_newer_version_and_preserves_old_files_on_refusal() {
        let fixture = Fixture::new();
        fixture.install();
        let (package, proof) =
            fixture.release("0.1.0", b"import QtQuick\nItem { property int v: 2 }\n");

        let error = install::update_with_commands(
            &package,
            &proof,
            &fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::VersionNotNewer { .. }));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
    }

    #[test]
    fn update_atomically_replaces_a_managed_plugin() {
        let fixture = Fixture::new();
        fixture.install();
        let new_panel = b"import QtQuick\nItem { property int v: 2 }\n";
        let (package, proof) = fixture.release("0.2.0", new_panel);

        let outcome = install::update_with_commands(
            &package,
            &proof,
            &fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap();

        assert_eq!(outcome.previous_version, "0.1.0");
        assert_eq!(outcome.version, "0.2.0");
        assert_eq!(outcome.publisher_continuity, "same_local_persona");
        assert!(outcome.atomic_exchange);
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            new_panel
        );
        assert_eq!(
            fs::read_dir(&fixture.plugins).unwrap().count(),
            1,
            "old release and staging directory should be removed"
        );
    }

    #[test]
    fn update_refuses_a_different_locally_trusted_persona() {
        let mut fixture = Fixture::new();
        fixture.install();
        let other_key = fixture.directory.path().join("other_publisher_key");
        generate_key(&other_key);
        let other_public_path = other_key.with_extension("pub");
        let other_public = fs::read_to_string(&other_public_path).unwrap();
        let other_persona = fixture
            .store
            .create_persona("Other Publisher", PersonaPurpose::Project)
            .unwrap();
        fixture
            .store
            .enroll_key(&other_persona.id, &other_public, KeyProvider::OpensshFile)
            .unwrap();
        let package = fixture.directory.path().join("takeover.tar.zst");
        let proof = fixture.directory.path().join("takeover.proof.json");
        create_release_archive(
            &package,
            "0.2.0",
            b"import QtQuick\nItem { property int takeover: 1 }\n",
        );
        let bundle = create_sshsig_proof(
            &package,
            &other_key,
            &other_public_path,
            &other_persona.label,
        )
        .unwrap();
        write_proof_new(&proof, &bundle).unwrap();

        let error = install::update_with_commands(
            &package,
            &proof,
            &fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::PublisherContinuityMismatch));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
    }

    #[test]
    fn update_allows_key_rotation_within_the_same_persona() {
        let mut fixture = Fixture::new();
        fixture.install();
        let replacement_key = fixture.directory.path().join("rotated_publisher_key");
        generate_key(&replacement_key);
        let replacement_public_path = replacement_key.with_extension("pub");
        let replacement_public = fs::read_to_string(&replacement_public_path).unwrap();
        fixture
            .store
            .rotate_key(
                &fixture.persona_id,
                &replacement_public,
                KeyProvider::OpensshFile,
                RotationReason::Routine,
                Some("publisher hardware rotation"),
            )
            .unwrap();
        let package = fixture.directory.path().join("rotated-key.tar.zst");
        let proof = fixture.directory.path().join("rotated-key.proof.json");
        create_release_archive(
            &package,
            "0.2.0",
            b"import QtQuick\nItem { property int rotated: 1 }\n",
        );
        let bundle = create_sshsig_proof(
            &package,
            &replacement_key,
            &replacement_public_path,
            "Example Publisher",
        )
        .unwrap();
        write_proof_new(&proof, &bundle).unwrap();

        let outcome = install::update_with_commands(
            &package,
            &proof,
            &fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap();

        assert_eq!(outcome.publisher_continuity, "same_local_persona");
        assert_eq!(outcome.version, "0.2.0");
    }

    #[test]
    fn update_rolls_back_exact_old_directory_when_rescan_fails() {
        let fixture = Fixture::new();
        fixture.install();
        let (package, proof) = fixture.release(
            "0.2.0",
            b"import QtQuick\nItem { property int candidate: 1 }\n",
        );
        let calls = Cell::new(0_u8);

        let error = install::update_with_rescan(
            &package,
            &proof,
            &fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call == 0 {
                    Err("simulated first rescan failure".to_owned())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UpdateRolledBack(_)));
        assert_eq!(calls.get(), 2);
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        let installed: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.target().join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(installed["version"], "0.1.0");
    }

    #[test]
    fn archive_rejects_duplicate_paths() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("duplicate.tar.zst");
        create_archive(
            &package,
            &[
                TestEntry::file("manifest.json", manifest_bytes("Panel.qml"), 0o644),
                TestEntry::file("Panel.qml", b"import QtQuick\n".to_vec(), 0o644),
                TestEntry::file("Panel.qml", b"duplicate\n".to_vec(), 0o644),
            ],
        );

        let error = archive::inspect_archive(&package).unwrap_err();
        assert!(matches!(error, OmarchyError::DuplicateArchivePath(_)));
    }

    #[test]
    fn archive_rejects_symbolic_links() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("link.tar.zst");
        create_archive(
            &package,
            &[
                TestEntry::file("manifest.json", manifest_bytes("Panel.qml"), 0o644),
                TestEntry::file("Panel.qml", b"import QtQuick\n".to_vec(), 0o644),
                TestEntry::Symlink {
                    path: "escape",
                    target: "../outside",
                },
            ],
        );

        let error = archive::inspect_archive(&package).unwrap_err();
        assert!(matches!(error, OmarchyError::UnsafeArchiveEntry { .. }));
    }

    #[test]
    fn archive_rejects_missing_manifest_entry_point() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("missing-entry.tar.zst");
        create_archive(
            &package,
            &[TestEntry::file(
                "manifest.json",
                manifest_bytes("Missing.qml"),
                0o644,
            )],
        );

        let error = archive::inspect_archive(&package).unwrap_err();
        assert!(matches!(error, OmarchyError::InvalidManifest(_)));
    }

    #[test]
    fn archive_rejects_forged_local_install_receipt() {
        let directory = tempdir().unwrap();
        let package = directory.path().join("receipt.tar.zst");
        create_archive(
            &package,
            &[
                TestEntry::file("manifest.json", manifest_bytes("Panel.qml"), 0o644),
                TestEntry::file("Panel.qml", b"import QtQuick\n".to_vec(), 0o644),
                TestEntry::file(
                    install::INSTALL_RECEIPT_NAME,
                    br#"{"publisher_persona_id":"forged"}"#.to_vec(),
                    0o644,
                ),
            ],
        );

        let error = archive::inspect_archive(&package).unwrap_err();
        assert!(matches!(error, OmarchyError::UnsafeArchiveEntry { .. }));
    }

    struct Fixture {
        directory: tempfile::TempDir,
        package: PathBuf,
        proof: PathBuf,
        plugins: PathBuf,
        store: PersonaStore,
        persona_id: String,
        private_key: PathBuf,
        public_key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempdir().unwrap();
            let package = directory.path().join("plugin.tar.zst");
            let proof = directory.path().join("plugin.proof.json");
            let plugins = directory.path().join("omarchy/plugins");
            fs::create_dir_all(&plugins).unwrap();
            create_archive(
                &package,
                &[
                    TestEntry::file("manifest.json", manifest_bytes("Panel.qml"), 0o644),
                    TestEntry::file("Panel.qml", b"import QtQuick\nItem {}\n".to_vec(), 0o644),
                    TestEntry::file("scripts/helper.sh", b"#!/bin/sh\nexit 0\n".to_vec(), 0o755),
                ],
            );

            let private_key = directory.path().join("publisher_key");
            generate_key(&private_key);
            let public_key_path = private_key.with_extension("pub");
            let public_key = fs::read_to_string(&public_key_path).unwrap();
            let mut store = PersonaStore::open_in_memory().unwrap();
            let persona = store
                .create_persona("Example Publisher", PersonaPurpose::Project)
                .unwrap();
            store
                .enroll_key(&persona.id, &public_key, KeyProvider::OpensshFile)
                .unwrap();
            let bundle =
                create_sshsig_proof(&package, &private_key, &public_key_path, &persona.label)
                    .unwrap();
            write_proof_new(&proof, &bundle).unwrap();

            Self {
                directory,
                package,
                proof,
                plugins,
                store,
                persona_id: persona.id,
                private_key,
                public_key: public_key_path,
            }
        }

        fn target(&self) -> PathBuf {
            self.plugins.join("example.signed-plugin")
        }

        fn install(&self) {
            install::install_with_commands(
                &self.package,
                &self.proof,
                &self.store,
                &self.plugins,
                Path::new("/usr/bin/true"),
                Path::new("/usr/bin/true"),
            )
            .unwrap();
        }

        fn release(&self, version: &str, panel: &[u8]) -> (PathBuf, PathBuf) {
            let stem = version.replace(['.', '+', '-'], "_");
            let package = self.directory.path().join(format!("plugin-{stem}.tar.zst"));
            let proof = self
                .directory
                .path()
                .join(format!("plugin-{stem}.proof.json"));
            create_release_archive(&package, version, panel);
            let bundle = create_sshsig_proof(
                &package,
                &self.private_key,
                &self.public_key,
                "Example Publisher",
            )
            .unwrap();
            write_proof_new(&proof, &bundle).unwrap();
            (package, proof)
        }
    }

    enum TestEntry {
        File {
            path: &'static str,
            bytes: Vec<u8>,
            mode: u32,
        },
        Symlink {
            path: &'static str,
            target: &'static str,
        },
    }

    impl TestEntry {
        fn file(path: &'static str, bytes: Vec<u8>, mode: u32) -> Self {
            Self::File { path, bytes, mode }
        }
    }

    fn create_archive(path: &Path, entries: &[TestEntry]) {
        let file = fs::File::create(path).unwrap();
        let encoder = zstd::stream::write::Encoder::new(file, 3).unwrap();
        let mut archive = TarBuilder::new(encoder);
        for entry in entries {
            match entry {
                TestEntry::File { path, bytes, mode } => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Regular);
                    header.set_size(bytes.len() as u64);
                    header.set_mode(*mode);
                    header.set_cksum();
                    archive
                        .append_data(&mut header, path, Cursor::new(bytes))
                        .unwrap();
                }
                TestEntry::Symlink { path, target } => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Symlink);
                    header.set_size(0);
                    header.set_mode(0o777);
                    header.set_link_name(target).unwrap();
                    header.set_cksum();
                    archive.append_data(&mut header, path, io::empty()).unwrap();
                }
            }
        }
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    fn manifest_bytes(panel_path: &str) -> Vec<u8> {
        manifest_bytes_for_version(panel_path, "0.1.0")
    }

    fn manifest_bytes_for_version(panel_path: &str, version: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schemaVersion": 1,
            "id": "example.signed-plugin",
            "name": "Example Signed Plugin",
            "version": version,
            "kinds": ["panel"],
            "entryPoints": { "panel": panel_path }
        }))
        .unwrap()
    }

    fn create_release_archive(path: &Path, version: &str, panel: &[u8]) {
        create_archive(
            path,
            &[
                TestEntry::file(
                    "manifest.json",
                    manifest_bytes_for_version("Panel.qml", version),
                    0o644,
                ),
                TestEntry::file("Panel.qml", panel.to_vec(), 0o644),
                TestEntry::file("scripts/helper.sh", b"#!/bin/sh\nexit 0\n".to_vec(), 0o755),
            ],
        );
    }

    fn generate_key(path: &Path) {
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
