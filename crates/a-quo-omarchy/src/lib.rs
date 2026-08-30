//! Guarded inspection and installation of signed Omarchy plugin packages.
//!
//! A valid package signature is publisher evidence, not a safety verdict.

mod archive;
#[cfg(all(test, target_os = "linux"))]
mod corpus_tests;
mod install;
mod model;
pub mod risk;

#[cfg(target_os = "linux")]
use std::fs::File;
use std::path::{Path, PathBuf};

use a_quo_core::{ProofBundle, ProofError, load_proof, verify_sshsig_proof};
#[cfg(target_os = "linux")]
use a_quo_core::{describe_open_artifact, verify_sshsig_proof_for_descriptor};
use a_quo_store::{KeyStatus, PersonaAuthorityDisposition, PersonaStore, StoreError};
use thiserror::Error;

pub use install::{install_signed_package, uninstall_managed_plugin, update_signed_package};
pub use model::{
    ArchiveReport, InstallOutcome, OmarchyManifest, PluginInspection, PublisherEvidence,
    PublisherRegistryStatus, UninstallOutcome, UpdateOutcome,
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

    #[cfg(target_os = "linux")]
    #[error("cannot create immutable package snapshot: {0}")]
    PackageSnapshot(#[from] a_quo_ipc::LinuxIpcError),

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

    #[error(
        "publisher key is evidence-only/quarantined imported continuity evidence, not installation authority: {0}"
    )]
    EvidenceOnlyPublisher(String),

    #[error("publisher persona is archived and cannot authorize installation: {0}")]
    ArchivedPublisher(String),

    #[error("publisher persona is permanently deauthorized and cannot authorize installation: {0}")]
    TerminalPublisher(String),

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

    #[error("Omarchy plugins directory does not exist: {0}")]
    PluginsDirectoryMissing(PathBuf),

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

    #[error("plugin update authorization failed before exchange: {cause}; {retained_state}")]
    UpdateAuthorizationRefused {
        #[source]
        cause: Box<OmarchyError>,
        retained_state: String,
    },

    #[error("plugin update authorization finalization failed after exchange: {0}")]
    UpdateAuthorizationFinalizationFailed(String),

    #[error("Omarchy shell rescan failed; the previous plugin was restored: {0}")]
    UpdateRolledBack(String),

    #[error("plugin update rollback needs manual attention: {0}")]
    UpdateRollbackFailed(String),

    #[error("plugin update state needs manual attention: {0}")]
    UpdateStateIndeterminate(String),

    #[error(
        "plugin is referenced by Omarchy configuration and must be unreferenced before removal: {0}"
    )]
    ReferencedPluginRemoval(String),

    #[error("atomic plugin removal failed: {0}")]
    AtomicRemoval(String),

    #[error("Omarchy shell rescan failed; the removed plugin was restored: {0}")]
    RemovalRolledBack(String),

    #[error("plugin removal rollback needs manual attention: {0}")]
    RemovalRollbackFailed(String),

    #[error("plugin removal state needs manual attention: {0}")]
    RemovalStateIndeterminate(String),
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
        a_quo_enablement_action: "not_performed".to_owned(),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn inspect_file_with_proof(
    package: &File,
    proof: &ProofBundle,
    store: Option<&PersonaStore>,
) -> Result<PluginInspection> {
    let descriptor = describe_open_artifact(package)?;
    let artifact_evidence = verify_sshsig_proof_for_descriptor(&descriptor, proof)?;
    let (manifest, archive) = archive::inspect_archive_file(package)?;
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
        a_quo_enablement_action: "not_performed".to_owned(),
    })
}

pub(crate) fn require_installable_publisher(inspection: &PluginInspection) -> Result<()> {
    let fingerprint = &inspection.artifact_evidence.signer.key_fingerprint;
    match inspection.publisher_evidence.registry_status {
        PublisherRegistryStatus::Active => {}
        PublisherRegistryStatus::NotChecked | PublisherRegistryStatus::Unrecognized => {
            return Err(OmarchyError::UnrecognizedPublisher(fingerprint.clone()));
        }
        PublisherRegistryStatus::EvidenceOnly => {
            return Err(OmarchyError::EvidenceOnlyPublisher(fingerprint.clone()));
        }
        PublisherRegistryStatus::Archived => {
            return Err(OmarchyError::ArchivedPublisher(fingerprint.clone()));
        }
        PublisherRegistryStatus::TerminallyRevoked => {
            return Err(OmarchyError::TerminalPublisher(fingerprint.clone()));
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

    let registry_status = match recognized.authority_disposition {
        PersonaAuthorityDisposition::EvidenceOnly => PublisherRegistryStatus::EvidenceOnly,
        PersonaAuthorityDisposition::Archived => PublisherRegistryStatus::Archived,
        PersonaAuthorityDisposition::TerminallyRevoked => {
            PublisherRegistryStatus::TerminallyRevoked
        }
        PersonaAuthorityDisposition::Operational => match recognized.key.status {
            KeyStatus::Active => PublisherRegistryStatus::Active,
            KeyStatus::Retired => PublisherRegistryStatus::Retired,
            KeyStatus::Compromised => PublisherRegistryStatus::Compromised,
        },
    };
    Ok(PublisherEvidence {
        registry_status,
        local_label: Some(recognized.persona.label.clone()),
        local_purpose: Some(recognized.persona.purpose),
        signed_label_agreement: Some(recognized.persona.label == signed_label),
        key_status: Some(recognized.key.status),
        meaning: match recognized.authority_disposition {
            PersonaAuthorityDisposition::Operational => {
                "local metadata only; legal identity, review, and runtime safety are not established"
                    .to_owned()
            }
            PersonaAuthorityDisposition::Archived => {
                "archived local publisher metadata only; current publisher authorization, review, and runtime safety are not established"
                    .to_owned()
            }
            PersonaAuthorityDisposition::TerminallyRevoked => {
                "terminal persona evidence: this publisher is permanently deauthorized locally; historical signature validity does not authorize installation"
                    .to_owned()
            }
            PersonaAuthorityDisposition::EvidenceOnly => {
                "imported continuity evidence only; current publisher authorization, non-revocation, review, and runtime safety are not established"
                    .to_owned()
            }
        },
    })
}

#[cfg(all(test, unix))]
mod tests {
    #[cfg(target_os = "linux")]
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{self, Cursor};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(target_os = "linux")]
    use a_quo_core::describe_artifact;
    use a_quo_core::{
        PersonaContinuityCheckpoint, RecoveryContinuityCheckpoint, RecoveryPolicyCapability,
        RecoverySigner, TerminalPersonaRevocationProof, TerminalPersonaRevocationReason,
        create_initial_recovery_policy_proof, create_persona_root_proof, create_sshsig_proof,
        create_terminal_persona_revocation_proof,
        new_initial_recovery_policy_statement_with_capabilities, new_persona_root_statement,
        new_terminal_persona_revocation_statement, public_key_fingerprint,
        verify_initial_recovery_policy_proof, verify_persona_root_proof, write_proof_new,
    };
    use a_quo_store::{
        BackupContinuityArchive, BackupPersonaRootEvidence, KeyProvider, PERSONA_BACKUP_V1_SCHEMA,
        PersonaPurpose, PersonaStore, RotationReason,
    };
    use serde_json::json;
    use tar::{Builder as TarBuilder, EntryType, Header};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn inspects_valid_package_without_a_safety_or_enablement_claim() {
        let fixture = Fixture::new();
        let inspection =
            inspect_signed_package(&fixture.package, &fixture.proof, Some(&fixture.store)).unwrap();

        assert_eq!(inspection.manifest.id, "example.signed-plugin");
        assert_eq!(
            inspection.publisher_evidence.registry_status,
            PublisherRegistryStatus::Active
        );
        assert_eq!(inspection.runtime_safety, "not_evaluated");
        assert_eq!(inspection.a_quo_enablement_action, "not_performed");
        assert_eq!(
            inspection.archive.executable_files,
            vec!["scripts/helper.sh".to_owned()]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installs_valid_package_without_an_enablement_action() {
        let mut fixture = Fixture::new();
        let outcome = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap();
        assert_eq!(outcome.a_quo_enablement_action, "not_performed");
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
        let mut empty_store = PersonaStore::open_in_memory().unwrap();

        let error = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &mut empty_store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UnrecognizedPublisher(_)));
        assert!(!fixture.plugins.join("example.signed-plugin").exists());
    }

    #[test]
    fn terminally_revoked_publisher_is_historically_inspectable_but_cannot_install() {
        let mut fixture = Fixture::new();
        fixture.terminally_revoke(TerminalPersonaRevocationReason::Cessation);

        let inspection =
            inspect_signed_package(&fixture.package, &fixture.proof, Some(&fixture.store)).unwrap();

        assert_eq!(
            inspection.artifact_evidence.signature,
            a_quo_core::EvidenceStatus::Verified
        );
        assert_eq!(
            inspection.publisher_evidence.registry_status,
            PublisherRegistryStatus::TerminallyRevoked
        );
        assert_eq!(
            serde_json::to_value(&inspection).unwrap()["publisher_evidence"]["registry_status"],
            "terminally_revoked"
        );
        assert_eq!(
            inspection.publisher_evidence.key_status,
            Some(KeyStatus::Retired)
        );
        assert!(
            inspection
                .publisher_evidence
                .meaning
                .contains("historical signature validity does not authorize installation")
        );
        assert!(matches!(
            require_installable_publisher(&inspection),
            Err(OmarchyError::TerminalPublisher(_))
        ));

        let files_before = regular_file_bytes(&fixture.plugins);
        let install_error = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();
        assert!(matches!(install_error, OmarchyError::TerminalPublisher(_)));
        assert_eq!(regular_file_bytes(&fixture.plugins), files_before);
        assert!(!fixture.target().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminally_revoked_publisher_cannot_update_installed_bytes() {
        let mut fixture = Fixture::new();
        fixture.install();
        let (package, proof) = fixture.release(
            "0.2.0",
            b"import QtQuick\nItem { property int terminal: 1 }\n",
        );
        let installed_before = regular_file_bytes(&fixture.target());
        fixture.terminally_revoke(TerminalPersonaRevocationReason::Cessation);

        let update_error = install::update_with_commands(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();

        assert!(matches!(update_error, OmarchyError::TerminalPublisher(_)));
        assert_eq!(regular_file_bytes(&fixture.target()), installed_before);
        let staging = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained refused update staging")
            .path();
        assert!(staging.join("package.tar.zst").is_file());
        assert!(!staging.join("plugin").exists());
    }

    #[test]
    fn evidence_only_publisher_is_inspectable_but_cannot_install_or_update() {
        let mut fixture = Fixture::new();
        let mut evidence_store = fixture.evidence_only_store();

        let inspection =
            inspect_signed_package(&fixture.package, &fixture.proof, Some(&evidence_store))
                .unwrap();
        assert_eq!(
            inspection.artifact_evidence.signature,
            a_quo_core::EvidenceStatus::Verified
        );
        assert_eq!(
            inspection.publisher_evidence.registry_status,
            PublisherRegistryStatus::EvidenceOnly
        );
        assert_eq!(
            serde_json::to_value(&inspection).unwrap()["publisher_evidence"]["registry_status"],
            "evidence_only"
        );
        assert_eq!(
            inspection.publisher_evidence.key_status,
            Some(KeyStatus::Active)
        );
        assert!(
            inspection
                .publisher_evidence
                .meaning
                .contains("imported continuity evidence only")
        );
        let defensive_error =
            install::publisher_persona_id(&evidence_store, &inspection).unwrap_err();
        assert!(matches!(
            defensive_error,
            OmarchyError::EvidenceOnlyPublisher(_)
        ));

        let install_error = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &mut evidence_store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();
        assert!(matches!(
            install_error,
            OmarchyError::EvidenceOnlyPublisher(_)
        ));
        assert!(!fixture.target().exists());

        #[cfg(target_os = "linux")]
        {
            fixture.install();
            let (package, proof) = fixture.release(
                "0.2.0",
                b"import QtQuick\nItem { property int quarantined: 1 }\n",
            );
            let update_error = install::update_with_commands(
                &package,
                &proof,
                &mut evidence_store,
                &fixture.plugins,
                Path::new("/usr/bin/true"),
                Path::new("/usr/bin/true"),
            )
            .unwrap_err();
            assert!(matches!(
                update_error,
                OmarchyError::EvidenceOnlyPublisher(_)
            ));
            assert_eq!(
                fs::read(fixture.target().join("Panel.qml")).unwrap(),
                b"import QtQuick\nItem {}\n"
            );
        }
    }

    #[test]
    fn archived_v1_publisher_is_inspectable_but_cannot_install() {
        let mut fixture = Fixture::new();
        let mut archived_store = fixture.archived_v1_store();

        let inspection =
            inspect_signed_package(&fixture.package, &fixture.proof, Some(&archived_store))
                .unwrap();
        assert_eq!(
            inspection.artifact_evidence.signature,
            a_quo_core::EvidenceStatus::Verified
        );
        assert_eq!(
            inspection.publisher_evidence.registry_status,
            PublisherRegistryStatus::Archived
        );
        assert_eq!(
            serde_json::to_value(&inspection).unwrap()["publisher_evidence"]["registry_status"],
            "archived"
        );

        let defensive_error =
            install::publisher_persona_id(&archived_store, &inspection).unwrap_err();
        assert!(matches!(
            defensive_error,
            OmarchyError::ArchivedPublisher(_)
        ));
        let install_error = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &mut archived_store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();
        assert!(matches!(install_error, OmarchyError::ArchivedPublisher(_)));
        assert!(!fixture.target().exists());
    }

    #[test]
    fn final_authorization_guard_blocks_a_publisher_status_race() {
        let mut fixture = Fixture::new();
        let store_path = fixture.store_path.clone();
        let fingerprint =
            public_key_fingerprint(&normalized_public_key(&fixture.public_key)).unwrap();

        let error = install::install_with_commands_and_authorization_hook(
            &fixture.package,
            &fixture.proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let mut concurrent = PersonaStore::open(&store_path)?;
                concurrent.mark_key_compromised(
                    &fingerprint,
                    "race-test",
                    "a-quo:test:publisher-status-race:v1",
                    None,
                )?;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            OmarchyError::InactivePublisher {
                fingerprint: ref rejected,
                status: "inactive",
            } if rejected == &fingerprint
        ));
        assert!(!fixture.target().exists());
    }

    #[test]
    fn final_install_authorization_guard_blocks_terminal_revocation_race() {
        let mut fixture = Fixture::new();
        let prepared =
            fixture.prepare_terminal_revocation(TerminalPersonaRevocationReason::Cessation);
        let store_path = fixture.store_path.clone();
        let persona_id = fixture.persona_id.clone();
        let files_before = regular_file_bytes(&fixture.plugins);

        let error = install::install_with_commands_and_authorization_hook(
            &fixture.package,
            &fixture.proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            move || {
                let mut concurrent = PersonaStore::open(&store_path)?;
                commit_prepared_terminal_revocation(&mut concurrent, &persona_id, &prepared)?;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::TerminalPublisher(_)));
        assert_eq!(regular_file_bytes(&fixture.plugins), files_before);
        assert!(!fixture.target().exists());
        assert_eq!(
            inspect_signed_package(&fixture.package, &fixture.proof, Some(&fixture.store))
                .unwrap()
                .publisher_evidence
                .registry_status,
            PublisherRegistryStatus::TerminallyRevoked
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn final_update_authorization_guard_blocks_terminal_revocation_race() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int raced: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let installed_before = regular_file_bytes(&fixture.target());
        let prepared =
            fixture.prepare_terminal_revocation(TerminalPersonaRevocationReason::Compromise);
        let store_path = fixture.store_path.clone();
        let persona_id = fixture.persona_id.clone();

        let error = install::update_with_commands_and_authorization_hook(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            move || {
                let mut concurrent = PersonaStore::open(&store_path)?;
                commit_prepared_terminal_revocation(&mut concurrent, &persona_id, &prepared)?;
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateAuthorizationRefused {
            cause,
            retained_state,
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert!(matches!(*cause, OmarchyError::TerminalPublisher(_)));
        assert!(retained_state.contains("retained update staging was revalidated at"));
        assert_eq!(regular_file_bytes(&fixture.target()), installed_before);
        let staging = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained unauthorized candidate")
            .path();
        assert_eq!(
            fs::read(staging.join("plugin/Panel.qml")).unwrap(),
            candidate
        );
        assert_eq!(
            inspect_signed_package(&package, &proof, Some(&fixture.store))
                .unwrap()
                .publisher_evidence
                .registry_status,
            PublisherRegistryStatus::TerminallyRevoked
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_restores_prior_release_after_authorization_finalization_failure() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let rescans = Cell::new(0_u8);

        let error = install::update_with_rescan_and_authorization_finalization_hook(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                Err(OmarchyError::AtomicUpdate(
                    "simulated authorization finalization failure".to_owned(),
                ))
            },
            || {
                rescans.set(rescans.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateAuthorizationFinalizationFailed(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(message.contains("simulated authorization finalization failure"));
        assert!(message.contains("exact prior release was restored and revalidated"));
        assert!(message.contains("rejected candidate remains at"));
        assert_eq!(rescans.get(), 1);
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        let recovery = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained rejected candidate")
            .path();
        assert_eq!(
            fs::read(recovery.join("plugin/Panel.qml")).unwrap(),
            candidate
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_omarchy_validator_accepts_fixture_when_available() {
        let validator = Path::new("/usr/bin/omarchy-plugin-validate");
        if !validator.is_file() {
            return;
        }
        let mut fixture = Fixture::new();

        let outcome = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &mut fixture.store,
            &fixture.plugins,
            validator,
            Path::new("/usr/bin/true"),
        )
        .unwrap();

        assert_eq!(outcome.a_quo_enablement_action, "not_performed");
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
            &mut fixture.store,
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
        let mut fixture = Fixture::new();
        fs::write(
            fixture.directory.path().join("omarchy/shell.json"),
            br#"{"version":1,"plugins":[{"id":"example.signed-plugin"}]}"#,
        )
        .unwrap();

        let error = install::install_with_commands(
            &fixture.package,
            &fixture.proof,
            &mut fixture.store,
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
    fn final_install_configuration_guard_blocks_a_new_plugin_reference() {
        let mut fixture = Fixture::new();
        let shell_configuration = fixture.directory.path().join("omarchy/shell.json");

        let error = install::install_with_commands_and_authorization_hook(
            &fixture.package,
            &fixture.proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            move || {
                fs::write(
                    shell_configuration,
                    br#"{"version":1,"plugins":[{"id":"example.signed-plugin"}]}"#,
                )
                .expect("write concurrent Omarchy plugin reference");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            OmarchyError::StaleEnabledConfiguration(ref id) if id == "example.signed-plugin"
        ));
        assert!(!fixture.target().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_requires_newer_version_and_preserves_old_files_on_refusal() {
        let mut fixture = Fixture::new();
        fixture.install();
        let (package, proof) =
            fixture.release("0.1.0", b"import QtQuick\nItem { property int v: 2 }\n");

        let error = install::update_with_commands(
            &package,
            &proof,
            &mut fixture.store,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn update_atomically_replaces_a_managed_plugin() {
        let mut fixture = Fixture::new();
        fixture.install();
        let new_panel = b"import QtQuick\nItem { property int v: 2 }\n";
        let (package, proof) = fixture.release("0.2.0", new_panel);

        let outcome = install::update_with_commands(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap();

        assert_eq!(outcome.previous_version, "0.1.0");
        assert_eq!(outcome.version, "0.2.0");
        assert_eq!(outcome.publisher_continuity, "same_local_persona");
        assert_eq!(
            outcome.omarchy_manifest_validation,
            "passed_path_observation_not_continuous"
        );
        assert!(outcome.atomic_exchange);
        assert!(outcome.recovery_retained);
        assert_eq!(outcome.disk_purge, "not_performed");
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            new_panel
        );
        assert_eq!(
            fs::read(outcome.previous_release_recovery.join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        let recovered_manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(outcome.previous_release_recovery.join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(recovered_manifest["version"], "0.1.0");
        assert!(
            outcome
                .previous_release_recovery
                .join(".a-quo-install.json")
                .is_file()
        );
        assert_eq!(
            fs::read_dir(&fixture.plugins).unwrap().count(),
            2,
            "the exact prior release must remain in one retained recovery directory"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_uses_one_sealed_signed_archive_after_staged_path_substitution() {
        let mut fixture = Fixture::new();
        fixture.install();
        let signed_panel = b"import QtQuick\nItem { property int marker: 000000 }\n";
        let (package, proof) = fixture.release("0.2.0", signed_panel);
        let forged_package = fixture.directory.path().join("forged-v2.tar.zst");
        let signed_compressed_size = fs::metadata(&package).unwrap().len();
        let forged_panel = (1..=999_999)
            .find_map(|marker| {
                let panel =
                    format!("import QtQuick\nItem {{ property int marker: {marker:06} }}\n")
                        .into_bytes();
                create_release_archive(&forged_package, "0.2.0", &panel);
                (fs::metadata(&forged_package).unwrap().len() == signed_compressed_size)
                    .then_some(panel)
            })
            .expect("construct a distinct same-size compressed replacement fixture");
        assert_ne!(forged_panel.as_slice(), signed_panel);
        assert_eq!(
            fs::metadata(&package).unwrap().len(),
            fs::metadata(&forged_package).unwrap().len(),
            "the regression fixture must preserve the old inspection-report shape"
        );
        let signed_descriptor = describe_artifact(&package).unwrap();
        let forged_descriptor = describe_artifact(&forged_package).unwrap();
        assert_ne!(
            signed_descriptor.digest.value,
            forged_descriptor.digest.value
        );

        let outcome = install::update_with_rescan_and_staged_package_hook(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            |staged_package| {
                fs::rename(&forged_package, staged_package).map_err(|source| OmarchyError::Io {
                    path: staged_package.to_path_buf(),
                    source,
                })
            },
            || Ok(()),
        )
        .unwrap();

        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            signed_panel
        );
        let receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(fixture.target().join(install::INSTALL_RECEIPT_NAME)).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["package_sha256"], signed_descriptor.digest.value);
        assert_ne!(receipt["package_sha256"], forged_descriptor.digest.value);
        assert_eq!(
            describe_artifact(
                outcome
                    .previous_release_recovery
                    .parent()
                    .unwrap()
                    .join("package.tar.zst")
            )
            .unwrap()
            .digest
            .value,
            forged_descriptor.digest.value,
            "the mutable staging pathname really was replaced after inspection"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_early_error_never_deletes_a_replacement_staging_path() {
        let mut fixture = Fixture::new();
        fixture.install();
        let (package, proof) = fixture.release(
            "0.2.0",
            b"import QtQuick\nItem { property int candidate: 1 }\n",
        );
        let displaced = fixture.directory.path().join("displaced-update-staging");
        let replacement = RefCell::new(None::<PathBuf>);

        let error = install::update_with_rescan_and_staged_package_hook(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            |staged_package| {
                let staging = staged_package.parent().unwrap();
                fs::rename(staging, &displaced).unwrap();
                fs::create_dir(staging).unwrap();
                fs::write(staging.join("replacement-marker"), b"must survive\n").unwrap();
                replacement.replace(Some(staging.to_path_buf()));
                Err(OmarchyError::AtomicUpdate(
                    "simulated early update refusal".to_owned(),
                ))
            },
            || Ok(()),
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::AtomicUpdate(_)));
        let replacement = replacement.into_inner().unwrap();
        assert_eq!(
            fs::read(replacement.join("replacement-marker")).unwrap(),
            b"must survive\n"
        );
        assert!(displaced.join("package.tar.zst").is_file());
    }

    #[cfg(target_os = "linux")]
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
            &mut fixture.store,
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

    #[cfg(target_os = "linux")]
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
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
        )
        .unwrap();

        assert_eq!(outcome.publisher_continuity, "same_local_persona");
        assert_eq!(outcome.version, "0.2.0");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_rolls_back_exact_old_directory_when_rescan_fails() {
        let mut fixture = Fixture::new();
        fixture.install();
        let (package, proof) = fixture.release(
            "0.2.0",
            b"import QtQuick\nItem { property int candidate: 1 }\n",
        );
        let calls = Cell::new(0_u8);

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
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
        let recoveries = retained_update_recoveries(&fixture.plugins);
        assert_eq!(recoveries.len(), 1);
        assert_eq!(
            fs::read(recoveries[0].path().join("plugin/Panel.qml")).unwrap(),
            b"import QtQuick\nItem { property int candidate: 1 }\n"
        );
        assert!(
            recoveries[0]
                .path()
                .join("plugin/.a-quo-install.json")
                .is_file()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_rollback_failure_retains_the_exact_prior_release() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let plugins = fixture.plugins.clone();
        let moved_prior = RefCell::new(None::<PathBuf>);

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let recovery = retained_update_recoveries(&plugins)
                    .pop()
                    .expect("retained update recovery")
                    .path();
                let moved = recovery.join("moved-prior-release");
                fs::rename(recovery.join("plugin"), &moved)
                    .expect("move prior release before rollback exchange");
                moved_prior.replace(Some(moved));
                Err("simulated first rescan failure".to_owned())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UpdateRollbackFailed(_)));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            candidate
        );
        let prior = moved_prior.borrow();
        let prior = prior.as_ref().unwrap();
        assert_eq!(
            fs::read(prior.join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        assert!(prior.join(".a-quo-install.json").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_panic_after_first_exchange_retains_the_prior_release() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = install::update_with_rescan(
                &package,
                &proof,
                &mut fixture.store,
                &fixture.plugins,
                Path::new("/usr/bin/true"),
                Path::new("/usr/bin/true"),
                || panic!("simulated panic after initial update exchange"),
            );
        }));

        assert!(result.is_err());
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            candidate
        );
        let recovery = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained update recovery")
            .path();
        assert_eq!(
            fs::read(recovery.join("plugin/Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        assert!(recovery.join("plugin/.a-quo-install.json").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_second_rescan_failure_retains_old_live_and_candidate_recovery() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let calls = Cell::new(0_u8);

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                calls.set(calls.get() + 1);
                Err(format!("simulated update rescan failure {}", calls.get()))
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UpdateRollbackFailed(_)));
        assert_eq!(calls.get(), 2);
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        let recovery = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained update recovery")
            .path();
        assert_eq!(
            fs::read(recovery.join("plugin/Panel.qml")).unwrap(),
            candidate
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_refuses_a_substituted_candidate_before_exchange_without_deleting_it() {
        let mut fixture = Fixture::new();
        fixture.install();
        let (package, proof) = fixture.release(
            "0.2.0",
            b"import QtQuick\nItem { property int candidate: 1 }\n",
        );
        let plugins = fixture.plugins.clone();
        let displaced_candidate = RefCell::new(None::<PathBuf>);

        let error = install::update_with_commands_and_authorization_hook(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let staging = retained_update_recoveries(&plugins)
                    .pop()
                    .expect("active update staging directory")
                    .path();
                let displaced = staging.join("displaced-candidate");
                fs::rename(staging.join("plugin"), &displaced)
                    .expect("displace validated candidate");
                fs::create_dir(staging.join("plugin")).expect("create replacement candidate");
                fs::write(staging.join("plugin/replacement"), b"replacement\n")
                    .expect("write replacement candidate marker");
                displaced_candidate.replace(Some(displaced));
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UpdateStateIndeterminate(_)));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        assert!(
            displaced_candidate
                .borrow()
                .as_ref()
                .unwrap()
                .join("Panel.qml")
                .is_file()
        );
        let recovery = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained update recovery")
            .path();
        assert_eq!(
            fs::read(recovery.join("plugin/replacement")).unwrap(),
            b"replacement\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_refuses_in_place_candidate_mutation_before_exchange() {
        let mut fixture = Fixture::new();
        fixture.install();
        let (package, proof) = fixture.release(
            "0.2.0",
            b"import QtQuick\nItem { property int candidate: 1 }\n",
        );
        let plugins = fixture.plugins.clone();

        let error = install::update_with_commands_and_authorization_hook(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let staging = retained_update_recoveries(&plugins)
                    .pop()
                    .expect("active update staging directory")
                    .path();
                fs::write(
                    staging.join("plugin/Panel.qml"),
                    b"import QtQuick\nItem { property string changed: 'yes' }\n",
                )
                .expect("mutate validated candidate in place");
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateStateIndeterminate(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(message.contains("staged candidate changed"));
        assert!(message.contains("retained update staging was revalidated at"));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        assert_eq!(retained_update_recoveries(&fixture.plugins).len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_refuses_a_replaced_plugins_root_and_reports_indeterminate_path() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let plugins = fixture.plugins.clone();
        let displaced_plugins = fixture.directory.path().join("displaced-plugins-root");
        let hook_displaced = displaced_plugins.clone();

        let error = install::update_with_commands_and_authorization_hook(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                fs::rename(&plugins, &hook_displaced).expect("displace plugins root");
                fs::create_dir(&plugins).expect("create replacement plugins root");
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateStateIndeterminate(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(message.contains("plugins directory changed after update staging began"));
        assert!(message.contains("pathname is indeterminate"));
        assert_eq!(
            fs::read(displaced_plugins.join("example.signed-plugin/Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        let staging = retained_update_recoveries(&displaced_plugins)
            .pop()
            .expect("retained staging beneath displaced root")
            .path();
        assert_eq!(
            fs::read(staging.join("plugin/Panel.qml")).unwrap(),
            candidate
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_reports_live_candidate_byte_mutation_as_indeterminate() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let target = fixture.target();
        let hook_target = target.clone();

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            move || {
                fs::write(
                    hook_target.join("Panel.qml"),
                    b"import QtQuick\nItem { property string mutated: 'yes' }\n",
                )
                .expect("mutate live candidate bytes");
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateStateIndeterminate(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(message.contains("candidate tree changed"));
        assert!(message.contains("exact prior release was revalidated at"));
        let recovery = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained prior release")
            .path();
        assert_eq!(
            fs::read(recovery.join("plugin/Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_never_calls_a_mutated_prior_recovery_exact() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let plugins = fixture.plugins.clone();

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let recovery = retained_update_recoveries(&plugins)
                    .pop()
                    .expect("retained update recovery")
                    .path();
                fs::write(
                    recovery.join("plugin/Panel.qml"),
                    b"import QtQuick\nItem { property string oldChanged: 'yes' }\n",
                )
                .expect("mutate retained prior release bytes");
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateStateIndeterminate(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(message.contains("prior release tree changed"));
        assert!(message.contains("file tree changed"));
        assert!(!message.contains("exact prior release was revalidated"));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            candidate
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_refuses_rollback_after_prior_tree_mutation() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let plugins = fixture.plugins.clone();

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let recovery = retained_update_recoveries(&plugins)
                    .pop()
                    .expect("retained prior release")
                    .path();
                fs::write(
                    recovery.join("plugin/Panel.qml"),
                    b"import QtQuick\nItem { property string oldChanged: 'yes' }\n",
                )
                .expect("mutate prior tree before rollback");
                Err("simulated rescan failure after prior mutation".to_owned())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateRollbackFailed(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(message.contains("prior release tree changed before rollback"));
        assert!(message.contains("file tree changed"));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            candidate
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_refuses_in_place_installed_tree_mutation_before_exchange() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let target = fixture.target();
        let hook_target = target.clone();

        let error = install::update_with_commands_and_authorization_hook(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            move || {
                fs::write(
                    hook_target.join("Panel.qml"),
                    b"import QtQuick\nItem { property string changed: 'yes' }\n",
                )
                .expect("mutate installed tree in place");
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateStateIndeterminate(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(message.contains("installed release changed before descriptor-relative exchange"));
        assert_eq!(retained_update_recoveries(&fixture.plugins).len(), 1);
        assert_eq!(
            fs::read(target.join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem { property string changed: 'yes' }\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_second_rescan_live_mutation_is_indeterminate() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let target = fixture.target();
        let calls = Cell::new(0_u8);

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    return Err("simulated first rescan failure".to_owned());
                }
                fs::write(
                    target.join("Panel.qml"),
                    b"import QtQuick\nItem { property string restoredChanged: 'yes' }\n",
                )
                .expect("mutate restored live tree during second rescan");
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateStateIndeterminate(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(calls.get(), 2);
        assert!(message.contains("prior release tree changed"));
        assert!(!message.contains("exact prior release was revalidated"));
        let recovery = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained rejected candidate")
            .path();
        assert_eq!(
            fs::read(recovery.join("plugin/Panel.qml")).unwrap(),
            candidate
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_success_rejects_relaxed_recovery_root_permissions() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let plugins = fixture.plugins.clone();

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let recovery = retained_update_recoveries(&plugins)
                    .pop()
                    .expect("retained prior release")
                    .path();
                fs::set_permissions(&recovery, fs::Permissions::from_mode(0o755))
                    .expect("relax recovery-root permissions");
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateStateIndeterminate(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(message.contains("recovery directory is no longer mode 0700"));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            candidate
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_rollback_rescan_rejects_relaxed_recovery_root_permissions() {
        let mut fixture = Fixture::new();
        fixture.install();
        let (package, proof) = fixture.release(
            "0.2.0",
            b"import QtQuick\nItem { property int candidate: 1 }\n",
        );
        let plugins = fixture.plugins.clone();
        let calls = Cell::new(0_u8);

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    return Err("simulated first rescan failure".to_owned());
                }
                let recovery = retained_update_recoveries(&plugins)
                    .pop()
                    .expect("retained rejected candidate")
                    .path();
                fs::set_permissions(&recovery, fs::Permissions::from_mode(0o755))
                    .expect("relax rollback recovery-root permissions");
                Ok(())
            },
        )
        .unwrap_err();

        let OmarchyError::UpdateStateIndeterminate(message) = error else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(calls.get(), 2);
        assert!(message.contains("recovery directory is no longer mode 0700"));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_never_rolls_back_a_replacement_live_target() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let target = fixture.target();
        let displaced_candidate = fixture.plugins.join("displaced-live-candidate");
        let hook_target = target.clone();
        let hook_displaced = displaced_candidate.clone();

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            move || {
                fs::rename(&hook_target, &hook_displaced).expect("displace live candidate");
                fs::create_dir(&hook_target).expect("create replacement live target");
                fs::write(hook_target.join("replacement"), b"replacement\n")
                    .expect("write replacement live target");
                Err("simulated first rescan failure after target replacement".to_owned())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UpdateRollbackFailed(_)));
        assert_eq!(
            fs::read(displaced_candidate.join("Panel.qml")).unwrap(),
            candidate
        );
        assert_eq!(
            fs::read(target.join("replacement")).unwrap(),
            b"replacement\n"
        );
        let recovery = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained prior release")
            .path();
        assert_eq!(
            fs::read(recovery.join("plugin/Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_reports_a_renamed_recovery_root_instead_of_success() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let plugins = fixture.plugins.clone();
        let moved_recovery = fixture.plugins.join("moved-update-recovery");
        let hook_moved_recovery = moved_recovery.clone();

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            || {
                let recovery = retained_update_recoveries(&plugins)
                    .pop()
                    .expect("retained update recovery")
                    .path();
                fs::rename(recovery, &hook_moved_recovery).expect("rename update recovery root");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UpdateStateIndeterminate(_)));
        assert_eq!(
            fs::read(fixture.target().join("Panel.qml")).unwrap(),
            candidate
        );
        assert_eq!(
            fs::read(moved_recovery.join("plugin/Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_reports_a_post_rescan_live_swap_instead_of_success() {
        let mut fixture = Fixture::new();
        fixture.install();
        let candidate = b"import QtQuick\nItem { property int candidate: 1 }\n";
        let (package, proof) = fixture.release("0.2.0", candidate);
        let target = fixture.target();
        let displaced_candidate = fixture.plugins.join("post-rescan-candidate");
        let hook_target = target.clone();
        let hook_displaced = displaced_candidate.clone();

        let error = install::update_with_rescan(
            &package,
            &proof,
            &mut fixture.store,
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            Path::new("/usr/bin/true"),
            move || {
                fs::rename(&hook_target, &hook_displaced).expect("displace live candidate");
                fs::create_dir(&hook_target).expect("create replacement live target");
                fs::write(hook_target.join("replacement"), b"replacement\n")
                    .expect("write replacement live target");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::UpdateStateIndeterminate(_)));
        assert_eq!(
            fs::read(displaced_candidate.join("Panel.qml")).unwrap(),
            candidate
        );
        assert_eq!(
            fs::read(target.join("replacement")).unwrap(),
            b"replacement\n"
        );
        let recovery = retained_update_recoveries(&fixture.plugins)
            .pop()
            .expect("retained prior release")
            .path();
        assert_eq!(
            fs::read(recovery.join("plugin/Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_atomically_quarantines_an_unreferenced_managed_plugin() {
        let mut fixture = Fixture::new();
        fixture.install();

        let outcome = install::uninstall_with_commands(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
        )
        .unwrap();

        assert_eq!(outcome.plugin_id, "example.signed-plugin");
        assert_eq!(outcome.version, "0.1.0");
        assert_eq!(
            outcome.observed_reference_state,
            "unreferenced_before_atomic_quarantine"
        );
        assert!(outcome.atomic_quarantine);
        assert_eq!(outcome.shell_rescan, "passed");
        assert_eq!(outcome.disk_purge, "not_performed");
        assert_eq!(outcome.a_quo_enablement_action, "not_performed");
        assert_eq!(outcome.runtime_safety, "not_evaluated");
        assert!(!fixture.target().exists());
        assert_eq!(
            outcome.recovery_quarantine.parent(),
            Some(fixture.plugins.as_path())
        );
        assert!(
            outcome
                .recovery_quarantine
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".a-quo-remove-")
        );
        assert_eq!(
            fs::read(outcome.recovery_quarantine.join("plugin/Panel.qml")).unwrap(),
            b"import QtQuick\nItem {}\n"
        );
        assert_eq!(fs::read_dir(&fixture.plugins).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_does_not_create_a_missing_plugins_directory() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("missing/plugins");

        let error = install::uninstall_with_commands(
            "example.signed-plugin",
            &missing,
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();

        assert!(
            matches!(error, OmarchyError::PluginsDirectoryMissing(ref path) if path == &missing)
        );
        assert!(!missing.exists());
        assert!(!directory.path().join("missing").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_refuses_a_referenced_plugin_without_changing_it() {
        let mut fixture = Fixture::new();
        fixture.install();
        let installed_before = regular_file_bytes(&fixture.target());
        fs::write(
            fixture.directory.path().join("omarchy/shell.json"),
            br#"{"version":1,"plugins":[{"id":"example.signed-plugin"}]}"#,
        )
        .unwrap();

        let error = install::uninstall_with_commands(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            OmarchyError::ReferencedPluginRemoval(ref id) if id == "example.signed-plugin"
        ));
        assert_eq!(regular_file_bytes(&fixture.target()), installed_before);
        assert_eq!(fs::read_dir(&fixture.plugins).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn final_uninstall_configuration_guard_blocks_a_new_plugin_reference() {
        let mut fixture = Fixture::new();
        fixture.install();
        let installed_before = regular_file_bytes(&fixture.target());
        let shell_configuration = fixture.directory.path().join("omarchy/shell.json");

        let error = install::uninstall_with_commands_and_quarantine_hook(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            move || {
                fs::write(
                    shell_configuration,
                    br#"{"version":1,"plugins":[{"id":"example.signed-plugin"}]}"#,
                )
                .expect("write concurrent Omarchy plugin reference");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            OmarchyError::ReferencedPluginRemoval(ref id) if id == "example.signed-plugin"
        ));
        assert_eq!(regular_file_bytes(&fixture.target()), installed_before);
        assert_eq!(fs::read_dir(&fixture.plugins).unwrap().count(), 2);
        let quarantines = retained_removal_quarantines(&fixture.plugins);
        assert_eq!(quarantines.len(), 1);
        assert_eq!(fs::read_dir(quarantines[0].path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn final_uninstall_identity_guard_preserves_both_paths_after_a_target_swap() {
        let mut fixture = Fixture::new();
        fixture.install();
        let target = fixture.target();
        let displaced = fixture.plugins.join("displaced-original");
        let hook_target = target.clone();
        let hook_displaced = displaced.clone();

        let error = install::uninstall_with_commands_and_quarantine_hook(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            move || {
                fs::rename(&hook_target, &hook_displaced).expect("displace original target");
                fs::create_dir(&hook_target).expect("create substituted target");
                fs::write(hook_target.join("replacement"), b"replacement\n")
                    .expect("write substituted target marker");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::AtomicRemoval(_)));
        assert!(displaced.join("Panel.qml").is_file());
        assert_eq!(
            fs::read(target.join("replacement")).unwrap(),
            b"replacement\n"
        );
        assert_eq!(fs::read_dir(&fixture.plugins).unwrap().count(), 3);
        let quarantines = retained_removal_quarantines(&fixture.plugins);
        assert_eq!(quarantines.len(), 1);
        assert_eq!(fs::read_dir(quarantines[0].path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pre_quarantine_failure_never_cleans_a_substituted_path() {
        let mut fixture = Fixture::new();
        fixture.install();
        let plugins = fixture.plugins.clone();
        let displaced = fixture.plugins.join("displaced-recovery-quarantine");
        let hook_displaced = displaced.clone();

        let error = install::uninstall_with_commands_and_quarantine_hook(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            move || {
                let quarantine = retained_removal_quarantines(&plugins)
                    .pop()
                    .expect("retained recovery quarantine")
                    .path();
                fs::rename(&quarantine, &hook_displaced)
                    .expect("displace recovery-quarantine path");
                fs::create_dir(&quarantine).expect("create substituted quarantine path");
                fs::write(quarantine.join("must-survive"), b"replacement\n")
                    .expect("write replacement marker");
                Err(OmarchyError::AtomicRemoval(
                    "simulated pre-quarantine failure".to_owned(),
                ))
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::AtomicRemoval(_)));
        assert!(fixture.target().join("Panel.qml").is_file());
        assert!(displaced.is_dir());
        let replacement = retained_removal_quarantines(&fixture.plugins)
            .pop()
            .expect("substituted quarantine path was not deleted")
            .path();
        assert_eq!(
            fs::read(replacement.join("must-survive")).unwrap(),
            b"replacement\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_rolls_back_the_exact_directory_when_rescan_fails() {
        let mut fixture = Fixture::new();
        fixture.install();
        let installed_before = regular_file_bytes(&fixture.target());
        let calls = Cell::new(0_u8);

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call == 0 {
                    Err("simulated removal rescan failure".to_owned())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalRolledBack(_)));
        assert_eq!(calls.get(), 2);
        assert_eq!(regular_file_bytes(&fixture.target()), installed_before);
        assert_eq!(fs::read_dir(&fixture.plugins).unwrap().count(), 2);
        assert_eq!(retained_removal_quarantines(&fixture.plugins).len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rollback_reports_indeterminate_if_the_quarantine_path_was_renamed() {
        let mut fixture = Fixture::new();
        fixture.install();
        let installed_before = regular_file_bytes(&fixture.target());
        let plugins = fixture.plugins.clone();
        let moved = fixture.plugins.join("moved-rollback-quarantine");
        let hook_moved = moved.clone();
        let calls = Cell::new(0_u8);

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call == 0 {
                    let quarantine = retained_removal_quarantines(&plugins)
                        .pop()
                        .expect("retained recovery quarantine")
                        .path();
                    fs::rename(quarantine, &hook_moved)
                        .expect("rename recovery quarantine during failed rescan");
                    Err("simulated first rescan failure".to_owned())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalStateIndeterminate(_)));
        assert_eq!(calls.get(), 2);
        assert_eq!(regular_file_bytes(&fixture.target()), installed_before);
        assert_eq!(fs::read_dir(moved).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rollback_never_reports_restored_after_a_second_rescan_target_swap() {
        let mut fixture = Fixture::new();
        fixture.install();
        let target = fixture.target();
        let displaced = fixture.plugins.join("displaced-restored-plugin");
        let hook_target = target.clone();
        let hook_displaced = displaced.clone();
        let calls = Cell::new(0_u8);

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call == 0 {
                    Err("simulated first rescan failure".to_owned())
                } else {
                    fs::rename(&hook_target, &hook_displaced)
                        .expect("displace exact restored target");
                    fs::create_dir(&hook_target).expect("create replacement live target");
                    fs::write(hook_target.join("replacement"), b"replacement\n")
                        .expect("write replacement live target");
                    Ok(())
                }
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalStateIndeterminate(_)));
        assert_eq!(calls.get(), 2);
        assert!(displaced.join("Panel.qml").is_file());
        assert_eq!(
            fs::read(target.join("replacement")).unwrap(),
            b"replacement\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_reports_manual_attention_when_the_restore_rescan_also_fails() {
        let mut fixture = Fixture::new();
        fixture.install();
        let installed_before = regular_file_bytes(&fixture.target());
        let calls = Cell::new(0_u8);

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                calls.set(calls.get() + 1);
                Err(format!("simulated rescan failure {}", calls.get()))
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalRollbackFailed(_)));
        assert_eq!(calls.get(), 2);
        assert_eq!(regular_file_bytes(&fixture.target()), installed_before);
        assert_eq!(fs::read_dir(&fixture.plugins).unwrap().count(), 2);
        assert_eq!(retained_removal_quarantines(&fixture.plugins).len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_retains_quarantine_when_exact_restore_is_blocked() {
        let mut fixture = Fixture::new();
        fixture.install();
        let target = fixture.target();

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                fs::create_dir(&target)
                    .expect("replace quarantined target with a conflicting path");
                fs::write(target.join("conflict"), b"do not overwrite\n")
                    .expect("write conflicting target");
                Err("simulated removal rescan failure".to_owned())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalRollbackFailed(_)));
        assert_eq!(
            fs::read(fixture.target().join("conflict")).unwrap(),
            b"do not overwrite\n"
        );
        let quarantine_directories = retained_removal_quarantines(&fixture.plugins);
        assert_eq!(quarantine_directories.len(), 1);
        assert!(
            quarantine_directories[0]
                .path()
                .join("plugin/Panel.qml")
                .is_file()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restore_failure_never_reports_a_stale_external_quarantine_path() {
        let mut fixture = Fixture::new();
        fixture.install();
        let original_plugins = fixture.plugins.clone();
        let moved_plugins = fixture.directory.path().join("omarchy/moved-plugins");
        let hook_moved_plugins = moved_plugins.clone();
        let recovery_path = RefCell::new(None::<PathBuf>);

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                let quarantine = retained_removal_quarantines(&original_plugins)
                    .pop()
                    .expect("retained recovery quarantine")
                    .path();
                let quarantine_name = quarantine.file_name().unwrap().to_owned();
                fs::rename(&original_plugins, &hook_moved_plugins)
                    .expect("rename the pinned plugins root");
                fs::create_dir(&original_plugins).expect("replace the external plugins root");
                let collision = hook_moved_plugins.join("example.signed-plugin");
                fs::create_dir(&collision).expect("block exact descriptor-relative restore");
                fs::write(collision.join("conflict"), b"conflict\n")
                    .expect("write restore collision");
                recovery_path.replace(Some(hook_moved_plugins.join(quarantine_name)));
                Err("simulated rescan failure after plugins-root replacement".to_owned())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalRollbackFailed(_)));
        assert!(error.to_string().contains("reported pathname changed"));
        assert!(
            recovery_path
                .borrow()
                .as_ref()
                .unwrap()
                .join("plugin/Panel.qml")
                .is_file()
        );
        assert_eq!(
            fs::read(moved_plugins.join("example.signed-plugin").join("conflict")).unwrap(),
            b"conflict\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_never_restores_a_replaced_quarantine_child() {
        let mut fixture = Fixture::new();
        fixture.install();
        let plugins = fixture.plugins.clone();

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                let quarantine = retained_removal_quarantines(&plugins)
                    .pop()
                    .expect("retained recovery quarantine")
                    .path();
                fs::rename(quarantine.join("plugin"), quarantine.join("moved-original"))
                    .expect("move pinned plugin within quarantine");
                fs::create_dir(quarantine.join("plugin"))
                    .expect("create replacement quarantine child");
                fs::write(quarantine.join("plugin/replacement"), b"replacement\n")
                    .expect("write replacement quarantine child");
                Err("simulated rescan failure after quarantine replacement".to_owned())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalRollbackFailed(_)));
        assert!(!fixture.target().exists());
        let quarantine = retained_removal_quarantines(&fixture.plugins)
            .pop()
            .unwrap()
            .path();
        assert!(quarantine.join("moved-original/Panel.qml").is_file());
        assert_eq!(
            fs::read(quarantine.join("plugin/replacement")).unwrap(),
            b"replacement\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_reports_a_renamed_quarantine_instead_of_a_false_success() {
        let mut fixture = Fixture::new();
        fixture.install();
        let plugins = fixture.plugins.clone();
        let moved_path = RefCell::new(None::<PathBuf>);

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                let quarantine = retained_removal_quarantines(&plugins)
                    .pop()
                    .expect("retained recovery quarantine")
                    .path();
                let moved = plugins.join("moved-recovery-quarantine");
                fs::rename(&quarantine, &moved).expect("rename recovery quarantine");
                moved_path.replace(Some(moved));
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalStateIndeterminate(_)));
        assert!(!fixture.target().exists());
        assert!(
            moved_path
                .borrow()
                .as_ref()
                .unwrap()
                .join("plugin/Panel.qml")
                .is_file()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_reports_a_new_live_target_instead_of_a_false_success() {
        let mut fixture = Fixture::new();
        fixture.install();
        let target = fixture.target();
        let hook_target = target.clone();

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            move || {
                fs::create_dir(&hook_target).expect("create replacement live target");
                fs::write(hook_target.join("replacement"), b"replacement\n")
                    .expect("write replacement live target");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalStateIndeterminate(_)));
        assert_eq!(
            fs::read(target.join("replacement")).unwrap(),
            b"replacement\n"
        );
        let quarantine = retained_removal_quarantines(&fixture.plugins)
            .pop()
            .expect("retained recovery quarantine")
            .path();
        assert!(quarantine.join("plugin/Panel.qml").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_reports_relaxed_quarantine_permissions_as_indeterminate() {
        let mut fixture = Fixture::new();
        fixture.install();
        let plugins = fixture.plugins.clone();

        let error = install::uninstall_with_rescan(
            "example.signed-plugin",
            &fixture.plugins,
            Path::new("/usr/bin/true"),
            || {
                let quarantine = retained_removal_quarantines(&plugins)
                    .pop()
                    .expect("retained recovery quarantine")
                    .path();
                fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o755))
                    .expect("relax recovery-quarantine permissions");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::RemovalStateIndeterminate(_)));
        assert!(!fixture.target().exists());
        let quarantine = retained_removal_quarantines(&fixture.plugins)
            .pop()
            .expect("retained recovery quarantine")
            .path();
        assert!(quarantine.join("plugin/Panel.qml").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_panic_after_quarantine_retains_the_exact_plugin() {
        let mut fixture = Fixture::new();
        fixture.install();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = install::uninstall_with_rescan(
                "example.signed-plugin",
                &fixture.plugins,
                Path::new("/usr/bin/true"),
                || panic!("simulated process unwind after quarantine"),
            );
        }));

        assert!(result.is_err());
        assert!(!fixture.target().exists());
        let quarantine = retained_removal_quarantines(&fixture.plugins)
            .pop()
            .unwrap()
            .path();
        assert!(quarantine.join("plugin/Panel.qml").is_file());
        assert!(quarantine.join("plugin/.a-quo-install.json").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uninstall_refuses_an_unmanaged_target_but_not_a_revoked_publisher() {
        let unmanaged = Fixture::new();
        fs::create_dir(unmanaged.target()).unwrap();
        fs::write(
            unmanaged.target().join("manifest.json"),
            manifest_bytes("Panel.qml"),
        )
        .unwrap();
        fs::write(
            unmanaged.target().join("Panel.qml"),
            b"import QtQuick\nItem {}\n",
        )
        .unwrap();
        let error = install::uninstall_with_commands(
            "example.signed-plugin",
            &unmanaged.plugins,
            Path::new("/usr/bin/true"),
        )
        .unwrap_err();
        assert!(matches!(error, OmarchyError::NotManagedInstall(_)));
        assert!(unmanaged.target().join("Panel.qml").is_file());

        let mut revoked = Fixture::new();
        revoked.install();
        let fingerprint =
            public_key_fingerprint(&normalized_public_key(&revoked.public_key)).unwrap();
        revoked
            .store
            .mark_key_compromised(
                &fingerprint,
                "publisher key compromise after installation",
                "a-quo:test:uninstall-compromised-publisher:v1",
                None,
            )
            .unwrap();
        install::uninstall_with_commands(
            "example.signed-plugin",
            &revoked.plugins,
            Path::new("/usr/bin/true"),
        )
        .expect("publisher deauthorization must not prevent local removal");
        assert!(!revoked.target().exists());
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

    struct PreparedTerminalRevocation {
        proof: TerminalPersonaRevocationProof,
        root_statement_sha256: String,
        recovery_policy_statement_sha256: String,
        previous_head: PersonaContinuityCheckpoint,
    }

    struct Fixture {
        directory: tempfile::TempDir,
        package: PathBuf,
        proof: PathBuf,
        plugins: PathBuf,
        store: PersonaStore,
        store_path: PathBuf,
        persona_id: String,
        private_key: PathBuf,
        public_key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let package = directory.path().join("plugin.tar.zst");
            let proof = directory.path().join("plugin.proof.json");
            let plugins = directory.path().join("omarchy/plugins");
            fs::create_dir_all(&plugins).unwrap();
            fs::write(
                directory.path().join("omarchy/shell.json"),
                br#"{"version":1,"plugins":[]}"#,
            )
            .unwrap();
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
            let store_path = directory.path().join("personas.sqlite3");
            let mut store = PersonaStore::open(&store_path).unwrap();
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
                store_path,
                persona_id: persona.id,
                private_key,
                public_key: public_key_path,
            }
        }

        fn target(&self) -> PathBuf {
            self.plugins.join("example.signed-plugin")
        }

        #[cfg(target_os = "linux")]
        fn install(&mut self) {
            install::install_with_commands(
                &self.package,
                &self.proof,
                &mut self.store,
                &self.plugins,
                Path::new("/usr/bin/true"),
                Path::new("/usr/bin/true"),
            )
            .unwrap();
        }

        fn prepare_terminal_revocation(
            &mut self,
            reason: TerminalPersonaRevocationReason,
        ) -> PreparedTerminalRevocation {
            let public_key = normalized_public_key(&self.public_key);
            let issued_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let root_statement =
                new_persona_root_statement("Example Publisher", issued_at - 10, &public_key)
                    .unwrap();
            let root_proof =
                create_persona_root_proof(root_statement, &self.private_key, &public_key).unwrap();
            let verified_root = verify_persona_root_proof(&root_proof).unwrap();
            self.store
                .record_continuity_root(
                    &self.persona_id,
                    &root_proof,
                    &verified_root.root_statement_sha256,
                )
                .unwrap();

            let authority_signers = (1..=2)
                .map(|index| {
                    let private_key_path = self
                        .directory
                        .path()
                        .join(format!("terminal_recovery_{index}"));
                    generate_key(&private_key_path);
                    let public_key = normalized_public_key(&private_key_path.with_extension("pub"));
                    RecoverySigner {
                        private_key_path,
                        public_key,
                    }
                })
                .collect::<Vec<_>>();
            let authority_public_keys = authority_signers
                .iter()
                .map(|signer| signer.public_key.clone())
                .collect::<Vec<_>>();
            let policy_statement = new_initial_recovery_policy_statement_with_capabilities(
                &verified_root,
                &authority_public_keys,
                2,
                &[
                    RecoveryPolicyCapability::KeyRecovery,
                    RecoveryPolicyCapability::TerminalRevocation,
                ],
                RecoveryContinuityCheckpoint {
                    transition_sequence: 0,
                    transition_sha256: None,
                },
                issued_at,
                issued_at + 3_600,
            )
            .unwrap();
            let policy_proof =
                create_initial_recovery_policy_proof(policy_statement, &authority_signers).unwrap();
            let verified_policy =
                verify_initial_recovery_policy_proof(&verified_root, &policy_proof).unwrap();
            let previous_head = PersonaContinuityCheckpoint {
                transition_sequence: 0,
                transition_sha256: None,
            };
            self.store
                .record_recovery_policy_chain(
                    &self.persona_id,
                    std::slice::from_ref(&policy_proof),
                    &verified_root.root_statement_sha256,
                    &verified_policy.policy_statement_sha256,
                    &previous_head,
                )
                .unwrap();

            let previous_key_fingerprint = public_key_fingerprint(&public_key).unwrap();
            let terminal_statement = new_terminal_persona_revocation_statement(
                &verified_root,
                1,
                None,
                &previous_key_fingerprint,
                &verified_policy,
                issued_at,
                reason,
            )
            .unwrap();
            let proof = create_terminal_persona_revocation_proof(
                terminal_statement,
                &verified_policy,
                &authority_signers,
            )
            .unwrap();
            PreparedTerminalRevocation {
                proof,
                root_statement_sha256: verified_root.root_statement_sha256,
                recovery_policy_statement_sha256: verified_policy.policy_statement_sha256,
                previous_head,
            }
        }

        fn terminally_revoke(&mut self, reason: TerminalPersonaRevocationReason) {
            let prepared = self.prepare_terminal_revocation(reason);
            commit_prepared_terminal_revocation(&mut self.store, &self.persona_id, &prepared)
                .unwrap();
        }

        fn evidence_only_store(&mut self) -> PersonaStore {
            let public_key = normalized_public_key(&self.public_key);
            let issued_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let statement =
                new_persona_root_statement("Example Publisher", issued_at, &public_key).unwrap();
            let proof =
                create_persona_root_proof(statement, &self.private_key, &public_key).unwrap();
            let archive = BackupContinuityArchive {
                root: BackupPersonaRootEvidence {
                    proof,
                    observed_at: None,
                },
                recovery_policies: Vec::new(),
                transitions: Vec::new(),
                terminal_revocation: None,
            };
            let backup = self
                .store
                .export_persona_backup_with_archive(&self.persona_id, Some(archive))
                .unwrap();
            let mut restored = PersonaStore::open_in_memory().unwrap();
            restored.import_persona_backup(&backup).unwrap();
            restored
        }

        fn archived_v1_store(&mut self) -> PersonaStore {
            let mut backup = self.store.export_persona_backup(&self.persona_id).unwrap();
            backup.schema = PERSONA_BACKUP_V1_SCHEMA.to_owned();
            backup.continuity = None;
            backup.persona.archived_at = Some(backup.exported_at);
            let mut restored = PersonaStore::open_in_memory().unwrap();
            restored.import_persona_backup(&backup).unwrap();
            restored
        }

        #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    fn normalized_public_key(public_key_path: &Path) -> String {
        let public_key = fs::read_to_string(public_key_path).unwrap();
        let mut fields = public_key.split_whitespace();
        format!(
            "{} {}",
            fields.next().expect("public-key algorithm"),
            fields.next().expect("public-key data")
        )
    }

    fn commit_prepared_terminal_revocation(
        store: &mut PersonaStore,
        persona_id: &str,
        prepared: &PreparedTerminalRevocation,
    ) -> std::result::Result<(), StoreError> {
        store
            .commit_terminal_persona_revocation(
                persona_id,
                &prepared.proof,
                &prepared.root_statement_sha256,
                &prepared.recovery_policy_statement_sha256,
                &prepared.previous_head,
            )
            .map(|_| ())
    }

    #[cfg(target_os = "linux")]
    fn retained_removal_quarantines(plugins: &Path) -> Vec<fs::DirEntry> {
        fs::read_dir(plugins)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".a-quo-remove-")
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn retained_update_recoveries(plugins: &Path) -> Vec<fs::DirEntry> {
        fs::read_dir(plugins)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".a-quo-update-")
            })
            .collect()
    }

    fn regular_file_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn collect(root: &Path, current: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(current).unwrap() {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                if metadata.is_dir() {
                    collect(root, &path, files);
                } else if metadata.is_file() {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }

        let mut files = BTreeMap::new();
        if root.is_dir() {
            collect(root, root, &mut files);
        }
        files
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod non_linux_update_tests {
    use a_quo_store::PersonaStore;
    use tempfile::tempdir;

    use super::{OmarchyError, update_signed_package};

    #[test]
    fn update_fails_closed_before_creating_staging() {
        let directory = tempdir().unwrap();
        let plugins = directory.path().join("plugins-does-not-exist");
        let mut store = PersonaStore::open_in_memory().unwrap();

        let error = update_signed_package(
            directory.path().join("missing-package"),
            directory.path().join("missing-proof"),
            &mut store,
            &plugins,
        )
        .unwrap_err();

        assert!(matches!(error, OmarchyError::AtomicUpdate(_)));
        assert!(!plugins.exists());
    }
}
