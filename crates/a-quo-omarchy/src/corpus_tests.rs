use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use a_quo_core::{create_sshsig_proof, describe_artifact, inspect_proof, write_proof_new};
use a_quo_store::{KeyProvider, PersonaPurpose, PersonaStore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

use crate::install::{self, INSTALL_RECEIPT_NAME};
use crate::{
    AQuoEnablementAction, DiskPurgeStatus, OmarchyError, OmarchyManifestValidationStatus,
    PluginReferenceState, PublisherContinuityStatus, PublisherRegistryStatus,
    ReferenceObservationBoundary, RuntimeSafetyStatus, UninstallOutcomeSchema,
    inspect_signed_package,
};

const CORPUS_ROOT_ENV: &str = "A_QUO_OMARCHY_CORPUS_ROOT";
const VALIDATOR: &str = "/usr/bin/omarchy-plugin-validate";
const SIMULATED_RESCAN: &str = "/usr/bin/true";
const PRIMARY_LABEL: &str = "A Quo corpus-v1 publisher — TEST FIXTURE — NOT ENDORSED";
const ALTERNATE_LABEL: &str = "A Quo corpus-v1 alternate publisher — TEST FIXTURE — NOT ENDORSED";

#[derive(Clone, Copy)]
struct FrozenPackage {
    fixture_id: &'static str,
    version: &'static str,
    package_sha256: &'static str,
    package_size: u64,
    entries: u64,
    files: u64,
    directories: u64,
    executable_files: &'static [&'static str],
}

const FRAME_0_5_0: FrozenPackage = FrozenPackage {
    fixture_id: "frame-0-5-0",
    version: "0.5.0",
    package_sha256: "13c5caf952ced1147611f4443dd715eafd09467010f6513f9260d957e70edecd",
    package_size: 4_549_836,
    entries: 33,
    files: 27,
    directories: 6,
    executable_files: &[
        "bin/frame-controller-linux-amd64",
        "bin/frame-controller-linux-arm64",
        "scripts/build-release.sh",
    ],
};

const FRAME_0_5_1: FrozenPackage = FrozenPackage {
    fixture_id: "frame-0-5-1",
    version: "0.5.1",
    package_sha256: "4d16dada015a14326548c794b9c937906c20e45b3e47d2c433e5f3e1eee6bf9a",
    package_size: 4_552_499,
    entries: 34,
    files: 28,
    directories: 6,
    executable_files: &[
        "bin/frame-controller",
        "bin/frame-controller-linux-amd64",
        "bin/frame-controller-linux-arm64",
        "scripts/build-release.sh",
    ],
};

struct SignedCorpus {
    _directory: TempDir,
    store: PersonaStore,
    frame_0_5_0: PathBuf,
    frame_0_5_1: PathBuf,
    proof_0_5_0: PathBuf,
    proof_0_5_1: PathBuf,
    alternate_proof_0_5_1: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct TreeSnapshot {
    root_device: u64,
    root_inode: u64,
    root_mode: u32,
    entries: BTreeMap<Vec<u8>, TreeEntrySnapshot>,
}

#[derive(Debug, Eq, PartialEq)]
enum TreeEntrySnapshot {
    Directory {
        mode: u32,
    },
    File {
        mode: u32,
        size: u64,
        sha256: String,
    },
}

#[test]
#[ignore = "requires the local unpublished corpus cohort and installed Omarchy validator"]
fn signed_frame_0_5_0_to_0_5_1_lifecycle() {
    let corpus_root = absolute_environment_path(CORPUS_ROOT_ENV);
    let mut corpus = SignedCorpus::new(&corpus_root);

    assert_signed_inspection(
        &corpus.frame_0_5_0,
        &corpus.proof_0_5_0,
        &corpus.store,
        FRAME_0_5_0,
        PRIMARY_LABEL,
    );
    assert_signed_inspection(
        &corpus.frame_0_5_1,
        &corpus.proof_0_5_1,
        &corpus.store,
        FRAME_0_5_1,
        PRIMARY_LABEL,
    );

    assert_proof_substitution_is_rejected(&corpus);
    exercise_install_enabled_update_and_uninstall(&mut corpus);
    exercise_failed_rescan_rollback(&mut corpus);
    exercise_downgrade_refusal(&mut corpus);
    exercise_publisher_change_refusal(&mut corpus);

    let validator = describe_artifact(VALIDATOR).expect("describe installed Omarchy validator");
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "urn:a-quo:omarchy-corpus-lifecycle-observation:v1",
            "status": "passed",
            "scope": "local opt-in real-package regression",
            "fixtures": [
                {
                    "fixture_id": FRAME_0_5_0.fixture_id,
                    "package_sha256": FRAME_0_5_0.package_sha256,
                    "package_size": FRAME_0_5_0.package_size,
                    "signed_inspection": "passed"
                },
                {
                    "fixture_id": FRAME_0_5_1.fixture_id,
                    "package_sha256": FRAME_0_5_1.package_sha256,
                    "package_size": FRAME_0_5_1.package_size,
                    "signed_inspection": "passed"
                }
            ],
            "signer": {
                "signed_label": PRIMARY_LABEL,
                "identity_binding": "self_asserted",
                "private_signing_files": "removed_after_proof_creation_not_claimed_securely_erased",
                "signer_test_persona_root": null
            },
            "temporary_evidence": "proofs_store_receipts_and_trees_private_not_published_with_best_effort_tempdir_cleanup",
            "validator": {
                "kind": "installed_omarchy_plugin_validate",
                "sha256": validator.digest.value,
                "size": validator.size
            },
            "shell_rescan": "simulated_success_or_injected_failure; live shell not invoked",
            "cases": {
                "proof_substitution": "rejected",
                "install_unreferenced": "passed_without_a_quo_enablement",
                "separate_enable_reference": "recorded_in_isolated_shell_configuration",
                "same_persona_update": "passed_with_prior_release_retained",
                "uninstall": "passed_with_removed_release_retained_and_no_disk_purge",
                "rescan_failure": "exact_prior_release_restored_and_candidate_retained",
                "downgrade": "rejected",
                "publisher_change": "rejected"
            },
            "package_publication": "not_performed",
            "proof_publication": "not_performed",
            "publication_permission_record": null,
            "behavioral_analysis": "not_run",
            "plug_and_prejudice": "not_invoked",
            "runtime_safety": "not_evaluated",
            "trusted_consent": "not_exercised",
            "clean_system_or_live_omarchy": "not_exercised",
            "power_loss_or_restart_recovery": "not_exercised",
            "independent_reproduction": "not_established"
        }))
        .expect("serialize sanitized corpus observation")
    );
}

impl SignedCorpus {
    fn new(corpus_root: &Path) -> Self {
        assert_trusted_system_command(Path::new(VALIDATOR));
        assert_trusted_system_command(Path::new(SIMULATED_RESCAN));

        let frame_0_5_0 = frozen_package_path(corpus_root, FRAME_0_5_0);
        let frame_0_5_1 = frozen_package_path(corpus_root, FRAME_0_5_1);
        let directory = tempdir().expect("create private corpus test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("set private corpus test directory permissions");

        let primary_key = directory.path().join("primary-key");
        let alternate_key = directory.path().join("alternate-key");
        generate_ephemeral_key(&primary_key);
        generate_ephemeral_key(&alternate_key);

        let primary_public_path = primary_key.with_extension("pub");
        let alternate_public_path = alternate_key.with_extension("pub");
        let primary_public =
            fs::read_to_string(&primary_public_path).expect("read ephemeral primary public key");
        let alternate_public = fs::read_to_string(&alternate_public_path)
            .expect("read ephemeral alternate public key");

        let mut store = PersonaStore::open(directory.path().join("personas.sqlite3"))
            .expect("create temporary persona store");
        let primary = store
            .create_persona(PRIMARY_LABEL, PersonaPurpose::Project)
            .expect("create primary test persona");
        store
            .enroll_key(&primary.id, &primary_public, KeyProvider::OpensshFile)
            .expect("enroll primary ephemeral public key");
        let alternate = store
            .create_persona(ALTERNATE_LABEL, PersonaPurpose::Project)
            .expect("create alternate test persona");
        store
            .enroll_key(&alternate.id, &alternate_public, KeyProvider::OpensshFile)
            .expect("enroll alternate ephemeral public key");

        let proof_0_5_0 = directory.path().join("frame-0-5-0.proof.json");
        let proof_0_5_1 = directory.path().join("frame-0-5-1.proof.json");
        let alternate_proof_0_5_1 = directory.path().join("frame-0-5-1-alternate.proof.json");
        sign_package(
            &frame_0_5_0,
            &primary_key,
            &primary_public_path,
            PRIMARY_LABEL,
            FRAME_0_5_0,
            &proof_0_5_0,
        );
        sign_package(
            &frame_0_5_1,
            &primary_key,
            &primary_public_path,
            PRIMARY_LABEL,
            FRAME_0_5_1,
            &proof_0_5_1,
        );
        sign_package(
            &frame_0_5_1,
            &alternate_key,
            &alternate_public_path,
            ALTERNATE_LABEL,
            FRAME_0_5_1,
            &alternate_proof_0_5_1,
        );
        remove_signing_file(&primary_key);
        remove_signing_file(&primary_public_path);
        remove_signing_file(&alternate_key);
        remove_signing_file(&alternate_public_path);

        Self {
            _directory: directory,
            store,
            frame_0_5_0,
            frame_0_5_1,
            proof_0_5_0,
            proof_0_5_1,
            alternate_proof_0_5_1,
        }
    }
}

fn absolute_environment_path(name: &str) -> PathBuf {
    let value = env::var_os(name).unwrap_or_else(|| panic!("{name} must name the cohort root"));
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{name} must be absolute");
    path
}

fn frozen_package_path(corpus_root: &Path, package: FrozenPackage) -> PathBuf {
    let path = corpus_root.join(package.fixture_id).join("package.tar.zst");
    let metadata = fs::symlink_metadata(&path).expect("read frozen package metadata");
    assert!(metadata.is_file(), "frozen package must be a regular file");
    assert!(
        !metadata.file_type().is_symlink(),
        "frozen package must not be a symlink"
    );
    let descriptor = describe_artifact(&path).expect("describe frozen package");
    assert_eq!(descriptor.digest.algorithm, "sha256");
    assert_eq!(descriptor.digest.value, package.package_sha256);
    assert_eq!(descriptor.size, package.package_size);
    path
}

fn assert_trusted_system_command(path: &Path) {
    let metadata = fs::symlink_metadata(path).expect("read trusted test-command metadata");
    assert!(metadata.is_file(), "test command must be a regular file");
    assert!(
        !metadata.file_type().is_symlink(),
        "test command must not be a symlink"
    );
}

fn generate_ephemeral_key(path: &Path) {
    let status = Command::new("/usr/bin/ssh-keygen")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "A Quo corpus test fixture",
            "-f",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run ssh-keygen for ephemeral corpus key");
    assert!(status.success(), "ephemeral ssh-keygen failed");
    let mode = fs::metadata(path)
        .expect("read ephemeral private-key metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "ephemeral private key is too permissive");
}

fn remove_signing_file(path: &Path) {
    fs::remove_file(path).expect("remove ephemeral corpus signing file after proof creation");
    assert!(
        fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "ephemeral corpus signing file still resolves after removal"
    );
}

fn sign_package(
    package: &Path,
    private_key: &Path,
    public_key: &Path,
    label: &str,
    expected: FrozenPackage,
    proof_path: &Path,
) {
    let proof = create_sshsig_proof(package, private_key, public_key, label)
        .expect("create ephemeral corpus proof");
    let statement = inspect_proof(&proof).expect("inspect ephemeral corpus proof");
    assert_eq!(statement.artifact.digest.algorithm, "sha256");
    assert_eq!(statement.artifact.digest.value, expected.package_sha256);
    assert_eq!(statement.artifact.size, expected.package_size);
    write_proof_new(proof_path, &proof).expect("write ephemeral corpus proof");
}

fn assert_signed_inspection(
    package_path: &Path,
    proof_path: &Path,
    store: &PersonaStore,
    package: FrozenPackage,
    expected_label: &str,
) {
    let inspection = inspect_signed_package(package_path, proof_path, Some(store))
        .expect("inspect signed frozen package");
    assert_eq!(inspection.artifact_evidence.signer.persona, expected_label);
    assert_eq!(
        inspection.artifact_evidence.signer.identity_binding,
        "self_asserted"
    );
    assert_eq!(
        inspection.publisher_evidence.registry_status,
        PublisherRegistryStatus::Active
    );
    assert_eq!(
        inspection.publisher_evidence.signed_label_agreement,
        Some(true)
    );
    assert_eq!(inspection.manifest.id, "swa.frame");
    assert_eq!(inspection.manifest.version, package.version);
    assert_eq!(inspection.archive.compressed_bytes, package.package_size);
    assert_eq!(inspection.archive.entries, package.entries);
    assert_eq!(inspection.archive.files, package.files);
    assert_eq!(inspection.archive.directories, package.directories);
    assert_eq!(
        inspection
            .archive
            .executable_files
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        package.executable_files.iter().copied().collect()
    );
    assert_eq!(inspection.runtime_safety, RuntimeSafetyStatus::NotEvaluated);
    assert_eq!(
        inspection.a_quo_enablement_action,
        AQuoEnablementAction::NotPerformed
    );
}

fn assert_proof_substitution_is_rejected(corpus: &SignedCorpus) {
    let error = inspect_signed_package(
        &corpus.frame_0_5_0,
        &corpus.proof_0_5_1,
        Some(&corpus.store),
    )
    .expect_err("proof for other package must be rejected");
    assert!(
        matches!(
            error,
            OmarchyError::Proof(a_quo_core::ProofError::ArtifactMismatch)
        ),
        "unexpected substituted-proof error: {error}"
    );
}

fn new_isolated_plugins_root(directory: &Path, case: &str) -> (PathBuf, PathBuf) {
    let omarchy = directory.join(case).join("omarchy");
    let plugins = omarchy.join("plugins");
    fs::create_dir_all(&plugins).expect("create isolated Omarchy plugins directory");
    let shell = omarchy.join("shell.json");
    fs::write(&shell, br#"{"version":1,"plugins":[]}"#)
        .expect("write isolated Omarchy configuration");
    (plugins, shell)
}

fn exercise_install_enabled_update_and_uninstall(corpus: &mut SignedCorpus) {
    let (plugins, shell) =
        new_isolated_plugins_root(corpus._directory.path(), "install-enabled-update-uninstall");
    let empty_shell = fs::read(&shell).expect("read isolated shell configuration");
    let install = install::install_with_commands(
        &corpus.frame_0_5_0,
        &corpus.proof_0_5_0,
        &mut corpus.store,
        &plugins,
        Path::new(VALIDATOR),
        Path::new(SIMULATED_RESCAN),
    )
    .expect("install frozen Frame 0.5.0");
    assert_eq!(install.plugin_id, "swa.frame");
    assert_eq!(install.version, "0.5.0");
    assert_eq!(
        install.a_quo_enablement_action,
        AQuoEnablementAction::NotPerformed
    );
    assert_eq!(
        install.omarchy_manifest_validation,
        OmarchyManifestValidationStatus::PassedPinnedRootObservationNotContentContinuous
    );
    assert!(install.staging_retained);
    assert_eq!(install.disk_purge, DiskPurgeStatus::NotPerformed);
    assert!(install.retained_staging.join("package.tar.zst").is_file());
    assert!(!install.retained_staging.join("plugin").exists());
    assert_eq!(install.runtime_safety, RuntimeSafetyStatus::NotEvaluated);
    assert_eq!(fs::read(&shell).unwrap(), empty_shell);
    assert_installed_release(&plugins.join("swa.frame"), FRAME_0_5_0);
    let installed_0_5_0 = tree_snapshot(&plugins.join("swa.frame"));

    let referenced_shell = br#"{"version":1,"plugins":[{"id":"swa.frame"}]}"#;
    fs::write(&shell, referenced_shell).expect("record separate simulated enable decision");
    let update = install::update_with_test_hooks(
        install::UpdateRequest::new(
            &corpus.frame_0_5_1,
            &corpus.proof_0_5_1,
            &plugins,
            Path::new(VALIDATOR),
            Path::new(SIMULATED_RESCAN),
        ),
        &mut corpus.store,
        install::UpdateTestHooks::new().rescan(|| Ok(())),
    )
    .expect("update frozen Frame 0.5.0 to 0.5.1");
    assert_eq!(update.plugin_id, "swa.frame");
    assert_eq!(update.previous_version, "0.5.0");
    assert_eq!(update.version, "0.5.1");
    assert_eq!(
        update.publisher_continuity,
        PublisherContinuityStatus::SameLocalPersona
    );
    assert_eq!(
        update.omarchy_manifest_validation,
        OmarchyManifestValidationStatus::PassedPathObservationNotContinuous
    );
    assert!(update.atomic_exchange);
    assert!(update.recovery_retained);
    assert_eq!(update.disk_purge, DiskPurgeStatus::NotPerformed);
    assert_eq!(
        update.a_quo_enablement_action,
        AQuoEnablementAction::NotPerformed
    );
    assert_eq!(update.runtime_safety, RuntimeSafetyStatus::NotEvaluated);
    assert_eq!(fs::read(&shell).unwrap(), referenced_shell);
    assert_installed_release(&plugins.join("swa.frame"), FRAME_0_5_1);
    assert_installed_release(&update.previous_release_recovery, FRAME_0_5_0);
    assert_eq!(
        tree_snapshot(&update.previous_release_recovery),
        installed_0_5_0,
        "successful update did not retain the exact installed 0.5.0 tree and root inode"
    );
    let installed_0_5_1 = tree_snapshot(&plugins.join("swa.frame"));
    let prior_recovery = update.previous_release_recovery.clone();

    fs::write(&shell, &empty_shell).expect("record separate simulated unreference decision");
    let uninstall =
        install::uninstall_with_rescan("swa.frame", &plugins, Path::new(SIMULATED_RESCAN), || {
            Ok(())
        })
        .expect("uninstall frozen Frame 0.5.1");
    assert_eq!(uninstall.plugin_id, "swa.frame");
    assert_eq!(uninstall.version, "0.5.1");
    assert_eq!(uninstall.schema, UninstallOutcomeSchema::V1);
    assert_eq!(
        uninstall.reference_observation.state(),
        PluginReferenceState::NotReferenced
    );
    assert_eq!(
        uninstall.reference_observation.boundary(),
        ReferenceObservationBoundary::BeforeAtomicQuarantine
    );
    assert!(uninstall.atomic_quarantine);
    assert_eq!(uninstall.disk_purge, DiskPurgeStatus::NotPerformed);
    assert_eq!(
        uninstall.a_quo_enablement_action,
        AQuoEnablementAction::NotPerformed
    );
    assert_eq!(uninstall.runtime_safety, RuntimeSafetyStatus::NotEvaluated);
    assert!(!plugins.join("swa.frame").exists());
    assert_installed_release(&uninstall.recovery_quarantine.join("plugin"), FRAME_0_5_1);
    assert_installed_release(&prior_recovery, FRAME_0_5_0);
    assert_eq!(
        tree_snapshot(&uninstall.recovery_quarantine.join("plugin")),
        installed_0_5_1,
        "uninstall did not retain the exact installed 0.5.1 tree and root inode"
    );
    assert_eq!(retained_paths(&plugins, ".a-quo-update-").len(), 1);
    assert_eq!(retained_paths(&plugins, ".a-quo-remove-").len(), 1);
}

fn exercise_failed_rescan_rollback(corpus: &mut SignedCorpus) {
    let (plugins, _) =
        new_isolated_plugins_root(corpus._directory.path(), "failed-rescan-rollback");
    install::install_with_commands(
        &corpus.frame_0_5_0,
        &corpus.proof_0_5_0,
        &mut corpus.store,
        &plugins,
        Path::new(VALIDATOR),
        Path::new(SIMULATED_RESCAN),
    )
    .expect("install rollback baseline");
    let installed_0_5_0 = tree_snapshot(&plugins.join("swa.frame"));
    let mut rescans = 0_u8;
    let mut rejected_0_5_1 = None;
    let error = install::update_with_test_hooks(
        install::UpdateRequest::new(
            &corpus.frame_0_5_1,
            &corpus.proof_0_5_1,
            &plugins,
            Path::new(VALIDATOR),
            Path::new(SIMULATED_RESCAN),
        ),
        &mut corpus.store,
        install::UpdateTestHooks::new().rescan(|| {
            rescans += 1;
            if rescans == 1 {
                rejected_0_5_1 = Some(tree_snapshot(&plugins.join("swa.frame")));
                Err("injected corpus rescan failure".to_owned())
            } else {
                Ok(())
            }
        }),
    )
    .expect_err("first rescan failure must roll back");
    assert!(matches!(error, OmarchyError::UpdateRolledBack(_)));
    assert_eq!(rescans, 2);
    assert_installed_release(&plugins.join("swa.frame"), FRAME_0_5_0);
    assert_eq!(
        tree_snapshot(&plugins.join("swa.frame")),
        installed_0_5_0,
        "failed-rescan rollback did not restore the exact 0.5.0 tree and root inode"
    );
    let retained = retained_paths(&plugins, ".a-quo-update-");
    assert_eq!(retained.len(), 1);
    assert_installed_release(&retained[0].join("plugin"), FRAME_0_5_1);
    assert_eq!(
        tree_snapshot(&retained[0].join("plugin")),
        rejected_0_5_1.expect("snapshot rejected 0.5.1 before injected rescan failure"),
        "failed-rescan rollback did not retain the exact rejected 0.5.1 tree and root inode"
    );
}

fn exercise_downgrade_refusal(corpus: &mut SignedCorpus) {
    let (plugins, _) = new_isolated_plugins_root(corpus._directory.path(), "downgrade-refusal");
    install::install_with_commands(
        &corpus.frame_0_5_1,
        &corpus.proof_0_5_1,
        &mut corpus.store,
        &plugins,
        Path::new(VALIDATOR),
        Path::new(SIMULATED_RESCAN),
    )
    .expect("install downgrade baseline");
    let baseline = tree_snapshot(&plugins.join("swa.frame"));
    let mut rescans = 0_u8;
    let error = install::update_with_test_hooks(
        install::UpdateRequest::new(
            &corpus.frame_0_5_0,
            &corpus.proof_0_5_0,
            &plugins,
            Path::new(VALIDATOR),
            Path::new(SIMULATED_RESCAN),
        ),
        &mut corpus.store,
        install::UpdateTestHooks::new().rescan(|| {
            rescans += 1;
            Ok(())
        }),
    )
    .expect_err("real Frame downgrade must be rejected");
    assert!(matches!(error, OmarchyError::VersionNotNewer { .. }));
    assert_eq!(rescans, 0, "downgrade refusal reached shell rescan");
    assert_installed_release(&plugins.join("swa.frame"), FRAME_0_5_1);
    assert_eq!(
        tree_snapshot(&plugins.join("swa.frame")),
        baseline,
        "downgrade refusal changed the installed tree or root inode"
    );
}

fn exercise_publisher_change_refusal(corpus: &mut SignedCorpus) {
    let (plugins, _) =
        new_isolated_plugins_root(corpus._directory.path(), "publisher-change-refusal");
    install::install_with_commands(
        &corpus.frame_0_5_0,
        &corpus.proof_0_5_0,
        &mut corpus.store,
        &plugins,
        Path::new(VALIDATOR),
        Path::new(SIMULATED_RESCAN),
    )
    .expect("install publisher-change baseline");
    let baseline = tree_snapshot(&plugins.join("swa.frame"));
    let mut rescans = 0_u8;
    let error = install::update_with_test_hooks(
        install::UpdateRequest::new(
            &corpus.frame_0_5_1,
            &corpus.alternate_proof_0_5_1,
            &plugins,
            Path::new(VALIDATOR),
            Path::new(SIMULATED_RESCAN),
        ),
        &mut corpus.store,
        install::UpdateTestHooks::new().rescan(|| {
            rescans += 1;
            Ok(())
        }),
    )
    .expect_err("alternate publisher must not replace the installed publisher");
    assert!(matches!(error, OmarchyError::PublisherContinuityMismatch));
    assert_eq!(rescans, 0, "publisher-change refusal reached shell rescan");
    assert_installed_release(&plugins.join("swa.frame"), FRAME_0_5_0);
    assert_eq!(
        tree_snapshot(&plugins.join("swa.frame")),
        baseline,
        "publisher-change refusal changed the installed tree or root inode"
    );
}

fn assert_installed_release(root: &Path, package: FrozenPackage) {
    let manifest: Value = serde_json::from_slice(
        &fs::read(root.join("manifest.json")).expect("read installed manifest"),
    )
    .expect("parse installed manifest");
    let receipt: Value = serde_json::from_slice(
        &fs::read(root.join(INSTALL_RECEIPT_NAME)).expect("read installed receipt"),
    )
    .expect("parse installed receipt");
    assert_eq!(manifest["id"], "swa.frame");
    assert_eq!(manifest["version"], package.version);
    assert_eq!(receipt["plugin_id"], "swa.frame");
    assert_eq!(receipt["version"], package.version);
    assert_eq!(receipt["package_sha256"], package.package_sha256);
}

fn retained_paths(plugins: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(plugins)
        .expect("read isolated plugins directory")
        .map(|entry| entry.expect("read retained directory entry").path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn tree_snapshot(root: &Path) -> TreeSnapshot {
    fn collect(root: &Path, current: &Path, entries: &mut BTreeMap<Vec<u8>, TreeEntrySnapshot>) {
        let mut children = fs::read_dir(current)
            .expect("read installed tree")
            .map(|entry| entry.expect("read installed tree entry").path())
            .collect::<Vec<_>>();
        children.sort_by(|left, right| {
            left.as_os_str()
                .as_bytes()
                .cmp(right.as_os_str().as_bytes())
        });
        for path in children {
            let metadata = fs::symlink_metadata(&path).expect("read installed entry metadata");
            assert!(
                !metadata.file_type().is_symlink(),
                "installed tree snapshot encountered a symlink"
            );
            let relative = path
                .strip_prefix(root)
                .expect("installed entry remains under snapshot root")
                .as_os_str()
                .as_bytes()
                .to_vec();
            let mode = metadata.mode() & 0o7777;
            if metadata.is_dir() {
                assert!(
                    entries
                        .insert(relative, TreeEntrySnapshot::Directory { mode })
                        .is_none(),
                    "installed tree snapshot contains a duplicate path"
                );
                collect(root, &path, entries);
            } else {
                assert!(metadata.is_file(), "installed tree contains a special file");
                let bytes = fs::read(&path).expect("read installed regular file");
                assert_eq!(bytes.len() as u64, metadata.len());
                assert!(
                    entries
                        .insert(
                            relative,
                            TreeEntrySnapshot::File {
                                mode,
                                size: metadata.len(),
                                sha256: format!("{:x}", Sha256::digest(&bytes)),
                            },
                        )
                        .is_none(),
                    "installed tree snapshot contains a duplicate path"
                );
            }
        }
    }

    let metadata = fs::symlink_metadata(root).expect("read installed root metadata");
    assert!(
        metadata.is_dir(),
        "installed snapshot root must be a directory"
    );
    assert!(
        !metadata.file_type().is_symlink(),
        "installed snapshot root must not be a symlink"
    );
    let mut entries = BTreeMap::new();
    collect(root, root, &mut entries);
    TreeSnapshot {
        root_device: metadata.dev(),
        root_inode: metadata.ino(),
        root_mode: metadata.mode() & 0o7777,
        entries,
    }
}
