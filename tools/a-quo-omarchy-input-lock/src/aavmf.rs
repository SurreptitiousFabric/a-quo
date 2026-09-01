use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};

use crate::model::{
    ExecutionState, ExpectedObjectSpec, LockAuthority, LockRecord, NonClaimState, ObjectSpec,
    ReportField, TargetBinding, VerificationMode, VerificationReport, parse_lock_fields,
    parse_object_specs,
};
use crate::{
    CANONICAL_V2_PROFILE, ExternalLockExpectation, MAX_LOCK_BYTES, MAX_PROFILE_BYTES, field,
    parse_profile, require,
};

const CANONICAL_LOCK_PATH: &str =
    "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-aavmf-v1.lock";
pub(crate) const RECEIPT_BYTES: u64 = 1_688;
pub(crate) const MANIFEST_BYTES: u64 = 14_988;
const PACKAGE_BYTES: u64 = 4_115_104;

const AAVMF_LOCK_KEYS: &[&str] = &[
    "target_kind",
    "architecture",
    "evidence_namespace",
    "input_class",
    "selected_input_scope",
    "apt_candidate_status",
    "apt_candidate_snapshot_id",
    "apt_candidate_archive_equivalence",
    "apt_candidate_signature_replay",
    "object_count",
    "object_01",
    "object_02",
    "object_03",
    "apt_manifest_package_record",
    "package_name",
    "package_source",
    "package_version",
    "package_architecture",
    "deb_format",
    "deb_member_count",
    "deb_member_01",
    "deb_member_02",
    "deb_member_03",
    "control_tar_uncompressed_size",
    "control_tar_uncompressed_sha256",
    "control_member",
    "data_tar_compression",
    "data_tar_uncompressed_size",
    "data_tar_uncompressed_sha256",
    "firmware_member_count",
    "firmware_member_01",
    "firmware_member_02",
    "firmware_member_03",
    "harness_code_path",
    "harness_vars_path",
    "harness_code_resolution",
    "archive_filesystem_extraction",
    "package_manager_execution",
    "maintainer_scripts_executed",
    "profile_unresolved_input_count",
    "remaining_input_count_if_lock_is_adopted",
    "class_02_lock_status",
    "publisher_authentication",
    "current_publisher_authorization",
    "trusted_time",
    "freshness",
    "source_to_firmware_provenance",
    "safety",
    "network_access",
    "mount_execution",
    "vm_execution",
];

pub type AavmfObjectSpec = ObjectSpec;
pub type AavmfLock = LockRecord;
pub type AavmfVerificationReport = VerificationReport;

pub fn parse_aavmf_lock(bytes: &[u8]) -> Result<AavmfLock> {
    let fields = parse_lock_fields(bytes, AAVMF_LOCK_KEYS, "AAVMF input lock")?;
    for (key, expected) in [
        (
            "selected_input_scope",
            "ubuntu-qemu-efi-aarch64-deb-and-harness-members",
        ),
        ("apt_candidate_status", "complete-candidate-no-authority"),
        ("apt_candidate_snapshot_id", "20260831T000000Z"),
        ("apt_candidate_archive_equivalence", "not-established"),
        (
            "apt_candidate_signature_replay",
            "not-independently-replayed",
        ),
        (
            "apt_manifest_package_record",
            "package|packages/qemu-efi-aarch64_2024.02-2ubuntu0.9_all.deb|4115104|50d7c5f780f215db81677e08d21e681b61295ffe9040429cff9d9c2a0d03fe3d",
        ),
        ("package_name", "qemu-efi-aarch64"),
        ("package_source", "edk2"),
        ("package_version", "2024.02-2ubuntu0.9"),
        ("package_architecture", "all"),
        ("deb_format", "2.0"),
        ("deb_member_count", "3"),
        (
            "deb_member_01",
            "debian-binary|4|d526eb4e878a23ef26ae190031b4efd2d58ed66789ac049ea3dbaf74c9df7402",
        ),
        (
            "deb_member_02",
            "control.tar.zst|1009|ac9657799880afcda6fe711ad6d06233fe68cdec0643016847f5088784efae87",
        ),
        (
            "deb_member_03",
            "data.tar.zst|4113902|9282d3f1a4374319e15d0f6469746f840ac129641c23b84b56cb8fc13112069c",
        ),
        ("control_tar_uncompressed_size", "10240"),
        (
            "control_tar_uncompressed_sha256",
            "3240cbed37ce42175baea118366b9391ec1abebac762ee7ec3c97189ddedeed5",
        ),
        (
            "control_member",
            "./control|605|d57bb317209726f735f760da3323e3a8abeb6d860b087b56a4f622b2bdf815b7",
        ),
        ("data_tar_compression", "zstd"),
        ("data_tar_uncompressed_size", "337694720"),
        (
            "data_tar_uncompressed_sha256",
            "7c1d8217b3928ab9f64099cfee0546684bab8fca670bed2a5e5f375d44bd9f78",
        ),
        ("firmware_member_count", "3"),
        (
            "firmware_member_01",
            "symlink|./usr/share/AAVMF/AAVMF_CODE.fd|AAVMF_CODE.no-secboot.fd",
        ),
        (
            "firmware_member_02",
            "regular|./usr/share/AAVMF/AAVMF_CODE.no-secboot.fd|67108864|4a4cb7f6d8106bb2a7dd8c763fab14b1810152136fc4304e5b728f0043e84f12|0644|0|0",
        ),
        (
            "firmware_member_03",
            "regular|./usr/share/AAVMF/AAVMF_VARS.fd|67108864|b3b855c5a80310168051164986855692d1bdb06e67619856177965cd87c6774f|0644|0|0",
        ),
        ("harness_code_path", "/usr/share/AAVMF/AAVMF_CODE.fd"),
        ("harness_vars_path", "/usr/share/AAVMF/AAVMF_VARS.fd"),
        (
            "harness_code_resolution",
            "/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd",
        ),
        ("archive_filesystem_extraction", "false"),
        ("package_manager_execution", "false"),
        ("maintainer_scripts_executed", "false"),
        ("profile_unresolved_input_count", "10"),
        ("remaining_input_count_if_lock_is_adopted", "9"),
        ("class_02_lock_status", "not-established"),
        ("publisher_authentication", "not-established"),
        ("current_publisher_authorization", "not-established"),
        ("trusted_time", "not-established"),
        ("freshness", "not-established"),
        ("source_to_firmware_provenance", "not-established"),
        ("safety", "not-established"),
        ("network_access", "forbidden"),
        ("mount_execution", "forbidden"),
        ("vm_execution", "forbidden"),
    ] {
        require(&fields, key, expected)?;
    }
    const EXPECTED: &[ExpectedObjectSpec] = &[
        ExpectedObjectSpec {
            role: "apt-candidate-receipt",
            path: "receipt.apt.v1",
            media_type: "text/plain",
            size: RECEIPT_BYTES,
            sha256: "c99f29429d8d6f87c0651154dee28153af4b6d6c0c47908ca767067d3f1f5d13",
        },
        ExpectedObjectSpec {
            role: "apt-object-manifest",
            path: "objects.manifest",
            media_type: "text/plain",
            size: MANIFEST_BYTES,
            sha256: "731cde75cece74a2b22cb22e24484951420b44321453fe1abd898b16744ebdaf",
        },
        ExpectedObjectSpec {
            role: "qemu-efi-package",
            path: "qemu-efi-aarch64_2024.02-2ubuntu0.9_all.deb",
            media_type: "application/vnd.debian.binary-package",
            size: PACKAGE_BYTES,
            sha256: "50d7c5f780f215db81677e08d21e681b61295ffe9040429cff9d9c2a0d03fe3d",
        },
    ];
    let objects = parse_object_specs(&fields, EXPECTED, "AAVMF")?;
    LockRecord::new(
        fields,
        objects,
        "a-quo-omarchy-aavmf-input-lock-v1",
        "a-quo-omarchy4-aarch64-dec29fa-aavmf-v1",
        LockAuthority::DebFirmwareMembers,
        CANONICAL_LOCK_PATH,
        TargetBinding::AAVMF,
    )
}

fn verify_profile(lock: &AavmfLock, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes == CANONICAL_V2_PROFILE.as_bytes(),
        "profile bytes differ from the canonical frozen v2 profile"
    );
    let profile = parse_profile(bytes, 129)?;
    for (key, expected) in [
        ("format", "a-quo-omarchy-evaluation-target-profile-v2"),
        ("profile_id", field(&lock.fields, "profile_id")?),
        ("state", field(&lock.fields, "profile_state")?),
        ("armable", field(&lock.fields, "profile_armable")?),
        ("architecture", field(&lock.fields, "architecture")?),
        ("retained_input_authority", "none"),
        ("release_claim", "not-established"),
        ("support_claim", "not-established"),
        ("reproducibility_claim", "not-established"),
        ("clean_system_claim", "not-established"),
        ("builder_apt_snapshot_and_closure", "required-not-retained"),
        ("unresolved_input_count", "10"),
        ("unresolved_input_07", "aavmf-firmware"),
    ] {
        require(&profile, key, expected)?;
    }
    Ok(())
}

fn validate_external_expectation(expectation: &ExternalLockExpectation) -> Result<()> {
    expectation.validate(CANONICAL_LOCK_PATH, "AAVMF")
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use a_quo_ipc::SealedArtifact;
    use anyhow::{Context, Result, ensure};
    use sha2::{Digest, Sha256};
    use tar::EntryType;

    use super::*;
    use crate::debian::{
        ArMember, canonical_tar_path, decompress_zstd, parse_deb, sha256, verify_manifest,
        verify_receipt,
    };
    use crate::snapshot::{snapshot_bytes, snapshot_exact_input_directory, snapshot_path};

    const CONTROL_TAR_MAXIMUM: u64 = 64 * 1024;
    const DATA_TAR_MAXIMUM: u64 = 512 * 1024 * 1024;
    const TARGET_CODE_PATH: &[u8] = b"./usr/share/AAVMF/AAVMF_CODE.no-secboot.fd";
    const TARGET_VARS_PATH: &[u8] = b"./usr/share/AAVMF/AAVMF_VARS.fd";
    const TARGET_LINK_PATH: &[u8] = b"./usr/share/AAVMF/AAVMF_CODE.fd";

    fn verify_ar_members(members: &[ArMember<'_>]) -> Result<()> {
        const EXPECTED: &[(&str, u64, &str)] = &[
            (
                "debian-binary",
                4,
                "d526eb4e878a23ef26ae190031b4efd2d58ed66789ac049ea3dbaf74c9df7402",
            ),
            (
                "control.tar.zst",
                1_009,
                "ac9657799880afcda6fe711ad6d06233fe68cdec0643016847f5088784efae87",
            ),
            (
                "data.tar.zst",
                4_113_902,
                "9282d3f1a4374319e15d0f6469746f840ac129641c23b84b56cb8fc13112069c",
            ),
        ];
        for (member, expected) in members.iter().zip(EXPECTED) {
            ensure!(
                member.name == expected.0
                    && member.bytes.len() as u64 == expected.1
                    && sha256(member.bytes) == expected.2,
                "Debian archive member differs from reviewed policy"
            );
        }
        ensure!(members[0].bytes == b"2.0\n", "unsupported Debian format");
        Ok(())
    }

    fn verify_control_tar(snapshot: &SealedArtifact, lock: &AavmfLock) -> Result<()> {
        ensure!(
            snapshot.descriptor().size == 10_240,
            "control tar size differs from the lock"
        );
        ensure!(
            snapshot.descriptor().digest.value
                == "3240cbed37ce42175baea118366b9391ec1abebac762ee7ec3c97189ddedeed5",
            "control tar SHA-256 differs from the lock"
        );
        let bytes = snapshot_bytes(snapshot, CONTROL_TAR_MAXIMUM)?;
        let mut archive = tar::Archive::new(Cursor::new(bytes));
        let mut count = 0_usize;
        let mut control = None;
        for entry in archive.entries().context("cannot parse control tar")? {
            let mut entry = entry.context("cannot parse control tar entry")?;
            count += 1;
            ensure!(count <= 16, "control tar exceeds its entry bound");
            if entry.path_bytes().as_ref() == b"./control" {
                ensure!(
                    entry.header().entry_type().is_file(),
                    "control member is not regular"
                );
                ensure!(entry.size() == 605, "control member has the wrong size");
                let mut bytes = Vec::with_capacity(605);
                entry
                    .read_to_end(&mut bytes)
                    .context("cannot read control member")?;
                ensure!(
                    sha256(&bytes)
                        == "d57bb317209726f735f760da3323e3a8abeb6d860b087b56a4f622b2bdf815b7",
                    "control member SHA-256 differs from the lock"
                );
                control = Some(bytes);
            } else {
                std::io::copy(&mut entry, &mut std::io::sink())
                    .context("cannot drain control tar entry")?;
            }
        }
        let control = control.context("control tar lacks ./control")?;
        let text = std::str::from_utf8(&control).context("package control is not UTF-8")?;
        for (key, lock_key) in [
            ("Package", "package_name"),
            ("Source", "package_source"),
            ("Version", "package_version"),
            ("Architecture", "package_architecture"),
        ] {
            let prefix = format!("{key}: ");
            let values = text
                .lines()
                .filter_map(|line| line.strip_prefix(&prefix))
                .collect::<Vec<_>>();
            ensure!(
                values == [field(&lock.fields, lock_key)?],
                "package control field {key} differs from the lock"
            );
        }
        Ok(())
    }

    pub(crate) fn digest_entry(
        entry: &mut tar::Entry<'_, impl Read>,
        expected_size: u64,
    ) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut observed = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = entry
                .read(&mut buffer)
                .context("cannot read firmware member")?;
            if count == 0 {
                break;
            }
            observed = observed
                .checked_add(count as u64)
                .context("firmware size overflow")?;
            ensure!(
                observed <= expected_size,
                "firmware member exceeds its locked size"
            );
            hasher.update(&buffer[..count]);
        }
        ensure!(observed == expected_size, "firmware member ended early");
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn verify_data_tar(snapshot: &SealedArtifact) -> Result<()> {
        ensure!(
            snapshot.descriptor().size == 337_694_720,
            "data tar size differs from the lock"
        );
        ensure!(
            snapshot.descriptor().digest.value
                == "7c1d8217b3928ab9f64099cfee0546684bab8fca670bed2a5e5f375d44bd9f78",
            "data tar SHA-256 differs from the lock"
        );
        let mut file = snapshot
            .file()
            .try_clone()
            .context("cannot clone sealed data tar")?;
        file.seek(SeekFrom::Start(0))
            .context("cannot rewind sealed data tar")?;
        let mut archive = tar::Archive::new(file);
        let mut paths = BTreeSet::new();
        let mut count = 0_usize;
        let mut code = 0_usize;
        let mut vars = 0_usize;
        let mut link = 0_usize;
        for entry in archive.entries().context("cannot parse data tar")? {
            let mut entry = entry.context("cannot parse data tar entry")?;
            count += 1;
            ensure!(count <= 64, "data tar exceeds its entry bound");
            let path = entry.path_bytes().into_owned();
            ensure!(
                canonical_tar_path(&path),
                "data tar has a noncanonical path"
            );
            ensure!(paths.insert(path.clone()), "data tar repeats a path");
            let entry_type = entry.header().entry_type();
            ensure!(
                entry_type.is_file() || entry_type.is_dir() || entry_type == EntryType::Symlink,
                "data tar has a forbidden entry type"
            );
            if path == TARGET_LINK_PATH {
                ensure!(
                    entry_type == EntryType::Symlink,
                    "AAVMF CODE path is not a symlink"
                );
                ensure!(entry.size() == 0, "AAVMF CODE symlink carries data");
                ensure!(
                    entry.link_name_bytes().as_deref() == Some(b"AAVMF_CODE.no-secboot.fd"),
                    "AAVMF CODE symlink target differs from the lock"
                );
                link += 1;
            } else if path == TARGET_CODE_PATH || path == TARGET_VARS_PATH {
                ensure!(entry_type.is_file(), "AAVMF firmware member is not regular");
                ensure!(
                    entry.header().mode()? == 0o644,
                    "AAVMF firmware mode is not 0644"
                );
                ensure!(entry.header().uid()? == 0, "AAVMF firmware UID is not zero");
                ensure!(entry.header().gid()? == 0, "AAVMF firmware GID is not zero");
                ensure!(
                    entry.size() == 67_108_864,
                    "AAVMF firmware size differs from the lock"
                );
                let digest = digest_entry(&mut entry, 67_108_864)?;
                if path == TARGET_CODE_PATH {
                    ensure!(
                        digest
                            == "4a4cb7f6d8106bb2a7dd8c763fab14b1810152136fc4304e5b728f0043e84f12",
                        "AAVMF CODE SHA-256 differs from the lock"
                    );
                    code += 1;
                } else {
                    ensure!(
                        digest
                            == "b3b855c5a80310168051164986855692d1bdb06e67619856177965cd87c6774f",
                        "AAVMF VARS SHA-256 differs from the lock"
                    );
                    vars += 1;
                }
            } else {
                std::io::copy(&mut entry, &mut std::io::sink())
                    .context("cannot drain data tar entry")?;
            }
        }
        ensure!(
            count == 26,
            "data tar does not have the reviewed entry count"
        );
        ensure!(
            (link, code, vars) == (1, 1, 1),
            "data tar does not contain the exact AAVMF harness members"
        );
        Ok(())
    }

    fn verify_package(bytes: &[u8], lock: &AavmfLock) -> Result<()> {
        let members = parse_deb(bytes)?;
        verify_ar_members(&members)?;
        let control = decompress_zstd(members[1].bytes, CONTROL_TAR_MAXIMUM)?;
        verify_control_tar(&control, lock)?;
        let data = decompress_zstd(members[2].bytes, DATA_TAR_MAXIMUM)?;
        verify_data_tar(&data)
    }

    fn report(
        lock: &AavmfLock,
        expectation: &ExternalLockExpectation,
        mode: VerificationMode,
    ) -> AavmfVerificationReport {
        let complete = mode.complete();
        let mut report = VerificationReport::for_lock(lock, expectation, mode, true);
        report.extend([
            ReportField::boolean("object_bytes_verified", complete),
            ReportField::boolean("sealed_snapshot_verification", complete),
            ReportField::boolean("deb_structure_verified", complete),
            ReportField::boolean("firmware_members_verified", complete),
            ReportField::text("apt_candidate_status", "complete-candidate-no-authority"),
            ReportField::nonclaim("class_02_lock_status", NonClaimState::Unestablished),
            ReportField::nonclaim(
                "archive_equivalence_to_original_ports",
                NonClaimState::Unestablished,
            ),
            ReportField::nonclaim(
                "apt_signature_replay",
                NonClaimState::NotIndependentlyReplayed,
            ),
            ReportField::boolean("external_lock_authentication_required", true),
            ReportField::boolean(
                "external_lock_authentication_established_by_verifier",
                false,
            ),
            ReportField::count("profile_unresolved_input_count", 10),
            ReportField::count("remaining_input_count_if_lock_is_adopted", 9),
            ReportField::nonclaim("durable_retention", NonClaimState::Unestablished),
            ReportField::nonclaim("build_authorization", lock.envelope.build_authorization),
            ReportField::execution("runnable", lock.envelope.runnable),
            ReportField::nonclaim("publisher_authentication", NonClaimState::Unestablished),
            ReportField::nonclaim(
                "current_publisher_authorization",
                NonClaimState::Unestablished,
            ),
            ReportField::nonclaim("trusted_time", NonClaimState::Unestablished),
            ReportField::nonclaim("freshness", NonClaimState::Unestablished),
            ReportField::nonclaim(
                "source_to_firmware_provenance",
                NonClaimState::Unestablished,
            ),
            ReportField::nonclaim("safety", NonClaimState::Unestablished),
            ReportField::execution(
                "archive_filesystem_extraction",
                ExecutionState::NotPerformed,
            ),
            ReportField::execution("package_manager_execution", ExecutionState::NotPerformed),
            ReportField::execution("maintainer_scripts_executed", ExecutionState::NotPerformed),
            ReportField::execution("verifier_network_activity", ExecutionState::NotPerformed),
            ReportField::nonclaim(
                "whole_machine_network_silence",
                NonClaimState::Unestablished,
            ),
            ReportField::execution("mount_execution", ExecutionState::NotPerformed),
            ReportField::execution("vm_execution", ExecutionState::NotPerformed),
        ]);
        report
    }

    fn inspect_common(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<AavmfLock> {
        validate_external_expectation(expectation)?;
        let lock_snapshot = snapshot_path(lock_path, MAX_LOCK_BYTES)?;
        ensure!(
            lock_snapshot.descriptor().digest.value == expectation.sha256,
            "lock bytes do not match the externally expected SHA-256"
        );
        let lock = parse_aavmf_lock(&snapshot_bytes(&lock_snapshot, MAX_LOCK_BYTES)?)?;
        require(&lock.fields, "lock_repository", &expectation.repository)?;
        require(&lock.fields, "lock_path", &expectation.path)?;
        let profile_snapshot = snapshot_path(profile_path, MAX_PROFILE_BYTES)?;
        ensure!(
            profile_snapshot.descriptor().digest.value == field(&lock.fields, "profile_sha256")?,
            "profile bytes do not match the lock"
        );
        verify_profile(
            &lock,
            &snapshot_bytes(&profile_snapshot, MAX_PROFILE_BYTES)?,
        )?;
        Ok(lock)
    }

    pub fn inspect_aavmf_lock(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<AavmfVerificationReport> {
        let lock = inspect_common(lock_path, expectation, profile_path)?;
        Ok(report(&lock, expectation, VerificationMode::LockAndProfile))
    }

    pub fn verify_aavmf_inputs(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
        input_directory: &Path,
    ) -> Result<AavmfVerificationReport> {
        let lock = inspect_common(lock_path, expectation, profile_path)?;
        let specifications = lock
            .objects
            .iter()
            .map(|object| {
                (
                    object.role.as_str(),
                    object.path.as_str(),
                    object.size,
                    object.sha256.as_str(),
                )
            })
            .collect::<Vec<_>>();
        let snapshots = snapshot_exact_input_directory(input_directory, &specifications)?;
        ensure!(snapshots.len() == 3, "AAVMF input set is not three objects");
        let receipt = snapshot_bytes(&snapshots[0], RECEIPT_BYTES)?;
        let manifest = snapshot_bytes(&snapshots[1], MANIFEST_BYTES)?;
        let package = snapshot_bytes(&snapshots[2], PACKAGE_BYTES)?;
        verify_receipt(&receipt, RECEIPT_BYTES)?;
        verify_manifest(
            &manifest,
            MANIFEST_BYTES,
            &[field(&lock.fields, "apt_manifest_package_record")?],
        )?;
        verify_package(&package, &lock)?;
        Ok(report(&lock, expectation, VerificationMode::InputSelection))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::debian::{verify_manifest_semantics, verify_receipt_semantics};
        use crate::model::CANONICAL_REPOSITORY;

        const LOCK_BYTES: &[u8] = include_bytes!(
            "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-aavmf-v1.lock"
        );

        #[test]
        fn canonical_lock_and_profile_are_closed() {
            let lock = parse_aavmf_lock(LOCK_BYTES).unwrap();
            verify_profile(&lock, CANONICAL_V2_PROFILE.as_bytes()).unwrap();
            assert_eq!(lock.objects.len(), 3);
            let mut reordered = LOCK_BYTES.to_vec();
            let first = b"format=a-quo-omarchy-aavmf-input-lock-v1\n";
            reordered.drain(..first.len());
            reordered.extend_from_slice(first);
            assert!(parse_aavmf_lock(&reordered).is_err());
            let substituted = String::from_utf8(LOCK_BYTES.to_vec())
                .unwrap()
                .replace("architecture=aarch64", "architecture=x86_64");
            assert!(parse_aavmf_lock(substituted.as_bytes()).is_err());
        }

        #[test]
        fn receipt_and_manifest_semantics_preserve_nonclaims() {
            let receipt = [
                "format=a-quo-omarchy-ubuntu-apt-candidate-v1",
                "status=complete-candidate",
                "authority=none",
                "profile_id=a-quo-omarchy4-aarch64-dec29fa-v2",
                "profile_sha256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6",
                "ubuntu_oci_lock_sha256=synthetic",
                "builder_context_lock_sha256=synthetic",
                "snapshot_id=20260831T000000Z",
                "snapshot_selection_authority=caller-supplied-none",
                "original_archive=http://ports.ubuntu.com/ubuntu-ports/",
                "effective_snapshot_archive=https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/",
                "archive_equivalence_to_original_ports=not-established",
                "apt_version=synthetic",
                "apt_sandbox_user=synthetic",
                "transport_ca_bundle_sha256=synthetic",
                "transport_ca_bundle_source=synthetic",
                "ubuntu_archive_signature_verification=performed-by-apt-not-independently-replayed",
                "top_level_request_count=14",
                "object_count=122",
                "index_count=19",
                "package_count=93",
                "object_manifest_sha256=731cde75cece74a2b22cb22e24484951420b44321453fe1abd898b16744ebdaf",
                "captured_byte_identity=verified-non-authoritative",
                "apt_solver_execution=reported-by-acquirer-not-replayed",
                "apt_solver_reexecution=false",
                "transitive_closure_independently_recomputed=false",
                "package_installation=false",
                "dpkg_transaction=false",
                "maintainer_scripts_executed=false",
                "publisher_authentication=not-established",
                "trusted_time=not-established",
                "freshness=not-established",
                "safety=not-established",
                "build_authorization=not-established",
                "final_builder_image=not-established",
                "acquisition_network_activity=true",
                "network_destination_allowlist=not-established",
                "vm_started=false",
            ]
            .join("\n")
                + "\n";
            verify_receipt_semantics(receipt.as_bytes()).unwrap();
            let target = "package|packages/qemu-efi-aarch64_2024.02-2ubuntu0.9_all.deb|4115104|50d7c5f780f215db81677e08d21e681b61295ffe9040429cff9d9c2a0d03fe3d";
            let hash = "0".repeat(64);
            let mut manifest =
                vec!["format=a-quo-omarchy-ubuntu-apt-object-manifest-v1".to_owned()];
            for index in 0..19 {
                manifest.push(format!("index|indexes/{index}|1|{hash}"));
            }
            manifest.push(target.to_owned());
            for index in 1..93 {
                manifest.push(format!("package|packages/synthetic-{index}.deb|1|{hash}"));
            }
            for index in 0..10 {
                manifest.push(format!("state|state/synthetic-{index}|1|{hash}"));
            }
            let manifest = manifest.join("\n") + "\n";
            verify_manifest_semantics(manifest.as_bytes(), &[target]).unwrap();
            let mut changed = receipt.into_bytes();
            let needle = b"authority=none";
            let offset = changed
                .windows(needle.len())
                .position(|part| part == needle)
                .unwrap();
            changed[offset..offset + needle.len()].copy_from_slice(b"authority=root");
            assert!(verify_receipt_semantics(&changed).is_err());
        }

        #[test]
        fn deb_parser_rejects_bad_magic_truncation_and_trailing_bytes() {
            let mut minimal = b"!<arch>\n".to_vec();
            for (name, body) in [
                ("debian-binary/", b"2.0\n".as_slice()),
                ("control.tar.zst/", b"x".as_slice()),
                ("data.tar.zst/", b"y".as_slice()),
            ] {
                let header = format!(
                    "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    0,
                    0,
                    0,
                    100644,
                    body.len()
                );
                assert_eq!(header.len(), 60);
                minimal.extend_from_slice(header.as_bytes());
                minimal.extend_from_slice(body);
                if body.len() % 2 == 1 {
                    minimal.push(b'\n');
                }
            }
            assert_eq!(parse_deb(&minimal).unwrap().len(), 3);
            let mut bad_magic = minimal.clone();
            bad_magic[0] = b'?';
            assert!(parse_deb(&bad_magic).is_err());
            assert!(parse_deb(&minimal[..minimal.len() - 1]).is_err());
            minimal.extend_from_slice(b"trailing");
            assert!(parse_deb(&minimal).is_err());
        }

        #[test]
        fn tar_path_policy_rejects_traversal_and_noncanonical_forms() {
            assert!(canonical_tar_path(b"./usr/share/AAVMF/AAVMF_CODE.fd"));
            for rejected in [
                b"../escape".as_slice(),
                b"./../escape",
                b"./usr/../../escape",
                b"./usr//share/file",
                b"/absolute",
                b"./bad\0name",
            ] {
                assert!(!canonical_tar_path(rejected));
            }
        }

        #[test]
        fn canonical_inspection_binds_digest_and_reports_nonclaims() {
            let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let lock_path = repository.join(CANONICAL_LOCK_PATH);
            let profile_path = repository
                .join("packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile");
            let digest = sha256(LOCK_BYTES);
            let expectation = ExternalLockExpectation {
                repository: CANONICAL_REPOSITORY.to_owned(),
                commit: "0000000000000000000000000000000000000000".to_owned(),
                path: CANONICAL_LOCK_PATH.to_owned(),
                sha256: digest,
            };
            let report = inspect_aavmf_lock(&lock_path, &expectation, &profile_path)
                .unwrap()
                .render();
            assert_eq!(
                report,
                include_str!("../tests/fixtures/aavmf-inspect.report")
            );
            for expected in [
                "verification_status=verified-aavmf-lock-and-profile-only",
                "object_bytes_verified=false",
                "class_02_lock_status=not-established",
                "archive_equivalence_to_original_ports=not-established",
                "publisher_authentication=not-established",
                "safety=not-established",
                "archive_filesystem_extraction=false",
                "package_manager_execution=false",
                "vm_execution=false",
            ] {
                assert!(
                    report.lines().any(|line| line == expected),
                    "missing {expected}"
                );
            }
            let mut wrong = expectation;
            wrong.sha256 = "0".repeat(64);
            assert!(inspect_aavmf_lock(&lock_path, &wrong, &profile_path).is_err());
        }

        #[test]
        fn implementation_has_no_execution_network_or_extraction_surface() {
            let source = include_str!("aavmf.rs");
            let production = source.split("#[cfg(test)]").next().unwrap();
            for forbidden in [
                "Command::new(",
                "std::process",
                "std::net",
                "TcpStream",
                "UdpSocket",
                "reqwest",
                "unpack(",
                "unpack_in(",
                "persist(",
                "Command::new(\"mount\")",
                "Command::new(\"qemu-system",
                "Command::new(\"dpkg\")",
                "Command::new(\"apt-get\")",
            ] {
                assert!(
                    !production.contains(forbidden),
                    "forbidden surface: {forbidden}"
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{inspect_aavmf_lock, verify_aavmf_inputs};

#[cfg(not(target_os = "linux"))]
pub fn inspect_aavmf_lock(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
) -> Result<AavmfVerificationReport> {
    anyhow::bail!("the AAVMF input-lock verifier requires Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn verify_aavmf_inputs(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
    _input_directory: &Path,
) -> Result<AavmfVerificationReport> {
    anyhow::bail!("the AAVMF input-lock verifier requires Linux")
}
