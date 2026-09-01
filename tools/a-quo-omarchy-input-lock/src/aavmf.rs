use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::{
    CANONICAL_V2_PROFILE, ExternalLockExpectation, MAX_LOCK_BYTES, MAX_PROFILE_BYTES, field,
    parse_ordered_record, parse_profile, require, valid_sha256,
};

const CANONICAL_REPOSITORY: &str = "https://github.com/SurreptitiousFabric/a-quo.git";
const CANONICAL_LOCK_PATH: &str =
    "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-aavmf-v1.lock";
pub(crate) const RECEIPT_BYTES: u64 = 1_688;
pub(crate) const MANIFEST_BYTES: u64 = 14_988;
const PACKAGE_BYTES: u64 = 4_115_104;

const LOCK_KEYS: &[&str] = &[
    "format",
    "lock_id",
    "state",
    "lock_authority",
    "build_authorization",
    "runnable",
    "retention",
    "durable_retention",
    "lock_authentication",
    "self_authentication",
    "lock_repository",
    "lock_path",
    "profile_repository",
    "profile_commit",
    "profile_path",
    "profile_sha256",
    "profile_id",
    "profile_state",
    "profile_armable",
    "profile_field_count",
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AavmfObjectSpec {
    pub role: String,
    pub path: String,
    pub media_type: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AavmfLock {
    pub fields: BTreeMap<String, String>,
    pub objects: Vec<AavmfObjectSpec>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerificationMode {
    LockAndProfile,
    InputSelection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AavmfVerificationReport {
    mode: VerificationMode,
    external_lock_repository: String,
    external_lock_commit: String,
    external_lock_path: String,
    lock_id: String,
    lock_sha256: String,
    profile_id: String,
    profile_sha256: String,
    object_records: Vec<String>,
}

impl AavmfVerificationReport {
    pub fn render(&self) -> String {
        let complete = self.mode == VerificationMode::InputSelection;
        let mut lines = vec![
            if complete {
                "verification_status=verified-aavmf-input-selection".to_owned()
            } else {
                "verification_status=verified-aavmf-lock-and-profile-only".to_owned()
            },
            "lock_authority=exact-deb-and-firmware-member-selection-only".to_owned(),
            format!("external_lock_repository={}", self.external_lock_repository),
            format!("external_lock_commit={}", self.external_lock_commit),
            format!("external_lock_path={}", self.external_lock_path),
            format!("lock_id={}", self.lock_id),
            format!("lock_sha256={}", self.lock_sha256),
            format!("profile_id={}", self.profile_id),
            format!("profile_sha256={}", self.profile_sha256),
            "architecture=aarch64".to_owned(),
            "evidence_namespace=phase-a-aarch64-dec29fa".to_owned(),
            "input_class=07-aavmf-firmware".to_owned(),
            "locked_object_count=3".to_owned(),
            format!("verified_object_count={}", self.object_records.len()),
        ];
        for (index, record) in self.object_records.iter().enumerate() {
            lines.push(format!("object_{:02}={record}", index + 1));
        }
        lines.extend([
            format!("object_bytes_verified={complete}"),
            format!("sealed_snapshot_verification={complete}"),
            format!("deb_structure_verified={complete}"),
            format!("firmware_members_verified={complete}"),
            "apt_candidate_status=complete-candidate-no-authority".to_owned(),
            "class_02_lock_status=not-established".to_owned(),
            "archive_equivalence_to_original_ports=not-established".to_owned(),
            "apt_signature_replay=not-independently-replayed".to_owned(),
            "external_lock_authentication_required=true".to_owned(),
            "external_lock_authentication_established_by_verifier=false".to_owned(),
            "profile_unresolved_input_count=10".to_owned(),
            "remaining_input_count_if_lock_is_adopted=9".to_owned(),
            "durable_retention=not-established".to_owned(),
            "build_authorization=not-established".to_owned(),
            "runnable=false".to_owned(),
            "publisher_authentication=not-established".to_owned(),
            "current_publisher_authorization=not-established".to_owned(),
            "trusted_time=not-established".to_owned(),
            "freshness=not-established".to_owned(),
            "source_to_firmware_provenance=not-established".to_owned(),
            "safety=not-established".to_owned(),
            "archive_filesystem_extraction=false".to_owned(),
            "package_manager_execution=false".to_owned(),
            "maintainer_scripts_executed=false".to_owned(),
            "verifier_network_activity=false".to_owned(),
            "whole_machine_network_silence=not-established".to_owned(),
            "mount_execution=false".to_owned(),
            "vm_execution=false".to_owned(),
        ]);
        lines.join("\n") + "\n"
    }
}

pub fn parse_aavmf_lock(bytes: &[u8]) -> Result<AavmfLock> {
    let fields = parse_ordered_record(bytes, LOCK_KEYS, "AAVMF input lock")?;
    for (key, expected) in [
        ("format", "a-quo-omarchy-aavmf-input-lock-v1"),
        ("lock_id", "a-quo-omarchy4-aarch64-dec29fa-aavmf-v1"),
        ("state", "reviewed-input-selection"),
        (
            "lock_authority",
            "exact-deb-and-firmware-member-selection-only",
        ),
        ("build_authorization", "not-established"),
        ("runnable", "false"),
        ("retention", "caller-supplied-local-exact-bytes-required"),
        ("durable_retention", "not-established"),
        ("lock_authentication", "external-pinned-git-object-required"),
        ("self_authentication", "none"),
        ("lock_repository", CANONICAL_REPOSITORY),
        ("lock_path", CANONICAL_LOCK_PATH),
        ("profile_repository", CANONICAL_REPOSITORY),
        ("profile_commit", "e13e74dca3472e54501b35c9b57ee89f57c6aed3"),
        (
            "profile_path",
            "packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile",
        ),
        (
            "profile_sha256",
            "3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6",
        ),
        ("profile_id", "a-quo-omarchy4-aarch64-dec29fa-v2"),
        ("profile_state", "bootstrap-unarmed"),
        ("profile_armable", "false"),
        ("profile_field_count", "129"),
        ("target_kind", "virtual-reference-target"),
        ("architecture", "aarch64"),
        ("evidence_namespace", "phase-a-aarch64-dec29fa"),
        ("input_class", "07-aavmf-firmware"),
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
        ("object_count", "3"),
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
    ensure!(
        valid_sha256(field(&fields, "profile_sha256")?),
        "invalid profile SHA-256"
    );
    ensure!(
        field(&fields, "profile_commit")?.len() == 40
            && field(&fields, "profile_commit")?
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "profile commit is not one lowercase Git object identifier"
    );

    const EXPECTED: &[(&str, &str, &str, u64, &str)] = &[
        (
            "apt-candidate-receipt",
            "receipt.apt.v1",
            "text/plain",
            RECEIPT_BYTES,
            "c99f29429d8d6f87c0651154dee28153af4b6d6c0c47908ca767067d3f1f5d13",
        ),
        (
            "apt-object-manifest",
            "objects.manifest",
            "text/plain",
            MANIFEST_BYTES,
            "731cde75cece74a2b22cb22e24484951420b44321453fe1abd898b16744ebdaf",
        ),
        (
            "qemu-efi-package",
            "qemu-efi-aarch64_2024.02-2ubuntu0.9_all.deb",
            "application/vnd.debian.binary-package",
            PACKAGE_BYTES,
            "50d7c5f780f215db81677e08d21e681b61295ffe9040429cff9d9c2a0d03fe3d",
        ),
    ];
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut objects = Vec::with_capacity(EXPECTED.len());
    for (index, expected) in EXPECTED.iter().enumerate() {
        let key = format!("object_{:02}", index + 1);
        let parts = field(&fields, &key)?.split('|').collect::<Vec<_>>();
        ensure!(parts.len() == 5, "{key} has the wrong field count");
        let size = parts[3]
            .parse::<u64>()
            .with_context(|| format!("{key} has an invalid size"))?;
        ensure!(
            (parts[0], parts[1], parts[2], size, parts[4]) == *expected,
            "{key} differs from the reviewed object policy"
        );
        ensure!(valid_sha256(parts[4]), "{key} has an invalid SHA-256");
        ensure!(roles.insert(parts[0]), "object role is duplicated");
        ensure!(paths.insert(parts[1]), "object path is duplicated");
        objects.push(AavmfObjectSpec {
            role: parts[0].to_owned(),
            path: parts[1].to_owned(),
            media_type: parts[2].to_owned(),
            size,
            sha256: parts[4].to_owned(),
        });
    }
    Ok(AavmfLock { fields, objects })
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
    ensure!(
        expectation.repository == CANONICAL_REPOSITORY,
        "external lock repository is not the canonical A Quo repository"
    );
    ensure!(
        expectation.path == CANONICAL_LOCK_PATH,
        "external lock path is not the canonical AAVMF lock path"
    );
    ensure!(
        expectation.commit.len() == 40
            && expectation
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "external lock commit is not one lowercase Git object identifier"
    );
    ensure!(
        valid_sha256(&expectation.sha256),
        "externally expected lock SHA-256 is malformed"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use a_quo_ipc::{SealedArtifact, snapshot_stream};
    use anyhow::{Context, Result, ensure};
    use sha2::{Digest, Sha256};
    use tar::EntryType;

    use super::*;
    use crate::linux::{snapshot_bytes, snapshot_exact_input_directory, snapshot_path};

    const CONTROL_TAR_MAXIMUM: u64 = 64 * 1024;
    const DATA_TAR_MAXIMUM: u64 = 512 * 1024 * 1024;
    const TARGET_CODE_PATH: &[u8] = b"./usr/share/AAVMF/AAVMF_CODE.no-secboot.fd";
    const TARGET_VARS_PATH: &[u8] = b"./usr/share/AAVMF/AAVMF_VARS.fd";
    const TARGET_LINK_PATH: &[u8] = b"./usr/share/AAVMF/AAVMF_CODE.fd";

    #[derive(Clone, Debug)]
    pub(crate) struct ArMember<'a> {
        pub(crate) name: String,
        pub(crate) bytes: &'a [u8],
    }

    pub(crate) fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn parse_decimal(bytes: &[u8], label: &str) -> Result<u64> {
        let text = std::str::from_utf8(bytes).context("ar numeric field is not ASCII")?;
        let trimmed = text.trim_matches(' ');
        ensure!(
            !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid ar {label}"
        );
        trimmed
            .parse()
            .with_context(|| format!("invalid ar {label}"))
    }

    pub(crate) fn parse_deb(bytes: &[u8]) -> Result<Vec<ArMember<'_>>> {
        ensure!(bytes.starts_with(b"!<arch>\n"), "invalid Debian ar magic");
        let mut offset = 8_usize;
        let mut members = Vec::with_capacity(3);
        while offset < bytes.len() {
            ensure!(members.len() < 3, "Debian archive has too many members");
            let end = offset.checked_add(60).context("ar header overflow")?;
            ensure!(end <= bytes.len(), "truncated ar header");
            let header = &bytes[offset..end];
            ensure!(&header[58..60] == b"`\n", "invalid ar header trailer");
            let raw_name = std::str::from_utf8(&header[..16]).context("ar name is not ASCII")?;
            let name = raw_name
                .trim_matches(' ')
                .strip_suffix('/')
                .unwrap_or(raw_name.trim_matches(' '));
            ensure!(
                !name.is_empty()
                    && name.len() <= 32
                    && name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    }),
                "invalid ar member name"
            );
            let size = parse_decimal(&header[48..58], "member size")?;
            let size = usize::try_from(size).context("ar member size does not fit memory")?;
            offset = end;
            let member_end = offset.checked_add(size).context("ar member overflow")?;
            ensure!(member_end <= bytes.len(), "truncated ar member");
            members.push(ArMember {
                name: name.to_owned(),
                bytes: &bytes[offset..member_end],
            });
            offset = member_end;
            if size % 2 == 1 {
                ensure!(
                    bytes.get(offset) == Some(&b'\n'),
                    "invalid ar alignment byte"
                );
                offset += 1;
            }
        }
        ensure!(offset == bytes.len(), "Debian archive has trailing bytes");
        ensure!(
            members.len() == 3,
            "Debian archive is not exactly three members"
        );
        Ok(members)
    }

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

    pub(crate) fn decompress_zstd(bytes: &[u8], maximum: u64) -> Result<SealedArtifact> {
        let decoder = zstd::stream::read::Decoder::new(Cursor::new(bytes))
            .context("cannot initialize zstd decoder")?;
        snapshot_stream(decoder, maximum).context("cannot snapshot bounded decompressed tar")
    }

    pub(crate) fn verify_receipt(bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() as u64 == RECEIPT_BYTES,
            "APT receipt has the wrong size"
        );
        verify_receipt_semantics(bytes)
    }

    fn verify_receipt_semantics(bytes: &[u8]) -> Result<()> {
        const REQUIRED: &[&str] = &[
            "format=a-quo-omarchy-ubuntu-apt-candidate-v1",
            "status=complete-candidate",
            "authority=none",
            "profile_id=a-quo-omarchy4-aarch64-dec29fa-v2",
            "profile_sha256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6",
            "snapshot_id=20260831T000000Z",
            "snapshot_selection_authority=caller-supplied-none",
            "original_archive=http://ports.ubuntu.com/ubuntu-ports/",
            "effective_snapshot_archive=https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/",
            "archive_equivalence_to_original_ports=not-established",
            "ubuntu_archive_signature_verification=performed-by-apt-not-independently-replayed",
            "object_count=122",
            "index_count=19",
            "package_count=93",
            "object_manifest_sha256=731cde75cece74a2b22cb22e24484951420b44321453fe1abd898b16744ebdaf",
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
            "vm_started=false",
        ];
        ensure!(
            bytes.last() == Some(&b'\n'),
            "APT receipt lacks its final LF"
        );
        let text = std::str::from_utf8(bytes).context("APT receipt is not UTF-8")?;
        ensure!(
            text.lines().count() == 38,
            "APT receipt has the wrong line count"
        );
        for required in REQUIRED {
            ensure!(
                text.lines().any(|line| line == *required),
                "APT receipt lacks required conservative state: {required}"
            );
        }
        Ok(())
    }

    pub(crate) fn verify_manifest(bytes: &[u8], expected_records: &[&str]) -> Result<()> {
        ensure!(
            bytes.len() as u64 == MANIFEST_BYTES,
            "APT manifest has the wrong size"
        );
        verify_manifest_semantics(bytes, expected_records)
    }

    fn verify_manifest_semantics(bytes: &[u8], expected_records: &[&str]) -> Result<()> {
        ensure!(
            !expected_records.is_empty() && expected_records.len() <= 8,
            "APT manifest expectation count is outside the closed bound"
        );
        let expected = expected_records.iter().copied().collect::<BTreeSet<_>>();
        ensure!(
            expected.len() == expected_records.len(),
            "APT manifest expectations repeat a record"
        );
        ensure!(
            bytes.last() == Some(&b'\n'),
            "APT manifest lacks its final LF"
        );
        ensure!(
            bytes
                .iter()
                .all(|byte| *byte == b'\n' || (0x20..=0x7e).contains(byte)),
            "APT manifest contains a forbidden byte"
        );
        let text = std::str::from_utf8(bytes).context("APT manifest is not UTF-8")?;
        let mut lines = text.lines();
        ensure!(
            lines.next() == Some("format=a-quo-omarchy-ubuntu-apt-object-manifest-v1"),
            "APT manifest format is wrong"
        );
        let mut paths = BTreeSet::new();
        let mut records = 0_usize;
        let mut indexes = 0_usize;
        let mut packages = 0_usize;
        let mut targets = BTreeMap::<&str, usize>::new();
        for line in lines {
            let parts = line.split('|').collect::<Vec<_>>();
            ensure!(
                parts.len() == 4,
                "APT manifest record has the wrong field count"
            );
            ensure!(
                parts[2].parse::<u64>().is_ok_and(|size| size > 0),
                "APT manifest record has an invalid size"
            );
            ensure!(
                valid_sha256(parts[3]),
                "APT manifest record has an invalid SHA-256"
            );
            ensure!(
                paths.insert(parts[1]),
                "APT manifest repeats an object path"
            );
            records += 1;
            indexes += usize::from(parts[0] == "index");
            packages += usize::from(parts[0] == "package");
            if expected.contains(line) {
                *targets.entry(line).or_default() += 1;
            }
        }
        ensure!(records == 122, "APT manifest does not contain 122 objects");
        ensure!(indexes == 19, "APT manifest does not contain 19 indexes");
        ensure!(packages == 93, "APT manifest does not contain 93 packages");
        ensure!(
            expected
                .iter()
                .all(|record| targets.get(record).copied() == Some(1)),
            "APT manifest does not bind every exact package record once"
        );
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

    pub(crate) fn canonical_tar_path(path: &[u8]) -> bool {
        path.starts_with(b"./")
            && !path.contains(&0)
            && !path.windows(2).any(|window| window == b"//")
            && !path.windows(4).any(|window| window == b"/../")
            && !path.ends_with(b"/..")
            && path.len() <= 255
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
        object_records: Vec<String>,
        mode: VerificationMode,
    ) -> AavmfVerificationReport {
        debug_assert!(
            (mode == VerificationMode::LockAndProfile && object_records.is_empty())
                || (mode == VerificationMode::InputSelection && object_records.len() == 3)
        );
        AavmfVerificationReport {
            mode,
            external_lock_repository: expectation.repository.clone(),
            external_lock_commit: expectation.commit.clone(),
            external_lock_path: expectation.path.clone(),
            lock_id: field(&lock.fields, "lock_id")
                .expect("validated lock")
                .to_owned(),
            lock_sha256: expectation.sha256.clone(),
            profile_id: field(&lock.fields, "profile_id")
                .expect("validated lock")
                .to_owned(),
            profile_sha256: field(&lock.fields, "profile_sha256")
                .expect("validated lock")
                .to_owned(),
            object_records,
        }
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
        Ok(report(
            &lock,
            expectation,
            Vec::new(),
            VerificationMode::LockAndProfile,
        ))
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
        verify_receipt(&receipt)?;
        verify_manifest(
            &manifest,
            &[field(&lock.fields, "apt_manifest_package_record")?],
        )?;
        verify_package(&package, &lock)?;
        let records = lock
            .objects
            .iter()
            .map(|object| {
                format!(
                    "{}|{}|{}|{}|{}",
                    object.role, object.path, object.media_type, object.size, object.sha256
                )
            })
            .collect();
        Ok(report(
            &lock,
            expectation,
            records,
            VerificationMode::InputSelection,
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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
