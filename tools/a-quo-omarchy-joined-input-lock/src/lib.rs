#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;

pub const MAX_LOCK_BYTES: u64 = 64 * 1024;
pub const MAX_PROFILE_BYTES: u64 = 64 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_POLICY_FILE_BYTES: u64 = 1024 * 1024;

const LOCK_REPOSITORY: &str = "https://github.com/SurreptitiousFabric/a-quo.git";
const LOCK_PATH: &str =
    "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1.lock";
const PROFILE_ID: &str = "a-quo-omarchy4-aarch64-dec29fa-v2";
const PROFILE_SHA256: &str = "3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6";
const POLICY_COMMIT: &str = "783ebf708b12be2f2bff16a2a2e3f47c0837ce90";
const CANONICAL_PROFILE: &str =
    include_str!("../../../packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile");

const LOCK_KEYS: &[&str] = &[
    "format",
    "lock_id",
    "state",
    "lock_authority",
    "evaluator_arming",
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
    "policy_repository",
    "policy_commit",
    "policy_commit_authentication",
    "input_class",
    "selected_input_scope",
    "artifact_count",
    "artifact_01",
    "artifact_02",
    "artifact_03",
    "artifact_04",
    "fixture_registry_path",
    "fixture_registry_sha256",
    "fixture_source_commit",
    "fixture_v1_source_tree",
    "fixture_v2_source_tree",
    "fixture_reproducibility",
    "policy_file_count",
    "policy_file_01",
    "policy_file_02",
    "policy_file_03",
    "policy_file_04",
    "policy_file_05",
    "policy_file_06",
    "object_count",
    "input_class_10_exact_selection_closed",
    "profile_unresolved_input_count",
    "remaining_input_count_if_lock_is_adopted",
    "package_static_verification",
    "package_signatures",
    "fixture_signatures",
    "source_to_binary_provenance",
    "evaluator_execution",
    "package_manager_execution",
    "network_access",
    "mount_execution",
    "vm_execution",
    "physical_target_evidence",
    "clean_system_claim",
    "lifecycle_evidence",
    "aarch64_evaluation_gate_satisfied",
    "cross_profile_evidence_accepted",
    "safety",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactSpec {
    pub role: String,
    pub input_name: String,
    pub kind: String,
    pub source_commit: String,
    pub version: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFileSpec {
    pub role: String,
    pub input_name: String,
    pub source_path: String,
    pub git_mode: String,
    pub git_blob_sha1: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputLock {
    pub fields: BTreeMap<String, String>,
    pub artifacts: Vec<ArtifactSpec>,
    pub policy_files: Vec<PolicyFileSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalLockExpectation {
    pub repository: String,
    pub commit: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerificationMode {
    LockAndProfile,
    InputSelection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    mode: VerificationMode,
    pub external_lock_repository: String,
    pub external_lock_commit: String,
    pub external_lock_path: String,
    pub lock_id: String,
    pub lock_sha256: String,
    pub profile_id: String,
    pub profile_sha256: String,
    pub policy_commit: String,
    pub object_records: Vec<String>,
}

impl VerificationReport {
    pub fn render(&self) -> String {
        let complete = self.mode == VerificationMode::InputSelection;
        let mut lines = vec![
            if complete {
                "verification_status=verified-joined-lifecycle-input-selection".to_owned()
            } else {
                "verification_status=verified-lock-and-profile-only".to_owned()
            },
            "lock_authority=exact-byte-selection-only".to_owned(),
            format!("external_lock_repository={}", self.external_lock_repository),
            format!("external_lock_commit={}", self.external_lock_commit),
            format!("external_lock_path={}", self.external_lock_path),
            format!("lock_id={}", self.lock_id),
            format!("lock_sha256={}", self.lock_sha256),
            format!("profile_id={}", self.profile_id),
            format!("profile_sha256={}", self.profile_sha256),
            "target_kind=virtual-reference-target".to_owned(),
            "architecture=aarch64".to_owned(),
            "evidence_namespace=phase-a-aarch64-dec29fa".to_owned(),
            format!("policy_commit={}", self.policy_commit),
            "input_class=10-evaluator-scripts-and-fixture-input-lock".to_owned(),
            "locked_object_count=10".to_owned(),
            format!("verified_object_count={}", self.object_records.len()),
        ];
        for (index, record) in self.object_records.iter().enumerate() {
            lines.push(format!("object_{:02}={record}", index + 1));
        }
        lines.extend([
            format!("object_bytes_verified={complete}"),
            format!("sealed_snapshot_verification={complete}"),
            format!("input_class_10_exact_selection_closed={complete}"),
            if complete {
                "remaining_input_count_if_lock_is_adopted=9".to_owned()
            } else {
                "remaining_input_count_if_lock_is_adopted=not-evaluated".to_owned()
            },
            "external_lock_authentication_required=true".to_owned(),
            "external_lock_authentication_established_by_verifier=false".to_owned(),
            "policy_commit_authentication=not-established".to_owned(),
            "durable_retention=not-established".to_owned(),
            "package_static_verification=not-performed-by-input-lock".to_owned(),
            "package_signatures=absent".to_owned(),
            "fixture_signatures=absent".to_owned(),
            "source_to_binary_provenance=not-established".to_owned(),
            "evaluator_arming_authorized=false".to_owned(),
            "evaluator_execution=false".to_owned(),
            "package_manager_execution=false".to_owned(),
            "network_activity=false".to_owned(),
            "whole_machine_network_silence=not-established".to_owned(),
            "mount_execution=false".to_owned(),
            "vm_execution=false".to_owned(),
            "physical_target_evidence=false".to_owned(),
            "clean_system_claim=not-established".to_owned(),
            "lifecycle_evidence=false".to_owned(),
            "aarch64_evaluation_gate_satisfied=false".to_owned(),
            "cross_profile_evidence_accepted=false".to_owned(),
            "safety=not-established".to_owned(),
        ]);
        lines.join("\n") + "\n"
    }
}

fn field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .with_context(|| format!("record is missing {key}"))
}

fn require(fields: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<()> {
    ensure!(
        field(fields, key)? == expected,
        "{key} differs from the closed value"
    );
    Ok(())
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_input_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains("//")
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        })
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn git_blob_sha1(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn parse_ordered_record(
    bytes: &[u8],
    expected_keys: &[&str],
    label: &str,
) -> Result<BTreeMap<String, String>> {
    ensure!(!bytes.is_empty(), "{label} is empty");
    ensure!(
        bytes.len() as u64 <= MAX_LOCK_BYTES,
        "{label} exceeds its byte bound"
    );
    ensure!(
        bytes.last() == Some(&b'\n'),
        "{label} lacks its final newline"
    );
    ensure!(
        !bytes.contains(&b'\r') && !bytes.contains(&0),
        "{label} has forbidden bytes"
    );
    let text = std::str::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let mut fields = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        ensure!(index < expected_keys.len(), "{label} has an extra field");
        ensure!(
            !line.is_empty()
                && line.len() <= 2048
                && line
                    .bytes()
                    .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte)),
            "{label} line {} is empty or not printable ASCII",
            index + 1
        );
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("{label} line {} is malformed", index + 1))?;
        ensure!(
            key == expected_keys[index],
            "{label} key order differs at line {}",
            index + 1
        );
        ensure!(!value.is_empty(), "{label} field {key} is empty");
        ensure!(
            fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "{label} repeats {key}"
        );
    }
    ensure!(fields.len() == expected_keys.len(), "{label} is incomplete");
    Ok(fields)
}

pub fn parse_input_lock(bytes: &[u8]) -> Result<InputLock> {
    let fields = parse_ordered_record(bytes, LOCK_KEYS, "joined-lifecycle input lock")?;
    for (key, expected) in [
        ("format", "a-quo-omarchy-joined-lifecycle-input-lock-v1"),
        (
            "lock_id",
            "a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1",
        ),
        ("state", "reviewed-input-selection"),
        ("lock_authority", "exact-byte-selection-only"),
        ("evaluator_arming", "not-authorized"),
        ("build_authorization", "not-established"),
        ("runnable", "false"),
        ("retention", "caller-supplied-local-exact-bytes-required"),
        ("durable_retention", "not-established"),
        ("lock_authentication", "external-pinned-git-object-required"),
        ("self_authentication", "none"),
        ("lock_repository", LOCK_REPOSITORY),
        ("lock_path", LOCK_PATH),
        ("profile_repository", LOCK_REPOSITORY),
        ("profile_commit", "e13e74dca3472e54501b35c9b57ee89f57c6aed3"),
        (
            "profile_path",
            "packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile",
        ),
        ("profile_sha256", PROFILE_SHA256),
        ("profile_id", PROFILE_ID),
        ("profile_state", "bootstrap-unarmed"),
        ("profile_armable", "false"),
        ("profile_field_count", "129"),
        ("target_kind", "virtual-reference-target"),
        ("architecture", "aarch64"),
        ("evidence_namespace", "phase-a-aarch64-dec29fa"),
        ("policy_repository", LOCK_REPOSITORY),
        ("policy_commit", POLICY_COMMIT),
        ("policy_commit_authentication", "not-established"),
        ("input_class", "10-evaluator-scripts-and-fixture-input-lock"),
        (
            "selected_input_scope",
            "two-a-quo-packages-two-joined-fixtures-six-policy-files",
        ),
        ("artifact_count", "4"),
        (
            "fixture_registry_path",
            "fixtures/omarchy/joined-lifecycle-v1/sources.json",
        ),
        (
            "fixture_registry_sha256",
            "73037188e202b9e06f8c402e494ad0aaf9a072deeac343b4b24cd5ca00e4fda0",
        ),
        (
            "fixture_source_commit",
            "54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04",
        ),
        (
            "fixture_v1_source_tree",
            "8672d1283d23be50affecbd79f4a94f49f51c4d4",
        ),
        (
            "fixture_v2_source_tree",
            "70d9948522bf458b70bf2b053958661814fbfb82",
        ),
        (
            "fixture_reproducibility",
            "deterministic-same-host-contract-only",
        ),
        ("policy_file_count", "6"),
        ("object_count", "10"),
        ("input_class_10_exact_selection_closed", "true"),
        ("profile_unresolved_input_count", "10"),
        ("remaining_input_count_if_lock_is_adopted", "9"),
        ("package_static_verification", "not-performed-by-input-lock"),
        ("package_signatures", "absent"),
        ("fixture_signatures", "absent"),
        ("source_to_binary_provenance", "not-established"),
        ("evaluator_execution", "forbidden"),
        ("package_manager_execution", "forbidden"),
        ("network_access", "forbidden"),
        ("mount_execution", "forbidden"),
        ("vm_execution", "forbidden"),
        ("physical_target_evidence", "false"),
        ("clean_system_claim", "not-established"),
        ("lifecycle_evidence", "false"),
        ("aarch64_evaluation_gate_satisfied", "false"),
        ("cross_profile_evidence_accepted", "false"),
        ("safety", "not-established"),
    ] {
        require(&fields, key, expected)?;
    }
    for key in ["profile_sha256", "fixture_registry_sha256"] {
        ensure!(
            valid_hex(field(&fields, key)?, 64),
            "{key} is not one lowercase SHA-256"
        );
    }
    for key in [
        "profile_commit",
        "policy_commit",
        "fixture_source_commit",
        "fixture_v1_source_tree",
        "fixture_v2_source_tree",
    ] {
        ensure!(
            valid_hex(field(&fields, key)?, 40),
            "{key} is not one lowercase Git object identifier"
        );
    }
    ensure!(
        valid_relative_path(field(&fields, "profile_path")?),
        "profile path is unsafe"
    );
    ensure!(
        valid_relative_path(field(&fields, "fixture_registry_path")?),
        "fixture registry path is unsafe"
    );

    let expected_artifacts = [
        (
            "old-a-quo-package",
            "a-quo-0.1.0.r51.g50945229817f-1-aarch64.pkg.tar.zst",
            "arch-package",
            "50945229817f2b5c29166d502f8d702dc0c61bcd",
            "0.1.0.r51.g50945229817f-1",
            12_089_177,
            "54d8b225f4f6f26e1ae7b9d46ec398147f25d40f475d9b619aee63d769190a30",
        ),
        (
            "new-a-quo-package",
            "a-quo-0.1.0.r61.g81658b7f8d48-1-aarch64.pkg.tar.zst",
            "arch-package",
            "81658b7f8d48b0fdadc860edd1b27e1bf4da7d2f",
            "0.1.0.r61.g81658b7f8d48-1",
            12_169_663,
            "ff906394c5fc3346db2e46f9d340d7ad49249380797b759caaef152b4432631d",
        ),
        (
            "joined-fixture-v1",
            "aquo.test.joined-lifecycle-1.0.0.pkg.tar.zst",
            "omarchy-plugin-package",
            "54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04",
            "1.0.0",
            1_119,
            "2141fc8de82f40ac6a44b412e640846667b0cc78fd7b83280d157c24f87eaa71",
        ),
        (
            "joined-fixture-v2",
            "aquo.test.joined-lifecycle-2.0.0.pkg.tar.zst",
            "omarchy-plugin-package",
            "54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04",
            "2.0.0",
            1_159,
            "806966a0bf27e902fc1e059c2a7004c72afcce085039c568c4ac5e17fead130a",
        ),
    ];
    let mut artifacts = Vec::with_capacity(expected_artifacts.len());
    let mut names = BTreeSet::new();
    for (index, expected) in expected_artifacts.iter().enumerate() {
        let key = format!("artifact_{:02}", index + 1);
        let parts = field(&fields, &key)?.split('|').collect::<Vec<_>>();
        ensure!(parts.len() == 7, "{key} does not have seven fields");
        ensure!(
            parts[0] == expected.0
                && parts[1] == expected.1
                && parts[2] == expected.2
                && parts[3] == expected.3
                && parts[4] == expected.4,
            "{key} differs from its frozen identity"
        );
        let size = parts[5]
            .parse::<u64>()
            .with_context(|| format!("{key} has an invalid size"))?;
        ensure!(
            size == expected.5 && size <= MAX_ARTIFACT_BYTES,
            "{key} has the wrong bounded size"
        );
        ensure!(
            parts[6] == expected.6 && valid_hex(parts[6], 64),
            "{key} has the wrong SHA-256"
        );
        ensure!(
            valid_input_name(parts[1]) && names.insert(parts[1]),
            "{key} has an unsafe or repeated input name"
        );
        ensure!(
            valid_hex(parts[3], 40),
            "{key} has an invalid source commit"
        );
        artifacts.push(ArtifactSpec {
            role: parts[0].to_owned(),
            input_name: parts[1].to_owned(),
            kind: parts[2].to_owned(),
            source_commit: parts[3].to_owned(),
            version: parts[4].to_owned(),
            size,
            sha256: parts[6].to_owned(),
        });
    }

    let expected_policy = [
        (
            "package-lifecycle-bridge",
            "package-lifecycle-bridge.sh",
            "scripts/test-installed-a-quo-package-lifecycle.sh",
            "100755",
            "350dad4da9ebdbfc83b863fdce63332a32f287d8",
            80_972,
            "ea046ec970a13daab18abddf235998a80c2dd3ecf266e44ca2ea9c2e252b647c",
        ),
        (
            "consent-lifecycle-evaluator",
            "consent-lifecycle-evaluator.sh",
            "scripts/test-installed-a-quo-consent-lifecycle.sh",
            "100755",
            "d2f05a3d5ec1b8c891287d8aa91967c77ef1b204",
            83_424,
            "5f9aa3c275185b65fc28be354e39ce9035cabe15033d1966a6f1cbf79e7b9201",
        ),
        (
            "omarchy-core-lifecycle-evaluator",
            "omarchy-core-lifecycle-evaluator.sh",
            "scripts/test-installed-omarchy-core-lifecycle.sh",
            "100755",
            "57a2538cf7165a7b0f284f44ab93495b2ebaaad0",
            76_930,
            "b0258322267fedc0b486aa5d8e323184dd1888022784b944f2318a0a76d327c3",
        ),
        (
            "arch-package-verifier",
            "arch-package-verifier.sh",
            "scripts/verify-arch-package-skeleton.sh",
            "100755",
            "c5d24b48ffffe0b603003bdc26070e3e2fd57734",
            16_798,
            "f0427319b1d6903261903c3756d1c2bf77b261be9a298b413fe317c41d495c92",
        ),
        (
            "arch-package-target-resolver",
            "arch-package-target-resolver.sh",
            "scripts/resolve-arch-package-target.sh",
            "100755",
            "161c327561d152543143cd6b0095fddcd7b713f3",
            7_863,
            "e1cbb386db5f890ae61509a2ca33acd6180c459c4a9778c203f9cefbe9b88831",
        ),
        (
            "aarch64-target-profile",
            "aarch64-target.profile",
            "packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile",
            "100644",
            "e1fdce869af4ba53b0a02ecf7afa2d24179efc45",
            10_526,
            PROFILE_SHA256,
        ),
    ];
    let mut policy_files = Vec::with_capacity(expected_policy.len());
    for (index, expected) in expected_policy.iter().enumerate() {
        let key = format!("policy_file_{:02}", index + 1);
        let parts = field(&fields, &key)?.split('|').collect::<Vec<_>>();
        ensure!(parts.len() == 7, "{key} does not have seven fields");
        ensure!(
            parts[0] == expected.0
                && parts[1] == expected.1
                && parts[2] == expected.2
                && parts[3] == expected.3
                && parts[4] == expected.4,
            "{key} differs from its frozen identity"
        );
        let size = parts[5]
            .parse::<u64>()
            .with_context(|| format!("{key} has an invalid size"))?;
        ensure!(
            size == expected.5 && size <= MAX_POLICY_FILE_BYTES,
            "{key} has the wrong bounded size"
        );
        ensure!(
            parts[6] == expected.6 && valid_hex(parts[6], 64),
            "{key} has the wrong SHA-256"
        );
        ensure!(
            valid_input_name(parts[1]) && names.insert(parts[1]),
            "{key} has an unsafe or repeated input name"
        );
        ensure!(
            valid_relative_path(parts[2]),
            "{key} has an unsafe source path"
        );
        ensure!(valid_hex(parts[4], 40), "{key} has an invalid Git blob ID");
        policy_files.push(PolicyFileSpec {
            role: parts[0].to_owned(),
            input_name: parts[1].to_owned(),
            source_path: parts[2].to_owned(),
            git_mode: parts[3].to_owned(),
            git_blob_sha1: parts[4].to_owned(),
            size,
            sha256: parts[6].to_owned(),
        });
    }
    ensure!(
        artifacts.len() + policy_files.len() == 10 && names.len() == 10,
        "lock does not select ten unique inputs"
    );
    Ok(InputLock {
        fields,
        artifacts,
        policy_files,
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::AsRawFd;

    use a_quo_ipc::{SealedArtifact, snapshot_artifact};
    use rustix::fs::{Dir, FileType, Mode, OFlags, fstat, open, openat};
    use rustix::process::getuid;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SourceIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        size: i64,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    struct SnapshotEntry {
        name: String,
        identity: SourceIdentity,
        snapshot: SealedArtifact,
    }

    fn widen_u64<T: Into<u64>>(value: T) -> u64 {
        value.into()
    }

    fn identity(stat: &rustix::fs::Stat) -> SourceIdentity {
        SourceIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
            links: widen_u64(stat.st_nlink),
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: widen_u64(stat.st_mtime_nsec),
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: widen_u64(stat.st_ctime_nsec),
        }
    }

    fn reopen_pinned(pinned: &rustix::fd::OwnedFd) -> Result<rustix::fd::OwnedFd> {
        open(
            format!("/proc/self/fd/{}", pinned.as_raw_fd()),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .context("cannot reopen an O_PATH pin through procfs")
    }

    fn snapshot_path(path: &Path, maximum: u64) -> Result<SealedArtifact> {
        let pinned = open(
            path,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| format!("cannot pin {} without following links", path.display()))?;
        let before =
            fstat(&pinned).with_context(|| format!("cannot inspect {}", path.display()))?;
        ensure!(
            FileType::from_raw_mode(before.st_mode) == FileType::RegularFile,
            "snapshot source is not a regular file"
        );
        ensure!(
            before.st_size >= 0 && before.st_size as u64 <= maximum,
            "snapshot source exceeds its byte bound"
        );
        let readable = reopen_pinned(&pinned)?;
        let after = fstat(&readable).context("cannot inspect reopened snapshot source")?;
        ensure!(
            identity(&before) == identity(&after),
            "snapshot source identity changed before reading"
        );
        snapshot_artifact(readable, maximum).context("cannot create sealed snapshot")
    }

    fn snapshot_bytes(snapshot: &SealedArtifact, maximum: u64) -> Result<Vec<u8>> {
        ensure!(
            snapshot.descriptor().size <= maximum,
            "sealed snapshot exceeds its byte bound"
        );
        let mut file = snapshot
            .file()
            .try_clone()
            .context("cannot clone sealed descriptor")?;
        file.seek(SeekFrom::Start(0))
            .context("cannot rewind sealed descriptor")?;
        let mut bytes = Vec::with_capacity(snapshot.descriptor().size as usize);
        file.take(maximum + 1)
            .read_to_end(&mut bytes)
            .context("cannot read sealed snapshot")?;
        ensure!(
            bytes.len() as u64 == snapshot.descriptor().size,
            "sealed snapshot size changed"
        );
        Ok(bytes)
    }

    fn validate_external(expectation: &ExternalLockExpectation) -> Result<()> {
        ensure!(
            expectation.repository == LOCK_REPOSITORY,
            "unexpected external lock repository"
        );
        ensure!(
            expectation.path == LOCK_PATH,
            "unexpected external lock path"
        );
        ensure!(
            valid_hex(&expectation.commit, 40),
            "external lock commit is not one lowercase Git object identifier"
        );
        ensure!(
            valid_hex(&expectation.sha256, 64),
            "external lock SHA-256 is malformed"
        );
        Ok(())
    }

    fn verify_profile(lock: &InputLock, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes == CANONICAL_PROFILE.as_bytes(),
            "profile is not the canonical frozen v2 bytes"
        );
        ensure!(
            sha256(bytes) == field(&lock.fields, "profile_sha256")?,
            "profile SHA-256 differs from the lock"
        );
        let mut values = BTreeMap::new();
        for (index, line) in CANONICAL_PROFILE.lines().enumerate() {
            let (key, value) = line
                .split_once('=')
                .with_context(|| format!("profile line {} is malformed", index + 1))?;
            ensure!(values.insert(key, value).is_none(), "profile repeats {key}");
        }
        ensure!(values.len() == 129, "profile field count is not 129");
        ensure!(
            values.get("profile_id") == Some(&PROFILE_ID),
            "profile ID differs from the lock"
        );
        ensure!(
            values.get("state") == Some(&"bootstrap-unarmed")
                && values.get("armable") == Some(&"false"),
            "profile is not unarmed"
        );
        ensure!(
            values.get("architecture") == Some(&"aarch64"),
            "profile architecture is not AArch64"
        );
        ensure!(
            values.get("unresolved_input_count") == Some(&"10")
                && values.get("unresolved_input_10")
                    == Some(&"evaluator-scripts-and-fixture-input-lock"),
            "profile input class 10 differs from the lock"
        );
        Ok(())
    }

    fn prepare(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<(InputLock, SealedArtifact, SealedArtifact)> {
        validate_external(expectation)?;
        let lock_snapshot = snapshot_path(lock_path, MAX_LOCK_BYTES)?;
        ensure!(
            lock_snapshot.descriptor().digest.value == expectation.sha256,
            "lock bytes do not match the externally expected SHA-256"
        );
        let lock = parse_input_lock(&snapshot_bytes(&lock_snapshot, MAX_LOCK_BYTES)?)?;
        require(&lock.fields, "lock_repository", &expectation.repository)?;
        require(&lock.fields, "lock_path", &expectation.path)?;
        let profile_snapshot = snapshot_path(profile_path, MAX_PROFILE_BYTES)?;
        verify_profile(
            &lock,
            &snapshot_bytes(&profile_snapshot, MAX_PROFILE_BYTES)?,
        )?;
        Ok((lock, lock_snapshot, profile_snapshot))
    }

    fn report(
        lock: &InputLock,
        expectation: &ExternalLockExpectation,
        records: Vec<String>,
        mode: VerificationMode,
    ) -> Result<VerificationReport> {
        Ok(VerificationReport {
            mode,
            external_lock_repository: expectation.repository.clone(),
            external_lock_commit: expectation.commit.clone(),
            external_lock_path: expectation.path.clone(),
            lock_id: field(&lock.fields, "lock_id")?.to_owned(),
            lock_sha256: expectation.sha256.clone(),
            profile_id: field(&lock.fields, "profile_id")?.to_owned(),
            profile_sha256: field(&lock.fields, "profile_sha256")?.to_owned(),
            policy_commit: field(&lock.fields, "policy_commit")?.to_owned(),
            object_records: records,
        })
    }

    pub(super) fn inspect_lock_impl(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<VerificationReport> {
        let (lock, _lock_snapshot, _profile_snapshot) =
            prepare(lock_path, expectation, profile_path)?;
        report(
            &lock,
            expectation,
            Vec::new(),
            VerificationMode::LockAndProfile,
        )
    }

    fn expected_inventory(
        directory: &rustix::fd::OwnedFd,
        expected: &BTreeSet<String>,
    ) -> Result<()> {
        let readable = openat(
            directory,
            ".",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("cannot enumerate input directory")?;
        let mut observed = BTreeSet::new();
        for entry in Dir::new(readable).context("cannot create input-directory iterator")? {
            let entry = entry.context("cannot read input-directory entry")?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            ensure!(bytes.len() <= 128, "input filename exceeds its byte bound");
            let name = std::str::from_utf8(bytes).context("input filename is not UTF-8")?;
            ensure!(valid_input_name(name), "input filename is unsafe");
            ensure!(
                expected.contains(name),
                "input directory has an unexpected entry"
            );
            ensure!(
                observed.insert(name.to_owned()),
                "input directory repeats an entry"
            );
        }
        ensure!(
            &observed == expected,
            "input directory is missing an expected entry"
        );
        Ok(())
    }

    fn snapshot_entry(
        directory: &rustix::fd::OwnedFd,
        root_device: u64,
        name: &str,
        expected_size: u64,
        maximum: u64,
    ) -> Result<SnapshotEntry> {
        let pinned = openat(
            directory,
            name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| format!("cannot pin {name} without following links"))?;
        let before = fstat(&pinned).with_context(|| format!("cannot inspect {name}"))?;
        ensure!(
            FileType::from_raw_mode(before.st_mode) == FileType::RegularFile,
            "locked input is not a regular file: {name}"
        );
        ensure!(
            before.st_dev == root_device,
            "locked input crosses a filesystem boundary: {name}"
        );
        ensure!(
            before.st_uid == getuid().as_raw(),
            "locked input has the wrong owner: {name}"
        );
        ensure!(
            before.st_mode & 0o7777 == 0o400,
            "locked input mode is not inert 0400: {name}"
        );
        ensure!(
            before.st_nlink == 1,
            "locked input has multiple hard links: {name}"
        );
        ensure!(
            before.st_size >= 0
                && before.st_size as u64 == expected_size
                && expected_size <= maximum,
            "locked input has the wrong bounded size: {name}"
        );
        let readable = reopen_pinned(&pinned)?;
        let after = fstat(&readable).context("cannot inspect reopened locked input")?;
        ensure!(
            identity(&before) == identity(&after),
            "locked input identity changed before snapshotting: {name}"
        );
        let snapshot = snapshot_artifact(readable, maximum)
            .with_context(|| format!("cannot seal snapshot of {name}"))?;
        Ok(SnapshotEntry {
            name: name.to_owned(),
            identity: identity(&before),
            snapshot,
        })
    }

    fn current_identity(directory: &rustix::fd::OwnedFd, name: &str) -> Result<SourceIdentity> {
        let pinned = openat(
            directory,
            name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| format!("cannot re-pin input entry {name}"))?;
        let stat =
            fstat(&pinned).with_context(|| format!("cannot re-inspect input entry {name}"))?;
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
            "input entry type changed after snapshotting: {name}"
        );
        Ok(identity(&stat))
    }

    fn find_snapshot<'a>(snapshots: &'a [SnapshotEntry], name: &str) -> Result<&'a SnapshotEntry> {
        snapshots
            .iter()
            .find(|entry| entry.name == name)
            .with_context(|| format!("sealed snapshot is missing: {name}"))
    }

    fn verify_directory(lock: &InputLock, input_directory: &Path) -> Result<Vec<String>> {
        let root = open(
            input_directory,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("cannot open joined input directory without following links")?;
        let root_before = fstat(&root).context("cannot inspect joined input directory")?;
        ensure!(
            FileType::from_raw_mode(root_before.st_mode) == FileType::Directory,
            "input root is not a directory"
        );
        ensure!(
            root_before.st_uid == getuid().as_raw(),
            "input root has the wrong owner"
        );
        ensure!(
            root_before.st_mode & 0o7777 == 0o700,
            "input root mode is not 0700"
        );
        let root_identity = identity(&root_before);
        let mut names = BTreeSet::new();
        names.extend(lock.artifacts.iter().map(|spec| spec.input_name.clone()));
        names.extend(lock.policy_files.iter().map(|spec| spec.input_name.clone()));
        ensure!(
            names.len() == 10,
            "joined lock does not contain ten unique input names"
        );
        expected_inventory(&root, &names)?;

        let mut snapshots = Vec::with_capacity(10);
        for spec in &lock.artifacts {
            snapshots.push(snapshot_entry(
                &root,
                root_before.st_dev,
                &spec.input_name,
                spec.size,
                MAX_ARTIFACT_BYTES,
            )?);
        }
        for spec in &lock.policy_files {
            snapshots.push(snapshot_entry(
                &root,
                root_before.st_dev,
                &spec.input_name,
                spec.size,
                MAX_POLICY_FILE_BYTES,
            )?);
        }
        expected_inventory(&root, &names)?;
        ensure!(
            identity(&fstat(&root).context("cannot re-inspect input root")?) == root_identity,
            "input root identity changed during snapshotting"
        );
        for entry in &snapshots {
            ensure!(
                current_identity(&root, &entry.name)? == entry.identity,
                "input identity changed after snapshotting: {}",
                entry.name
            );
        }

        let mut records = Vec::with_capacity(10);
        for spec in &lock.artifacts {
            let entry = find_snapshot(&snapshots, &spec.input_name)?;
            ensure!(
                entry.snapshot.descriptor().size == spec.size,
                "artifact snapshot size differs from the lock: {}",
                spec.input_name
            );
            ensure!(
                entry.snapshot.descriptor().digest.value == spec.sha256,
                "artifact snapshot SHA-256 differs from the lock: {}",
                spec.input_name
            );
            records.push(format!(
                "{}|{}|{}|{}",
                spec.role, spec.input_name, spec.size, spec.sha256
            ));
        }
        for spec in &lock.policy_files {
            let entry = find_snapshot(&snapshots, &spec.input_name)?;
            ensure!(
                entry.snapshot.descriptor().size == spec.size,
                "policy snapshot size differs from the lock: {}",
                spec.input_name
            );
            ensure!(
                entry.snapshot.descriptor().digest.value == spec.sha256,
                "policy snapshot SHA-256 differs from the lock: {}",
                spec.input_name
            );
            let bytes = snapshot_bytes(&entry.snapshot, MAX_POLICY_FILE_BYTES)?;
            ensure!(
                git_blob_sha1(&bytes) == spec.git_blob_sha1,
                "policy snapshot Git blob differs from the lock: {}",
                spec.input_name
            );
            records.push(format!(
                "{}|{}|{}|{}",
                spec.role, spec.input_name, spec.size, spec.sha256
            ));
        }
        let profile_entry = find_snapshot(&snapshots, "aarch64-target.profile")?;
        verify_profile(
            lock,
            &snapshot_bytes(&profile_entry.snapshot, MAX_PROFILE_BYTES)?,
        )?;
        Ok(records)
    }

    pub(super) fn verify_inputs_impl(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
        input_directory: &Path,
    ) -> Result<VerificationReport> {
        let (lock, _lock_snapshot, _profile_snapshot) =
            prepare(lock_path, expectation, profile_path)?;
        let records = verify_directory(&lock, input_directory)?;
        report(
            &lock,
            expectation,
            records,
            VerificationMode::InputSelection,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};
        use tempfile::TempDir;

        fn inert_file(path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        }

        #[test]
        fn external_lock_and_profile_pins_are_mandatory() {
            let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1.lock");
            let profile_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile",
            );
            let bytes = fs::read(&lock_path).unwrap();
            let exact = ExternalLockExpectation {
                repository: LOCK_REPOSITORY.to_owned(),
                commit: "1".repeat(40),
                path: LOCK_PATH.to_owned(),
                sha256: sha256(&bytes),
            };
            inspect_lock_impl(&lock_path, &exact, &profile_path).unwrap();
            let mut wrong = exact.clone();
            wrong.sha256 = "0".repeat(64);
            assert!(inspect_lock_impl(&lock_path, &wrong, &profile_path).is_err());
            let mut wrong = exact.clone();
            wrong.repository = "https://example.invalid/a-quo.git".to_owned();
            assert!(inspect_lock_impl(&lock_path, &wrong, &profile_path).is_err());
            let mut wrong = exact.clone();
            wrong.commit = "A".repeat(40);
            assert!(inspect_lock_impl(&lock_path, &wrong, &profile_path).is_err());
        }

        #[test]
        fn file_gate_rejects_size_mode_link_and_symlink_before_hash_acceptance() {
            let temporary = TempDir::new().unwrap();
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let root = open(
                temporary.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let root_device = fstat(&root).unwrap().st_dev;
            let input = temporary.path().join("input");
            inert_file(&input, b"x");
            let error = snapshot_entry(&root, root_device, "input", 2, 2)
                .err()
                .expect("wrong-size input must fail");
            assert!(error.to_string().contains("wrong bounded size"));
            fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(snapshot_entry(&root, root_device, "input", 1, 2).is_err());
            fs::set_permissions(&input, fs::Permissions::from_mode(0o400)).unwrap();
            fs::hard_link(&input, temporary.path().join("other")).unwrap();
            assert!(snapshot_entry(&root, root_device, "input", 1, 2).is_err());
            fs::remove_file(temporary.path().join("other")).unwrap();
            fs::remove_file(&input).unwrap();
            symlink("missing", &input).unwrap();
            assert!(snapshot_entry(&root, root_device, "input", 1, 2).is_err());
        }

        #[test]
        fn inventory_rejects_extra_and_missing_entries() {
            let temporary = TempDir::new().unwrap();
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let root = open(
                temporary.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let expected = BTreeSet::from(["one".to_owned()]);
            inert_file(&temporary.path().join("one"), b"x");
            expected_inventory(&root, &expected).unwrap();
            inert_file(&temporary.path().join("extra"), b"x");
            assert!(expected_inventory(&root, &expected).is_err());
            fs::remove_file(temporary.path().join("extra")).unwrap();
            fs::remove_file(temporary.path().join("one")).unwrap();
            assert!(expected_inventory(&root, &expected).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub fn inspect_lock(
    lock_path: &Path,
    expectation: &ExternalLockExpectation,
    profile_path: &Path,
) -> Result<VerificationReport> {
    linux::inspect_lock_impl(lock_path, expectation, profile_path)
}

#[cfg(not(target_os = "linux"))]
pub fn inspect_lock(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
) -> Result<VerificationReport> {
    anyhow::bail!("the exact-descriptor joined-input verifier requires Linux")
}

#[cfg(target_os = "linux")]
pub fn verify_inputs(
    lock_path: &Path,
    expectation: &ExternalLockExpectation,
    profile_path: &Path,
    input_directory: &Path,
) -> Result<VerificationReport> {
    linux::verify_inputs_impl(lock_path, expectation, profile_path, input_directory)
}

#[cfg(not(target_os = "linux"))]
pub fn verify_inputs(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
    _input_directory: &Path,
) -> Result<VerificationReport> {
    anyhow::bail!("the exact-descriptor joined-input verifier requires Linux")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn lock_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1.lock")
    }

    #[test]
    fn canonical_lock_is_closed_and_conservative() {
        let lock = parse_input_lock(&std::fs::read(lock_path()).unwrap()).unwrap();
        assert_eq!(lock.artifacts.len(), 4);
        assert_eq!(lock.policy_files.len(), 6);
        assert_eq!(field(&lock.fields, "architecture").unwrap(), "aarch64");
        assert_eq!(
            field(&lock.fields, "evaluator_arming").unwrap(),
            "not-authorized"
        );
        assert_eq!(
            field(&lock.fields, "aarch64_evaluation_gate_satisfied").unwrap(),
            "false"
        );
    }

    #[test]
    fn reordered_unknown_duplicate_and_escalated_records_are_rejected() {
        let bytes = std::fs::read(lock_path()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let reordered = text.replace(
            "state=reviewed-input-selection\nlock_authority=exact-byte-selection-only\n",
            "lock_authority=exact-byte-selection-only\nstate=reviewed-input-selection\n",
        );
        assert!(parse_input_lock(reordered.as_bytes()).is_err());
        let unknown = text.replace(
            "safety=not-established\n",
            "unknown=true\nsafety=not-established\n",
        );
        assert!(parse_input_lock(unknown.as_bytes()).is_err());
        let duplicate = text.replace(
            "safety=not-established\n",
            "safety=not-established\nsafety=not-established\n",
        );
        assert!(parse_input_lock(duplicate.as_bytes()).is_err());
        let escalated = text.replace(
            "evaluator_arming=not-authorized",
            "evaluator_arming=authorized",
        );
        assert!(parse_input_lock(escalated.as_bytes()).is_err());
        let cross_profile = text.replace("architecture=aarch64", "architecture=x86_64");
        assert!(parse_input_lock(cross_profile.as_bytes()).is_err());
    }

    #[test]
    fn hash_helpers_match_known_vectors() {
        assert_eq!(
            sha256(b"test\n"),
            "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
        );
        assert_eq!(
            git_blob_sha1(b"test\n"),
            "9daeafb9864cf43055ae93beb0afd6c7d144bfa4"
        );
    }
}
