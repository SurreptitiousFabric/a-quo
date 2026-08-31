#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};

pub const MAX_LOCK_BYTES: u64 = 64 * 1024;
pub const MAX_PROFILE_BYTES: u64 = 64 * 1024;
pub const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1024;
const CANONICAL_PROFILE: &str =
    include_str!("../../../packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile");

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
    "subject_repository",
    "subject_commit",
    "subject_authentication",
    "current_publisher_authorization",
    "input_class",
    "selected_input_scope",
    "file_count",
    "file_01",
    "file_02",
    "file_03",
    "file_04",
    "file_05",
    "file_06",
    "file_07",
    "file_08",
    "file_09",
    "file_10",
    "dependency_route_count",
    "dependency_route_01",
    "dependency_route_02",
    "dependency_route_03",
    "dependency_route_04",
    "dependency_route_05",
    "dependency_route_06",
    "dependency_route_07",
    "dependency_route_08",
    "dependency_route_09",
    "dependency_route_10",
    "dependency_route_11",
    "dependency_route_12",
    "dependency_route_13",
    "dependency_route_14",
    "dependency_route_15",
    "dependency_route_16",
    "dependency_route_17",
    "unconsumed_input_09",
    "git_object_hash_algorithm",
    "source_checkout_consumed",
    "git_execution",
    "verifier_network_access",
    "harness_process_execution",
    "container_execution",
    "package_manager_execution",
    "mount_execution",
    "vm_execution",
    "final_builder_image",
    "source_to_image_provenance",
    "freshness",
    "safety",
    "profile_unresolved_input_count",
    "remaining_input_count_if_lock_is_adopted",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSpec {
    pub role: &'static str,
    pub path: &'static str,
    pub git_mode: &'static str,
    pub git_blob_sha1: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

pub const FILES: &[FileSpec] = &[
    FileSpec {
        role: "builder-definition",
        path: "test/vm/asahi-fresh/Dockerfile",
        git_mode: "100644",
        git_blob_sha1: "dd8d6e71e0ff14e91937c7763a176d24338d29fc",
        size: 409,
        sha256: "e77219761f9384f56831a07c8b2dfbdf101e5274d2409f7757ae9c015bffd139",
    },
    FileSpec {
        role: "harness-documentation",
        path: "test/vm/asahi-fresh/README.md",
        git_mode: "100644",
        git_blob_sha1: "18e59a324d0b2476607e520ad13b89179d7f0032",
        size: 1_341,
        sha256: "beea767fcac887a8332befdab4ee0f7fb11101d646fe76536bbcc571503306ab",
    },
    FileSpec {
        role: "base-image-builder",
        path: "test/vm/asahi-fresh/container/build-base",
        git_mode: "100755",
        git_blob_sha1: "8efbd82ed8d7562f457b24c9245badd887695b25",
        size: 6_352,
        sha256: "25762ae1a636a603427d16e21ac0331484d11b1557bb7f3d919bb9626579b734",
    },
    FileSpec {
        role: "vm-launcher",
        path: "test/vm/asahi-fresh/container/start-vm",
        git_mode: "100755",
        git_blob_sha1: "0647e5d4fb937048b9016ee2b69988e2b51b7ad0",
        size: 1_077,
        sha256: "66dd99fad26eee42cdf7062bfbeefc2951f7edf83114312217b007cb43e735e0",
    },
    FileSpec {
        role: "guest-installer",
        path: "test/vm/asahi-fresh/guest/install",
        git_mode: "100755",
        git_blob_sha1: "caad5eee58a533fbcf0408be3af702be37f11baf",
        size: 11_642,
        sha256: "c003bf3f58efaee2e4e4321da3a6969b897cf99687587ace5e6bf1634759d144",
    },
    FileSpec {
        role: "guest-rerun-check",
        path: "test/vm/asahi-fresh/guest/rerun",
        git_mode: "100755",
        git_blob_sha1: "6342e562dff33c1cb6abeff9b4e5e0ac8677edc5",
        size: 1_602,
        sha256: "ec5ec0da28d21946af6946d2d2ee9774d9f7fdd52d36f6361b91f6c58f6f5b48",
    },
    FileSpec {
        role: "guest-verifier",
        path: "test/vm/asahi-fresh/guest/verify",
        git_mode: "100755",
        git_blob_sha1: "d7ac8554ffe6edea4577ccfe2eb8958ca5d408d4",
        size: 3_227,
        sha256: "0de6da973c8c467c48c3a759f43b22c775232b29a99d5d62409b5a9f0dc0a6ad",
    },
    FileSpec {
        role: "harness-entrypoint",
        path: "test/vm/asahi-fresh/run",
        git_mode: "100755",
        git_blob_sha1: "5347c308e2a2988ac62e1e882f3177bed363a0f1",
        size: 3_597,
        sha256: "90f28d49c1e90f96e55ca6ea892a5177c5d384401f1743d0d7deda20457a0956",
    },
    FileSpec {
        role: "asahi-fresh-installer",
        path: "bin/omarchy-install-asahi-fresh",
        git_mode: "100755",
        git_blob_sha1: "5b351071c820c59edf238cb83f7f1344c8dfe5c5",
        size: 17_606,
        sha256: "e6bee59ec4e42e5c4678cd682016e7e4f57f208463c8b62e1a07a2e204bfebcf",
    },
    FileSpec {
        role: "asahi-bundle-updater",
        path: "bin/omarchy-update-asahi-bundle",
        git_mode: "100755",
        git_blob_sha1: "2b967c76d9d4f9ace291b4c8f82cd54b06d0abae",
        size: 14_494,
        sha256: "621df4ba4bc286e7b5b6541b38ec0043d95244ccbb04ee2c0f51fb0e559898a7",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DependencyRoute {
    input: &'static str,
    path: &'static str,
    literal: &'static [u8],
    sha256: &'static str,
    count: usize,
    label: &'static str,
}

const ROUTES: &[DependencyRoute] = &[
    DependencyRoute {
        input: "01",
        path: "test/vm/asahi-fresh/Dockerfile",
        literal: b"FROM ubuntu:24.04",
        sha256: "fd410507966cb0d19cfdda0d872f3bb53a2d0d760d7fcf00de7d3023efc04299",
        count: 1,
        label: "ubuntu-base-oci-and-final-builder-image",
    },
    DependencyRoute {
        input: "02",
        path: "test/vm/asahi-fresh/Dockerfile",
        literal: b"apt-get update && apt-get install -y --no-install-recommends",
        sha256: "ed4c894a31297a987816ad8cb742b74fc777b7071511cd42e39014115cfc67cc",
        count: 1,
        label: "ubuntu-apt-snapshot-and-package-closure",
    },
    DependencyRoute {
        input: "04",
        path: "test/vm/asahi-fresh/container/build-base",
        literal: b"https://ca.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz",
        sha256: "04786b808f80c4f6d026531e3790669fd419c5a3c122cde8fb8337830d7faa42",
        count: 1,
        label: "alarm-rootfs-bytes-and-signature",
    },
    DependencyRoute {
        input: "04",
        path: "test/vm/asahi-fresh/container/build-base",
        literal: b"hkps://keyserver.ubuntu.com",
        sha256: "3d4f49776118d479328bbc1382eb0a4ad71d2f4808f89788ae4171843959c9a0",
        count: 1,
        label: "alarm-builder-key-acquisition",
    },
    DependencyRoute {
        input: "05",
        path: "test/vm/asahi-fresh/container/build-base",
        literal: b"https://ca.us.mirror.archlinuxarm.org/$arch/$repo",
        sha256: "3f0d048c2751feb3c1c854ff2ea16f009d20776b27b9c4b737c154c5d3c4342a",
        count: 1,
        label: "alarm-pacman-mirror",
    },
    DependencyRoute {
        input: "05",
        path: "test/vm/asahi-fresh/container/build-base",
        literal: b"https://github.com/asahi-alarm/asahi-alarm/releases/download/$arch",
        sha256: "40b1d7500f2331bea0d607411c81543388df4a0a84d9ef3d19b4f44dbe6475ed",
        count: 1,
        label: "asahi-pacman-repository",
    },
    DependencyRoute {
        input: "06",
        path: "test/vm/asahi-fresh/container/start-vm",
        literal: b"qemu-system-aarch64",
        sha256: "022af0a178ee37e98747886ded9263a70f94e33bb3c3235eaca132e647b673f1",
        count: 1,
        label: "qemu-binary-and-machine-configuration",
    },
    DependencyRoute {
        input: "07",
        path: "test/vm/asahi-fresh/container/start-vm",
        literal: b"/usr/share/AAVMF/AAVMF_CODE.fd",
        sha256: "418ed38a896146d1b6ffbba8a3fc7f0497ebcda4b4c2384edb48d8ef8f3aada2",
        count: 1,
        label: "aavmf-code-firmware",
    },
    DependencyRoute {
        input: "08",
        path: "test/vm/asahi-fresh/container/start-vm",
        literal: b"/work/cache/archarm-base.qcow2",
        sha256: "5a19241a04fc6ca863e4d1cf5bcfd214532d28cbff89f23aea1c716fbf1faad9",
        count: 1,
        label: "base-qcow2",
    },
    DependencyRoute {
        input: "10",
        path: "test/vm/asahi-fresh/guest/install",
        literal: b"https://github.com/maralcbr/omarchy-mx-mac/releases/latest/download",
        sha256: "11905be6e2b54f706b72193e60f25da50efef5375e351b5633c3bbe6e78d3e70",
        count: 1,
        label: "moving-stable-release-download",
    },
    DependencyRoute {
        input: "10",
        path: "test/vm/asahi-fresh/guest/install",
        literal:
            b"https://github.com/maralcbr/omarchy-pkgs/releases/download/asahi-quattro-channel",
        sha256: "d29a9d72649a28ad77f1772dfb6dac6fc46066158da501ddf0c7f52cbaf17bc3",
        count: 1,
        label: "moving-bundle-channel-download",
    },
    DependencyRoute {
        input: "10",
        path: "bin/omarchy-update-asahi-bundle",
        literal: b"https://github.com/$repo/releases/download/$tag",
        sha256: "3f48a42baff313783e0f1ba2956bc2dacf57c6bd459fce1db470bae0212fd0ab",
        count: 1,
        label: "moving-bundle-update-download",
    },
    DependencyRoute {
        input: "05",
        path: "test/vm/asahi-fresh/container/build-base",
        literal: b"https://fl.us.mirror.archlinuxarm.org/$arch/$repo",
        sha256: "edc244e5b4877176d9cad50702f874dc4de0107ce265cc29d5a8fb9d20900df0",
        count: 1,
        label: "second-alarm-pacman-mirror",
    },
    DependencyRoute {
        input: "06",
        path: "test/vm/asahi-fresh/container/start-vm",
        literal: b"-machine virt,accel=kvm,gic-version=host",
        sha256: "d35b56d13297792fab98652c06e82a4fffdda835677687d504570f2230689862",
        count: 1,
        label: "qemu-machine-configuration",
    },
    DependencyRoute {
        input: "07",
        path: "test/vm/asahi-fresh/container/start-vm",
        literal: b"/usr/share/AAVMF/AAVMF_VARS.fd",
        sha256: "c52209db8e2ade92400b8b9653d4e3d06a77aa8d4aed6687e9bf189de0fd5978",
        count: 1,
        label: "aavmf-vars-firmware",
    },
    DependencyRoute {
        input: "10",
        path: "test/vm/asahi-fresh/container/build-base",
        literal: b"/work/ssh/id_ed25519.pub",
        sha256: "589f25c4124fd36372a18ad4c7a3de118afee8e61c144e0e2c2c90d5865b4611",
        count: 2,
        label: "generated-vm-ssh-public-key",
    },
    DependencyRoute {
        input: "10",
        path: "bin/omarchy-install-asahi-fresh",
        literal: b"https://github.com/maralcbr/omarchy-pkgs.git",
        sha256: "66aa542a35c2c0999ba7ac8118c4e7ef8e4070e4f52304ec9da094197726aa4f",
        count: 1,
        label: "runtime-package-source-clone",
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputLock {
    fields: BTreeMap<String, String>,
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
    external: ExternalLockExpectation,
    lock_id: String,
    lock_sha256: String,
    profile_sha256: String,
    file_records: Vec<String>,
}

impl VerificationReport {
    #[must_use]
    pub fn render(&self) -> String {
        let complete = self.mode == VerificationMode::InputSelection;
        let mut lines = vec![
            if complete {
                "verification_status=verified-builder-context-input-selection".to_owned()
            } else {
                "verification_status=verified-lock-and-profile-only".to_owned()
            },
            "lock_authority=exact-byte-selection-only".to_owned(),
            format!("external_lock_repository={}", self.external.repository),
            format!("external_lock_commit={}", self.external.commit),
            format!("external_lock_path={}", self.external.path),
            format!("lock_id={}", self.lock_id),
            format!("lock_sha256={}", self.lock_sha256),
            format!("profile_sha256={}", self.profile_sha256),
            "external_lock_authentication_required=true".to_owned(),
            "external_lock_authentication_established_by_verifier=false".to_owned(),
            "profile_state=bootstrap-unarmed".to_owned(),
            "profile_armable=false".to_owned(),
            "locked_file_count=10".to_owned(),
            format!("verified_file_count={}", self.file_records.len()),
        ];
        for (index, record) in self.file_records.iter().enumerate() {
            lines.push(format!("file_{:02}={record}", index + 1));
        }
        lines.extend([
            format!("source_file_bytes_verified={complete}"),
            if complete {
                "git_blob_bindings=verified-from-sealed-snapshots".to_owned()
            } else {
                "git_blob_bindings=not-run".to_owned()
            },
            if complete {
                "dependency_routes=verified-from-sealed-snapshots".to_owned()
            } else {
                "dependency_routes=not-run".to_owned()
            },
            if complete {
                "input_class_03_exact_selection=verified-from-caller-export".to_owned()
            } else {
                "input_class_03_exact_selection=described-by-reviewed-lock".to_owned()
            },
            "source_checkout_consumed=false".to_owned(),
            "subject_authentication=signed-release-record-only".to_owned(),
            "git_execution=false".to_owned(),
            "verifier_network_activity=false".to_owned(),
            "whole_machine_network_silence=not-established".to_owned(),
            "harness_process_execution=false".to_owned(),
            "container_execution=false".to_owned(),
            "package_manager_execution=false".to_owned(),
            "mount_execution=false".to_owned(),
            "vm_execution=false".to_owned(),
            "durable_retention=not-established".to_owned(),
            "build_authorization=not-established".to_owned(),
            "runnable=false".to_owned(),
            "current_publisher_authorization=not-established".to_owned(),
            "source_to_image_provenance=not-established".to_owned(),
            "final_builder_image=not-established".to_owned(),
            "input_class_09_consumed=false".to_owned(),
            "profile_unresolved_input_count=10".to_owned(),
            "remaining_input_count_if_lock_is_adopted=9".to_owned(),
            "clean_system=not-established".to_owned(),
            "freshness=not-established".to_owned(),
            "safety=not-established".to_owned(),
        ]);
        lines.join("\n") + "\n"
    }
}

pub fn parse_input_lock(bytes: &[u8]) -> Result<InputLock> {
    let fields = parse_ordered_record(bytes, LOCK_KEYS, "builder-context input lock")?;
    for (key, expected) in [
        ("format", "a-quo-omarchy-builder-context-input-lock-v1"),
        (
            "lock_id",
            "a-quo-omarchy4-aarch64-dec29fa-builder-context-v1",
        ),
        ("state", "reviewed-input-selection"),
        ("lock_authority", "exact-byte-selection-only"),
        ("build_authorization", "not-established"),
        ("runnable", "false"),
        ("retention", "caller-supplied-inert-export-required"),
        ("durable_retention", "not-established"),
        ("lock_authentication", "external-pinned-git-object-required"),
        ("self_authentication", "none"),
        (
            "lock_repository",
            "https://github.com/SurreptitiousFabric/a-quo.git",
        ),
        (
            "lock_path",
            "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-builder-context-v1.lock",
        ),
        (
            "profile_repository",
            "https://github.com/SurreptitiousFabric/a-quo.git",
        ),
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
        (
            "subject_repository",
            "https://github.com/maralcbr/omarchy-mx-mac.git",
        ),
        ("subject_commit", "dec29fa90afc3d16a7e0c487c1869c7e512282ca"),
        ("subject_authentication", "signed-release-record-only"),
        ("current_publisher_authorization", "not-established"),
        ("input_class", "03-builder-context-and-harness-hash"),
        ("selected_input_scope", "ten-reviewed-source-blobs-only"),
        ("file_count", "10"),
        ("dependency_route_count", "17"),
        (
            "unconsumed_input_09",
            "flattened-golden-qcow2-not-referenced-by-reviewed-harness",
        ),
        ("git_object_hash_algorithm", "sha1"),
        ("source_checkout_consumed", "false"),
        ("git_execution", "forbidden"),
        ("verifier_network_access", "forbidden"),
        ("harness_process_execution", "forbidden"),
        ("container_execution", "forbidden"),
        ("package_manager_execution", "forbidden"),
        ("mount_execution", "forbidden"),
        ("vm_execution", "forbidden"),
        ("final_builder_image", "not-established"),
        ("source_to_image_provenance", "not-established"),
        ("freshness", "not-established"),
        ("safety", "not-established"),
        ("profile_unresolved_input_count", "10"),
        ("remaining_input_count_if_lock_is_adopted", "9"),
    ] {
        require(&fields, key, expected)?;
    }

    let mut paths = BTreeSet::new();
    let mut folded_paths = BTreeSet::new();
    for (index, spec) in FILES.iter().enumerate() {
        validate_relative_path(spec.path)?;
        ensure!(paths.insert(spec.path), "file records repeat a path");
        ensure!(
            folded_paths.insert(spec.path.to_ascii_lowercase()),
            "file records have a case-colliding path"
        );
        ensure!(
            spec.size > 0 && spec.size <= MAX_SOURCE_FILE_BYTES,
            "file size is outside the closed bound"
        );
        ensure!(
            valid_hex(spec.git_blob_sha1, 40),
            "file Git blob is malformed"
        );
        ensure!(valid_hex(spec.sha256, 64), "file SHA-256 is malformed");
        let expected = format!(
            "{}|{}|{}|{}|{}|{}",
            spec.role, spec.path, spec.git_mode, spec.git_blob_sha1, spec.size, spec.sha256
        );
        require(&fields, &format!("file_{:02}", index + 1), &expected)?;
    }
    for (index, route) in ROUTES.iter().enumerate() {
        validate_relative_path(route.path)?;
        ensure!(
            FILES.iter().any(|file| file.path == route.path),
            "dependency route names an unlocked path"
        );
        ensure!(
            valid_hex(route.sha256, 64),
            "dependency literal SHA-256 is malformed"
        );
        let expected = format!(
            "{}|{}|{}|{}|{}",
            route.input, route.path, route.sha256, route.count, route.label
        );
        require(
            &fields,
            &format!("dependency_route_{:02}", index + 1),
            &expected,
        )?;
    }
    Ok(InputLock { fields })
}

fn parse_ordered_record(
    bytes: &[u8],
    expected_keys: &[&str],
    label: &str,
) -> Result<BTreeMap<String, String>> {
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_LOCK_BYTES,
        "{label} exceeds its byte bound"
    );
    ensure!(bytes.last() == Some(&b'\n'), "{label} must end with one LF");
    ensure!(
        bytes
            .iter()
            .all(|byte| *byte == b'\n' || (0x20..=0x7e).contains(byte)),
        "{label} contains a control, carriage-return, NUL, or non-ASCII byte"
    );
    let text = std::str::from_utf8(bytes).context("record is not UTF-8")?;
    let lines = text
        .strip_suffix('\n')
        .expect("final LF checked")
        .split('\n')
        .collect::<Vec<_>>();
    ensure!(
        lines.len() == expected_keys.len(),
        "{label} does not have the exact field count"
    );
    let mut fields = BTreeMap::new();
    for (index, (line, expected_key)) in lines.iter().zip(expected_keys).enumerate() {
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("{label} line {} has no separator", index + 1))?;
        ensure!(
            key == *expected_key,
            "{label} field order is invalid at line {}",
            index + 1
        );
        ensure!(
            !value.is_empty() && value.len() <= 4096 && value.trim_matches(' ') == value,
            "{label} line {} has invalid value bounds",
            index + 1
        );
        ensure!(
            fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "{label} repeats {key}"
        );
    }
    Ok(fields)
}

fn field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .with_context(|| format!("missing field {key}"))
}

fn require(fields: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<()> {
    ensure!(
        field(fields, key)? == expected,
        "unexpected value for {key}"
    );
    Ok(())
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_relative_path(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 255,
        "path is outside the closed bound"
    );
    let path = Path::new(value);
    ensure!(!path.is_absolute(), "absolute path is forbidden");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "path traversal or non-normal component is forbidden"
    );
    ensure!(
        !value.contains("//") && !value.ends_with('/'),
        "noncanonical path is forbidden"
    );
    ensure!(
        value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
        "path contains whitespace, control, or non-ASCII bytes"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsStr;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::AsRawFd;
    use std::path::Path;

    use a_quo_ipc::{SealedArtifact, snapshot_artifact};
    use anyhow::{Context, Result, ensure};
    use rustix::fs::{Dir, FileType, Mode, OFlags, fstat, open, openat};
    use rustix::process::getuid;
    use sha1::{Digest, Sha1};
    use sha2::Sha256;

    use super::{
        CANONICAL_PROFILE, ExternalLockExpectation, FILES, InputLock, MAX_LOCK_BYTES,
        MAX_PROFILE_BYTES, MAX_SOURCE_FILE_BYTES, ROUTES, VerificationMode, VerificationReport,
        field, parse_input_lock, require, valid_hex,
    };

    const INVENTORIES: &[(&str, &[&str])] = &[
        ("", &["bin", "test"]),
        (
            "bin",
            &["omarchy-install-asahi-fresh", "omarchy-update-asahi-bundle"],
        ),
        ("test", &["vm"]),
        ("test/vm", &["asahi-fresh"]),
        (
            "test/vm/asahi-fresh",
            &["Dockerfile", "README.md", "container", "guest", "run"],
        ),
        ("test/vm/asahi-fresh/container", &["build-base", "start-vm"]),
        ("test/vm/asahi-fresh/guest", &["install", "rerun", "verify"]),
    ];

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn git_blob_sha1(bytes: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn snapshot_path(path: &Path, maximum: u64) -> Result<SealedArtifact> {
        let pinned = open(
            path,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| format!("cannot pin {} without following links", path.display()))?;
        let before =
            fstat(&pinned).with_context(|| format!("cannot inspect pinned {}", path.display()))?;
        ensure!(
            FileType::from_raw_mode(before.st_mode) == FileType::RegularFile,
            "snapshot source is not a regular file: {}",
            path.display()
        );
        ensure!(
            before.st_size >= 0 && before.st_size as u64 <= maximum,
            "snapshot source exceeds its byte bound: {}",
            path.display()
        );
        let readable = reopen_pinned(&pinned)?;
        let after = fstat(&readable).context("cannot inspect reopened snapshot source")?;
        ensure!(
            after.st_dev == before.st_dev
                && after.st_ino == before.st_ino
                && after.st_size == before.st_size
                && FileType::from_raw_mode(after.st_mode) == FileType::RegularFile,
            "snapshot source identity changed before reading"
        );
        snapshot_artifact(readable, maximum).context("cannot create sealed snapshot")
    }

    fn reopen_pinned(pinned: &rustix::fd::OwnedFd) -> Result<rustix::fd::OwnedFd> {
        open(
            format!("/proc/self/fd/{}", pinned.as_raw_fd()),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .context("cannot reopen an O_PATH pin through procfs")
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
            bytes.len() as u64 == snapshot.descriptor().size && bytes.len() as u64 <= maximum,
            "sealed snapshot size changed"
        );
        Ok(bytes)
    }

    fn validate_external(expectation: &ExternalLockExpectation) -> Result<()> {
        ensure!(
            expectation.repository == "https://github.com/SurreptitiousFabric/a-quo.git",
            "unexpected external lock repository"
        );
        ensure!(
            expectation.path
                == "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-builder-context-v1.lock",
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
            values.get("profile_id") == Some(&"a-quo-omarchy4-aarch64-dec29fa-v2"),
            "profile ID differs from the lock"
        );
        ensure!(
            values.get("state") == Some(&"bootstrap-unarmed")
                && values.get("armable") == Some(&"false"),
            "profile is not unarmed"
        );
        ensure!(
            values.get("omarchy_source_repository")
                == Some(&"https://github.com/maralcbr/omarchy-mx-mac.git"),
            "profile subject repository differs from the lock"
        );
        ensure!(
            values.get("omarchy_source_commit")
                == Some(&"dec29fa90afc3d16a7e0c487c1869c7e512282ca"),
            "profile subject commit differs from the lock"
        );
        ensure!(
            values.get("omarchy_source_authentication") == Some(&"signed-release-record-only"),
            "profile subject authentication differs from the lock"
        );
        ensure!(
            values.get("unresolved_input_03") == Some(&"builder-context-and-harness-hash"),
            "profile input class 03 differs from the lock"
        );
        ensure!(
            values.get("unresolved_input_count") == Some(&"10"),
            "profile unresolved count differs from the lock"
        );
        Ok(())
    }

    fn report(
        lock: &InputLock,
        expectation: &ExternalLockExpectation,
        records: Vec<String>,
        mode: VerificationMode,
    ) -> Result<VerificationReport> {
        Ok(VerificationReport {
            mode,
            external: expectation.clone(),
            lock_id: field(&lock.fields, "lock_id")?.to_owned(),
            lock_sha256: expectation.sha256.clone(),
            profile_sha256: field(&lock.fields, "profile_sha256")?.to_owned(),
            file_records: records,
        })
    }

    pub fn inspect_lock(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<VerificationReport> {
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
        report(
            &lock,
            expectation,
            Vec::new(),
            VerificationMode::LockAndProfile,
        )
    }

    pub fn verify_export(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
        input_directory: &Path,
    ) -> Result<VerificationReport> {
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
        let snapshots = snapshot_context(input_directory)?;
        let records = verify_snapshots(&snapshots)?;
        report(
            &lock,
            expectation,
            records,
            VerificationMode::InputSelection,
        )
    }

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

    fn check_directory(
        directory: &rustix::fd::OwnedFd,
        root_device: u64,
    ) -> Result<SourceIdentity> {
        let stat = fstat(directory).context("cannot inspect input directory")?;
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
            "input component is not a directory"
        );
        ensure!(
            stat.st_dev == root_device,
            "input directory crosses a filesystem boundary"
        );
        ensure!(
            stat.st_uid == getuid().as_raw(),
            "input directory has the wrong owner"
        );
        ensure!(
            stat.st_mode & 0o7777 == 0o700,
            "input directory mode is not 0700"
        );
        Ok(identity(&stat))
    }

    fn expected_inventory(directory: &rustix::fd::OwnedFd, expected: &[&str]) -> Result<()> {
        let readable = openat(
            directory,
            ".",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("cannot enumerate input directory")?;
        let allowed = expected.iter().copied().collect::<BTreeSet<_>>();
        ensure!(
            allowed.len() == expected.len(),
            "expected inventory repeats a name"
        );
        let mut observed = BTreeSet::new();
        for entry in Dir::new(readable).context("cannot create input-directory iterator")? {
            let entry = entry.context("cannot read input-directory entry")?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            ensure!(bytes.len() <= 128, "input filename exceeds its byte bound");
            let name = std::str::from_utf8(bytes).context("input filename is not UTF-8")?;
            ensure!(
                name.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
                "input filename contains whitespace, control, or non-ASCII bytes"
            );
            ensure!(
                allowed.contains(name),
                "input directory has an unexpected entry"
            );
            ensure!(
                observed.insert(name.to_owned()),
                "input directory repeats an entry"
            );
        }
        ensure!(
            observed.len() == allowed.len()
                && observed
                    .iter()
                    .map(String::as_str)
                    .eq(allowed.iter().copied()),
            "input directory is missing an expected entry"
        );
        Ok(())
    }

    fn snapshot_file(
        directory: &rustix::fd::OwnedFd,
        root_device: u64,
        spec: &super::FileSpec,
    ) -> Result<(SealedArtifact, SourceIdentity)> {
        let path = Path::new(spec.path);
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .context("locked path has no UTF-8 filename")?;
        let pinned = openat(
            directory,
            name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| format!("cannot pin {} without following links", spec.path))?;
        let before = fstat(&pinned).with_context(|| format!("cannot inspect {}", spec.path))?;
        ensure!(
            FileType::from_raw_mode(before.st_mode) == FileType::RegularFile,
            "locked input is not a regular file: {}",
            spec.path
        );
        ensure!(
            before.st_dev == root_device,
            "locked input crosses a filesystem boundary: {}",
            spec.path
        );
        ensure!(
            before.st_uid == getuid().as_raw(),
            "locked input has the wrong owner: {}",
            spec.path
        );
        ensure!(
            before.st_mode & 0o7777 == 0o400,
            "locked input mode is not inert 0400: {}",
            spec.path
        );
        ensure!(
            before.st_nlink == 1,
            "locked input has multiple hard links: {}",
            spec.path
        );
        ensure!(
            before.st_size >= 0
                && before.st_size as u64 == spec.size
                && spec.size <= MAX_SOURCE_FILE_BYTES,
            "locked input has the wrong bounded size: {}",
            spec.path
        );
        let readable = reopen_pinned(&pinned)?;
        let after = fstat(&readable).context("cannot inspect reopened locked input")?;
        ensure!(
            after.st_dev == before.st_dev
                && after.st_ino == before.st_ino
                && after.st_size == before.st_size
                && after.st_mode == before.st_mode
                && after.st_uid == before.st_uid
                && after.st_gid == before.st_gid
                && after.st_nlink == before.st_nlink,
            "locked input identity changed before snapshotting: {}",
            spec.path
        );
        let snapshot = snapshot_artifact(readable, MAX_SOURCE_FILE_BYTES)
            .with_context(|| format!("cannot seal snapshot of {}", spec.path))?;
        Ok((snapshot, identity(&before)))
    }

    fn current_entry_identity(
        directory: &rustix::fd::OwnedFd,
        name: &str,
        directory_expected: bool,
    ) -> Result<SourceIdentity> {
        let mut flags = OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        if directory_expected {
            flags |= OFlags::DIRECTORY;
        }
        let pinned = openat(directory, name, flags, Mode::empty())
            .with_context(|| format!("cannot re-pin input entry {name}"))?;
        let stat =
            fstat(&pinned).with_context(|| format!("cannot re-inspect input entry {name}"))?;
        let expected_type = if directory_expected {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == expected_type,
            "input entry type changed after snapshotting: {name}"
        );
        Ok(identity(&stat))
    }

    fn path_parent_and_name(path: &str) -> Result<(&str, &str)> {
        let path = Path::new(path);
        let parent = path
            .parent()
            .and_then(Path::to_str)
            .context("locked path has no UTF-8 parent")?;
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .context("locked path has no UTF-8 filename")?;
        Ok((parent, name))
    }

    fn snapshot_context(input_directory: &Path) -> Result<BTreeMap<&'static str, SealedArtifact>> {
        let root = open(
            input_directory,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("cannot open inert input export without following links")?;
        let root_before = fstat(&root).context("cannot inspect inert input export")?;
        let root_identity = check_directory(&root, root_before.st_dev)?;
        let mut directories = BTreeMap::new();
        let mut directory_identities = BTreeMap::new();
        directory_identities.insert("", root_identity);
        directories.insert("", root);
        for (relative, _) in INVENTORIES.iter().skip(1) {
            let (parent, name) = path_parent_and_name(relative)?;
            let parent_directory = directories
                .get(parent)
                .with_context(|| format!("missing pinned parent directory {parent}"))?;
            let directory = openat(
                parent_directory,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .with_context(|| format!("cannot pin input directory {relative}"))?;
            let directory_identity = check_directory(&directory, root_before.st_dev)?;
            directory_identities.insert(*relative, directory_identity);
            directories.insert(*relative, directory);
        }
        for (relative, expected) in INVENTORIES {
            expected_inventory(
                directories
                    .get(relative)
                    .with_context(|| format!("missing pinned directory {relative}"))?,
                expected,
            )?;
        }
        let mut snapshots = BTreeMap::new();
        let mut file_identities = BTreeMap::new();
        for spec in FILES {
            let (parent, _) = path_parent_and_name(spec.path)?;
            let directory = directories
                .get(parent)
                .with_context(|| format!("missing pinned parent directory {parent}"))?;
            let (snapshot, file_identity) = snapshot_file(directory, root_before.st_dev, spec)?;
            ensure!(
                snapshots.insert(spec.path, snapshot).is_none()
                    && file_identities.insert(spec.path, file_identity).is_none(),
                "locked input path repeats"
            );
        }
        for (relative, expected) in INVENTORIES {
            expected_inventory(
                directories
                    .get(relative)
                    .with_context(|| format!("missing pinned directory {relative}"))?,
                expected,
            )?;
        }
        for (relative, _) in INVENTORIES.iter().skip(1) {
            let (parent, name) = path_parent_and_name(relative)?;
            let current = current_entry_identity(
                directories
                    .get(parent)
                    .with_context(|| format!("missing pinned parent directory {parent}"))?,
                name,
                true,
            )?;
            ensure!(
                Some(&current) == directory_identities.get(relative),
                "input directory identity changed during snapshotting: {relative}"
            );
        }
        for spec in FILES {
            let (parent, name) = path_parent_and_name(spec.path)?;
            let current = current_entry_identity(
                directories
                    .get(parent)
                    .with_context(|| format!("missing pinned parent directory {parent}"))?,
                name,
                false,
            )?;
            ensure!(
                Some(&current) == file_identities.get(spec.path),
                "input file identity changed during snapshotting: {}",
                spec.path
            );
        }
        let root_after = fstat(
            directories
                .get("")
                .context("missing pinned input export root")?,
        )
        .context("cannot re-inspect inert input export")?;
        ensure!(
            identity(&root_after) == root_identity,
            "input export identity or permissions changed during snapshotting"
        );
        Ok(snapshots)
    }

    fn literal_count(bytes: &[u8], literal: &[u8]) -> usize {
        if literal.is_empty() || literal.len() > bytes.len() {
            return 0;
        }
        bytes
            .windows(literal.len())
            .filter(|window| *window == literal)
            .count()
    }

    fn verify_snapshots(snapshots: &BTreeMap<&'static str, SealedArtifact>) -> Result<Vec<String>> {
        ensure!(
            snapshots.len() == FILES.len(),
            "sealed input set does not contain ten files"
        );
        let mut bytes_by_path = BTreeMap::new();
        let mut records = Vec::with_capacity(FILES.len());
        for spec in FILES {
            let snapshot = snapshots
                .get(spec.path)
                .with_context(|| format!("missing sealed snapshot for {}", spec.path))?;
            let bytes = snapshot_bytes(snapshot, MAX_SOURCE_FILE_BYTES)?;
            ensure!(
                bytes.len() as u64 == spec.size,
                "sealed input size differs from the lock: {}",
                spec.path
            );
            ensure!(
                sha256(&bytes) == spec.sha256,
                "sealed input SHA-256 differs from the lock: {}",
                spec.path
            );
            ensure!(
                git_blob_sha1(&bytes) == spec.git_blob_sha1,
                "sealed input Git blob differs from the lock: {}",
                spec.path
            );
            records.push(format!(
                "{}|{}|{}|{}|{}|{}",
                spec.role, spec.path, spec.git_mode, spec.git_blob_sha1, spec.size, spec.sha256
            ));
            bytes_by_path.insert(spec.path, bytes);
        }
        for route in ROUTES {
            ensure!(
                sha256(route.literal) == route.sha256,
                "compiled dependency literal differs from the lock route"
            );
            let bytes = bytes_by_path
                .get(route.path)
                .with_context(|| format!("missing dependency-route subject {}", route.path))?;
            ensure!(
                literal_count(bytes, route.literal) == route.count,
                "dependency route {} no longer has the exact reviewed literal occurrence count",
                route.label
            );
        }
        Ok(records)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::FileSpec;
        use std::fs::File;
        use std::io::Write;
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::path::PathBuf;

        use rustix::fs::{CWD, FileType, Mode, mknodat};
        use tempfile::TempDir;

        fn repository_path(relative: &str) -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(relative)
        }

        fn expectation(lock_bytes: &[u8]) -> ExternalLockExpectation {
            ExternalLockExpectation {
                repository: "https://github.com/SurreptitiousFabric/a-quo.git".to_owned(),
                commit: "1".repeat(40),
                path: "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-builder-context-v1.lock".to_owned(),
                sha256: sha256(lock_bytes),
            }
        }

        fn inert_file(path: &Path, bytes: &[u8]) {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }

        fn zero_context() -> TempDir {
            let temporary = TempDir::new().unwrap();
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            for (relative, _) in INVENTORIES.iter().skip(1) {
                let directory = temporary.path().join(relative);
                std::fs::create_dir_all(&directory).unwrap();
            }
            for entry in walk_directories(temporary.path()) {
                std::fs::set_permissions(entry, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            for spec in FILES {
                inert_file(
                    &temporary.path().join(spec.path),
                    &vec![0_u8; spec.size as usize],
                );
            }
            temporary
        }

        fn walk_directories(root: &Path) -> Vec<PathBuf> {
            let mut pending = vec![root.to_owned()];
            let mut found = Vec::new();
            while let Some(directory) = pending.pop() {
                found.push(directory.clone());
                for entry in std::fs::read_dir(directory).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_type().unwrap().is_dir() {
                        pending.push(entry.path());
                    }
                }
            }
            found
        }

        #[test]
        fn git_blob_hash_matches_known_vector() {
            assert_eq!(
                git_blob_sha1(b"test\n"),
                "9daeafb9864cf43055ae93beb0afd6c7d144bfa4"
            );
        }

        #[test]
        fn external_lock_and_profile_pins_are_mandatory() {
            let lock_path = repository_path(
                "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-builder-context-v1.lock",
            );
            let profile_path = repository_path(
                "packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile",
            );
            let bytes = std::fs::read(&lock_path).unwrap();
            let exact = expectation(&bytes);
            inspect_lock(&lock_path, &exact, &profile_path).unwrap();
            let mut wrong = exact.clone();
            wrong.sha256 = "0".repeat(64);
            assert!(inspect_lock(&lock_path, &wrong, &profile_path).is_err());
            let mut wrong = exact.clone();
            wrong.repository = "https://example.invalid/a-quo.git".to_owned();
            assert!(inspect_lock(&lock_path, &wrong, &profile_path).is_err());
            let mut wrong = exact.clone();
            wrong.path = "packaging/evaluation-input-locks/other.lock".to_owned();
            assert!(inspect_lock(&lock_path, &wrong, &profile_path).is_err());
            let mut wrong = exact.clone();
            wrong.commit = "A".repeat(40);
            assert!(inspect_lock(&lock_path, &wrong, &profile_path).is_err());
            let temp = TempDir::new().unwrap();
            let changed_profile = temp.path().join("profile");
            let mut changed = std::fs::read(&profile_path).unwrap();
            changed[0] ^= 1;
            std::fs::write(&changed_profile, changed).unwrap();
            assert!(inspect_lock(&lock_path, &exact, &changed_profile).is_err());
        }

        #[test]
        fn inventory_rejects_extra_missing_symlink_and_special_entries() {
            let temp = TempDir::new().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            inert_file(&temp.path().join("one"), b"x");
            let root = open(
                temp.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            expected_inventory(&root, &["one"]).unwrap();
            inert_file(&temp.path().join("extra"), b"x");
            assert!(expected_inventory(&root, &["one"]).is_err());
            std::fs::remove_file(temp.path().join("extra")).unwrap();
            std::fs::remove_file(temp.path().join("one")).unwrap();
            assert!(expected_inventory(&root, &["one"]).is_err());
            symlink("target", temp.path().join("one")).unwrap();
            assert!(expected_inventory(&root, &["one"]).is_ok());
            std::fs::remove_file(temp.path().join("one")).unwrap();
            mknodat(
                CWD,
                temp.path().join("one"),
                FileType::Fifo,
                Mode::from_raw_mode(0o400),
                0,
            )
            .unwrap();
            assert!(expected_inventory(&root, &["one"]).is_ok());
        }

        #[test]
        fn canonical_context_inventory_rejects_dockerignore_extra_case_collision_and_git_state() {
            let exact = zero_context();
            assert_eq!(snapshot_context(exact.path()).unwrap().len(), 10);

            inert_file(
                &exact.path().join("test/vm/asahi-fresh/.dockerignore"),
                b"*",
            );
            assert!(snapshot_context(exact.path()).is_err());
            std::fs::remove_file(exact.path().join("test/vm/asahi-fresh/.dockerignore")).unwrap();

            inert_file(
                &exact
                    .path()
                    .join("test/vm/asahi-fresh/container/unreviewed"),
                b"x",
            );
            assert!(snapshot_context(exact.path()).is_err());
            std::fs::remove_file(
                exact
                    .path()
                    .join("test/vm/asahi-fresh/container/unreviewed"),
            )
            .unwrap();

            inert_file(&exact.path().join("test/vm/asahi-fresh/dockerfile"), b"x");
            assert!(snapshot_context(exact.path()).is_err());
            std::fs::remove_file(exact.path().join("test/vm/asahi-fresh/dockerfile")).unwrap();

            std::fs::create_dir(exact.path().join(".git")).unwrap();
            std::fs::set_permissions(
                exact.path().join(".git"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            assert!(snapshot_context(exact.path()).is_err());
        }

        #[test]
        fn file_snapshot_rejects_symlink_fifo_hardlink_and_non_inert_mode() {
            let temp = TempDir::new().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let spec = FileSpec {
                role: "test",
                path: "one",
                git_mode: "100644",
                git_blob_sha1: "0",
                size: 1,
                sha256: "0",
            };
            let root = open(
                temp.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let stat = fstat(&root).unwrap();
            inert_file(&temp.path().join("one"), b"x");
            snapshot_file(&root, stat.st_dev, &spec).unwrap();
            std::fs::set_permissions(
                temp.path().join("one"),
                std::fs::Permissions::from_mode(0o500),
            )
            .unwrap();
            assert!(snapshot_file(&root, stat.st_dev, &spec).is_err());
            std::fs::remove_file(temp.path().join("one")).unwrap();
            symlink("target", temp.path().join("one")).unwrap();
            assert!(snapshot_file(&root, stat.st_dev, &spec).is_err());
            std::fs::remove_file(temp.path().join("one")).unwrap();
            mknodat(
                CWD,
                temp.path().join("one"),
                FileType::Fifo,
                Mode::from_raw_mode(0o400),
                0,
            )
            .unwrap();
            assert!(snapshot_file(&root, stat.st_dev, &spec).is_err());
            std::fs::remove_file(temp.path().join("one")).unwrap();
            inert_file(&temp.path().join("target"), b"x");
            std::fs::hard_link(temp.path().join("target"), temp.path().join("one")).unwrap();
            assert!(snapshot_file(&root, stat.st_dev, &spec).is_err());
        }

        #[test]
        fn sealed_snapshot_survives_post_open_replacement_and_never_executes_bytes() {
            let temp = TempDir::new().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = temp.path().join("executed");
            let malicious = format!("#!/bin/sh\ntouch {}\n", marker.display());
            let spec = FileSpec {
                role: "test",
                path: "one",
                git_mode: "100755",
                git_blob_sha1: "0",
                size: malicious.len() as u64,
                sha256: "0",
            };
            inert_file(&temp.path().join("one"), malicious.as_bytes());
            let root = open(
                temp.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let stat = fstat(&root).unwrap();
            let (snapshot, original_identity) = snapshot_file(&root, stat.st_dev, &spec).unwrap();
            inert_file(
                &temp.path().join("replacement"),
                &vec![b'z'; malicious.len()],
            );
            std::fs::rename(temp.path().join("replacement"), temp.path().join("one")).unwrap();
            assert_eq!(
                snapshot_bytes(&snapshot, MAX_SOURCE_FILE_BYTES).unwrap(),
                malicious.as_bytes()
            );
            assert_ne!(
                current_entry_identity(&root, "one", false).unwrap(),
                original_identity
            );
            assert!(!marker.exists());
        }

        #[test]
        fn same_inode_mutation_after_snapshot_changes_the_revalidated_identity() {
            let temp = TempDir::new().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let spec = FileSpec {
                role: "test",
                path: "one",
                git_mode: "100644",
                git_blob_sha1: "0",
                size: 1,
                sha256: "0",
            };
            inert_file(&temp.path().join("one"), b"x");
            let root = open(
                temp.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let stat = fstat(&root).unwrap();
            let (snapshot, original_identity) = snapshot_file(&root, stat.st_dev, &spec).unwrap();
            std::fs::set_permissions(
                temp.path().join("one"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            std::fs::write(temp.path().join("one"), b"y").unwrap();
            std::fs::set_permissions(
                temp.path().join("one"),
                std::fs::Permissions::from_mode(0o400),
            )
            .unwrap();
            assert_ne!(
                current_entry_identity(&root, "one", false).unwrap(),
                original_identity
            );
            assert_eq!(snapshot_bytes(&snapshot, 1).unwrap(), b"x");
        }

        #[test]
        fn every_dependency_literal_is_exact_and_mutation_fails_its_route() {
            for route in ROUTES {
                assert_eq!(sha256(route.literal), route.sha256);
                let mut exact = Vec::new();
                for _ in 0..route.count {
                    exact.extend_from_slice(b"prefix\n");
                    exact.extend_from_slice(route.literal);
                    exact.push(b'\n');
                }
                exact.extend_from_slice(b"\nsuffix");
                assert_eq!(literal_count(&exact, route.literal), route.count);
                let offset = 7;
                exact[offset] ^= 1;
                assert_ne!(literal_count(&exact, route.literal), route.count);
            }
        }

        #[test]
        fn implementation_has_no_execution_or_network_client_api() {
            let source = include_str!("lib.rs");
            let main = include_str!("main.rs");
            let forbidden = [
                ["std", "::process"].concat(),
                ["Command", "::new"].concat(),
                ["process", "::Command"].concat(),
                ["rustix", "::process::exec"].concat(),
                ["nix", "::unistd::exec"].concat(),
                ["std", "::net"].concat(),
                ["std", "::os::unix::net"].concat(),
                ["rustix", "::net"].concat(),
                ["tokio", "::net"].concat(),
                ["Tcp", "Stream"].concat(),
                ["Tcp", "Listener"].concat(),
                ["Udp", "Socket"].concat(),
                ["Unix", "Stream"].concat(),
                ["Unix", "Datagram"].concat(),
                ["socket", "2"].concat(),
                ["req", "west"].concat(),
                ["u", "req::"].concat(),
                ["hyper", "::Client"].concat(),
                ["curl", "::"].concat(),
            ];
            for forbidden in forbidden {
                assert!(!source.contains(&forbidden));
                assert!(!main.contains(&forbidden));
            }
        }

        #[test]
        fn reports_keep_inspection_and_complete_claims_distinct() {
            let lock_path = repository_path(
                "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-builder-context-v1.lock",
            );
            let profile_path = repository_path(
                "packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile",
            );
            let bytes = std::fs::read(&lock_path).unwrap();
            let rendered = inspect_lock(&lock_path, &expectation(&bytes), &profile_path)
                .unwrap()
                .render();
            assert!(rendered.contains("verification_status=verified-lock-and-profile-only"));
            assert!(rendered.contains("source_file_bytes_verified=false"));
            assert!(rendered.contains("dependency_routes=not-run"));
            assert!(
                rendered.contains("external_lock_authentication_established_by_verifier=false")
            );
            assert!(rendered.contains("profile_state=bootstrap-unarmed"));
            assert!(rendered.contains("remaining_input_count_if_lock_is_adopted=9"));
            for forbidden in [
                "runnable=true",
                "safety=safe",
                "build_authorization=established",
                "durable_retention=established",
            ] {
                assert!(!rendered.contains(forbidden));
            }

            let complete = VerificationReport {
                mode: VerificationMode::InputSelection,
                external: expectation(&bytes),
                lock_id: "a-quo-omarchy4-aarch64-dec29fa-builder-context-v1".to_owned(),
                lock_sha256: sha256(&bytes),
                profile_sha256: "3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6"
                    .to_owned(),
                file_records: FILES
                    .iter()
                    .map(|spec| {
                        format!(
                            "{}|{}|{}|{}|{}|{}",
                            spec.role,
                            spec.path,
                            spec.git_mode,
                            spec.git_blob_sha1,
                            spec.size,
                            spec.sha256
                        )
                    })
                    .collect(),
            }
            .render();
            for required in [
                "verification_status=verified-builder-context-input-selection",
                "verified_file_count=10",
                "source_file_bytes_verified=true",
                "git_blob_bindings=verified-from-sealed-snapshots",
                "dependency_routes=verified-from-sealed-snapshots",
                "external_lock_authentication_established_by_verifier=false",
                "source_checkout_consumed=false",
                "verifier_network_activity=false",
                "harness_process_execution=false",
                "durable_retention=not-established",
                "build_authorization=not-established",
                "runnable=false",
                "source_to_image_provenance=not-established",
                "final_builder_image=not-established",
                "clean_system=not-established",
                "safety=not-established",
            ] {
                assert!(complete.contains(required));
            }
            for forbidden in [
                "runnable=true",
                "safety=safe",
                "build_authorization=established",
                "durable_retention=established",
                "verifier_network_activity=true",
                "harness_process_execution=true",
            ] {
                assert!(!complete.contains(forbidden));
            }
        }

        #[test]
        fn snapshot_reader_rejects_unsealed_or_oversized_content() {
            let fd = rustix::fs::memfd_create(
                "builder-context-test",
                rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
            )
            .unwrap();
            let mut file = File::from(fd);
            file.write_all(b"bytes").unwrap();
            rustix::fs::fcntl_add_seals(
                &file,
                rustix::fs::SealFlags::SEAL
                    | rustix::fs::SealFlags::SHRINK
                    | rustix::fs::SealFlags::GROW
                    | rustix::fs::SealFlags::WRITE,
            )
            .unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            let snapshot = snapshot_artifact(file.into(), 5).unwrap();
            assert_eq!(snapshot_bytes(&snapshot, 5).unwrap(), b"bytes");
            assert!(snapshot_bytes(&snapshot, 4).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{inspect_lock, verify_export};

#[cfg(not(target_os = "linux"))]
pub fn inspect_lock(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
) -> Result<VerificationReport> {
    anyhow::bail!("the exact-descriptor builder-context verifier requires Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn verify_export(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
    _input_directory: &Path,
) -> Result<VerificationReport> {
    anyhow::bail!("the exact-descriptor builder-context verifier requires Linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_lock() -> Vec<u8> {
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-builder-context-v1.lock")).unwrap()
    }

    #[test]
    fn canonical_lock_is_closed_and_non_authorizing() {
        let lock = parse_input_lock(&canonical_lock()).unwrap();
        assert_eq!(field(&lock.fields, "file_count").unwrap(), "10");
        assert_eq!(
            field(&lock.fields, "build_authorization").unwrap(),
            "not-established"
        );
        assert_eq!(field(&lock.fields, "runnable").unwrap(), "false");
        assert_eq!(
            field(&lock.fields, "source_checkout_consumed").unwrap(),
            "false"
        );
    }

    #[test]
    fn lock_rejects_reordering_extra_fields_controls_and_claim_escalation() {
        let canonical = canonical_lock();
        let text = String::from_utf8(canonical.clone()).unwrap();
        for changed in [
            text.replacen(
                "build_authorization=not-established",
                "build_authorization=established",
                1,
            ),
            text.replacen("runnable=false", "runnable=true", 1),
            text.replacen(
                "durable_retention=not-established",
                "durable_retention=established",
                1,
            ),
            text.replacen("safety=not-established", "safety=safe", 1),
            text.replacen("git_execution=forbidden", "git_execution=allowed", 1),
            text.replacen("test/vm/asahi-fresh/Dockerfile", "../Dockerfile", 1),
            text.replacen("|100644|", "|100755|", 1),
        ] {
            assert!(parse_input_lock(changed.as_bytes()).is_err());
        }
        let mut reordered = text.lines().map(str::to_owned).collect::<Vec<_>>();
        reordered.swap(0, 1);
        assert!(parse_input_lock((reordered.join("\n") + "\n").as_bytes()).is_err());
        assert!(parse_input_lock(format!("{text}extra=value\n").as_bytes()).is_err());
        let mut control = canonical;
        control[0] = 0;
        assert!(parse_input_lock(&control).is_err());
    }
}
