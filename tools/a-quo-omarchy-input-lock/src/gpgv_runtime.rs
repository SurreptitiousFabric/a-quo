use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::model::{
    ExecutionState, ExpectedObjectSpec, LockAuthority, LockRecord, NonClaimState, ReportField,
    TargetBinding, VerificationMode, VerificationReport, parse_object_specs,
};
use crate::{
    ExternalLockExpectation, MAX_LOCK_BYTES, field, parse_ordered_record, require,
    validate_relative_path,
};

const CANONICAL_LOCK_PATH: &str =
    "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-gpgv-runtime-v1.lock";
const CANONICAL_LOCK: &str = include_str!(
    "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-gpgv-runtime-v1.lock"
);
const PARENT_OCI_LOCK_PATH: &str =
    "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock";
const ELF_FILE_MAXIMUM: usize = 4 * 1024 * 1024;
const PROGRAM_HEADER_MAXIMUM: usize = 64;
const DYNAMIC_ENTRY_MAXIMUM: usize = 256;
const STRING_TABLE_MAXIMUM: u64 = 1024 * 1024;
const STRING_MAXIMUM: usize = 127;
const NEEDED_MAXIMUM: usize = 16;

pub type GpgvRuntimeVerificationReport = VerificationReport;

#[derive(Clone, Debug)]
pub struct GpgvRuntimeLock {
    record: LockRecord,
    metadata: Vec<RuntimeMetadata>,
    elfs: Vec<ElfSpec>,
    dependencies: Vec<DependencySpec>,
}

#[cfg(target_os = "linux")]
impl GpgvRuntimeLock {
    pub(crate) fn locked_field(&self, key: &str) -> Result<&str> {
        field(&self.record.fields, key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RuntimeObjectType {
    Regular,
    Symlink,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeMaterializationKind {
    Regular,
    Symlink,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeMaterialization {
    pub(crate) path: String,
    pub(crate) kind: RuntimeMaterializationKind,
    pub(crate) mode: u32,
    pub(crate) size: u64,
    pub(crate) sha256: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeMetadata {
    kind: RuntimeObjectType,
    mode: u32,
    symlink_target: Option<String>,
    resolved_target: String,
    resolved_regular: String,
    package: String,
    package_version: String,
    record: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ElfSpec {
    path: String,
    os_abi: u8,
    abi_version: u8,
    pie: bool,
    interpreter: Option<String>,
    needed: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DependencySpec {
    source: String,
    needed: String,
    lookup: String,
    resolved: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedElf {
    interpreter: Option<String>,
    needed: Vec<String>,
}

const EXPECTED_OBJECTS: &[ExpectedObjectSpec] = &[
    ExpectedObjectSpec {
        role: "gpgv-executable",
        path: "usr/bin/gpgv",
        media_type: "application/x-elf",
        size: 330_648,
        sha256: "a7b1bc1a88927e6f5b30101c415c311aaa9810f51642c12a6b1a824a4c1df1fa",
    },
    ExpectedObjectSpec {
        role: "interpreter-prefix-symlink",
        path: "lib",
        media_type: "inode/symlink",
        size: 7,
        sha256: "bb40df61b3e0947109adb2e4d4ec41261d2c50580463391f34d67b5f30712176",
    },
    ExpectedObjectSpec {
        role: "interpreter-symlink",
        path: "usr/lib/ld-linux-aarch64.so.1",
        media_type: "inode/symlink",
        size: 39,
        sha256: "8f5d71dfa5070a28dd64d8d3694da7521290a475809f29b01ed81ffa4984584b",
    },
    ExpectedObjectSpec {
        role: "elf-loader",
        path: "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        media_type: "application/x-elf",
        size: 203_968,
        sha256: "49005ef8e9db9a45691ff875e6ca18dd8723c7ec5c1a863a276a1186dbf22774",
    },
    ExpectedObjectSpec {
        role: "libz-soname-symlink",
        path: "usr/lib/aarch64-linux-gnu/libz.so.1",
        media_type: "inode/symlink",
        size: 11,
        sha256: "21b6cae17d670c4d95b7650d380358688099d2d5166dc2aa8413c47d088a1721",
    },
    ExpectedObjectSpec {
        role: "libz-runtime",
        path: "usr/lib/aarch64-linux-gnu/libz.so.1.3",
        media_type: "application/x-elf",
        size: 133_272,
        sha256: "170380b4e7ab28ec86eb090b48df90f84089392cb72fecd5067e5b7a4dc5239f",
    },
    ExpectedObjectSpec {
        role: "libbz2-soname-symlink",
        path: "usr/lib/aarch64-linux-gnu/libbz2.so.1.0",
        media_type: "inode/symlink",
        size: 15,
        sha256: "e6413b74f6eecc9668978f1423a2a6ac511c1d191225e10d5d9a4ad725efa20e",
    },
    ExpectedObjectSpec {
        role: "libbz2-runtime",
        path: "usr/lib/aarch64-linux-gnu/libbz2.so.1.0.4",
        media_type: "application/x-elf",
        size: 70_504,
        sha256: "89a72a9874f39034ece340558678398522a05d143541659b7dcc1f7b8cfbc145",
    },
    ExpectedObjectSpec {
        role: "libgcrypt-soname-symlink",
        path: "usr/lib/aarch64-linux-gnu/libgcrypt.so.20",
        media_type: "inode/symlink",
        size: 19,
        sha256: "3c25038d012c0b9c5a462bd5e981aad18da3f537fed5ffa45c3db3acf1805426",
    },
    ExpectedObjectSpec {
        role: "libgcrypt-runtime",
        path: "usr/lib/aarch64-linux-gnu/libgcrypt.so.20.4.3",
        media_type: "application/x-elf",
        size: 1_000_536,
        sha256: "fab6cc79218fb1af1327af5bb25d41d165b7a2185cc3852c8682805816182ed4",
    },
    ExpectedObjectSpec {
        role: "libassuan-soname-symlink",
        path: "usr/lib/aarch64-linux-gnu/libassuan.so.0",
        media_type: "inode/symlink",
        size: 18,
        sha256: "2ba3ea2f99d7a4c55364e19c2faf7033ee3123b36df553277ded265636f35534",
    },
    ExpectedObjectSpec {
        role: "libassuan-runtime",
        path: "usr/lib/aarch64-linux-gnu/libassuan.so.0.8.6",
        media_type: "application/x-elf",
        size: 133_200,
        sha256: "436eb6f36289ffabff387b68ac62df342f7b229783b865c60baa346ecf59e31b",
    },
    ExpectedObjectSpec {
        role: "libnpth-soname-symlink",
        path: "usr/lib/aarch64-linux-gnu/libnpth.so.0",
        media_type: "inode/symlink",
        size: 16,
        sha256: "33f3a92748193b66c2212ba1e0544595b09e76dc2991dbad1a5a919f4b9757cb",
    },
    ExpectedObjectSpec {
        role: "libnpth-runtime",
        path: "usr/lib/aarch64-linux-gnu/libnpth.so.0.1.2",
        media_type: "application/x-elf",
        size: 67_888,
        sha256: "56aec4d8faab7df2b03f615bf18ab959d182cc13e564d6bcbb95c9fd662a6782",
    },
    ExpectedObjectSpec {
        role: "libgpg-error-soname-symlink",
        path: "usr/lib/aarch64-linux-gnu/libgpg-error.so.0",
        media_type: "inode/symlink",
        size: 22,
        sha256: "ccaa480de455b5f6bee3ed3a84353ebe988d23180c64ac792adbc32096243092",
    },
    ExpectedObjectSpec {
        role: "libgpg-error-runtime",
        path: "usr/lib/aarch64-linux-gnu/libgpg-error.so.0.34.0",
        media_type: "application/x-elf",
        size: 198_648,
        sha256: "ff2dccba4993ef97775b70c1ed1144f70dfe8581ee48c1eb25c76878c6cdfdf7",
    },
    ExpectedObjectSpec {
        role: "libc-runtime",
        path: "usr/lib/aarch64-linux-gnu/libc.so.6",
        media_type: "application/x-elf",
        size: 1_722_920,
        sha256: "6e3cc56b98887cb3cc2a9fe78b6dd4610184aa27bd05d592cb287db93e82d494",
    },
];

pub fn parse_gpgv_runtime_lock(bytes: &[u8]) -> Result<GpgvRuntimeLock> {
    ensure!(
        bytes == CANONICAL_LOCK.as_bytes(),
        "gpgv runtime lock bytes differ from the canonical reviewed lock"
    );
    let keys = CANONICAL_LOCK
        .lines()
        .map(|line| {
            line.split_once('=')
                .expect("canonical gpgv runtime lock syntax")
                .0
        })
        .collect::<Vec<_>>();
    let fields = parse_ordered_record(bytes, &keys, "gpgv runtime lock")?;
    for (key, expected) in [
        (
            "selected_input_scope",
            "parent-ubuntu-oci-gpgv-static-runtime-closure",
        ),
        ("oci_filesystem_root", "/"),
        (
            "parent_oci_lock_repository",
            "https://github.com/SurreptitiousFabric/a-quo.git",
        ),
        (
            "parent_oci_lock_commit",
            "4487debf6c218d9f13b93c60242887830ecc6d73",
        ),
        ("parent_oci_lock_path", PARENT_OCI_LOCK_PATH),
        (
            "parent_oci_lock_sha256",
            "667545062b9c34b990f1d6441b749a11f01f13bdf3f4aeb87ad9f0fb4a03c878",
        ),
        ("parent_oci_layer_path", "layer-01.tar.gz"),
        ("parent_oci_layer_size", "28887235"),
        (
            "parent_oci_layer_sha256",
            "0b613318ea879878918380aa3aeb220dfe824e311b83bc955cb8a1d4319650ab",
        ),
        ("runtime_regular_file_count", "9"),
        ("runtime_symlink_count", "8"),
        ("elf_object_count", "9"),
        ("dependency_count", "23"),
        (
            "runtime_metadata_format",
            "type|mode|symlink-target-or-none|immediate-resolved-target|selected-traversal-final-regular-object|package|version",
        ),
        ("symlink_identity", "target-text-size-and-sha256"),
        ("interpreter_path", "/lib/ld-linux-aarch64.so.1"),
        (
            "interpreter_resolved_path",
            "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        ),
        ("direct_needed_count", "8"),
        (
            "direct_needed_order",
            "libz.so.1,libbz2.so.1.0,libgcrypt.so.20,libassuan.so.0,libnpth.so.0,libgpg-error.so.0,libc.so.6,ld-linux-aarch64.so.1",
        ),
        ("rpath", "absent"),
        ("runpath", "absent"),
        (
            "package_metadata_authority",
            "non-authoritative-descriptive-observation",
        ),
        ("future_execution_contract", "selected-not-executed"),
        (
            "future_direct_loader",
            "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        ),
        (
            "future_loader_arguments",
            "--inhibit-cache,--library-path,/usr/lib/aarch64-linux-gnu",
        ),
        ("future_program", "/usr/bin/gpgv"),
        ("future_no_default_keyring", "true"),
        ("future_no_host_configuration", "true"),
        ("future_no_helper_binaries", "true"),
        ("future_no_network", "true"),
        ("future_read_only_runtime_and_inputs", "true"),
        ("future_private_writable_temporary_area", "true"),
        ("future_cleanup_required", "true"),
        ("runtime_option_compatibility", "not-established"),
        ("nss_passwd_requirements", "not-established"),
        ("locale_and_gconv_requirements", "not-established"),
        ("randomness_requirements", "not-established"),
        ("dev_null_and_proc_self_fd_requirements", "not-established"),
        ("helper_config_keybox_access", "not-established"),
        ("status_fd_sequence", "not-established"),
        ("temporary_root_cleanup", "not-established"),
        ("publisher_authentication", "not-established"),
        ("current_publisher_authorization", "not-established"),
        ("current_revocation_status", "not-established"),
        ("trusted_time", "not-established"),
        ("freshness", "not-established"),
        ("source_to_binary_provenance", "not-established"),
        ("verifier_correctness", "not-established"),
        ("safety", "not-established"),
        ("runtime_materialization", "false"),
        ("retained_loader_execution", "false"),
        ("gpgv_execution", "false"),
        ("signature_replay", "false"),
        ("archive_filesystem_extraction", "false"),
        ("package_manager_execution", "false"),
        ("mount_execution", "false"),
        ("namespace_creation", "false"),
        ("network_access", "forbidden"),
        ("vm_execution", "false"),
    ] {
        require(&fields, key, expected)?;
    }
    for key in [
        "future_program_arguments",
        "future_environment",
        "future_keyring_path",
        "future_keyring_size",
        "future_keyring_sha256",
        "future_required_signer_fingerprint",
    ] {
        ensure!(!field(&fields, key)?.is_empty(), "{key} is empty");
    }

    let objects = parse_object_specs(&fields, EXPECTED_OBJECTS, "gpgv runtime")?;
    let metadata = parse_runtime_metadata(&fields, &objects)?;
    let elfs = parse_elf_specs(&fields, &objects, &metadata)?;
    let dependencies = parse_dependencies(&fields, &elfs)?;
    let record = LockRecord::new(
        fields,
        objects,
        "a-quo-omarchy-gpgv-runtime-input-lock-v1",
        "a-quo-omarchy4-aarch64-dec29fa-gpgv-runtime-v1",
        LockAuthority::GpgvRuntime,
        CANONICAL_LOCK_PATH,
        TargetBinding::GPGV_RUNTIME,
    )?;
    Ok(GpgvRuntimeLock {
        record,
        metadata,
        elfs,
        dependencies,
    })
}

fn parse_runtime_metadata(
    fields: &BTreeMap<String, String>,
    objects: &[crate::ObjectSpec],
) -> Result<Vec<RuntimeMetadata>> {
    let mut metadata = Vec::with_capacity(objects.len());
    let mut regular = 0_usize;
    let mut symlinks = 0_usize;
    for (index, object) in objects.iter().enumerate() {
        let key = format!("runtime_metadata_{:02}", index + 1);
        let record = field(fields, &key)?.to_owned();
        let parts = record.split('|').collect::<Vec<_>>();
        ensure!(parts.len() == 7, "{key} has the wrong field count");
        let kind = match parts[0] {
            "regular" => {
                regular += 1;
                ensure!(
                    object.media_type == "application/x-elf",
                    "{key} regular type differs from its object record"
                );
                RuntimeObjectType::Regular
            }
            "symlink" => {
                symlinks += 1;
                ensure!(
                    object.media_type == "inode/symlink",
                    "{key} symlink type differs from its object record"
                );
                RuntimeObjectType::Symlink
            }
            _ => anyhow::bail!("{key} has an unknown file type"),
        };
        ensure!(parts[1].len() == 4, "{key} mode is not four octal digits");
        let mode = u32::from_str_radix(parts[1], 8).context("invalid runtime object mode")?;
        ensure!(
            matches!(mode, 0o644 | 0o755 | 0o777),
            "{key} mode is outside the closed policy"
        );
        let symlink_target = if parts[2] == "none" {
            None
        } else {
            validate_relative_path(parts[2])?;
            Some(parts[2].to_owned())
        };
        ensure!(
            matches!(kind, RuntimeObjectType::Symlink) == symlink_target.is_some(),
            "{key} symlink target does not match its type"
        );
        validate_relative_path(parts[3])?;
        validate_relative_path(parts[4])?;
        ensure!(
            !parts[5].is_empty()
                && !parts[6].is_empty()
                && parts[5..]
                    .iter()
                    .all(|value| value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))),
            "{key} package observation has invalid text"
        );
        metadata.push(RuntimeMetadata {
            kind,
            mode,
            symlink_target,
            resolved_target: parts[3].to_owned(),
            resolved_regular: parts[4].to_owned(),
            package: parts[5].to_owned(),
            package_version: parts[6].to_owned(),
            record,
        });
    }
    ensure!(
        regular == 9,
        "runtime lock does not have nine regular files"
    );
    ensure!(symlinks == 8, "runtime lock does not have eight symlinks");
    Ok(metadata)
}

fn parse_elf_specs(
    fields: &BTreeMap<String, String>,
    objects: &[crate::ObjectSpec],
    metadata: &[RuntimeMetadata],
) -> Result<Vec<ElfSpec>> {
    let count = field(fields, "elf_object_count")?
        .parse::<usize>()
        .context("invalid ELF object count")?;
    ensure!(
        count == 9,
        "ELF object count differs from the closed policy"
    );
    let regular_paths = objects
        .iter()
        .zip(metadata)
        .filter(|(_, metadata)| metadata.kind == RuntimeObjectType::Regular)
        .map(|(object, _)| object.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut paths = BTreeSet::new();
    let mut elfs = Vec::with_capacity(count);
    for index in 0..count {
        let key = format!("elf_{:02}", index + 1);
        let parts = field(fields, &key)?.split('|').collect::<Vec<_>>();
        ensure!(parts.len() == 10, "{key} has the wrong field count");
        validate_relative_path(parts[0])?;
        ensure!(
            regular_paths.contains(parts[0]),
            "{key} does not name a locked regular object"
        );
        ensure!(paths.insert(parts[0]), "ELF path is duplicated");
        let os_abi = match parts[1] {
            "system-v" => 0,
            "gnu-linux" => 3,
            _ => anyhow::bail!("{key} has an unsupported OS ABI"),
        };
        ensure!(parts[2] == "0", "{key} has a nonzero ABI version");
        ensure!(parts[3] == "et-dyn", "{key} is not ET_DYN");
        ensure!(parts[4] == "aarch64", "{key} is not AArch64");
        let pie = match parts[5] {
            "pie-executable" => true,
            "shared-object" => false,
            _ => anyhow::bail!("{key} has an unknown ET_DYN role"),
        };
        let interpreter = match parts[6] {
            "none" => None,
            value => {
                ensure!(
                    value.starts_with('/') && value.len() <= STRING_MAXIMUM,
                    "{key} interpreter is outside the closed bound"
                );
                Some(value.to_owned())
            }
        };
        let needed = if parts[7] == "none" {
            Vec::new()
        } else {
            parts[7].split(',').map(str::to_owned).collect::<Vec<_>>()
        };
        ensure!(
            needed.len() <= NEEDED_MAXIMUM
                && needed.iter().all(|name| {
                    !name.is_empty()
                        && name.len() <= STRING_MAXIMUM
                        && !name.contains('/')
                        && name.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
                }),
            "{key} needed sequence is outside the closed bound"
        );
        ensure!(
            parts[8] == "absent" && parts[9] == "absent",
            "{key} permits RPATH or RUNPATH"
        );
        elfs.push(ElfSpec {
            path: parts[0].to_owned(),
            os_abi,
            abi_version: 0,
            pie,
            interpreter,
            needed,
        });
    }
    ensure!(
        paths == regular_paths,
        "ELF records do not cover exactly the regular runtime objects"
    );
    Ok(elfs)
}

fn parse_dependencies(
    fields: &BTreeMap<String, String>,
    elfs: &[ElfSpec],
) -> Result<Vec<DependencySpec>> {
    let count = field(fields, "dependency_count")?
        .parse::<usize>()
        .context("invalid dependency count")?;
    ensure!(
        count == 23,
        "dependency count differs from the closed policy"
    );
    let expected = elfs
        .iter()
        .flat_map(|elf| {
            elf.needed
                .iter()
                .map(move |needed| (elf.path.as_str(), needed.as_str()))
        })
        .collect::<Vec<_>>();
    ensure!(
        expected.len() == count,
        "ELF closure is not 23 dependencies"
    );
    let mut dependencies = Vec::with_capacity(count);
    let mut unique = BTreeSet::new();
    for (index, (expected_source, expected_needed)) in expected.into_iter().enumerate() {
        let key = format!("dependency_{:02}", index + 1);
        let parts = field(fields, &key)?.split('|').collect::<Vec<_>>();
        ensure!(parts.len() == 4, "{key} has the wrong field count");
        ensure!(
            (parts[0], parts[1]) == (expected_source, expected_needed),
            "{key} differs from the ordered ELF dependency graph"
        );
        validate_relative_path(parts[0])?;
        validate_relative_path(parts[2])?;
        validate_relative_path(parts[3])?;
        ensure!(
            unique.insert((parts[0], parts[1])),
            "dependency source/name pair is duplicated"
        );
        dependencies.push(DependencySpec {
            source: parts[0].to_owned(),
            needed: parts[1].to_owned(),
            lookup: parts[2].to_owned(),
            resolved: parts[3].to_owned(),
        });
    }
    Ok(dependencies)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes.get(offset..offset + 2).context("truncated ELF u16")?;
    Ok(u16::from_le_bytes(value.try_into().expect("two bytes")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).context("truncated ELF u32")?;
    Ok(u32::from_le_bytes(value.try_into().expect("four bytes")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).context("truncated ELF u64")?;
    Ok(u64::from_le_bytes(value.try_into().expect("eight bytes")))
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

fn file_range(bytes: &[u8], offset: u64, size: u64, label: &str) -> Result<std::ops::Range<usize>> {
    let start = usize::try_from(offset).context("ELF offset does not fit memory")?;
    let length = usize::try_from(size).context("ELF size does not fit memory")?;
    let end = start.checked_add(length).context("ELF range overflow")?;
    ensure!(end <= bytes.len(), "{label} exceeds the ELF object");
    Ok(start..end)
}

fn ranges_overlap(left: &std::ops::Range<usize>, right: &std::ops::Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

fn virtual_range(
    bytes: &[u8],
    headers: &[ProgramHeader],
    address: u64,
    size: u64,
) -> Result<std::ops::Range<usize>> {
    let matches = headers
        .iter()
        .filter(|header| header.kind == 1 && address >= header.virtual_address)
        .filter(|header| {
            let relative = address - header.virtual_address;
            relative <= header.file_size && size <= header.file_size - relative
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "ELF virtual range is not backed by exactly one load segment"
    );
    file_range(
        bytes,
        matches[0]
            .offset
            .checked_add(address - matches[0].virtual_address)
            .context("ELF address overflow")?,
        size,
        "ELF virtual range",
    )
}

fn c_string(bytes: &[u8], offset: u64, label: &str) -> Result<String> {
    let offset = usize::try_from(offset).context("ELF string offset does not fit memory")?;
    let tail = bytes
        .get(offset..)
        .context("ELF string offset is out of range")?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .context("ELF string is unterminated")?;
    ensure!(
        (1..=STRING_MAXIMUM).contains(&end),
        "{label} is outside the closed string bound"
    );
    let value = std::str::from_utf8(&tail[..end]).context("ELF string is not UTF-8")?;
    ensure!(
        value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
        "{label} contains a forbidden byte"
    );
    Ok(value.to_owned())
}

fn parse_elf(bytes: &[u8], spec: &ElfSpec) -> Result<ParsedElf> {
    ensure!(
        (64..=ELF_FILE_MAXIMUM).contains(&bytes.len()),
        "ELF object is outside the closed byte bound"
    );
    ensure!(
        &bytes[..4] == b"\x7fELF",
        "ELF magic differs from the policy"
    );
    ensure!(bytes[4] == 2, "ELF object is not ELF64");
    ensure!(bytes[5] == 1, "ELF object is not little endian");
    ensure!(bytes[6] == 1, "ELF identity version is not current");
    ensure!(bytes[7] == spec.os_abi, "ELF OS ABI differs from the lock");
    ensure!(
        bytes[8] == spec.abi_version,
        "ELF ABI version differs from the lock"
    );
    ensure!(
        bytes[9..16].iter().all(|byte| *byte == 0),
        "ELF identity padding is nonzero"
    );
    ensure!(read_u16(bytes, 16)? == 3, "ELF type is not ET_DYN");
    ensure!(read_u16(bytes, 18)? == 183, "ELF machine is not AArch64");
    ensure!(read_u32(bytes, 20)? == 1, "ELF version is not current");
    ensure!(read_u16(bytes, 52)? == 64, "ELF header size is not 64");
    ensure!(
        read_u16(bytes, 54)? == 56,
        "ELF program-header size is not 56"
    );
    let program_offset = read_u64(bytes, 32)?;
    let program_count = read_u16(bytes, 56)? as usize;
    ensure!(
        (1..=PROGRAM_HEADER_MAXIMUM).contains(&program_count),
        "ELF program-header count is outside the closed bound"
    );
    let table_size = (program_count as u64)
        .checked_mul(56)
        .context("ELF program-header table overflow")?;
    let program_range = file_range(
        bytes,
        program_offset,
        table_size,
        "ELF program-header table",
    )?;
    ensure!(
        !ranges_overlap(&(0..64), &program_range),
        "ELF header and program-header table overlap"
    );

    let mut headers = Vec::with_capacity(program_count);
    for index in 0..program_count {
        let offset = program_range
            .start
            .checked_add(index * 56)
            .context("ELF program-header offset overflow")?;
        let header = ProgramHeader {
            kind: read_u32(bytes, offset)?,
            offset: read_u64(bytes, offset + 8)?,
            virtual_address: read_u64(bytes, offset + 16)?,
            file_size: read_u64(bytes, offset + 32)?,
            memory_size: read_u64(bytes, offset + 40)?,
        };
        ensure!(
            header.file_size <= header.memory_size || header.kind != 1,
            "ELF load segment file size exceeds memory size"
        );
        file_range(
            bytes,
            header.offset,
            header.file_size,
            "ELF program segment",
        )?;
        headers.push(header);
    }

    let interpreters = headers
        .iter()
        .filter(|header| header.kind == 3)
        .collect::<Vec<_>>();
    let interpreter = match interpreters.as_slice() {
        [] => None,
        [header] => {
            ensure!(
                (2..=128).contains(&header.file_size),
                "ELF interpreter is outside its byte bound"
            );
            let range = file_range(bytes, header.offset, header.file_size, "ELF interpreter")?;
            ensure!(
                !ranges_overlap(&range, &program_range),
                "ELF interpreter overlaps the program-header table"
            );
            let raw = &bytes[range];
            ensure!(
                raw.last() == Some(&0) && !raw[..raw.len() - 1].contains(&0),
                "ELF interpreter is not exactly one NUL-terminated string"
            );
            let value = std::str::from_utf8(&raw[..raw.len() - 1])
                .context("ELF interpreter is not UTF-8")?;
            ensure!(
                value.starts_with('/')
                    && value.len() <= STRING_MAXIMUM
                    && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
                "ELF interpreter is outside the closed path policy"
            );
            Some(value.to_owned())
        }
        _ => anyhow::bail!("ELF has multiple interpreter segments"),
    };
    ensure!(
        interpreter == spec.interpreter,
        "ELF interpreter differs from the lock"
    );

    let dynamics = headers
        .iter()
        .filter(|header| header.kind == 2)
        .collect::<Vec<_>>();
    ensure!(
        dynamics.len() == 1,
        "ELF does not have exactly one dynamic segment"
    );
    let dynamic = dynamics[0];
    ensure!(
        dynamic.file_size > 0
            && dynamic.file_size % 16 == 0
            && dynamic.file_size / 16 <= DYNAMIC_ENTRY_MAXIMUM as u64,
        "ELF dynamic segment is outside the closed bound"
    );
    let dynamic_range = file_range(
        bytes,
        dynamic.offset,
        dynamic.file_size,
        "ELF dynamic segment",
    )?;
    ensure!(
        !ranges_overlap(&dynamic_range, &program_range),
        "ELF dynamic segment overlaps the program-header table"
    );
    if let [interpreter] = interpreters.as_slice() {
        let interpreter_range = file_range(
            bytes,
            interpreter.offset,
            interpreter.file_size,
            "ELF interpreter",
        )?;
        ensure!(
            !ranges_overlap(&dynamic_range, &interpreter_range),
            "ELF dynamic and interpreter segments overlap"
        );
    }

    let mut needed_offsets = Vec::new();
    let mut string_address = None;
    let mut string_size = None;
    let mut flags_1 = None;
    let mut terminated = false;
    for offset in (dynamic_range.start..dynamic_range.end).step_by(16) {
        let tag = read_u64(bytes, offset)?;
        let value = read_u64(bytes, offset + 8)?;
        if terminated {
            ensure!(tag == 0 && value == 0, "ELF dynamic data follows DT_NULL");
            continue;
        }
        match tag {
            0 => {
                ensure!(value == 0, "ELF DT_NULL has a nonzero value");
                terminated = true;
            }
            1 => {
                ensure!(
                    needed_offsets.len() < NEEDED_MAXIMUM,
                    "ELF DT_NEEDED count exceeds the closed bound"
                );
                needed_offsets.push(value);
            }
            5 => ensure!(
                string_address.replace(value).is_none(),
                "ELF repeats DT_STRTAB"
            ),
            10 => ensure!(string_size.replace(value).is_none(), "ELF repeats DT_STRSZ"),
            15 => anyhow::bail!("ELF contains forbidden DT_RPATH"),
            29 => anyhow::bail!("ELF contains forbidden DT_RUNPATH"),
            0x6fff_fefa | 0x6fff_fefb | 0x6fff_fefc | 0x7fff_fffd | 0x7fff_ffff => {
                anyhow::bail!("ELF contains an unmodeled dynamic dependency mechanism")
            }
            0x6fff_fffb => ensure!(flags_1.replace(value).is_none(), "ELF repeats DT_FLAGS_1"),
            _ => {}
        }
    }
    ensure!(terminated, "ELF dynamic segment lacks DT_NULL");
    ensure!(
        (flags_1.unwrap_or(0) & 0x0800_0000 != 0) == spec.pie,
        "ELF PIE state differs from the lock"
    );
    let string_size = string_size.context("ELF lacks DT_STRSZ")?;
    ensure!(
        (1..=STRING_TABLE_MAXIMUM).contains(&string_size),
        "ELF dynamic string table is outside the closed bound"
    );
    let string_range = virtual_range(
        bytes,
        &headers,
        string_address.context("ELF lacks DT_STRTAB")?,
        string_size,
    )?;
    ensure!(
        !ranges_overlap(&string_range, &dynamic_range),
        "ELF dynamic string table overlaps the dynamic segment"
    );
    let strings = &bytes[string_range];
    let mut needed = Vec::with_capacity(needed_offsets.len());
    let mut unique = BTreeSet::new();
    for offset in needed_offsets {
        let value = c_string(strings, offset, "ELF needed name")?;
        ensure!(unique.insert(value.clone()), "ELF repeats a DT_NEEDED name");
        needed.push(value);
    }
    ensure!(
        needed == spec.needed,
        "ELF DT_NEEDED order differs from the lock"
    );
    Ok(ParsedElf {
        interpreter,
        needed,
    })
}

fn report(
    lock: &GpgvRuntimeLock,
    expectation: &ExternalLockExpectation,
    parent: &crate::InputLock,
) -> GpgvRuntimeVerificationReport {
    let fields = &lock.record.fields;
    let mut report = VerificationReport::for_lock(
        &lock.record,
        expectation,
        VerificationMode::InputSelection,
        true,
    );
    report.extend(lock.metadata.iter().enumerate().map(|(index, metadata)| {
        ReportField::text(
            format!("runtime_metadata_{:02}", index + 1),
            &metadata.record,
        )
    }));
    report.extend([
        ReportField::text(
            "locked_state",
            field(fields, "state").expect("validated runtime lock"),
        ),
        ReportField::text(
            "locked_retention",
            field(fields, "retention").expect("validated runtime lock"),
        ),
        ReportField::text(
            "locked_lock_authentication",
            field(fields, "lock_authentication").expect("validated runtime lock"),
        ),
        ReportField::text(
            "locked_self_authentication",
            field(fields, "self_authentication").expect("validated runtime lock"),
        ),
        ReportField::text(
            "locked_selected_input_scope",
            field(fields, "selected_input_scope").expect("validated runtime lock"),
        ),
        ReportField::text(
            "oci_filesystem_root",
            field(fields, "oci_filesystem_root").expect("validated runtime lock"),
        ),
        ReportField::text(
            "profile_state",
            field(fields, "profile_state").expect("validated runtime lock"),
        ),
        ReportField::boolean("profile_armable", false),
        ReportField::boolean("external_lock_authentication_required", true),
        ReportField::boolean(
            "external_lock_authentication_established_by_verifier",
            false,
        ),
        ReportField::text(
            "parent_oci_lock_repository",
            field(fields, "parent_oci_lock_repository").expect("validated runtime lock"),
        ),
        ReportField::text(
            "parent_oci_lock_commit",
            field(fields, "parent_oci_lock_commit").expect("validated runtime lock"),
        ),
        ReportField::text(
            "parent_oci_lock_path",
            field(fields, "parent_oci_lock_path").expect("validated runtime lock"),
        ),
        ReportField::text(
            "parent_oci_lock_sha256",
            field(fields, "parent_oci_lock_sha256").expect("validated runtime lock"),
        ),
        ReportField::boolean("parent_oci_lock_bytes_verified", true),
        ReportField::boolean("parent_oci_input_selection_verified", true),
        ReportField::text(
            "parent_oci_source_to_image_provenance",
            field(&parent.fields, "source_to_image_provenance").expect("validated parent OCI lock"),
        ),
        ReportField::boolean("parent_oci_git_object_authenticated", false),
        ReportField::text(
            "parent_oci_layer_path",
            field(fields, "parent_oci_layer_path").expect("validated runtime lock"),
        ),
        ReportField::text(
            "parent_oci_layer_size",
            field(fields, "parent_oci_layer_size").expect("validated runtime lock"),
        ),
        ReportField::text(
            "parent_oci_layer_sha256",
            field(fields, "parent_oci_layer_sha256").expect("validated runtime lock"),
        ),
        ReportField::count("runtime_regular_file_count", lock.metadata.len() - 8),
        ReportField::count("runtime_symlink_count", 8),
        ReportField::count("elf_object_count", lock.elfs.len()),
        ReportField::count("dependency_count", lock.dependencies.len()),
        ReportField::text(
            "runtime_metadata_format",
            field(fields, "runtime_metadata_format").expect("validated runtime lock"),
        ),
        ReportField::text(
            "symlink_identity",
            field(fields, "symlink_identity").expect("validated runtime lock"),
        ),
        ReportField::boolean("runtime_object_bytes_verified", true),
        ReportField::boolean("runtime_object_types_and_modes_verified", true),
        ReportField::boolean("runtime_archive_stream_inspected", true),
        ReportField::boolean("static_elf_parsing_performed", true),
        ReportField::text(
            "static_elf_parser",
            "bounded-in-process-elf64-little-endian-aarch64-policy",
        ),
        ReportField::text("elf_type", "et-dyn"),
        ReportField::boolean("gpgv_pie", true),
        ReportField::text(
            "elf_osabi_policy",
            "system-v-or-gnu-linux-as-locked-per-object",
        ),
        ReportField::text(
            "interpreter_path",
            field(fields, "interpreter_path").expect("validated runtime lock"),
        ),
        ReportField::text(
            "interpreter_resolved_path",
            field(fields, "interpreter_resolved_path").expect("validated runtime lock"),
        ),
        ReportField::text(
            "direct_needed_order",
            field(fields, "direct_needed_order").expect("validated runtime lock"),
        ),
        ReportField::boolean("interpreter_and_dependency_graph_verified", true),
        ReportField::boolean("symlink_graph_verified", true),
        ReportField::boolean(
            "dt_needed_dependency_outside_selected_oci_filesystem",
            false,
        ),
        ReportField::boolean("all_elf_rpath_absent", true),
        ReportField::boolean("all_elf_runpath_absent", true),
        ReportField::text("rpath", "absent"),
        ReportField::text("runpath", "absent"),
        ReportField::text(
            "package_metadata_authority",
            "non-authoritative-descriptive-observation",
        ),
        ReportField::text("future_execution_contract", "selected-not-executed"),
        ReportField::text(
            "future_direct_loader",
            field(fields, "future_direct_loader").expect("validated runtime lock"),
        ),
        ReportField::text(
            "future_loader_arguments",
            field(fields, "future_loader_arguments").expect("validated runtime lock"),
        ),
        ReportField::text(
            "future_program",
            field(fields, "future_program").expect("validated runtime lock"),
        ),
        ReportField::text(
            "future_program_arguments",
            field(fields, "future_program_arguments").expect("validated runtime lock"),
        ),
        ReportField::text(
            "future_environment",
            field(fields, "future_environment").expect("validated runtime lock"),
        ),
        ReportField::text(
            "future_keyring_path",
            field(fields, "future_keyring_path").expect("validated runtime lock"),
        ),
        ReportField::text(
            "future_keyring_size",
            field(fields, "future_keyring_size").expect("validated runtime lock"),
        ),
        ReportField::text(
            "future_keyring_sha256",
            field(fields, "future_keyring_sha256").expect("validated runtime lock"),
        ),
        ReportField::text(
            "future_required_signer_fingerprint",
            field(fields, "future_required_signer_fingerprint").expect("validated runtime lock"),
        ),
        ReportField::boolean("future_no_default_keyring", true),
        ReportField::boolean("future_no_host_configuration", true),
        ReportField::boolean("future_no_helper_binaries", true),
        ReportField::boolean("future_no_network", true),
        ReportField::boolean("future_read_only_runtime_and_inputs", true),
        ReportField::boolean("future_private_writable_temporary_area", true),
        ReportField::boolean("future_cleanup_required", true),
        ReportField::nonclaim("runtime_option_compatibility", NonClaimState::Unestablished),
        ReportField::text("runtime_configuration_isolation", "not-execution-proven"),
        ReportField::nonclaim("nss_passwd_requirements", NonClaimState::Unestablished),
        ReportField::nonclaim(
            "locale_and_gconv_requirements",
            NonClaimState::Unestablished,
        ),
        ReportField::nonclaim("randomness_requirements", NonClaimState::Unestablished),
        ReportField::nonclaim(
            "dev_null_and_proc_self_fd_requirements",
            NonClaimState::Unestablished,
        ),
        ReportField::nonclaim("helper_config_keybox_access", NonClaimState::Unestablished),
        ReportField::nonclaim("status_fd_sequence", NonClaimState::Unestablished),
        ReportField::nonclaim("temporary_root_cleanup", NonClaimState::Unestablished),
        ReportField::nonclaim("durable_retention", NonClaimState::Unestablished),
        ReportField::nonclaim("ubuntu_signature_validity", NonClaimState::Unestablished),
        ReportField::execution(
            "release_to_packages_verification",
            ExecutionState::NotPerformed,
        ),
        ReportField::execution("package_archive_verification", ExecutionState::NotPerformed),
        ReportField::execution("apt_solver_replay", ExecutionState::NotPerformed),
        ReportField::nonclaim(
            "apt_dependency_closure_correctness",
            NonClaimState::Unestablished,
        ),
        ReportField::nonclaim(
            "archive_equivalence_to_original_ports",
            NonClaimState::Unestablished,
        ),
        ReportField::nonclaim("durable_candidate_retention", NonClaimState::Unestablished),
        ReportField::nonclaim("publisher_authentication", NonClaimState::Unestablished),
        ReportField::nonclaim(
            "current_publisher_authorization",
            NonClaimState::Unestablished,
        ),
        ReportField::nonclaim("current_revocation_status", NonClaimState::Unestablished),
        ReportField::nonclaim("trusted_time", NonClaimState::Unestablished),
        ReportField::nonclaim("freshness", NonClaimState::Unestablished),
        ReportField::nonclaim("source_to_binary_provenance", NonClaimState::Unestablished),
        ReportField::nonclaim("verifier_correctness", NonClaimState::Unestablished),
        ReportField::nonclaim("safety", NonClaimState::Unestablished),
        ReportField::nonclaim("construction_authority", NonClaimState::Unestablished),
        ReportField::nonclaim(
            "build_authorization",
            lock.record.envelope.build_authorization,
        ),
        ReportField::execution("runnable", lock.record.envelope.runnable),
        ReportField::execution("runtime_materialization", ExecutionState::NotPerformed),
        ReportField::execution("retained_loader_execution", ExecutionState::NotPerformed),
        ReportField::execution("gpgv_execution", ExecutionState::NotPerformed),
        ReportField::execution("signature_replay", ExecutionState::NotPerformed),
        ReportField::execution("process_execution", ExecutionState::NotPerformed),
        ReportField::execution(
            "archive_filesystem_extraction",
            ExecutionState::NotPerformed,
        ),
        ReportField::execution("package_manager_execution", ExecutionState::NotPerformed),
        ReportField::execution("mount_execution", ExecutionState::NotPerformed),
        ReportField::execution("namespace_creation", ExecutionState::NotPerformed),
        ReportField::text("network_access_policy", "forbidden"),
        ReportField::execution("verifier_network_activity", ExecutionState::NotPerformed),
        ReportField::nonclaim(
            "whole_machine_network_silence",
            NonClaimState::Unestablished,
        ),
        ReportField::execution("vm_execution", ExecutionState::NotPerformed),
    ]);
    report
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::io::{BufReader, Read, Seek, SeekFrom};

    use a_quo_ipc::SealedArtifact;
    use anyhow::{Context, Result, ensure};
    use flate2::bufread::GzDecoder;
    use tar::EntryType;

    use super::*;
    use crate::debian::sha256;
    use crate::snapshot::{snapshot_bytes, snapshot_exact_input_directory, snapshot_path};
    use crate::{MAX_UNCOMPRESSED_LAYER_BYTES, parse_input_lock, verify_inputs};

    const ARCHIVE_ENTRY_MAXIMUM: usize = 32 * 1024;
    const ARCHIVE_PATH_MAXIMUM: usize = 4096;

    fn verify_selected_header(
        entry_type: EntryType,
        mode: u32,
        size: u64,
        object: &crate::ObjectSpec,
        metadata: &RuntimeMetadata,
    ) -> Result<()> {
        ensure!(mode == metadata.mode, "runtime object has the wrong mode");
        match metadata.kind {
            RuntimeObjectType::Regular => {
                ensure!(
                    entry_type == EntryType::Regular,
                    "runtime regular object has the wrong type"
                );
                ensure!(
                    size == object.size && object.size as usize <= ELF_FILE_MAXIMUM,
                    "runtime regular object has the wrong size"
                );
            }
            RuntimeObjectType::Symlink => {
                ensure!(
                    entry_type == EntryType::Symlink,
                    "runtime symlink has the wrong type"
                );
                ensure!(size == 0, "runtime symlink has a file payload");
            }
        }
        Ok(())
    }

    fn verify_regular_identity(object: &crate::ObjectSpec, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() as u64 == object.size,
            "runtime regular object ended early or exceeded its bound"
        );
        ensure!(
            sha256(bytes) == object.sha256,
            "runtime regular object has the wrong SHA-256"
        );
        Ok(())
    }

    fn verify_symlink_identity(
        object: &crate::ObjectSpec,
        metadata: &RuntimeMetadata,
        target: &[u8],
    ) -> Result<()> {
        let expected_target = metadata
            .symlink_target
            .as_deref()
            .expect("validated symlink metadata")
            .as_bytes();
        ensure!(
            target == expected_target,
            "runtime symlink target differs from the lock"
        );
        ensure!(
            target.len() as u64 == object.size && sha256(target) == object.sha256,
            "runtime symlink target identity differs from the lock"
        );
        Ok(())
    }

    pub fn verify_gpgv_runtime(
        runtime_lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
        parent_oci_lock_path: &Path,
        parent_oci_input_directory: &Path,
    ) -> Result<GpgvRuntimeVerificationReport> {
        expectation.validate(CANONICAL_LOCK_PATH, "gpgv runtime")?;
        let lock_snapshot = snapshot_path(runtime_lock_path, MAX_LOCK_BYTES)?;
        ensure!(
            lock_snapshot.descriptor().digest.value == expectation.sha256,
            "gpgv runtime lock bytes do not match the externally expected SHA-256"
        );
        let (lock, parent, _) = load_runtime_materialization(
            runtime_lock_path,
            parent_oci_lock_path,
            parent_oci_input_directory,
        )?;
        require(
            &lock.record.fields,
            "lock_repository",
            &expectation.repository,
        )?;
        require(&lock.record.fields, "lock_path", &expectation.path)?;
        let parent_expectation = ExternalLockExpectation {
            repository: field(&lock.record.fields, "parent_oci_lock_repository")?.to_owned(),
            commit: field(&lock.record.fields, "parent_oci_lock_commit")?.to_owned(),
            path: field(&lock.record.fields, "parent_oci_lock_path")?.to_owned(),
            sha256: field(&lock.record.fields, "parent_oci_lock_sha256")?.to_owned(),
        };
        let _parent_report = verify_inputs(
            parent_oci_lock_path,
            &parent_expectation,
            profile_path,
            parent_oci_input_directory,
        )?;
        Ok(report(&lock, expectation, &parent))
    }

    pub(crate) fn load_runtime_materialization(
        runtime_lock_path: &Path,
        parent_oci_lock_path: &Path,
        parent_oci_input_directory: &Path,
    ) -> Result<(
        GpgvRuntimeLock,
        crate::InputLock,
        Vec<RuntimeMaterialization>,
    )> {
        let lock_snapshot = snapshot_path(runtime_lock_path, MAX_LOCK_BYTES)?;
        let lock = parse_gpgv_runtime_lock(&snapshot_bytes(&lock_snapshot, MAX_LOCK_BYTES)?)?;
        let parent_snapshot = snapshot_path(parent_oci_lock_path, MAX_LOCK_BYTES)?;
        ensure!(
            parent_snapshot.descriptor().digest.value
                == field(&lock.record.fields, "parent_oci_lock_sha256")?,
            "parent OCI lock bytes differ from the runtime lock"
        );
        let parent = parse_input_lock(&snapshot_bytes(&parent_snapshot, MAX_LOCK_BYTES)?)?;
        for (parent_key, runtime_key) in [
            ("lock_repository", "parent_oci_lock_repository"),
            ("lock_path", "parent_oci_lock_path"),
            ("profile_sha256", "profile_sha256"),
            ("profile_id", "profile_id"),
        ] {
            ensure!(
                field(&parent.fields, parent_key)? == field(&lock.record.fields, runtime_key)?,
                "parent OCI {parent_key} differs from the runtime lock"
            );
        }
        let specifications = parent
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
        let parent_snapshots =
            snapshot_exact_input_directory(parent_oci_input_directory, &specifications)?;
        let layer_index = parent
            .objects
            .iter()
            .position(|object| object.role == "layer")
            .context("parent OCI lock has no layer object")?;
        let layer = &parent_snapshots[layer_index];
        ensure!(
            layer.descriptor().size
                == field(&lock.record.fields, "parent_oci_layer_size")?.parse::<u64>()?
                && layer.descriptor().digest.value
                    == field(&lock.record.fields, "parent_oci_layer_sha256")?,
            "selected parent OCI layer differs from the runtime lock"
        );
        let payloads = read_runtime_layer(layer, &lock)?;
        let materialization = lock
            .record
            .objects
            .iter()
            .zip(&lock.metadata)
            .zip(payloads)
            .map(|((object, metadata), bytes)| RuntimeMaterialization {
                path: object.path.clone(),
                kind: match metadata.kind {
                    RuntimeObjectType::Regular => RuntimeMaterializationKind::Regular,
                    RuntimeObjectType::Symlink => RuntimeMaterializationKind::Symlink,
                },
                mode: metadata.mode,
                size: object.size,
                sha256: object.sha256.clone(),
                bytes,
            })
            .collect::<Vec<_>>();
        Ok((lock, parent, materialization))
    }

    fn read_runtime_layer(layer: &SealedArtifact, lock: &GpgvRuntimeLock) -> Result<Vec<Vec<u8>>> {
        let mut file = layer
            .file()
            .try_clone()
            .context("cannot clone the sealed OCI layer descriptor")?;
        file.seek(SeekFrom::Start(0))
            .context("cannot rewind the sealed OCI layer")?;
        let decoder = GzDecoder::new(BufReader::new(file));
        let bounded = decoder.take(MAX_UNCOMPRESSED_LAYER_BYTES + 1);
        let mut archive = tar::Archive::new(bounded);
        archive.set_ignore_zeros(true);

        let expected = lock
            .record
            .objects
            .iter()
            .enumerate()
            .map(|(index, object)| (object.path.as_bytes(), index))
            .collect::<BTreeMap<_, _>>();
        let mut selected = vec![None; lock.record.objects.len()];
        let mut entry_count = 0_usize;
        for entry in archive
            .entries()
            .context("cannot parse the selected OCI layer")?
        {
            let entry = entry.context("cannot parse one selected OCI layer entry")?;
            entry_count += 1;
            ensure!(
                entry_count <= ARCHIVE_ENTRY_MAXIMUM,
                "OCI layer exceeds its entry bound"
            );
            let path = entry.path_bytes();
            ensure!(
                path.len() <= ARCHIVE_PATH_MAXIMUM,
                "OCI layer path exceeds its byte bound"
            );
            let Some(index) = expected.get(path.as_ref()).copied() else {
                continue;
            };
            ensure!(selected[index].is_none(), "runtime object is duplicated");
            let object = &lock.record.objects[index];
            let metadata = &lock.metadata[index];
            let mode = entry
                .header()
                .mode()
                .context("invalid runtime object mode")?;
            verify_selected_header(
                entry.header().entry_type(),
                mode,
                entry.size(),
                object,
                metadata,
            )?;
            match metadata.kind {
                RuntimeObjectType::Regular => {
                    let mut bytes = Vec::with_capacity(object.size as usize);
                    entry
                        .take(object.size + 1)
                        .read_to_end(&mut bytes)
                        .context("cannot read a selected runtime object")?;
                    verify_regular_identity(object, &bytes)?;
                    selected[index] = Some(bytes);
                }
                RuntimeObjectType::Symlink => {
                    let target = entry
                        .link_name_bytes()
                        .context("runtime symlink lacks target text")?;
                    verify_symlink_identity(object, metadata, target.as_ref())?;
                    selected[index] = Some(target.into_owned());
                }
            }
        }
        let bounded = archive.into_inner();
        ensure!(
            bounded.limit() > 0,
            "OCI layer reaches or exceeds the uncompressed byte bound"
        );
        ensure!(
            selected.iter().all(Option::is_some),
            "OCI layer lacks a selected runtime object"
        );
        verify_symlink_and_dependency_graph(lock)?;
        for elf in &lock.elfs {
            let index = lock
                .record
                .objects
                .iter()
                .position(|object| object.path == elf.path)
                .expect("validated ELF path");
            let parsed = parse_elf(
                selected[index]
                    .as_deref()
                    .expect("selected runtime object present"),
                elf,
            )?;
            ensure!(
                parsed.interpreter == elf.interpreter && parsed.needed == elf.needed,
                "parsed ELF result differs from the lock"
            );
        }
        Ok(selected
            .into_iter()
            .map(|bytes| bytes.expect("selected runtime object checked"))
            .collect())
    }

    fn immediate_target(path: &str, target: &str) -> Result<String> {
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        let value = if parent.is_empty() {
            target.to_owned()
        } else {
            format!("{parent}/{target}")
        };
        validate_relative_path(&value)?;
        Ok(value)
    }

    pub(super) fn resolve_path(path: &str, lock: &GpgvRuntimeLock) -> Result<String> {
        let path = path.strip_prefix('/').unwrap_or(path);
        validate_relative_path(path)?;
        let objects = lock
            .record
            .objects
            .iter()
            .zip(&lock.metadata)
            .map(|(object, metadata)| (object.path.as_str(), metadata))
            .collect::<BTreeMap<_, _>>();
        let mut pending = path.split('/').map(str::to_owned).collect::<VecDeque<_>>();
        let mut resolved = Vec::<String>::new();
        let mut visited = BTreeSet::new();
        let mut traversals = 0_usize;
        while let Some(component) = pending.pop_front() {
            ensure!(
                !component.is_empty() && component != "." && component != "..",
                "runtime resolution contains a forbidden component"
            );
            resolved.push(component);
            let current = resolved.join("/");
            let Some(metadata) = objects.get(current.as_str()) else {
                continue;
            };
            match metadata.kind {
                RuntimeObjectType::Regular => ensure!(
                    pending.is_empty(),
                    "runtime resolution traverses through a regular object"
                ),
                RuntimeObjectType::Symlink => {
                    traversals += 1;
                    ensure!(
                        traversals <= 8,
                        "runtime symlink traversal exceeds its bound"
                    );
                    ensure!(
                        visited.insert(current),
                        "runtime symlink resolution contains a loop"
                    );
                    resolved.pop();
                    let target = metadata
                        .symlink_target
                        .as_deref()
                        .expect("validated symlink metadata");
                    let mut replacement = target
                        .split('/')
                        .map(str::to_owned)
                        .collect::<VecDeque<_>>();
                    replacement.append(&mut pending);
                    pending = replacement;
                }
            }
        }
        let result = resolved.join("/");
        ensure!(
            objects
                .get(result.as_str())
                .is_some_and(|metadata| metadata.kind == RuntimeObjectType::Regular),
            "runtime path does not resolve to one selected regular object"
        );
        Ok(result)
    }

    pub(super) fn verify_symlink_and_dependency_graph(lock: &GpgvRuntimeLock) -> Result<()> {
        for (object, metadata) in lock.record.objects.iter().zip(&lock.metadata) {
            match metadata.kind {
                RuntimeObjectType::Regular => ensure!(
                    metadata.resolved_target == object.path
                        && metadata.resolved_regular == object.path,
                    "regular runtime resolution metadata differs from its path"
                ),
                RuntimeObjectType::Symlink => {
                    let target = metadata
                        .symlink_target
                        .as_deref()
                        .expect("validated symlink metadata");
                    ensure!(
                        immediate_target(&object.path, target)? == metadata.resolved_target,
                        "runtime symlink immediate target differs from the lock"
                    );
                    let probe = if object.path == "lib" {
                        "lib/ld-linux-aarch64.so.1"
                    } else {
                        object.path.as_str()
                    };
                    ensure!(
                        resolve_path(probe, lock)? == metadata.resolved_regular,
                        "runtime symlink final regular object differs from the lock"
                    );
                }
            }
        }
        let interpreter = field(&lock.record.fields, "interpreter_path")?;
        ensure!(
            resolve_path(interpreter, lock)?
                == field(&lock.record.fields, "interpreter_resolved_path")?,
            "ELF interpreter resolution differs from the lock"
        );
        for dependency in &lock.dependencies {
            ensure!(
                resolve_path(&dependency.lookup, lock)? == dependency.resolved,
                "ELF dependency resolution differs from the lock"
            );
            ensure!(
                lock.elfs.iter().any(|elf| {
                    elf.path == dependency.source && elf.needed.contains(&dependency.needed)
                }),
                "dependency record is not present in its source ELF"
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::io::{Seek, Write};

        use a_quo_ipc::snapshot_artifact;
        use flate2::{Compression, write::GzEncoder};
        use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

        use super::*;

        fn sealed_gzip(plaintext: &[u8]) -> SealedArtifact {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(plaintext).unwrap();
            let bytes = encoder.finish().unwrap();
            let fd = memfd_create(
                "gpgv-runtime-test",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .unwrap();
            let mut file = std::fs::File::from(fd);
            file.write_all(&bytes).unwrap();
            fcntl_add_seals(
                &file,
                SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
            )
            .unwrap();
            file.rewind().unwrap();
            snapshot_artifact(file.into(), bytes.len() as u64).unwrap()
        }

        #[test]
        fn selected_member_policy_rejects_byte_type_mode_size_and_link_tampering() {
            let lock = parse_gpgv_runtime_lock(CANONICAL_LOCK.as_bytes()).unwrap();
            for index in [0_usize, 3, 5, 15] {
                let bytes = [1_u8, 2, index as u8];
                let mut object = lock.record.objects[index].clone();
                object.size = bytes.len() as u64;
                object.sha256 = sha256(&bytes);
                verify_regular_identity(&object, &bytes).unwrap();
                let mut changed = bytes;
                changed[0] ^= 1;
                assert!(verify_regular_identity(&object, &changed).is_err());
            }

            let regular = &lock.record.objects[0];
            let regular_metadata = &lock.metadata[0];
            verify_selected_header(
                EntryType::Regular,
                0o755,
                regular.size,
                regular,
                regular_metadata,
            )
            .unwrap();
            assert!(
                verify_selected_header(
                    EntryType::Symlink,
                    0o755,
                    regular.size,
                    regular,
                    regular_metadata,
                )
                .is_err()
            );
            assert!(
                verify_selected_header(
                    EntryType::Regular,
                    0o777,
                    regular.size,
                    regular,
                    regular_metadata,
                )
                .is_err()
            );
            assert!(
                verify_selected_header(
                    EntryType::Regular,
                    0o755,
                    regular.size + 1,
                    regular,
                    regular_metadata,
                )
                .is_err()
            );

            let link = &lock.record.objects[4];
            let link_metadata = &lock.metadata[4];
            verify_selected_header(EntryType::Symlink, 0o777, 0, link, link_metadata).unwrap();
            verify_symlink_identity(link, link_metadata, b"libz.so.1.3").unwrap();
            assert!(verify_symlink_identity(link, link_metadata, b"libz.so.1.4").is_err());

            let mut oversized = regular.clone();
            oversized.size = ELF_FILE_MAXIMUM as u64 + 1;
            assert!(
                verify_selected_header(
                    EntryType::Regular,
                    0o755,
                    oversized.size,
                    &oversized,
                    regular_metadata,
                )
                .is_err()
            );
        }

        #[test]
        fn symlink_policy_rejects_loops_escape_and_alternate_paths() {
            let lock = parse_gpgv_runtime_lock(CANONICAL_LOCK.as_bytes()).unwrap();
            verify_symlink_and_dependency_graph(&lock).unwrap();
            assert_eq!(
                resolve_path("/lib/ld-linux-aarch64.so.1", &lock).unwrap(),
                "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
            );

            let mut looped = lock.clone();
            looped.metadata[1].symlink_target = Some("lib".to_owned());
            assert!(resolve_path("lib/ld-linux-aarch64.so.1", &looped).is_err());

            let mut escaping = lock.clone();
            escaping.metadata[1].symlink_target = Some("../usr/lib".to_owned());
            assert!(resolve_path("lib/ld-linux-aarch64.so.1", &escaping).is_err());

            let mut alternate = lock.clone();
            alternate.metadata[4].symlink_target = Some("./libz.so.1.3".to_owned());
            assert!(resolve_path(&alternate.record.objects[4].path, &alternate).is_err());

            let mut wrong_final = lock;
            wrong_final.metadata[4].resolved_regular =
                "usr/lib/aarch64-linux-gnu/libc.so.6".to_owned();
            assert!(verify_symlink_and_dependency_graph(&wrong_final).is_err());
        }

        #[test]
        fn malformed_or_incomplete_layer_withholds_static_success() {
            let lock = parse_gpgv_runtime_lock(CANONICAL_LOCK.as_bytes()).unwrap();
            assert!(read_runtime_layer(&sealed_gzip(b"not a tar"), &lock).is_err());
            assert!(read_runtime_layer(&sealed_gzip(&[0_u8; 1024]), &lock).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::load_runtime_materialization;
#[cfg(target_os = "linux")]
pub use linux::verify_gpgv_runtime;

#[cfg(not(target_os = "linux"))]
pub fn verify_gpgv_runtime(
    _runtime_lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
    _parent_oci_lock_path: &Path,
    _parent_oci_input_directory: &Path,
) -> Result<GpgvRuntimeVerificationReport> {
    anyhow::bail!("gpgv runtime static inspection requires Linux sealed-file support")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CANONICAL_REPOSITORY;

    const LOCK_BYTES: &[u8] = include_bytes!(
        "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-gpgv-runtime-v1.lock"
    );
    const PROGRAM_OFFSET: usize = 64;
    const INTERPRETER_OFFSET: usize = 512;
    const DYNAMIC_OFFSET: usize = 600;
    const STRING_OFFSET: usize = 768;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_program_header(
        bytes: &mut [u8],
        index: usize,
        kind: u32,
        offset: u64,
        virtual_address: u64,
        size: u64,
    ) {
        let base = PROGRAM_OFFSET + index * 56;
        write_u32(bytes, base, kind);
        write_u32(bytes, base + 4, 4);
        write_u64(bytes, base + 8, offset);
        write_u64(bytes, base + 16, virtual_address);
        write_u64(bytes, base + 24, virtual_address);
        write_u64(bytes, base + 32, size);
        write_u64(bytes, base + 40, size);
        write_u64(bytes, base + 48, 8);
    }

    fn write_dynamic(bytes: &mut [u8], index: usize, tag: u64, value: u64) {
        let base = DYNAMIC_OFFSET + index * 16;
        write_u64(bytes, base, tag);
        write_u64(bytes, base + 8, value);
    }

    fn synthetic_elf(needed: &[&str]) -> (Vec<u8>, ElfSpec) {
        const FILE_SIZE: usize = 1024;
        const LOAD_ADDRESS: u64 = 0x1000;
        const INTERPRETER: &str = "/lib/ld-linux-aarch64.so.1";

        let mut strings = vec![0_u8];
        let mut needed_offsets = Vec::new();
        for name in needed {
            needed_offsets.push(strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let dynamic_count = needed.len() + 4;
        let mut bytes = vec![0_u8; FILE_SIZE];
        bytes[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        write_u16(&mut bytes, 16, 3);
        write_u16(&mut bytes, 18, 183);
        write_u32(&mut bytes, 20, 1);
        write_u64(&mut bytes, 32, PROGRAM_OFFSET as u64);
        write_u16(&mut bytes, 52, 64);
        write_u16(&mut bytes, 54, 56);
        write_u16(&mut bytes, 56, 3);
        write_program_header(&mut bytes, 0, 1, 0, LOAD_ADDRESS, FILE_SIZE as u64);
        write_program_header(
            &mut bytes,
            1,
            3,
            INTERPRETER_OFFSET as u64,
            LOAD_ADDRESS + INTERPRETER_OFFSET as u64,
            (INTERPRETER.len() + 1) as u64,
        );
        write_program_header(
            &mut bytes,
            2,
            2,
            DYNAMIC_OFFSET as u64,
            LOAD_ADDRESS + DYNAMIC_OFFSET as u64,
            (dynamic_count * 16) as u64,
        );
        bytes[INTERPRETER_OFFSET..INTERPRETER_OFFSET + INTERPRETER.len()]
            .copy_from_slice(INTERPRETER.as_bytes());
        bytes[INTERPRETER_OFFSET + INTERPRETER.len()] = 0;
        write_dynamic(&mut bytes, 0, 5, LOAD_ADDRESS + STRING_OFFSET as u64);
        write_dynamic(&mut bytes, 1, 10, strings.len() as u64);
        write_dynamic(&mut bytes, 2, 0x6fff_fffb, 0x0800_0000);
        for (index, offset) in needed_offsets.into_iter().enumerate() {
            write_dynamic(&mut bytes, index + 3, 1, offset);
        }
        write_dynamic(&mut bytes, dynamic_count - 1, 0, 0);
        bytes[STRING_OFFSET..STRING_OFFSET + strings.len()].copy_from_slice(&strings);
        (
            bytes,
            ElfSpec {
                path: "synthetic/gpgv".to_owned(),
                os_abi: 0,
                abi_version: 0,
                pie: true,
                interpreter: Some(INTERPRETER.to_owned()),
                needed: needed.iter().map(|value| (*value).to_owned()).collect(),
            },
        )
    }

    #[test]
    fn canonical_lock_closes_runtime_objects_graph_and_nonclaims() {
        let lock = parse_gpgv_runtime_lock(LOCK_BYTES).unwrap();
        assert_eq!(lock.record.objects.len(), 17);
        assert_eq!(lock.metadata.len(), 17);
        assert_eq!(lock.elfs.len(), 9);
        assert_eq!(lock.dependencies.len(), 23);
        assert_eq!(
            lock.elfs[0].needed,
            [
                "libz.so.1",
                "libbz2.so.1.0",
                "libgcrypt.so.20",
                "libassuan.so.0",
                "libnpth.so.0",
                "libgpg-error.so.0",
                "libc.so.6",
                "ld-linux-aarch64.so.1",
            ]
        );
        for key in [
            "publisher_authentication",
            "current_publisher_authorization",
            "current_revocation_status",
            "trusted_time",
            "freshness",
            "source_to_binary_provenance",
            "verifier_correctness",
            "safety",
        ] {
            assert_eq!(field(&lock.record.fields, key).unwrap(), "not-established");
        }
    }

    #[test]
    fn bounded_elf_parser_accepts_exact_shape_and_order() {
        let (bytes, spec) = synthetic_elf(&["libfirst.so.1", "libsecond.so.2"]);
        let parsed = parse_elf(&bytes, &spec).unwrap();
        assert_eq!(parsed.interpreter, spec.interpreter);
        assert_eq!(parsed.needed, spec.needed);
    }

    #[test]
    fn bounded_elf_parser_rejects_identity_header_and_interpreter_attacks() {
        let (bytes, spec) = synthetic_elf(&["libtest.so.1"]);
        for (offset, value) in [(4, 1), (5, 2), (7, 3), (8, 1)] {
            let mut changed = bytes.clone();
            changed[offset] = value;
            assert!(parse_elf(&changed, &spec).is_err());
        }
        for (offset, value) in [(16, 2_u16), (18, 62_u16)] {
            let mut changed = bytes.clone();
            write_u16(&mut changed, offset, value);
            assert!(parse_elf(&changed, &spec).is_err());
        }
        let mut excessive_headers = bytes.clone();
        write_u16(&mut excessive_headers, 56, 65);
        assert!(parse_elf(&excessive_headers, &spec).is_err());
        let mut overflow = bytes.clone();
        write_u64(&mut overflow, 32, u64::MAX);
        assert!(parse_elf(&overflow, &spec).is_err());
        let mut missing_interpreter = bytes.clone();
        write_u32(&mut missing_interpreter, PROGRAM_OFFSET + 56, 1);
        assert!(parse_elf(&missing_interpreter, &spec).is_err());
        let mut duplicate_interpreter = bytes.clone();
        write_u16(&mut duplicate_interpreter, 56, 4);
        write_program_header(
            &mut duplicate_interpreter,
            3,
            3,
            INTERPRETER_OFFSET as u64,
            0x1000 + INTERPRETER_OFFSET as u64,
            spec.interpreter.as_ref().unwrap().len() as u64 + 1,
        );
        assert!(parse_elf(&duplicate_interpreter, &spec).is_err());
        let mut wrong_interpreter = bytes.clone();
        wrong_interpreter[INTERPRETER_OFFSET + 1] ^= 1;
        assert!(parse_elf(&wrong_interpreter, &spec).is_err());
        assert!(parse_elf(&bytes[..128], &spec).is_err());
        assert!(parse_elf(&vec![0_u8; ELF_FILE_MAXIMUM + 1], &spec).is_err());
    }

    #[test]
    fn bounded_elf_parser_rejects_dynamic_and_string_attacks() {
        let (bytes, spec) = synthetic_elf(&["libfirst.so.1", "libsecond.so.2"]);
        let mut reordered = spec.clone();
        reordered.needed.reverse();
        assert!(parse_elf(&bytes, &reordered).is_err());

        let mut not_pie = bytes.clone();
        write_u64(&mut not_pie, DYNAMIC_OFFSET + 2 * 16 + 8, 0);
        assert!(parse_elf(&not_pie, &spec).is_err());

        for forbidden_tag in [
            15_u64,
            29,
            0x6fff_fefa,
            0x6fff_fefb,
            0x6fff_fefc,
            0x7fff_fffd,
            0x7fff_ffff,
        ] {
            let mut changed = bytes.clone();
            write_u64(&mut changed, DYNAMIC_OFFSET + 2 * 16, forbidden_tag);
            assert!(parse_elf(&changed, &spec).is_err());
        }
        let mut bad_string_address = bytes.clone();
        write_u64(&mut bad_string_address, DYNAMIC_OFFSET + 8, u64::MAX);
        assert!(parse_elf(&bad_string_address, &spec).is_err());
        let mut huge_string_table = bytes.clone();
        write_u64(
            &mut huge_string_table,
            DYNAMIC_OFFSET + 16 + 8,
            STRING_TABLE_MAXIMUM + 1,
        );
        assert!(parse_elf(&huge_string_table, &spec).is_err());
        let mut bad_string_offset = bytes.clone();
        write_u64(&mut bad_string_offset, DYNAMIC_OFFSET + 3 * 16 + 8, 999);
        assert!(parse_elf(&bad_string_offset, &spec).is_err());
        let mut unterminated = bytes.clone();
        let string_size = read_u64(&unterminated, DYNAMIC_OFFSET + 16 + 8).unwrap() as usize;
        unterminated[STRING_OFFSET..STRING_OFFSET + string_size].fill(b'x');
        assert!(parse_elf(&unterminated, &spec).is_err());
        let mut duplicate_string_table = bytes.clone();
        write_u64(&mut duplicate_string_table, DYNAMIC_OFFSET + 2 * 16, 5);
        assert!(parse_elf(&duplicate_string_table, &spec).is_err());
        let mut missing_null = bytes.clone();
        write_u64(&mut missing_null, DYNAMIC_OFFSET + 5 * 16, 0x1234);
        assert!(parse_elf(&missing_null, &spec).is_err());

        let excessive_needed = [
            "lib01.so", "lib02.so", "lib03.so", "lib04.so", "lib05.so", "lib06.so", "lib07.so",
            "lib08.so", "lib09.so", "lib10.so", "lib11.so", "lib12.so", "lib13.so", "lib14.so",
            "lib15.so", "lib16.so", "lib17.so",
        ];
        let (excessive_bytes, excessive_spec) = synthetic_elf(&excessive_needed);
        assert!(parse_elf(&excessive_bytes, &excessive_spec).is_err());
        let (duplicate_bytes, duplicate_spec) = synthetic_elf(&["libsame.so", "libsame.so"]);
        assert!(parse_elf(&duplicate_bytes, &duplicate_spec).is_err());
    }

    #[test]
    fn canonical_lock_rejects_runtime_and_graph_tampering() {
        let text = std::str::from_utf8(LOCK_BYTES).unwrap();
        for changed in [
            text.replace(
                "a7b1bc1a88927e6f5b30101c415c311aaa9810f51642c12a6b1a824a4c1df1fa",
                "07b1bc1a88927e6f5b30101c415c311aaa9810f51642c12a6b1a824a4c1df1fa",
            ),
            text.replace(
                "regular|0755|none|usr/bin/gpgv",
                "regular|0644|none|usr/bin/gpgv",
            ),
            text.replace("symlink|0777|libz.so.1.3", "symlink|0777|libz.so.1.4"),
            text.replace("libz.so.1,libbz2.so.1.0", "libbz2.so.1.0,libz.so.1"),
            text.replace("|absent|absent\n", "|present|absent\n"),
            text.replace("|et-dyn|aarch64|", "|et-exec|aarch64|"),
            text.replace("|et-dyn|aarch64|", "|et-dyn|x86_64|"),
            text.replacen("pie-executable", "shared-object", 1),
            text.replacen("object_17=", "removed_object_17=", 1),
            text.replacen("object_02=", "object_01=", 1),
            format!("{text}unexpected_field=value\n"),
        ] {
            assert!(parse_gpgv_runtime_lock(changed.as_bytes()).is_err());
        }
    }

    #[test]
    fn byte_exact_report_preserves_static_and_execution_boundaries() {
        let lock = parse_gpgv_runtime_lock(LOCK_BYTES).unwrap();
        let parent = crate::parse_input_lock(include_bytes!(
            "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock"
        ))
        .unwrap();
        let expectation = ExternalLockExpectation {
            repository: CANONICAL_REPOSITORY.to_owned(),
            commit: "0000000000000000000000000000000000000000".to_owned(),
            path: CANONICAL_LOCK_PATH.to_owned(),
            sha256: "a70ff31f4de6885619887e68f0633b2ddbe904ea910046b6b520df0e25bec925".to_owned(),
        };
        let rendered = report(&lock, &expectation, &parent).render();
        assert_eq!(
            rendered,
            include_str!("../tests/fixtures/gpgv-runtime-verify.report")
        );
        for required in [
            "runtime_object_bytes_verified=true",
            "static_elf_parsing_performed=true",
            "interpreter_and_dependency_graph_verified=true",
            "parent_oci_source_to_image_provenance=not-established",
            "runtime_materialization=false",
            "retained_loader_execution=false",
            "gpgv_execution=false",
            "signature_replay=false",
            "verifier_network_activity=false",
            "whole_machine_network_silence=not-established",
            "runtime_configuration_isolation=not-execution-proven",
            "publisher_authentication=not-established",
            "verifier_correctness=not-established",
            "safety=not-established",
            "construction_authority=not-established",
            "runnable=false",
        ] {
            assert!(rendered.lines().any(|line| line == required));
        }
    }

    #[test]
    fn production_inspector_has_no_execution_network_or_materialization_surface() {
        let production = include_str!("gpgv_runtime.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "std::process",
            "Command::new(",
            "std::net",
            "TcpStream",
            "UdpSocket",
            "fork(",
            "execve(",
            "unshare(",
            "mount(",
            "chroot(",
            "pivot_root",
            "File::create(",
            "std::fs::write",
            "tempfile::",
        ] {
            assert!(
                !production.contains(forbidden),
                "production gpgv runtime inspector contains {forbidden}"
            );
        }
    }
}
