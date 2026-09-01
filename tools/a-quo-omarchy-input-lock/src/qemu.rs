use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};

use crate::model::{
    ExecutionState, ExpectedObjectSpec, LockAuthority, LockRecord, NonClaimState, ObjectSpec,
    ReportField, TargetBinding, VerificationMode, VerificationReport, parse_object_specs,
};
use crate::{
    CANONICAL_V2_PROFILE, ExternalLockExpectation, MAX_LOCK_BYTES, MAX_PROFILE_BYTES, field,
    parse_ordered_record, parse_profile, require,
};

const CANONICAL_LOCK_PATH: &str =
    "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-qemu-v1.lock";
const CANONICAL_LOCK: &str = include_str!(
    "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-qemu-v1.lock"
);

pub type QemuObjectSpec = ObjectSpec;
pub type QemuLock = LockRecord;
pub type QemuVerificationReport = VerificationReport;

pub fn parse_qemu_lock(bytes: &[u8]) -> Result<QemuLock> {
    ensure!(
        bytes == CANONICAL_LOCK.as_bytes(),
        "QEMU lock bytes differ from the canonical reviewed lock"
    );
    let keys = CANONICAL_LOCK
        .lines()
        .map(|line| line.split_once('=').expect("canonical QEMU lock syntax").0)
        .collect::<Vec<_>>();
    let fields = parse_ordered_record(bytes, &keys, "QEMU input lock")?;
    for (key, expected) in [
        (
            "selected_input_scope",
            "ubuntu-qemu-debs-elf-members-and-reviewed-start-vm",
        ),
        ("apt_candidate_status", "complete-candidate-no-authority"),
        ("apt_candidate_snapshot_id", "20260831T000000Z"),
        ("apt_candidate_archive_equivalence", "not-established"),
        (
            "apt_candidate_signature_replay",
            "not-independently-replayed",
        ),
        (
            "builder_context_lock_id",
            "a-quo-omarchy4-aarch64-dec29fa-builder-context-v1",
        ),
        (
            "builder_context_lock_sha256",
            "4865e1c9bf4159541afff7d138dee41edc215d988862a0b2d30ed81b09b53f8d",
        ),
        (
            "builder_source_commit",
            "dec29fa90afc3d16a7e0c487c1869c7e512282ca",
        ),
        ("builder_start_vm_size", "1077"),
        (
            "builder_start_vm_sha256",
            "66dd99fad26eee42cdf7062bfbeefc2951f7edf83114312217b007cb43e735e0",
        ),
        ("package_count", "4"),
        ("elf_member_count", "4"),
        ("qemu_img_argument_count", "8"),
        ("qemu_system_argument_count", "40"),
        ("qemu_machine", "virt"),
        ("qemu_accelerator", "kvm"),
        ("qemu_gic_version", "host"),
        ("qemu_cpu", "host"),
        ("qemu_host_forward", "tcp:0.0.0.0:22-:22"),
        ("qemu_vnc_bind", "0.0.0.0:0"),
        (
            "qemu_public_bind_risk",
            "ssh-forward-and-vnc-bind-all-interfaces-if-executed",
        ),
        ("qemu_kvm_host_coupling", "required-not-executed"),
        ("archive_filesystem_extraction", "false"),
        ("package_manager_execution", "false"),
        ("maintainer_scripts_executed", "false"),
        ("script_execution", "false"),
        ("profile_unresolved_input_count", "10"),
        ("remaining_input_count_if_lock_is_adopted", "9"),
        ("class_02_lock_status", "not-established"),
        ("dynamic_library_package_closure", "not-established"),
        ("qemu_module_load_trace", "not-executed"),
        ("kvm_acceleration_verification", "not-executed"),
        ("publisher_authentication", "not-established"),
        ("current_publisher_authorization", "not-established"),
        ("trusted_time", "not-established"),
        ("freshness", "not-established"),
        ("source_to_binary_provenance", "not-established"),
        ("safety", "not-established"),
        ("network_access", "forbidden"),
        ("mount_execution", "forbidden"),
        ("qemu_execution", "forbidden"),
        ("vm_execution", "forbidden"),
    ] {
        require(&fields, key, expected)?;
    }
    const EXPECTED: &[ExpectedObjectSpec] = &[
        ExpectedObjectSpec {
            role: "apt-candidate-receipt",
            path: "receipt.apt.v1",
            media_type: "text/plain",
            size: 1_688,
            sha256: "c99f29429d8d6f87c0651154dee28153af4b6d6c0c47908ca767067d3f1f5d13",
        },
        ExpectedObjectSpec {
            role: "apt-object-manifest",
            path: "objects.manifest",
            media_type: "text/plain",
            size: 14_988,
            sha256: "731cde75cece74a2b22cb22e24484951420b44321453fe1abd898b16744ebdaf",
        },
        ExpectedObjectSpec {
            role: "qemu-system-arm-package",
            path: "qemu-system-arm_1%3a8.2.2+ds-0ubuntu1.18_arm64.deb",
            media_type: "application/vnd.debian.binary-package",
            size: 10_250_374,
            sha256: "3f7024459848a11bd171045da5d3c8f2e0a93e67e5651ab6b164f45bad954200",
        },
        ExpectedObjectSpec {
            role: "qemu-system-common-package",
            path: "qemu-system-common_1%3a8.2.2+ds-0ubuntu1.18_arm64.deb",
            media_type: "application/vnd.debian.binary-package",
            size: 1_221_176,
            sha256: "ed4a606a664cd0090b0316150f2ee1d131573e573f954db56166c1385f001801",
        },
        ExpectedObjectSpec {
            role: "qemu-system-data-package",
            path: "qemu-system-data_1%3a8.2.2+ds-0ubuntu1.18_all.deb",
            media_type: "application/vnd.debian.binary-package",
            size: 1_796_342,
            sha256: "a14b88d864859bd61c8a3274971da4ecb7da6cec15be6c265d0d411f783d5f2e",
        },
        ExpectedObjectSpec {
            role: "qemu-utils-package",
            path: "qemu-utils_1%3a8.2.2+ds-0ubuntu1.18_arm64.deb",
            media_type: "application/vnd.debian.binary-package",
            size: 2_038_370,
            sha256: "a7f7ded1090721ea524ad4616fb4ea8111c45b5690bbb066d7d703e63fcef7c6",
        },
        ExpectedObjectSpec {
            role: "machine-config-script",
            path: "start-vm",
            media_type: "text/x-shellscript",
            size: 1_077,
            sha256: "66dd99fad26eee42cdf7062bfbeefc2951f7edf83114312217b007cb43e735e0",
        },
    ];
    let objects = parse_object_specs(&fields, EXPECTED, "QEMU")?;
    LockRecord::new(
        fields,
        objects,
        "a-quo-omarchy-qemu-input-lock-v1",
        "a-quo-omarchy4-aarch64-dec29fa-qemu-v1",
        LockAuthority::QemuElfMachine,
        CANONICAL_LOCK_PATH,
        TargetBinding::QEMU,
    )
}

fn verify_profile(lock: &QemuLock, bytes: &[u8]) -> Result<()> {
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
        ("unresolved_input_06", "qemu-binaries-and-machine-config"),
    ] {
        require(&profile, key, expected)?;
    }
    Ok(())
}

fn validate_external_expectation(expectation: &ExternalLockExpectation) -> Result<()> {
    expectation.validate(CANONICAL_LOCK_PATH, "QEMU")
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use a_quo_ipc::SealedArtifact;
    use anyhow::{Context, Result, ensure};
    use tar::EntryType;

    use super::*;
    use crate::aavmf::{MANIFEST_BYTES, RECEIPT_BYTES};
    use crate::debian::{
        canonical_tar_path, decompress_zstd, parse_deb, sha256, verify_manifest, verify_receipt,
    };
    use crate::snapshot::{snapshot_bytes, snapshot_exact_input_directory, snapshot_path};

    const CONTROL_TAR_MAXIMUM: u64 = 64 * 1024;
    const DATA_TAR_MAXIMUM: u64 = 128 * 1024 * 1024;
    const ELF_MEMBER_MAXIMUM: u64 = 32 * 1024 * 1024;
    const MAX_TAR_ENTRIES: usize = 256;

    #[derive(Clone, Copy)]
    struct PackageSpec {
        object_index: usize,
        identity: (&'static str, &'static str, &'static str, &'static str),
        ar: [(&'static str, u64, &'static str); 3],
        control_tar: (u64, &'static str),
        control_member: (u64, &'static str),
        data_tar: (u64, &'static str),
        data_entries: usize,
    }

    #[derive(Clone, Copy)]
    struct ElfSpec {
        package_object_index: usize,
        path: &'static [u8],
        size: u64,
        sha256: &'static str,
        mode: u32,
        interpreter: Option<&'static str>,
        build_id: &'static str,
        flags_1: u64,
        needed: &'static [&'static str],
    }

    const PACKAGES: &[PackageSpec] = &[
        PackageSpec {
            object_index: 2,
            identity: ("qemu-system-arm", "qemu", "1:8.2.2+ds-0ubuntu1.18", "arm64"),
            ar: [
                (
                    "debian-binary",
                    4,
                    "d526eb4e878a23ef26ae190031b4efd2d58ed66789ac049ea3dbaf74c9df7402",
                ),
                (
                    "control.tar.zst",
                    1_421,
                    "8175720f516904c8c8ae742a7e9a746d2d2127c0fa2717f01c8b207b440b7fc7",
                ),
                (
                    "data.tar.zst",
                    10_248_760,
                    "5e2c9e5c07e01a2fca655808473505a4fb8a9896d36caf730203c6fbb71829eb",
                ),
            ],
            control_tar: (
                10_240,
                "f5d962f43e7b3e0d710ff1d30507035aa14b84bd5ac8608ed9b24ad2d1f6e15d",
            ),
            control_member: (
                2_213,
                "a96e862b666126019c7f1327f3c40a5414e6c29927b48d89b31bee28e2d24e78",
            ),
            data_tar: (
                60_108_800,
                "eebb85b5716497ca99aed8836268d469124be4b92ba2752b4e1bf4ed43dd18a4",
            ),
            data_entries: 20,
        },
        PackageSpec {
            object_index: 3,
            identity: (
                "qemu-system-common",
                "qemu",
                "1:8.2.2+ds-0ubuntu1.18",
                "arm64",
            ),
            ar: [
                (
                    "debian-binary",
                    4,
                    "d526eb4e878a23ef26ae190031b4efd2d58ed66789ac049ea3dbaf74c9df7402",
                ),
                (
                    "control.tar.zst",
                    5_945,
                    "e1436d4da275b33c058d8cbe28e786e25f95bfa0fa98b821ef435bae3ca8a8c1",
                ),
                (
                    "data.tar.zst",
                    1_215_037,
                    "0fb096a9d75f8dba3c1cb7209505f11c6d9f7f15b687f36b167bd832992fddc0",
                ),
            ],
            control_tar: (
                30_720,
                "ed9e04b7fdef1595bbd745414decf50d3a350e4cb40d3057935d35855d36af89",
            ),
            control_member: (
                1_272,
                "3232c5d59e454c2d9658ba49ed1f7ddd88721587e29a756273ca273dfb7b698f",
            ),
            data_tar: (
                7_925_760,
                "ed15186727791d6f32537c0b569888293e7594cda4fa4acd3ff30b1948d86aeb",
            ),
            data_entries: 194,
        },
        PackageSpec {
            object_index: 4,
            identity: ("qemu-system-data", "qemu", "1:8.2.2+ds-0ubuntu1.18", "all"),
            ar: [
                (
                    "debian-binary",
                    4,
                    "d526eb4e878a23ef26ae190031b4efd2d58ed66789ac049ea3dbaf74c9df7402",
                ),
                (
                    "control.tar.zst",
                    3_414,
                    "e4fb4a492f4f64710a795c27ed25e33fa2a1ce4ffb19fcbc50aa21d1eb91e62a",
                ),
                (
                    "data.tar.zst",
                    1_792_735,
                    "7b145dac919ee437942c90dcc01ac9f8d654cd5421128cb5659204eccea2db78",
                ),
            ],
            control_tar: (
                20_480,
                "26fc72e009aca88278c225e4449d101a2dc6602915060b7d4e5b30c03c7f1ec0",
            ),
            control_member: (
                842,
                "d1acaee572b14d4c7d40912b16895810baf5c8a98cb40861463984473e6319a2",
            ),
            data_tar: (
                9_328_640,
                "366faf3142552bf087d80de2eacf711da319e6431f6deb0096472465beb5ac0f",
            ),
            data_entries: 123,
        },
        PackageSpec {
            object_index: 5,
            identity: ("qemu-utils", "qemu", "1:8.2.2+ds-0ubuntu1.18", "arm64"),
            ar: [
                (
                    "debian-binary",
                    4,
                    "d526eb4e878a23ef26ae190031b4efd2d58ed66789ac049ea3dbaf74c9df7402",
                ),
                (
                    "control.tar.zst",
                    1_298,
                    "67a81192b143050abcbf1a25e07adcffdad450a111c5ca24b5e277aa5c505168",
                ),
                (
                    "data.tar.zst",
                    2_036_879,
                    "ed9596072fea2a1d220333d63bfba2db642f6c039efff1235d32a996b60cd88e",
                ),
            ],
            control_tar: (
                10_240,
                "01730d101ca1095759b3a361b8a5fd43ff3ce33e3fce142104ae1588221d75a0",
            ),
            control_member: (
                1_306,
                "adb5be209291061b67d925be091f11fbe864d1f10c3345412ea3a00f93bca819",
            ),
            data_tar: (
                11_520_000,
                "c7398a44515a27ffed739b568ec476463c3894fd454e2f7d86ac7db081922739",
            ),
            data_entries: 22,
        },
    ];

    const QEMU_SYSTEM_NEEDED: &[&str] = &[
        "libfdt.so.1",
        "libz.so.1",
        "libpixman-1.so.0",
        "libgnutls.so.30",
        "libpng16.so.16",
        "libjpeg.so.8",
        "libsasl2.so.2",
        "libudev.so.1",
        "libpmem.so.1",
        "libseccomp.so.2",
        "libnuma.so.1",
        "libgio-2.0.so.0",
        "libgobject-2.0.so.0",
        "libglib-2.0.so.0",
        "librdmacm.so.1",
        "libibverbs.so.1",
        "libzstd.so.1",
        "libslirp.so.0",
        "libbpf.so.1",
        "liburing.so.2",
        "libgmodule-2.0.so.0",
        "libm.so.6",
        "libnettle.so.8",
        "libgmp.so.10",
        "libhogweed.so.6",
        "libfuse3.so.3",
        "libaio.so.1t64",
        "libc.so.6",
        "ld-linux-aarch64.so.1",
    ];
    const QEMU_IMG_NEEDED: &[&str] = &[
        "libnuma.so.1",
        "liburing.so.2",
        "libglib-2.0.so.0",
        "libgmodule-2.0.so.0",
        "libgnutls.so.30",
        "libm.so.6",
        "libzstd.so.1",
        "libz.so.1",
        "libaio.so.1t64",
        "libnettle.so.8",
        "libgmp.so.10",
        "libhogweed.so.6",
        "libc.so.6",
        "ld-linux-aarch64.so.1",
    ];
    const GPU_NEEDED: &[&str] = &["libpixman-1.so.0", "libc.so.6", "ld-linux-aarch64.so.1"];
    const ELFS: &[ElfSpec] = &[
        ElfSpec {
            package_object_index: 2,
            path: b"./usr/bin/qemu-system-aarch64",
            size: 31_341_600,
            sha256: "e19e11bd054ccf0f3cfcea8e0acdcc4288de6abd2ed6c30f743092c362eb2673",
            mode: 0o755,
            interpreter: Some("/lib/ld-linux-aarch64.so.1"),
            build_id: "8696f29ac7f83e7028bafb117a8afeb486303374",
            flags_1: 0x0800_0001,
            needed: QEMU_SYSTEM_NEEDED,
        },
        ElfSpec {
            package_object_index: 5,
            path: b"./usr/bin/qemu-img",
            size: 2_553_056,
            sha256: "f26da24f8a7fd880ab13f6fcabf42d099fb68ea86df5de0c55e6faadfe2d9a6e",
            mode: 0o755,
            interpreter: Some("/lib/ld-linux-aarch64.so.1"),
            build_id: "bb60f504d7f955c84688915bfe32af2a21fe0b74",
            flags_1: 0x0800_0001,
            needed: QEMU_IMG_NEEDED,
        },
        ElfSpec {
            package_object_index: 3,
            path: b"./usr/lib/aarch64-linux-gnu/qemu/hw-display-virtio-gpu-pci.so",
            size: 67_704,
            sha256: "886cba427448cb7fe429b4bdd2b7016956e7c7e406bb362792a29aaf2b58d7ec",
            mode: 0o644,
            interpreter: None,
            build_id: "c214e906aa0e6affe63d1ede6bb8fb8a12a8cd0a",
            flags_1: 1,
            needed: &[],
        },
        ElfSpec {
            package_object_index: 3,
            path: b"./usr/lib/aarch64-linux-gnu/qemu/hw-display-virtio-gpu.so",
            size: 70_632,
            sha256: "617f8b2b61080dc4a7aa09e895cd895f852973e9ed33d7e024fdf4ccfcbb4793",
            mode: 0o644,
            interpreter: None,
            build_id: "c7d6f7e5bfe1da4b10a275eb921116b8a869d459",
            flags_1: 1,
            needed: GPU_NEEDED,
        },
    ];

    const EXPECTED_START_VM: &[u8] = br#"#!/bin/bash

set -euo pipefail

run=/work/run
base=/work/cache/archarm-base.qcow2
code=/usr/share/AAVMF/AAVMF_CODE.fd
vars_template=/usr/share/AAVMF/AAVMF_VARS.fd

rm -rf "$run"
mkdir -p "$run"
qemu-img create -f qcow2 -F qcow2 -b "$base" "$run/disk.qcow2"
cp "$vars_template" "$run/AAVMF_VARS.fd"

qemu-system-aarch64 \
  -nodefaults \
  -machine virt,accel=kvm,gic-version=host \
  -cpu host \
  -smp 8 \
  -m 8192 \
  -drive if=pflash,format=raw,readonly=on,file="$code" \
  -drive if=pflash,format=raw,file="$run/AAVMF_VARS.fd" \
  -drive file="$run/disk.qcow2",format=qcow2,if=none,id=drive0,discard=unmap \
  -device virtio-blk-pci,drive=drive0,bootindex=1,romfile= \
  -netdev user,id=net0,hostfwd=tcp:0.0.0.0:22-:22 \
  -device virtio-net-pci,netdev=net0,romfile= \
  -device virtio-gpu-pci,romfile= \
  -device qemu-xhci \
  -device usb-kbd \
  -device usb-tablet \
  -vnc 0.0.0.0:0 \
  -qmp unix:"$run/qmp.sock",server=on,wait=off \
  -monitor unix:"$run/monitor.sock",server=on,wait=off \
  -serial file:"$run/serial.log" \
  -daemonize \
  -pidfile "$run/qemu.pid"
"#;

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
        flags: u32,
        offset: u64,
        virtual_address: u64,
        file_size: u64,
    }

    fn file_range(
        bytes: &[u8],
        offset: u64,
        size: u64,
        label: &str,
    ) -> Result<std::ops::Range<usize>> {
        let start = usize::try_from(offset).context("ELF offset does not fit memory")?;
        let length = usize::try_from(size).context("ELF size does not fit memory")?;
        let end = start.checked_add(length).context("ELF range overflow")?;
        ensure!(end <= bytes.len(), "{label} exceeds the ELF member");
        Ok(start..end)
    }

    fn virtual_range(
        bytes: &[u8],
        headers: &[ProgramHeader],
        address: u64,
        size: u64,
    ) -> Result<std::ops::Range<usize>> {
        for header in headers.iter().filter(|header| header.kind == 1) {
            if address >= header.virtual_address {
                let relative = address - header.virtual_address;
                if relative <= header.file_size && size <= header.file_size - relative {
                    return file_range(
                        bytes,
                        header
                            .offset
                            .checked_add(relative)
                            .context("ELF address overflow")?,
                        size,
                        "ELF virtual range",
                    );
                }
            }
        }
        anyhow::bail!("ELF virtual address is not backed by one load segment")
    }

    fn c_string(bytes: &[u8], offset: usize, label: &str) -> Result<String> {
        let tail = bytes
            .get(offset..)
            .context("ELF string offset is out of range")?;
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .context("ELF string is unterminated")?;
        ensure!(end > 0 && end <= 127, "{label} has invalid bounds");
        let value = std::str::from_utf8(&tail[..end]).context("ELF string is not UTF-8")?;
        ensure!(
            value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
            "{label} contains a forbidden byte"
        );
        Ok(value.to_owned())
    }

    fn align4(value: usize) -> Result<usize> {
        value
            .checked_add(3)
            .map(|value| value & !3)
            .context("ELF note alignment overflow")
    }

    fn parse_build_id(bytes: &[u8], headers: &[ProgramHeader]) -> Result<String> {
        let mut build_ids = Vec::new();
        for header in headers.iter().filter(|header| header.kind == 4) {
            ensure!(
                header.file_size <= 64 * 1024,
                "ELF note segment is too large"
            );
            let range = file_range(bytes, header.offset, header.file_size, "ELF note segment")?;
            let notes = &bytes[range];
            let mut offset = 0_usize;
            while offset < notes.len() {
                ensure!(notes.len() - offset >= 12, "truncated ELF note header");
                let name_size = read_u32(notes, offset)? as usize;
                let description_size = read_u32(notes, offset + 4)? as usize;
                let kind = read_u32(notes, offset + 8)?;
                offset += 12;
                let name_end = offset
                    .checked_add(name_size)
                    .context("ELF note name overflow")?;
                ensure!(name_end <= notes.len(), "truncated ELF note name");
                let name = &notes[offset..name_end];
                offset = align4(name_end)?;
                let description_end = offset
                    .checked_add(description_size)
                    .context("ELF note description overflow")?;
                ensure!(
                    description_end <= notes.len(),
                    "truncated ELF note description"
                );
                if kind == 3 && name == b"GNU\0" {
                    ensure!(description_size == 20, "GNU build ID is not 20 bytes");
                    build_ids.push(
                        notes[offset..description_end]
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>(),
                    );
                }
                offset = align4(description_end)?;
            }
        }
        ensure!(
            build_ids.len() == 1,
            "ELF does not contain exactly one GNU build ID"
        );
        Ok(build_ids.remove(0))
    }

    fn verify_elf(bytes: &[u8], spec: &ElfSpec) -> Result<()> {
        ensure!(
            bytes.len() as u64 == spec.size,
            "ELF member has the wrong size"
        );
        ensure!(
            sha256(bytes) == spec.sha256,
            "ELF member has the wrong SHA-256"
        );
        ensure!(bytes.len() >= 64, "ELF header is truncated");
        ensure!(
            &bytes[..16] == b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0",
            "ELF identity differs from the closed policy"
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
            (1..=64).contains(&program_count),
            "ELF program-header count is outside the bound"
        );
        let table_size = (program_count as u64)
            .checked_mul(56)
            .context("ELF program table overflow")?;
        let range = file_range(
            bytes,
            program_offset,
            table_size,
            "ELF program-header table",
        )?;
        let mut headers = Vec::with_capacity(program_count);
        for index in 0..program_count {
            let offset = range.start + index * 56;
            let header = ProgramHeader {
                kind: read_u32(bytes, offset)?,
                flags: read_u32(bytes, offset + 4)?,
                offset: read_u64(bytes, offset + 8)?,
                virtual_address: read_u64(bytes, offset + 16)?,
                file_size: read_u64(bytes, offset + 32)?,
            };
            file_range(
                bytes,
                header.offset,
                header.file_size,
                "ELF program segment",
            )?;
            headers.push(header);
        }
        let stacks = headers
            .iter()
            .filter(|header| header.kind == 0x6474_e551)
            .collect::<Vec<_>>();
        ensure!(
            stacks.len() == 1 && stacks[0].flags & 1 == 0,
            "ELF stack policy is not one non-executable segment"
        );

        let interpreters = headers
            .iter()
            .filter(|header| header.kind == 3)
            .collect::<Vec<_>>();
        let interpreter = match interpreters.as_slice() {
            [] => None,
            [header] => {
                ensure!(header.file_size <= 128, "ELF interpreter exceeds its bound");
                let range = file_range(bytes, header.offset, header.file_size, "ELF interpreter")?;
                let raw = &bytes[range];
                ensure!(
                    raw.last() == Some(&0),
                    "ELF interpreter is not NUL terminated"
                );
                Some(
                    std::str::from_utf8(&raw[..raw.len() - 1])
                        .context("ELF interpreter is not UTF-8")?,
                )
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
            dynamic.file_size > 0 && dynamic.file_size <= 64 * 1024 && dynamic.file_size % 16 == 0,
            "ELF dynamic segment has invalid bounds"
        );
        let dynamic_range = file_range(
            bytes,
            dynamic.offset,
            dynamic.file_size,
            "ELF dynamic segment",
        )?;
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
                1 => needed_offsets.push(value),
                5 => ensure!(
                    string_address.replace(value).is_none(),
                    "ELF repeats DT_STRTAB"
                ),
                10 => ensure!(string_size.replace(value).is_none(), "ELF repeats DT_STRSZ"),
                0x6fff_fffb => ensure!(flags_1.replace(value).is_none(), "ELF repeats DT_FLAGS_1"),
                _ => {}
            }
        }
        ensure!(terminated, "ELF dynamic segment lacks DT_NULL");
        ensure!(
            flags_1 == Some(spec.flags_1),
            "ELF DT_FLAGS_1 differs from the lock"
        );
        let string_size = string_size.context("ELF lacks DT_STRSZ")?;
        ensure!(
            string_size > 0 && string_size <= 1024 * 1024,
            "ELF dynamic string table is outside the bound"
        );
        let string_range = virtual_range(
            bytes,
            &headers,
            string_address.context("ELF lacks DT_STRTAB")?,
            string_size,
        )?;
        let strings = &bytes[string_range];
        let mut needed = Vec::with_capacity(needed_offsets.len());
        for offset in needed_offsets {
            let offset =
                usize::try_from(offset).context("ELF needed offset does not fit memory")?;
            needed.push(c_string(strings, offset, "ELF needed name")?);
        }
        ensure!(
            needed
                .iter()
                .map(String::as_str)
                .eq(spec.needed.iter().copied()),
            "ELF NEEDED sequence differs from the lock"
        );
        ensure!(
            parse_build_id(bytes, &headers)? == spec.build_id,
            "ELF build ID differs from the lock"
        );
        Ok(())
    }

    fn verify_control_tar(snapshot: &SealedArtifact, spec: &PackageSpec) -> Result<()> {
        ensure!(
            (
                snapshot.descriptor().size,
                snapshot.descriptor().digest.value.as_str()
            ) == spec.control_tar,
            "QEMU control tar differs from the lock"
        );
        let bytes = snapshot_bytes(snapshot, CONTROL_TAR_MAXIMUM)?;
        let mut archive = tar::Archive::new(Cursor::new(bytes));
        let mut count = 0_usize;
        let mut control = None;
        for entry in archive.entries().context("cannot parse QEMU control tar")? {
            let mut entry = entry.context("cannot parse QEMU control entry")?;
            count += 1;
            ensure!(count <= 64, "QEMU control tar exceeds its entry bound");
            if entry.path_bytes().as_ref() == b"./control" {
                ensure!(
                    entry.header().entry_type().is_file(),
                    "QEMU control member is not regular"
                );
                ensure!(
                    entry.size() == spec.control_member.0,
                    "QEMU control member has the wrong size"
                );
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .context("cannot read QEMU control member")?;
                ensure!(
                    sha256(&bytes) == spec.control_member.1,
                    "QEMU control member has the wrong SHA-256"
                );
                control = Some(bytes);
            } else {
                std::io::copy(&mut entry, &mut std::io::sink())
                    .context("cannot drain QEMU control entry")?;
            }
        }
        let control = control.context("QEMU control tar lacks ./control")?;
        let text = std::str::from_utf8(&control).context("QEMU package control is not UTF-8")?;
        for (key, expected) in [
            ("Package", spec.identity.0),
            ("Source", spec.identity.1),
            ("Version", spec.identity.2),
            ("Architecture", spec.identity.3),
        ] {
            let prefix = format!("{key}: ");
            let values = text
                .lines()
                .filter_map(|line| line.strip_prefix(&prefix))
                .collect::<Vec<_>>();
            ensure!(
                values == [expected],
                "QEMU package control field {key} differs from the lock"
            );
        }
        Ok(())
    }

    fn read_selected_entry(
        entry: &mut tar::Entry<'_, impl Read>,
        spec: &ElfSpec,
    ) -> Result<Vec<u8>> {
        ensure!(
            spec.size <= ELF_MEMBER_MAXIMUM,
            "selected ELF exceeds its closed bound"
        );
        let capacity =
            usize::try_from(spec.size).context("selected ELF size does not fit memory")?;
        let mut bytes = Vec::with_capacity(capacity);
        entry
            .read_to_end(&mut bytes)
            .context("cannot read selected ELF member")?;
        ensure!(bytes.len() as u64 == spec.size, "selected ELF ended early");
        Ok(bytes)
    }

    fn verify_data_tar(snapshot: &SealedArtifact, package: &PackageSpec) -> Result<()> {
        ensure!(
            (
                snapshot.descriptor().size,
                snapshot.descriptor().digest.value.as_str()
            ) == package.data_tar,
            "QEMU data tar differs from the lock"
        );
        let mut file = snapshot
            .file()
            .try_clone()
            .context("cannot clone sealed QEMU data tar")?;
        file.seek(SeekFrom::Start(0))
            .context("cannot rewind sealed QEMU data tar")?;
        let mut archive = tar::Archive::new(file);
        let mut paths = BTreeSet::new();
        let mut count = 0_usize;
        let mut selected = BTreeSet::new();
        for entry in archive.entries().context("cannot parse QEMU data tar")? {
            let mut entry = entry.context("cannot parse QEMU data entry")?;
            count += 1;
            ensure!(
                count <= MAX_TAR_ENTRIES,
                "QEMU data tar exceeds its entry bound"
            );
            let path = entry.path_bytes().into_owned();
            ensure!(
                canonical_tar_path(&path),
                "QEMU data tar has a noncanonical path"
            );
            ensure!(paths.insert(path.clone()), "QEMU data tar repeats a path");
            let kind = entry.header().entry_type();
            ensure!(
                kind.is_file() || kind.is_dir() || kind == EntryType::Symlink,
                "QEMU data tar has a forbidden entry type"
            );
            if kind == EntryType::Symlink {
                ensure!(entry.size() == 0, "QEMU package symlink carries data");
                let target = entry
                    .link_name_bytes()
                    .context("QEMU package symlink lacks a target")?;
                ensure!(
                    !target.is_empty()
                        && target.len() <= 128
                        && !target.contains(&b'/')
                        && target.iter().all(|byte| (0x21..=0x7e).contains(byte)),
                    "QEMU package symlink target is outside the closed relative-basename policy"
                );
            }
            if let Some((index, spec)) = ELFS.iter().enumerate().find(|(_, spec)| {
                spec.package_object_index == package.object_index && spec.path == path
            }) {
                ensure!(kind.is_file(), "selected QEMU ELF is not regular");
                ensure!(
                    entry.header().mode()? == spec.mode,
                    "selected QEMU ELF has the wrong mode"
                );
                ensure!(
                    entry.header().uid()? == 0 && entry.header().gid()? == 0,
                    "selected QEMU ELF is not root-owned in the archive"
                );
                ensure!(
                    entry.size() == spec.size,
                    "selected QEMU ELF has the wrong size"
                );
                let bytes = read_selected_entry(&mut entry, spec)?;
                verify_elf(&bytes, spec)?;
                ensure!(selected.insert(index), "selected QEMU ELF is duplicated");
            } else {
                std::io::copy(&mut entry, &mut std::io::sink())
                    .context("cannot drain QEMU data entry")?;
            }
        }
        ensure!(
            count == package.data_entries,
            "QEMU data tar has the wrong entry count"
        );
        let expected = ELFS
            .iter()
            .enumerate()
            .filter_map(|(index, spec)| {
                (spec.package_object_index == package.object_index).then_some(index)
            })
            .collect::<BTreeSet<_>>();
        ensure!(
            selected == expected,
            "QEMU data tar lacks a selected ELF member"
        );
        Ok(())
    }

    fn verify_package(bytes: &[u8], spec: &PackageSpec) -> Result<()> {
        let members = parse_deb(bytes)?;
        ensure!(
            members.len() == 3,
            "QEMU Debian archive is not three members"
        );
        for (member, expected) in members.iter().zip(spec.ar) {
            ensure!(
                member.name == expected.0
                    && member.bytes.len() as u64 == expected.1
                    && sha256(member.bytes) == expected.2,
                "QEMU Debian ar member differs from the lock"
            );
        }
        ensure!(members[0].bytes == b"2.0\n", "unsupported Debian format");
        let control = decompress_zstd(members[1].bytes, CONTROL_TAR_MAXIMUM)?;
        verify_control_tar(&control, spec)?;
        let data = decompress_zstd(members[2].bytes, DATA_TAR_MAXIMUM)?;
        verify_data_tar(&data, spec)
    }

    fn verify_script(bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes == EXPECTED_START_VM,
            "start-vm bytes differ from the reviewed machine configuration"
        );
        ensure!(bytes.len() == 1_077, "start-vm has the wrong byte count");
        ensure!(
            sha256(bytes) == "66dd99fad26eee42cdf7062bfbeefc2951f7edf83114312217b007cb43e735e0",
            "start-vm has the wrong SHA-256"
        );
        Ok(())
    }

    fn report(
        lock: &QemuLock,
        expectation: &ExternalLockExpectation,
        mode: VerificationMode,
    ) -> QemuVerificationReport {
        let complete = mode.complete();
        let mut report = VerificationReport::for_lock(lock, expectation, mode, true);
        report.extend([
            ReportField::boolean("object_bytes_verified", complete),
            ReportField::boolean("sealed_snapshot_verification", complete),
            ReportField::boolean("deb_structure_verified", complete),
            ReportField::boolean("selected_elf_members_verified", complete),
            ReportField::boolean("machine_config_bytes_verified", complete),
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
            ReportField::nonclaim(
                "dynamic_library_package_closure",
                NonClaimState::Unestablished,
            ),
            ReportField::execution("qemu_module_load_trace", ExecutionState::NotExecuted),
            ReportField::execution("kvm_acceleration_verification", ExecutionState::NotExecuted),
            ReportField::text(
                "qemu_public_bind_risk",
                "ssh-forward-and-vnc-bind-all-interfaces-if-executed",
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
            ReportField::nonclaim("source_to_binary_provenance", NonClaimState::Unestablished),
            ReportField::nonclaim("safety", NonClaimState::Unestablished),
            ReportField::execution(
                "archive_filesystem_extraction",
                ExecutionState::NotPerformed,
            ),
            ReportField::execution("package_manager_execution", ExecutionState::NotPerformed),
            ReportField::execution("maintainer_scripts_executed", ExecutionState::NotPerformed),
            ReportField::execution("script_execution", ExecutionState::NotPerformed),
            ReportField::execution("verifier_network_activity", ExecutionState::NotPerformed),
            ReportField::nonclaim(
                "whole_machine_network_silence",
                NonClaimState::Unestablished,
            ),
            ReportField::execution("mount_execution", ExecutionState::NotPerformed),
            ReportField::execution("qemu_execution", ExecutionState::NotPerformed),
            ReportField::execution("vm_execution", ExecutionState::NotPerformed),
        ]);
        report
    }

    fn inspect_common(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<QemuLock> {
        validate_external_expectation(expectation)?;
        let lock_snapshot = snapshot_path(lock_path, MAX_LOCK_BYTES)?;
        ensure!(
            lock_snapshot.descriptor().digest.value == expectation.sha256,
            "lock bytes do not match the externally expected SHA-256"
        );
        let lock = parse_qemu_lock(&snapshot_bytes(&lock_snapshot, MAX_LOCK_BYTES)?)?;
        require(&lock.fields, "lock_repository", &expectation.repository)?;
        require(&lock.fields, "lock_path", &expectation.path)?;
        let profile_snapshot = snapshot_path(profile_path, MAX_PROFILE_BYTES)?;
        ensure!(
            profile_snapshot.descriptor().digest.value == field(&lock.fields, "profile_sha256")?,
            "profile bytes do not match the QEMU lock"
        );
        verify_profile(
            &lock,
            &snapshot_bytes(&profile_snapshot, MAX_PROFILE_BYTES)?,
        )?;
        Ok(lock)
    }

    pub fn inspect_qemu_lock(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<QemuVerificationReport> {
        let lock = inspect_common(lock_path, expectation, profile_path)?;
        Ok(report(&lock, expectation, VerificationMode::LockAndProfile))
    }

    pub fn verify_qemu_inputs(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
        input_directory: &Path,
    ) -> Result<QemuVerificationReport> {
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
        ensure!(snapshots.len() == 7, "QEMU input set is not seven objects");
        verify_receipt(
            &snapshot_bytes(&snapshots[0], RECEIPT_BYTES)?,
            RECEIPT_BYTES,
        )?;
        let manifest = snapshot_bytes(&snapshots[1], MANIFEST_BYTES)?;
        let records = (1..=4)
            .map(|index| {
                field(
                    &lock.fields,
                    &format!("apt_manifest_package_record_{index:02}"),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        verify_manifest(&manifest, MANIFEST_BYTES, &records)?;
        for package in PACKAGES {
            let bytes = snapshot_bytes(
                &snapshots[package.object_index],
                lock.objects[package.object_index].size,
            )?;
            verify_package(&bytes, package)?;
        }
        verify_script(&snapshot_bytes(&snapshots[6], 1_077)?)?;
        Ok(report(&lock, expectation, VerificationMode::InputSelection))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::model::CANONICAL_REPOSITORY;

        const LOCK_BYTES: &[u8] = include_bytes!(
            "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-qemu-v1.lock"
        );
        const SYNTHETIC_PROGRAM_OFFSET: usize = 64;
        const SYNTHETIC_DYNAMIC_OFFSET: usize = 320;

        fn synthetic_elf() -> (Vec<u8>, ElfSpec) {
            const FILE_SIZE: usize = 512;
            const NOTE_OFFSET: usize = 400;
            const STRING_OFFSET: usize = 448;
            const LOAD_ADDRESS: u64 = 0x1000;
            const BUILD_ID: [u8; 20] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            ];
            const NEEDED: &[&str] = &["libtest.so"];

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
                flags: u32,
                offset: u64,
                virtual_address: u64,
                file_size: u64,
            ) {
                let base = SYNTHETIC_PROGRAM_OFFSET + index * 56;
                write_u32(bytes, base, kind);
                write_u32(bytes, base + 4, flags);
                write_u64(bytes, base + 8, offset);
                write_u64(bytes, base + 16, virtual_address);
                write_u64(bytes, base + 24, virtual_address);
                write_u64(bytes, base + 32, file_size);
                write_u64(bytes, base + 40, file_size);
                write_u64(bytes, base + 48, 8);
            }

            fn write_dynamic(bytes: &mut [u8], index: usize, tag: u64, value: u64) {
                let base = SYNTHETIC_DYNAMIC_OFFSET + index * 16;
                write_u64(bytes, base, tag);
                write_u64(bytes, base + 8, value);
            }

            let mut bytes = vec![0_u8; FILE_SIZE];
            bytes[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
            write_u16(&mut bytes, 16, 3);
            write_u16(&mut bytes, 18, 183);
            write_u32(&mut bytes, 20, 1);
            write_u64(&mut bytes, 32, SYNTHETIC_PROGRAM_OFFSET as u64);
            write_u16(&mut bytes, 52, 64);
            write_u16(&mut bytes, 54, 56);
            write_u16(&mut bytes, 56, 4);

            write_program_header(&mut bytes, 0, 1, 4, 0, LOAD_ADDRESS, FILE_SIZE as u64);
            write_program_header(
                &mut bytes,
                1,
                2,
                4,
                SYNTHETIC_DYNAMIC_OFFSET as u64,
                LOAD_ADDRESS + SYNTHETIC_DYNAMIC_OFFSET as u64,
                5 * 16,
            );
            write_program_header(
                &mut bytes,
                2,
                4,
                4,
                NOTE_OFFSET as u64,
                LOAD_ADDRESS + NOTE_OFFSET as u64,
                36,
            );
            write_program_header(&mut bytes, 3, 0x6474_e551, 6, 0, 0, 0);

            write_dynamic(&mut bytes, 0, 5, LOAD_ADDRESS + STRING_OFFSET as u64);
            write_dynamic(&mut bytes, 1, 10, 12);
            write_dynamic(&mut bytes, 2, 0x6fff_fffb, 1);
            write_dynamic(&mut bytes, 3, 1, 1);
            write_dynamic(&mut bytes, 4, 0, 0);

            write_u32(&mut bytes, NOTE_OFFSET, 4);
            write_u32(&mut bytes, NOTE_OFFSET + 4, BUILD_ID.len() as u32);
            write_u32(&mut bytes, NOTE_OFFSET + 8, 3);
            bytes[NOTE_OFFSET + 12..NOTE_OFFSET + 16].copy_from_slice(b"GNU\0");
            bytes[NOTE_OFFSET + 16..NOTE_OFFSET + 36].copy_from_slice(&BUILD_ID);
            bytes[STRING_OFFSET..STRING_OFFSET + 12].copy_from_slice(b"\0libtest.so\0");

            let digest = Box::leak(sha256(&bytes).into_boxed_str());
            (
                bytes,
                ElfSpec {
                    package_object_index: 0,
                    path: b"./synthetic",
                    size: FILE_SIZE as u64,
                    sha256: digest,
                    mode: 0o755,
                    interpreter: None,
                    build_id: "000102030405060708090a0b0c0d0e0f10111213",
                    flags_1: 1,
                    needed: NEEDED,
                },
            )
        }

        #[test]
        fn canonical_lock_profile_and_nonclaims_are_closed() {
            let lock = parse_qemu_lock(LOCK_BYTES).unwrap();
            verify_profile(&lock, CANONICAL_V2_PROFILE.as_bytes()).unwrap();
            assert_eq!(lock.objects.len(), 7);
            let changed = String::from_utf8(LOCK_BYTES.to_vec())
                .unwrap()
                .replace("qemu_execution=forbidden", "qemu_execution=allowed");
            assert!(parse_qemu_lock(changed.as_bytes()).is_err());
        }

        #[test]
        fn machine_script_is_exact_and_exposes_public_bind_risk() {
            verify_script(EXPECTED_START_VM).unwrap();
            let mut changed = EXPECTED_START_VM.to_vec();
            changed[0] ^= 1;
            assert!(verify_script(&changed).is_err());
            let lock = parse_qemu_lock(LOCK_BYTES).unwrap();
            assert_eq!(
                field(&lock.fields, "qemu_public_bind_risk").unwrap(),
                "ssh-forward-and-vnc-bind-all-interfaces-if-executed"
            );
        }

        #[test]
        fn elf_parser_rejects_truncation_wrong_identity_and_machine() {
            let mut header = vec![0_u8; 64];
            header[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
            header[16..18].copy_from_slice(&3_u16.to_le_bytes());
            header[18..20].copy_from_slice(&183_u16.to_le_bytes());
            header[20..24].copy_from_slice(&1_u32.to_le_bytes());
            header[52..54].copy_from_slice(&64_u16.to_le_bytes());
            header[54..56].copy_from_slice(&56_u16.to_le_bytes());
            header[56..58].copy_from_slice(&1_u16.to_le_bytes());
            let mut spec = ELFS[2];
            spec.size = 64;
            spec.sha256 = Box::leak(sha256(&header).into_boxed_str());
            assert!(verify_elf(&header, &spec).is_err());
            header[18..20].copy_from_slice(&62_u16.to_le_bytes());
            spec.sha256 = Box::leak(sha256(&header).into_boxed_str());
            assert!(verify_elf(&header, &spec).is_err());
            assert!(verify_elf(&header[..20], &spec).is_err());
        }

        #[test]
        fn elf_parser_accepts_closed_fixture_and_rejects_policy_mutations() {
            let (bytes, spec) = synthetic_elf();
            verify_elf(&bytes, &spec).unwrap();

            let mut executable_stack = bytes.clone();
            executable_stack
                [SYNTHETIC_PROGRAM_OFFSET + 3 * 56 + 4..SYNTHETIC_PROGRAM_OFFSET + 3 * 56 + 8]
                .copy_from_slice(&7_u32.to_le_bytes());
            let mut changed_spec = spec;
            changed_spec.sha256 = Box::leak(sha256(&executable_stack).into_boxed_str());
            assert!(verify_elf(&executable_stack, &changed_spec).is_err());

            let mut data_after_null = bytes;
            data_after_null[SYNTHETIC_DYNAMIC_OFFSET + 4 * 16 + 8] = 1;
            changed_spec.sha256 = Box::leak(sha256(&data_after_null).into_boxed_str());
            assert!(verify_elf(&data_after_null, &changed_spec).is_err());
        }

        #[test]
        fn canonical_inspection_binds_digest_and_reports_nonclaims() {
            let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let lock_path = repository.join(CANONICAL_LOCK_PATH);
            let profile_path = repository
                .join("packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile");
            let expectation = ExternalLockExpectation {
                repository: CANONICAL_REPOSITORY.to_owned(),
                commit: "0000000000000000000000000000000000000000".to_owned(),
                path: CANONICAL_LOCK_PATH.to_owned(),
                sha256: sha256(LOCK_BYTES),
            };
            let report = inspect_qemu_lock(&lock_path, &expectation, &profile_path)
                .unwrap()
                .render();
            assert_eq!(
                report,
                include_str!("../tests/fixtures/qemu-inspect.report")
            );
            for expected in [
                "verification_status=verified-qemu-lock-and-profile-only",
                "object_bytes_verified=false",
                "dynamic_library_package_closure=not-established",
                "qemu_module_load_trace=not-executed",
                "kvm_acceleration_verification=not-executed",
                "qemu_execution=false",
                "vm_execution=false",
            ] {
                assert!(
                    report.lines().any(|line| line == expected),
                    "missing {expected}"
                );
            }
        }

        #[test]
        fn implementation_has_no_execution_network_or_extraction_surface() {
            let source = include_str!("qemu.rs");
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
                "File::create(",
                "OpenOptions",
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
pub use linux::{inspect_qemu_lock, verify_qemu_inputs};

#[cfg(not(target_os = "linux"))]
pub fn inspect_qemu_lock(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
) -> Result<QemuVerificationReport> {
    anyhow::bail!("the QEMU input-lock verifier requires Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn verify_qemu_inputs(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
    _input_directory: &Path,
) -> Result<QemuVerificationReport> {
    anyhow::bail!("the QEMU input-lock verifier requires Linux")
}
