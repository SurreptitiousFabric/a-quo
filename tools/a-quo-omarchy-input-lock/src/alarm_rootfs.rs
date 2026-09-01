use std::collections::{BTreeMap, BTreeSet};
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

pub const MAX_ALARM_ROOTFS_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
const MAX_KEY_BYTES: u64 = 64 * 1024;
const CANONICAL_LOCK_PATH: &str =
    "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-alarm-rootfs-v1.lock";
const EXPECTED_PRIMARY_FINGERPRINT: &str = "68B3537F39A313B3E574D06777193F152BDBE6A6";

const ALARM_LOCK_KEYS: &[&str] = &[
    "target_kind",
    "architecture",
    "evidence_namespace",
    "input_class",
    "selected_input_scope",
    "archive_source_url",
    "signature_source_url",
    "key_source_repository",
    "key_source_commit",
    "key_source_path",
    "key_source_git_blob_sha1",
    "key_source_url",
    "object_count",
    "object_01",
    "object_02",
    "object_03",
    "signature_scheme",
    "signature_expected_primary_fingerprint",
    "signature_expected_signing_fingerprint",
    "signature_creation_unix",
    "signature_public_key_algorithm",
    "signature_hash_algorithm",
    "signature_class",
    "signature_status_policy",
    "keyserver_consumed",
    "openpgp_verifier",
    "openpgp_verifier_bytes",
    "profile_unresolved_input_count",
    "remaining_input_count_if_lock_is_adopted",
    "publisher_authentication",
    "current_publisher_authorization",
    "current_key_revocation",
    "freshness",
    "source_to_rootfs_provenance",
    "safety",
    "archive_extraction",
    "package_manager_execution",
    "network_access",
    "mount_execution",
    "vm_execution",
];

pub type AlarmObjectSpec = ObjectSpec;
pub type AlarmRootfsLock = LockRecord;
pub type AlarmRootfsVerificationReport = VerificationReport;

pub fn parse_alarm_rootfs_lock(bytes: &[u8]) -> Result<AlarmRootfsLock> {
    let fields = parse_lock_fields(bytes, ALARM_LOCK_KEYS, "ALARM rootfs input lock")?;
    for (key, expected) in [
        (
            "selected_input_scope",
            "alarm-rootfs-archive-detached-signature-and-pinned-key-blob",
        ),
        (
            "archive_source_url",
            "https://ca.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz",
        ),
        (
            "signature_source_url",
            "https://ca.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz.sig",
        ),
        (
            "key_source_repository",
            "https://github.com/archlinuxarm/archlinuxarm-keyring.git",
        ),
        (
            "key_source_commit",
            "91e6b11698f8df66042d56aaa56fbe9c9263847d",
        ),
        ("key_source_path", "packager/builder.asc"),
        (
            "key_source_git_blob_sha1",
            "991d04afb7c980921d25642cc53e5c465740f60c",
        ),
        (
            "key_source_url",
            "https://raw.githubusercontent.com/archlinuxarm/archlinuxarm-keyring/91e6b11698f8df66042d56aaa56fbe9c9263847d/packager/builder.asc",
        ),
        ("signature_scheme", "openpgp-detached"),
        (
            "signature_expected_primary_fingerprint",
            EXPECTED_PRIMARY_FINGERPRINT,
        ),
        (
            "signature_expected_signing_fingerprint",
            EXPECTED_PRIMARY_FINGERPRINT,
        ),
        ("signature_creation_unix", "1785933702"),
        ("signature_public_key_algorithm", "rsa"),
        ("signature_hash_algorithm", "sha512"),
        ("signature_class", "00"),
        (
            "signature_status_policy",
            "one-newsig-one-goodsig-one-validsig-no-expiry-or-revocation-status",
        ),
        ("keyserver_consumed", "false"),
        ("openpgp_verifier", "/usr/bin/gpg"),
        ("openpgp_verifier_bytes", "not-locked"),
        ("profile_unresolved_input_count", "10"),
        ("remaining_input_count_if_lock_is_adopted", "9"),
        ("publisher_authentication", "not-established"),
        ("current_publisher_authorization", "not-established"),
        ("current_key_revocation", "not-established"),
        ("freshness", "not-established"),
        ("source_to_rootfs_provenance", "not-established"),
        ("safety", "not-established"),
        ("archive_extraction", "false"),
        ("package_manager_execution", "forbidden"),
        ("network_access", "forbidden"),
        ("mount_execution", "forbidden"),
        ("vm_execution", "forbidden"),
    ] {
        require(&fields, key, expected)?;
    }

    const EXPECTED_OBJECTS: &[ExpectedObjectSpec] = &[
        ExpectedObjectSpec {
            role: "rootfs-archive",
            path: "ArchLinuxARM-aarch64-latest.tar.gz",
            media_type: "application/gzip",
            size: 829_367_415,
            sha256: "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319",
        },
        ExpectedObjectSpec {
            role: "rootfs-detached-signature",
            path: "ArchLinuxARM-aarch64-latest.tar.gz.sig",
            media_type: "application/pgp-signature",
            size: 566,
            sha256: "0157d8cd6261c85205931c766b754d6d56112b28800666fb64add1de192ebe11",
        },
        ExpectedObjectSpec {
            role: "builder-public-key",
            path: "builder.asc",
            media_type: "application/pgp-keys",
            size: 5_304,
            sha256: "26196ae6d6efbb1138be6805245d577adbcd94b887eaf0569f88efe003e6b3d9",
        },
    ];
    let objects = parse_object_specs(&fields, EXPECTED_OBJECTS, "ALARM rootfs")?;
    ensure!(
        objects[0].size <= MAX_ALARM_ROOTFS_BYTES,
        "rootfs exceeds its closed bound"
    );
    ensure!(
        objects[1].size <= MAX_SIGNATURE_BYTES,
        "signature exceeds its closed bound"
    );
    ensure!(
        objects[2].size <= MAX_KEY_BYTES,
        "key exceeds its closed bound"
    );
    LockRecord::new(
        fields,
        objects,
        "a-quo-omarchy-alarm-rootfs-input-lock-v1",
        "a-quo-omarchy4-aarch64-dec29fa-alarm-rootfs-v1",
        LockAuthority::DetachedSignature,
        CANONICAL_LOCK_PATH,
        TargetBinding::ALARM_ROOTFS,
    )
}

fn verify_profile(lock: &AlarmRootfsLock, bytes: &[u8]) -> Result<BTreeMap<String, String>> {
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
        ("retained_input_authority", "none"),
        ("architecture", field(&lock.fields, "architecture")?),
        (
            "profile_authentication",
            "external-pinned-git-object-required",
        ),
        ("self_authentication", "none"),
        ("release_claim", "not-established"),
        ("support_claim", "not-established"),
        ("reproducibility_claim", "not-established"),
        ("clean_system_claim", "not-established"),
        (
            "alarm_rootfs_expected_signer_fingerprint",
            field(&lock.fields, "signature_expected_primary_fingerprint")?,
        ),
        (
            "alarm_builder_key_source_repository",
            field(&lock.fields, "key_source_repository")?,
        ),
        (
            "alarm_builder_key_source_commit",
            field(&lock.fields, "key_source_commit")?,
        ),
        (
            "alarm_builder_key_source_path",
            field(&lock.fields, "key_source_path")?,
        ),
        (
            "alarm_builder_key_source_git_blob_sha1",
            field(&lock.fields, "key_source_git_blob_sha1")?,
        ),
        (
            "alarm_builder_key_url",
            field(&lock.fields, "key_source_url")?,
        ),
        ("alarm_builder_key_size", "5304"),
        ("alarm_builder_key_sha256", &lock.objects[2].sha256),
        (
            "alarm_builder_key_fingerprint",
            EXPECTED_PRIMARY_FINGERPRINT,
        ),
        (
            "alarm_builder_key_source_authentication",
            "unsigned-git-commit",
        ),
        ("alarm_builder_key_authentication", "sha256-policy-pin-only"),
        (
            "alarm_builder_key_role",
            "future-rootfs-signature-policy-expectation",
        ),
        (
            "alarm_builder_key_current_publisher_authorization",
            "not-established",
        ),
        ("alarm_builder_key_current_revocation", "not-established"),
        ("unresolved_input_count", "10"),
        (
            "unresolved_input_04",
            "alarm-rootfs-bytes-signature-and-key-blob",
        ),
    ] {
        require(&profile, key, expected)?;
    }
    Ok(profile)
}

fn validate_external_expectation(expectation: &ExternalLockExpectation) -> Result<()> {
    expectation.validate(CANONICAL_LOCK_PATH, "ALARM rootfs")
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
    use std::process::{Command, Stdio};

    use anyhow::{Context, Result, bail, ensure};
    use rustix::fs::{
        Dir, FileType, MemfdFlags, Mode, OFlags, SealFlags, Stat, fcntl_add_seals, fcntl_get_seals,
        fstat, memfd_create, open, openat,
    };
    use rustix::process::getuid;
    use sha2::{Digest, Sha256};
    use tempfile::Builder;

    use super::*;

    const SNAPSHOT_SEALS: SealFlags = SealFlags::SEAL
        .union(SealFlags::SHRINK)
        .union(SealFlags::GROW)
        .union(SealFlags::WRITE);

    #[derive(Debug)]
    struct SealedSnapshot {
        file: File,
        size: u64,
        sha256: String,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SourceIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        links: u64,
        uid: u32,
        gid: u32,
        size: i64,
        modified_seconds: i128,
        modified_nanoseconds: i128,
        changed_seconds: i128,
        changed_nanoseconds: i128,
    }

    fn stat_link_count<T: Into<u64>>(links: T) -> u64 {
        links.into()
    }

    fn identity(stat: &Stat) -> SourceIdentity {
        SourceIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            links: stat_link_count(stat.st_nlink),
            uid: stat.st_uid,
            gid: stat.st_gid,
            size: stat.st_size,
            modified_seconds: stat.st_mtime as i128,
            modified_nanoseconds: stat.st_mtime_nsec as i128,
            changed_seconds: stat.st_ctime as i128,
            changed_nanoseconds: stat.st_ctime_nsec as i128,
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

    fn snapshot_descriptor(
        descriptor: rustix::fd::OwnedFd,
        expected_size: u64,
        maximum: u64,
    ) -> Result<SealedSnapshot> {
        ensure!(
            expected_size > 0 && expected_size <= maximum,
            "invalid snapshot byte bound"
        );
        let source = File::from(descriptor);
        let before = source
            .metadata()
            .context("cannot inspect snapshot source")?;
        ensure!(before.is_file(), "snapshot source is not regular");
        ensure!(
            before.len() == expected_size,
            "snapshot source has the wrong size"
        );
        let snapshot_fd = memfd_create(
            "a-quo-alarm-rootfs-input",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .context("cannot create ALARM input snapshot")?;
        let mut snapshot = File::from(snapshot_fd);
        let mut hasher = Sha256::new();
        let mut offset = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        while offset < expected_size {
            let remaining = expected_size - offset;
            let limit = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("bounded buffer length fits usize");
            let count = source
                .read_at(&mut buffer[..limit], offset)
                .context("cannot read snapshot source")?;
            ensure!(count > 0, "snapshot source ended early");
            snapshot
                .write_all(&buffer[..count])
                .context("cannot write ALARM input snapshot")?;
            hasher.update(&buffer[..count]);
            offset += count as u64;
        }
        let mut extra = [0_u8; 1];
        ensure!(
            source
                .read_at(&mut extra, expected_size)
                .context("cannot check snapshot end")?
                == 0,
            "snapshot source exceeds the expected size"
        );
        let after = source
            .metadata()
            .context("cannot re-inspect snapshot source")?;
        ensure!(
            before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.len() == after.len()
                && before.mode() == after.mode()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "snapshot source changed while being copied"
        );
        snapshot
            .flush()
            .context("cannot flush ALARM input snapshot")?;
        fcntl_add_seals(&snapshot, SNAPSHOT_SEALS).context("cannot seal ALARM input snapshot")?;
        let seals = fcntl_get_seals(&snapshot).context("cannot inspect ALARM input seals")?;
        ensure!(
            seals.contains(SNAPSHOT_SEALS),
            "ALARM input snapshot is incompletely sealed"
        );
        snapshot
            .seek(SeekFrom::Start(0))
            .context("cannot rewind ALARM input snapshot")?;
        Ok(SealedSnapshot {
            file: snapshot,
            size: expected_size,
            sha256: format!("{:x}", hasher.finalize()),
        })
    }

    fn snapshot_path(path: &Path, maximum: u64) -> Result<SealedSnapshot> {
        let pinned = open(
            path,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| format!("cannot pin {}", path.display()))?;
        let stat = fstat(&pinned).context("cannot inspect pinned snapshot path")?;
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && stat.st_size > 0
                && stat.st_size as u64 <= maximum,
            "snapshot path is not one bounded regular file"
        );
        let readable = reopen_pinned(&pinned)?;
        let readable_stat = fstat(&readable).context("cannot inspect readable snapshot path")?;
        ensure!(
            identity(&readable_stat) == identity(&stat),
            "snapshot path identity changed"
        );
        snapshot_descriptor(readable, stat.st_size as u64, maximum)
    }

    fn expected_inventory(directory: &rustix::fd::OwnedFd, expected: &[&str]) -> Result<()> {
        let readable = openat(
            directory,
            ".",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("cannot enumerate ALARM input directory")?;
        let allowed = expected.iter().copied().collect::<BTreeSet<_>>();
        ensure!(
            allowed.len() == 3,
            "expected ALARM inventory is not three objects"
        );
        let mut observed = BTreeSet::new();
        for entry in Dir::new(readable).context("cannot create ALARM directory iterator")? {
            let entry = entry.context("cannot read ALARM directory entry")?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = std::str::from_utf8(bytes).context("ALARM input name is not UTF-8")?;
            ensure!(
                allowed.contains(name),
                "ALARM input directory has an unexpected entry"
            );
            ensure!(
                observed.insert(name.to_owned()),
                "ALARM input directory repeats an entry"
            );
        }
        ensure!(
            observed
                .iter()
                .map(String::as_str)
                .eq(allowed.iter().copied()),
            "ALARM input directory does not have the exact inventory"
        );
        Ok(())
    }

    fn snapshot_input(
        directory: &rustix::fd::OwnedFd,
        directory_device: u64,
        object: &AlarmObjectSpec,
        maximum: u64,
    ) -> Result<(SealedSnapshot, SourceIdentity)> {
        let pinned = openat(
            directory,
            OsStr::new(&object.path),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| format!("cannot pin ALARM input {}", object.path))?;
        let stat = fstat(&pinned).context("cannot inspect pinned ALARM input")?;
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
            "ALARM input is not regular"
        );
        ensure!(
            stat.st_dev == directory_device,
            "ALARM input crosses a filesystem boundary"
        );
        ensure!(stat.st_nlink == 1, "ALARM input is multiply linked");
        ensure!(
            stat.st_uid == getuid().as_raw(),
            "ALARM input has the wrong owner"
        );
        ensure!(
            stat.st_mode & 0o7777 == 0o400,
            "ALARM input mode is not 0400"
        );
        ensure!(
            stat.st_size >= 0 && stat.st_size as u64 == object.size,
            "ALARM input has the wrong size"
        );
        let readable = reopen_pinned(&pinned)?;
        let readable_stat = fstat(&readable).context("cannot inspect readable ALARM input")?;
        ensure!(
            identity(&readable_stat) == identity(&stat),
            "ALARM input identity changed"
        );
        let source_identity = identity(&stat);
        let snapshot = snapshot_descriptor(readable, object.size, maximum)?;
        ensure!(
            snapshot.sha256 == object.sha256,
            "ALARM input SHA-256 differs from the lock"
        );
        Ok((snapshot, source_identity))
    }

    fn current_identity(
        directory: &rustix::fd::OwnedFd,
        object: &AlarmObjectSpec,
    ) -> Result<SourceIdentity> {
        let current = openat(
            directory,
            OsStr::new(&object.path),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .context("cannot re-pin ALARM input")?;
        let stat = fstat(&current).context("cannot re-inspect ALARM input")?;
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
            "ALARM input type changed"
        );
        Ok(identity(&stat))
    }

    fn verify_gpg_program() -> Result<()> {
        let metadata =
            std::fs::symlink_metadata("/usr/bin/gpg").context("/usr/bin/gpg is unavailable")?;
        ensure!(
            metadata.file_type().is_file(),
            "/usr/bin/gpg is not a regular file"
        );
        ensure!(metadata.uid() == 0, "/usr/bin/gpg is not root-owned");
        ensure!(
            metadata.permissions().mode() & 0o022 == 0,
            "/usr/bin/gpg is writable"
        );
        ensure!(
            metadata.permissions().mode() & 0o111 != 0,
            "/usr/bin/gpg is not executable"
        );
        Ok(())
    }

    fn snapshot_stdio(snapshot: &SealedSnapshot) -> Result<Stdio> {
        let mut file = snapshot
            .file
            .try_clone()
            .context("cannot clone sealed input descriptor")?;
        file.seek(SeekFrom::Start(0))
            .context("cannot rewind sealed input descriptor")?;
        Ok(Stdio::from(file))
    }

    fn gpg_base(home: &Path) -> Command {
        let mut command = Command::new("/usr/bin/gpg");
        command
            .env_clear()
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .arg("--batch")
            .arg("--no-options")
            .arg("--homedir")
            .arg(home)
            .arg("--auto-key-locate")
            .arg("clear")
            .arg("--no-auto-key-retrieve");
        command
    }

    fn parse_primary_key(listing: &[u8], expected: &str) -> Result<()> {
        let text = std::str::from_utf8(listing).context("GPG key listing is not UTF-8")?;
        let mut public_keys = 0_u8;
        let mut secret_keys = 0_u8;
        let mut want_primary_fingerprint = false;
        let mut primary_fingerprints = Vec::new();
        for line in text.lines() {
            let fields = line.split(':').collect::<Vec<_>>();
            match fields.first().copied() {
                Some("pub") => {
                    public_keys = public_keys.saturating_add(1);
                    want_primary_fingerprint = true;
                }
                Some("sec") => secret_keys = secret_keys.saturating_add(1),
                Some("fpr") if want_primary_fingerprint => {
                    let fingerprint = fields
                        .get(9)
                        .context("GPG fingerprint record is incomplete")?;
                    primary_fingerprints.push((*fingerprint).to_owned());
                    want_primary_fingerprint = false;
                }
                _ => {}
            }
        }
        ensure!(
            public_keys == 1,
            "key blob does not contain exactly one primary public key"
        );
        ensure!(secret_keys == 0, "key blob contains secret key material");
        ensure!(
            primary_fingerprints == [expected],
            "key blob primary fingerprint differs from the lock"
        );
        Ok(())
    }

    fn verify_signature(lock: &AlarmRootfsLock, snapshots: &[SealedSnapshot]) -> Result<()> {
        ensure!(
            snapshots.len() == 3,
            "ALARM snapshot set is not three objects"
        );
        verify_gpg_program()?;
        let home = Builder::new()
            .prefix("a-quo-alarm-gpg.")
            .tempdir()
            .context("cannot create isolated GPG home")?;

        let listing = gpg_base(home.path())
            .arg("--with-colons")
            .arg("--import-options")
            .arg("show-only")
            .arg("--import")
            .stdin(snapshot_stdio(&snapshots[2])?)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("cannot inspect sealed builder key")?;
        ensure!(
            listing.status.success(),
            "GPG refused the sealed builder key"
        );
        parse_primary_key(
            &listing.stdout,
            field(&lock.fields, "signature_expected_primary_fingerprint")?,
        )?;

        let imported = gpg_base(home.path())
            .arg("--import")
            .stdin(snapshot_stdio(&snapshots[2])?)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .context("cannot import sealed builder key")?;
        ensure!(
            imported.status.success(),
            "GPG could not import the sealed builder key"
        );

        let verified = gpg_base(home.path())
            .arg("--status-fd")
            .arg("2")
            .arg("--verify")
            .arg("/proc/self/fd/0")
            .arg("/proc/self/fd/1")
            .stdin(snapshot_stdio(&snapshots[1])?)
            .stdout(snapshot_stdio(&snapshots[0])?)
            .stderr(Stdio::piped())
            .output()
            .context("cannot verify sealed rootfs signature")?;
        ensure!(
            verified.status.success(),
            "GPG rejected the sealed rootfs signature"
        );
        let status = std::str::from_utf8(&verified.stderr).context("GPG status is not UTF-8")?;
        let mut newsig = 0_u8;
        let mut goodsig = 0_u8;
        let mut validsig = Vec::new();
        let mut trust_undefined = 0_u8;
        for line in status.lines() {
            let Some(record) = line.strip_prefix("[GNUPG:] ") else {
                continue;
            };
            let tokens = record.split_whitespace().collect::<Vec<_>>();
            match tokens.first().copied() {
                Some("NEWSIG") => newsig = newsig.saturating_add(1),
                Some("GOODSIG") => goodsig = goodsig.saturating_add(1),
                Some("VALIDSIG") => validsig.push(tokens),
                Some("TRUST_UNDEFINED") => trust_undefined = trust_undefined.saturating_add(1),
                Some(
                    "BADSIG" | "ERRSIG" | "NO_PUBKEY" | "EXPKEYSIG" | "EXPSIG" | "REVKEYSIG"
                    | "KEYEXPIRED" | "SIGEXPIRED" | "KEYREVOKED",
                ) => bail!("GPG status includes a signature, expiry, or revocation failure"),
                _ => {}
            }
        }
        ensure!(
            newsig == 1 && goodsig == 1,
            "GPG did not emit exactly one NEWSIG and GOODSIG"
        );
        ensure!(validsig.len() == 1, "GPG did not emit exactly one VALIDSIG");
        ensure!(
            trust_undefined == 1,
            "GPG did not preserve undefined trust as evidence"
        );
        let signature = &validsig[0];
        ensure!(
            signature.len() == 11,
            "GPG VALIDSIG record has an unexpected shape"
        );
        ensure!(
            signature[1] == field(&lock.fields, "signature_expected_signing_fingerprint")?
                && signature[3] == field(&lock.fields, "signature_creation_unix")?
                && signature[7] == "1"
                && signature[8] == "10"
                && signature[9] == field(&lock.fields, "signature_class")?
                && signature[10] == field(&lock.fields, "signature_expected_primary_fingerprint")?,
            "GPG VALIDSIG record differs from the locked signature policy"
        );
        for snapshot in snapshots {
            let seals =
                fcntl_get_seals(&snapshot.file).context("cannot re-inspect snapshot seals")?;
            ensure!(
                seals.contains(SNAPSHOT_SEALS)
                    && snapshot
                        .file
                        .metadata()
                        .context("cannot re-inspect snapshot")?
                        .len()
                        == snapshot.size,
                "sealed snapshot changed during GPG verification"
            );
        }
        Ok(())
    }

    fn open_and_verify_lock(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<(AlarmRootfsLock, SealedSnapshot, SealedSnapshot)> {
        validate_external_expectation(expectation)?;
        let lock_snapshot = snapshot_path(lock_path, MAX_LOCK_BYTES)?;
        ensure!(
            lock_snapshot.sha256 == expectation.sha256,
            "lock bytes do not match the externally expected SHA-256"
        );
        let mut lock_file = lock_snapshot
            .file
            .try_clone()
            .context("cannot clone lock snapshot")?;
        lock_file
            .seek(SeekFrom::Start(0))
            .context("cannot rewind lock snapshot")?;
        let mut lock_bytes = Vec::with_capacity(lock_snapshot.size as usize);
        lock_file
            .read_to_end(&mut lock_bytes)
            .context("cannot read lock snapshot")?;
        let lock = parse_alarm_rootfs_lock(&lock_bytes)?;
        require(&lock.fields, "lock_repository", &expectation.repository)?;
        require(&lock.fields, "lock_path", &expectation.path)?;

        let profile_snapshot = snapshot_path(profile_path, MAX_PROFILE_BYTES)?;
        ensure!(
            profile_snapshot.sha256 == field(&lock.fields, "profile_sha256")?,
            "profile bytes do not match the ALARM rootfs lock"
        );
        let mut profile_file = profile_snapshot
            .file
            .try_clone()
            .context("cannot clone profile snapshot")?;
        profile_file
            .seek(SeekFrom::Start(0))
            .context("cannot rewind profile snapshot")?;
        let mut profile_bytes = Vec::with_capacity(profile_snapshot.size as usize);
        profile_file
            .read_to_end(&mut profile_bytes)
            .context("cannot read profile snapshot")?;
        verify_profile(&lock, &profile_bytes)?;
        Ok((lock, lock_snapshot, profile_snapshot))
    }

    fn report(
        lock: &AlarmRootfsLock,
        expectation: &ExternalLockExpectation,
        mode: VerificationMode,
    ) -> AlarmRootfsVerificationReport {
        let complete = mode.complete();
        let mut report = VerificationReport::for_lock(lock, expectation, mode, true);
        report.extend([
            ReportField::boolean("object_bytes_verified", complete),
            ReportField::boolean("sealed_snapshot_verification", complete),
            ReportField::boolean("detached_signature_verified", complete),
            ReportField::text(
                "primary_fingerprint",
                field(&lock.fields, "signature_expected_primary_fingerprint")
                    .expect("validated lock"),
            ),
            ReportField::text(
                "signing_fingerprint",
                field(&lock.fields, "signature_expected_signing_fingerprint")
                    .expect("validated lock"),
            ),
            ReportField::text(
                "signature_creation_unix",
                field(&lock.fields, "signature_creation_unix").expect("validated lock"),
            ),
            ReportField::execution("keyserver_consumed", ExecutionState::NotPerformed),
            ReportField::text("openpgp_verifier", "/usr/bin/gpg"),
            ReportField::nonclaim("openpgp_verifier_bytes", NonClaimState::NotLocked),
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
            ReportField::nonclaim("current_key_revocation", NonClaimState::Unestablished),
            ReportField::nonclaim("freshness", NonClaimState::Unestablished),
            ReportField::nonclaim("source_to_rootfs_provenance", NonClaimState::Unestablished),
            ReportField::nonclaim("safety", NonClaimState::Unestablished),
            ReportField::execution("archive_extraction", ExecutionState::NotPerformed),
            ReportField::execution("package_manager_execution", ExecutionState::NotPerformed),
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

    pub fn inspect_alarm_rootfs_lock(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<AlarmRootfsVerificationReport> {
        let (lock, _lock_snapshot, _profile_snapshot) =
            open_and_verify_lock(lock_path, expectation, profile_path)?;
        Ok(report(&lock, expectation, VerificationMode::LockAndProfile))
    }

    pub fn verify_alarm_rootfs_inputs(
        lock_path: &Path,
        expectation: &ExternalLockExpectation,
        profile_path: &Path,
        input_directory: &Path,
    ) -> Result<AlarmRootfsVerificationReport> {
        let (lock, _lock_snapshot, _profile_snapshot) =
            open_and_verify_lock(lock_path, expectation, profile_path)?;
        let directory = open(
            input_directory,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .context("cannot pin ALARM input directory")?;
        let root_before = fstat(&directory).context("cannot inspect ALARM input directory")?;
        ensure!(
            FileType::from_raw_mode(root_before.st_mode) == FileType::Directory
                && root_before.st_uid == getuid().as_raw()
                && root_before.st_mode & 0o7777 == 0o700,
            "ALARM input directory has the wrong type, owner, or mode"
        );
        let expected_names = lock
            .objects
            .iter()
            .map(|object| object.path.as_str())
            .collect::<Vec<_>>();
        expected_inventory(&directory, &expected_names)?;
        let maximums = [MAX_ALARM_ROOTFS_BYTES, MAX_SIGNATURE_BYTES, MAX_KEY_BYTES];
        let mut snapshots = Vec::with_capacity(3);
        let mut identities = Vec::with_capacity(3);
        for (object, maximum) in lock.objects.iter().zip(maximums) {
            let (snapshot, source_identity) =
                snapshot_input(&directory, root_before.st_dev, object, maximum)?;
            snapshots.push(snapshot);
            identities.push(source_identity);
        }
        ensure!(
            identity(&fstat(&directory).context("cannot re-inspect ALARM input directory")?)
                == identity(&root_before),
            "ALARM input directory changed during snapshotting"
        );
        expected_inventory(&directory, &expected_names)?;
        for (object, expected_identity) in lock.objects.iter().zip(&identities) {
            ensure!(
                current_identity(&directory, object)? == *expected_identity,
                "ALARM input changed during snapshotting"
            );
        }
        verify_signature(&lock, &snapshots)?;
        Ok(report(&lock, expectation, VerificationMode::InputSelection))
    }

    #[cfg(test)]
    mod tests {
        use std::os::unix::fs::PermissionsExt;

        use super::*;
        use crate::model::CANONICAL_REPOSITORY;

        const LOCK_BYTES: &[u8] = include_bytes!(
            "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-alarm-rootfs-v1.lock"
        );

        #[test]
        fn committed_lock_and_profile_are_closed() {
            let lock = parse_alarm_rootfs_lock(LOCK_BYTES).unwrap();
            verify_profile(&lock, CANONICAL_V2_PROFILE.as_bytes()).unwrap();
            assert_eq!(lock.objects.len(), 3);
            assert_eq!(lock.objects[0].size, 829_367_415);
        }

        #[test]
        fn trust_and_scope_escalations_are_rejected() {
            for (from, to) in [
                (
                    "publisher_authentication=not-established",
                    "publisher_authentication=established",
                ),
                (
                    "current_key_revocation=not-established",
                    "current_key_revocation=not-revoked",
                ),
                (
                    "build_authorization=not-established",
                    "build_authorization=authorized",
                ),
                (
                    "remaining_input_count_if_lock_is_adopted=9",
                    "remaining_input_count_if_lock_is_adopted=8",
                ),
                ("network_access=forbidden", "network_access=allowed"),
            ] {
                let mutant = std::str::from_utf8(LOCK_BYTES)
                    .unwrap()
                    .replacen(from, to, 1);
                assert!(
                    parse_alarm_rootfs_lock(mutant.as_bytes()).is_err(),
                    "accepted {to}"
                );
            }
        }

        #[test]
        fn object_and_signature_substitution_are_rejected() {
            for (from, to) in [
                (
                    "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319",
                    "02a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319",
                ),
                (
                    "signature_hash_algorithm=sha512",
                    "signature_hash_algorithm=sha256",
                ),
                (
                    "signature_expected_primary_fingerprint=68B3537F39A313B3E574D06777193F152BDBE6A6",
                    "signature_expected_primary_fingerprint=08B3537F39A313B3E574D06777193F152BDBE6A6",
                ),
            ] {
                let mutant = std::str::from_utf8(LOCK_BYTES)
                    .unwrap()
                    .replacen(from, to, 1);
                assert!(
                    parse_alarm_rootfs_lock(mutant.as_bytes()).is_err(),
                    "accepted {to}"
                );
            }
        }

        #[test]
        fn local_snapshot_supports_rootfs_bound_without_changing_ipc_limit() {
            assert_eq!(MAX_ALARM_ROOTFS_BYTES, 1024 * 1024 * 1024);
            assert_eq!(a_quo_ipc::MAX_ARTIFACT_BYTES, 512 * 1024 * 1024);
            let source = tempfile::tempfile().unwrap();
            source.set_len(5).unwrap();
            source.write_all_at(b"bytes", 0).unwrap();
            let descriptor = source.into();
            let snapshot = snapshot_descriptor(descriptor, 5, 5).unwrap();
            assert_eq!(snapshot.sha256, format!("{:x}", Sha256::digest(b"bytes")));
            assert!(
                fcntl_get_seals(&snapshot.file)
                    .unwrap()
                    .contains(SNAPSHOT_SEALS)
            );
        }

        fn test_gpg(home: &Path) -> Command {
            let mut command = Command::new("/usr/bin/gpg");
            command
                .env_clear()
                .env("LC_ALL", "C")
                .env("TZ", "UTC")
                .arg("--batch")
                .arg("--no-options")
                .arg("--homedir")
                .arg(home)
                .arg("--auto-key-locate")
                .arg("clear")
                .arg("--no-auto-key-retrieve");
            command
        }

        fn seal_file(path: &Path) -> SealedSnapshot {
            let file = File::open(path).unwrap();
            let size = file.metadata().unwrap().len();
            snapshot_descriptor(file.into(), size, 1024 * 1024).unwrap()
        }

        fn seal_file_from_snapshot(snapshot: &SealedSnapshot) -> SealedSnapshot {
            let mut source = snapshot.file.try_clone().unwrap();
            source.seek(SeekFrom::Start(0)).unwrap();
            let mut destination = tempfile::tempfile().unwrap();
            std::io::copy(&mut source, &mut destination).unwrap();
            destination.seek(SeekFrom::Start(0)).unwrap();
            snapshot_descriptor(destination.into(), snapshot.size, snapshot.size).unwrap()
        }

        fn synthetic_signed_snapshots() -> (AlarmRootfsLock, Vec<SealedSnapshot>) {
            let fixture = tempfile::tempdir().unwrap();
            let gpg_home = fixture.path().join("gpg");
            std::fs::create_dir(&gpg_home).unwrap();
            std::fs::set_permissions(&gpg_home, std::fs::Permissions::from_mode(0o700)).unwrap();
            let generated = test_gpg(&gpg_home)
                .arg("--pinentry-mode")
                .arg("loopback")
                .arg("--passphrase")
                .arg("")
                .arg("--quick-generate-key")
                .arg("A Quo ALARM Contract <alarm-contract@example.invalid>")
                .arg("rsa2048")
                .arg("sign")
                .arg("0")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .unwrap();
            assert!(generated.status.success());
            let listing = test_gpg(&gpg_home)
                .arg("--with-colons")
                .arg("--list-keys")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .unwrap();
            assert!(listing.status.success());
            let listing = std::str::from_utf8(&listing.stdout).unwrap();
            let mut want = false;
            let mut fingerprint = None;
            for line in listing.lines() {
                let fields = line.split(':').collect::<Vec<_>>();
                match fields.first().copied() {
                    Some("pub") => want = true,
                    Some("fpr") if want => {
                        fingerprint = fields.get(9).map(|value| (*value).to_owned());
                        break;
                    }
                    _ => {}
                }
            }
            let fingerprint = fingerprint.unwrap();
            assert_eq!(fingerprint.len(), 40);

            let archive = fixture.path().join("rootfs.tar.gz");
            let signature = fixture.path().join("rootfs.tar.gz.sig");
            let public_key = fixture.path().join("builder.asc");
            std::fs::write(&archive, b"synthetic inert ALARM rootfs bytes\n").unwrap();
            let signed = test_gpg(&gpg_home)
                .arg("--pinentry-mode")
                .arg("loopback")
                .arg("--passphrase")
                .arg("")
                .arg("--local-user")
                .arg(&fingerprint)
                .arg("--digest-algo")
                .arg("SHA512")
                .arg("--detach-sign")
                .arg("--output")
                .arg(&signature)
                .arg(&archive)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .unwrap();
            assert!(signed.status.success());
            let exported = test_gpg(&gpg_home)
                .arg("--armor")
                .arg("--export")
                .arg(&fingerprint)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .unwrap();
            assert!(exported.status.success());
            std::fs::write(&public_key, &exported.stdout).unwrap();

            let status = test_gpg(&gpg_home)
                .arg("--status-fd")
                .arg("1")
                .arg("--verify")
                .arg(&signature)
                .arg(&archive)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .unwrap();
            assert!(status.status.success());
            let status = std::str::from_utf8(&status.stdout).unwrap();
            let creation = status
                .lines()
                .find_map(|line| {
                    let tokens = line.split_whitespace().collect::<Vec<_>>();
                    (tokens.get(1) == Some(&"VALIDSIG")).then(|| tokens[4].to_owned())
                })
                .unwrap();

            let mut lock = parse_alarm_rootfs_lock(LOCK_BYTES).unwrap();
            lock.fields.insert(
                "signature_expected_primary_fingerprint".to_owned(),
                fingerprint.clone(),
            );
            lock.fields.insert(
                "signature_expected_signing_fingerprint".to_owned(),
                fingerprint,
            );
            lock.fields
                .insert("signature_creation_unix".to_owned(), creation);
            let snapshots = vec![
                seal_file(&archive),
                seal_file(&signature),
                seal_file(&public_key),
            ];
            let _ = Command::new("/usr/bin/gpgconf")
                .arg("--homedir")
                .arg(&gpg_home)
                .arg("--kill")
                .arg("all")
                .status();
            (lock, snapshots)
        }

        #[test]
        fn sealed_descriptor_signature_verification_is_behavioral_and_fail_closed() {
            let (lock, snapshots) = synthetic_signed_snapshots();
            verify_signature(&lock, &snapshots).unwrap();

            let changed = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(changed.path(), b"changed inert rootfs bytes\n").unwrap();
            let changed_snapshots = vec![
                seal_file(changed.path()),
                seal_file_from_snapshot(&snapshots[1]),
                seal_file_from_snapshot(&snapshots[2]),
            ];
            assert!(verify_signature(&lock, &changed_snapshots).is_err());

            let mut wrong_fingerprint = lock;
            wrong_fingerprint.fields.insert(
                "signature_expected_primary_fingerprint".to_owned(),
                "08B3537F39A313B3E574D06777193F152BDBE6A6".to_owned(),
            );
            assert!(verify_signature(&wrong_fingerprint, &snapshots).is_err());
        }

        #[test]
        fn canonical_inspection_binds_external_digest_and_nonclaims() {
            let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let lock_path = repository.join(CANONICAL_LOCK_PATH);
            let profile_path = repository
                .join("packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile");
            let expectation = ExternalLockExpectation {
                repository: CANONICAL_REPOSITORY.to_owned(),
                commit: "0000000000000000000000000000000000000000".to_owned(),
                path: CANONICAL_LOCK_PATH.to_owned(),
                sha256: "eed752c3e42f1d6d62d4f6cf4d618f0fe480eb95f44d9141e79fb039edc34775"
                    .to_owned(),
            };
            let report = inspect_alarm_rootfs_lock(&lock_path, &expectation, &profile_path)
                .unwrap()
                .render();
            assert_eq!(
                report,
                include_str!("../tests/fixtures/alarm-rootfs-inspect.report")
            );
            for expected in [
                "verification_status=verified-alarm-rootfs-lock-and-profile-only",
                "object_bytes_verified=false",
                "detached_signature_verified=false",
                "build_authorization=not-established",
                "publisher_authentication=not-established",
                "current_key_revocation=not-established",
                "remaining_input_count_if_lock_is_adopted=9",
                "verifier_network_activity=false",
                "vm_execution=false",
            ] {
                assert!(
                    report.lines().any(|line| line == expected),
                    "missing {expected}"
                );
            }
            let mut wrong_digest = expectation;
            wrong_digest.sha256 = "0".repeat(64);
            assert!(inspect_alarm_rootfs_lock(&lock_path, &wrong_digest, &profile_path).is_err());
        }

        #[test]
        fn sealed_snapshot_survives_but_detects_post_open_path_replacement() {
            let directory_path = tempfile::tempdir().unwrap();
            std::fs::set_permissions(
                directory_path.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let name = "rootfs.tar.gz";
            let path = directory_path.path().join(name);
            std::fs::write(&path, b"first").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            let object = AlarmObjectSpec {
                role: "rootfs-archive".to_owned(),
                path: name.to_owned(),
                media_type: "application/gzip".to_owned(),
                size: 5,
                sha256: format!("{:x}", Sha256::digest(b"first")),
            };
            let directory = open(
                directory_path.path(),
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let directory_stat = fstat(&directory).unwrap();
            let (snapshot, original_identity) =
                snapshot_input(&directory, directory_stat.st_dev, &object, 5).unwrap();
            let displaced = directory_path.path().join("displaced");
            std::fs::rename(&path, &displaced).unwrap();
            std::fs::write(&path, b"later").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            assert_ne!(
                current_identity(&directory, &object).unwrap(),
                original_identity
            );
            let mut sealed = snapshot.file.try_clone().unwrap();
            sealed.seek(SeekFrom::Start(0)).unwrap();
            let mut bytes = Vec::new();
            sealed.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"first");
        }

        #[test]
        fn input_path_policy_rejects_extra_entries_modes_hardlinks_and_symlinks() {
            let directory_path = tempfile::tempdir().unwrap();
            std::fs::set_permissions(
                directory_path.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let name = "rootfs.tar.gz";
            let path = directory_path.path().join(name);
            std::fs::write(&path, b"first").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            let signature_name = "rootfs.tar.gz.sig";
            let key_name = "builder.asc";
            std::fs::write(directory_path.path().join(signature_name), b"signature").unwrap();
            std::fs::write(directory_path.path().join(key_name), b"key").unwrap();
            let object = AlarmObjectSpec {
                role: "rootfs-archive".to_owned(),
                path: name.to_owned(),
                media_type: "application/gzip".to_owned(),
                size: 5,
                sha256: format!("{:x}", Sha256::digest(b"first")),
            };
            let directory = open(
                directory_path.path(),
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let directory_stat = fstat(&directory).unwrap();

            expected_inventory(&directory, &[name, signature_name, key_name]).unwrap();
            let unexpected = directory_path.path().join("unexpected");
            std::fs::write(&unexpected, b"unexpected").unwrap();
            expected_inventory(&directory, &[name, signature_name, key_name]).unwrap_err();
            std::fs::remove_file(unexpected).unwrap();
            snapshot_input(&directory, directory_stat.st_dev, &object, 5).unwrap();

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            snapshot_input(&directory, directory_stat.st_dev, &object, 5).unwrap_err();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

            let linked = directory_path.path().join("linked");
            std::fs::hard_link(&path, &linked).unwrap();
            snapshot_input(&directory, directory_stat.st_dev, &object, 5).unwrap_err();
            std::fs::remove_file(&linked).unwrap();

            let target = directory_path.path().join("target");
            std::fs::rename(&path, &target).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
            snapshot_input(&directory, directory_stat.st_dev, &object, 5).unwrap_err();
        }

        #[test]
        fn implementation_has_a_closed_process_and_network_surface() {
            let source = include_str!("alarm_rootfs.rs");
            let production = source.split("#[cfg(test)]").next().unwrap();
            assert_eq!(production.matches("Command::new(").count(), 1);
            assert_eq!(
                production.matches("Command::new(\"/usr/bin/gpg\")").count(),
                1
            );
            for forbidden in [
                "std::net",
                "TcpStream",
                "UdpSocket",
                "reqwest",
                "/usr/bin/curl",
                "/usr/bin/wget",
                "Command::new(\"docker\")",
                "Command::new(\"podman\")",
                "Command::new(\"pacman\")",
                "Command::new(\"qemu",
                "Command::new(\"mount\")",
                "Command::new(\"sudo\")",
            ] {
                assert!(
                    !production.contains(forbidden),
                    "forbidden implementation surface: {forbidden}"
                );
            }
            assert!(production.contains(".arg(\"--auto-key-locate\")"));
            assert!(production.contains(".arg(\"clear\")"));
            assert!(production.contains(".arg(\"--no-auto-key-retrieve\")"));
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{inspect_alarm_rootfs_lock, verify_alarm_rootfs_inputs};

#[cfg(not(target_os = "linux"))]
pub fn inspect_alarm_rootfs_lock(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
) -> Result<AlarmRootfsVerificationReport> {
    anyhow::bail!("the ALARM rootfs input-lock verifier requires Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn verify_alarm_rootfs_inputs(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
    _input_directory: &Path,
) -> Result<AlarmRootfsVerificationReport> {
    anyhow::bail!("the ALARM rootfs input-lock verifier requires Linux")
}
