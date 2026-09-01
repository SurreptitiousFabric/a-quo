use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::fd::AsRawFd;
use std::path::Path;

use a_quo_ipc::{SealedArtifact, snapshot_artifact};
use anyhow::{Context, Result, ensure};
use rustix::fs::{Dir, FileType, Mode, OFlags, fstat, open, openat};
use rustix::process::getuid;

pub(crate) fn snapshot_path(path: &Path, maximum: u64) -> Result<SealedArtifact> {
    let pinned = open(
        path,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .with_context(|| format!("cannot pin {} without following links", path.display()))?;
    let pinned_stat =
        fstat(&pinned).with_context(|| format!("cannot inspect pinned {}", path.display()))?;
    ensure!(
        FileType::from_raw_mode(pinned_stat.st_mode) == FileType::RegularFile,
        "snapshot source is not a regular file: {}",
        path.display()
    );
    ensure!(
        pinned_stat.st_size >= 0 && pinned_stat.st_size as u64 <= maximum,
        "snapshot source exceeds its byte bound: {}",
        path.display()
    );
    let descriptor = reopen_pinned(&pinned)
        .with_context(|| format!("cannot reopen pinned {} for reading", path.display()))?;
    let readable_stat = fstat(&descriptor)
        .with_context(|| format!("cannot inspect readable {}", path.display()))?;
    ensure!(
        FileType::from_raw_mode(readable_stat.st_mode) == FileType::RegularFile
            && readable_stat.st_dev == pinned_stat.st_dev
            && readable_stat.st_ino == pinned_stat.st_ino
            && readable_stat.st_size == pinned_stat.st_size,
        "snapshot source identity changed before reading: {}",
        path.display()
    );
    snapshot_artifact(descriptor, maximum)
        .with_context(|| format!("cannot snapshot {}", path.display()))
}

fn reopen_pinned(pinned: &rustix::fd::OwnedFd) -> Result<rustix::fd::OwnedFd> {
    let proc_path = format!("/proc/self/fd/{}", pinned.as_raw_fd());
    open(
        proc_path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .context("cannot reopen an O_PATH pin through procfs")
}

pub(crate) fn expected_inventory(directory: &rustix::fd::OwnedFd, expected: &[&str]) -> Result<()> {
    let readable = openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .context("cannot enumerate pinned input directory")?;
    ensure!(
        !expected.is_empty() && expected.len() <= 8,
        "expected inventory is outside the closed bound"
    );
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
            allowed.contains(name),
            "input directory has an unexpected entry"
        );
        ensure!(
            observed.insert(name.to_owned()),
            "input directory repeats an entry"
        );
        ensure!(
            observed.len() <= expected.len(),
            "input directory exceeds its entry bound"
        );
    }
    ensure!(
        observed.len() == allowed.len()
            && observed
                .iter()
                .map(String::as_str)
                .eq(allowed.iter().copied()),
        "input directory does not have the exact locked inventory"
    );
    Ok(())
}

pub(crate) fn snapshot_input(
    directory: &rustix::fd::OwnedFd,
    directory_device: u64,
    name: &str,
    expected_size: u64,
) -> Result<SealedArtifact> {
    let pinned = openat(
        directory,
        OsStr::new(name),
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .with_context(|| format!("cannot pin locked input {name}"))?;
    let metadata =
        fstat(&pinned).with_context(|| format!("cannot inspect pinned locked input {name}"))?;
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile,
        "locked input is not regular: {name}"
    );
    ensure!(
        metadata.st_dev == directory_device,
        "locked input crosses a filesystem boundary: {name}"
    );
    ensure!(
        metadata.st_nlink == 1,
        "locked input is multiply linked: {name}"
    );
    ensure!(
        metadata.st_uid == getuid().as_raw(),
        "locked input has the wrong owner: {name}"
    );
    ensure!(
        metadata.st_mode & 0o7777 == 0o400,
        "locked input mode is not 0400: {name}"
    );
    ensure!(
        metadata.st_size >= 0 && metadata.st_size as u64 == expected_size,
        "locked input has the wrong size: {name}"
    );
    let descriptor = reopen_pinned(&pinned)
        .with_context(|| format!("cannot reopen pinned locked input {name} for reading"))?;
    let readable = fstat(&descriptor)
        .with_context(|| format!("cannot inspect readable locked input {name}"))?;
    ensure!(
        FileType::from_raw_mode(readable.st_mode) == FileType::RegularFile
            && readable.st_dev == metadata.st_dev
            && readable.st_ino == metadata.st_ino
            && readable.st_size == metadata.st_size,
        "locked input identity changed before reading: {name}"
    );
    snapshot_artifact(descriptor, expected_size)
        .with_context(|| format!("cannot seal locked input {name}"))
}

pub(crate) fn snapshot_bytes(snapshot: &SealedArtifact, maximum: u64) -> Result<Vec<u8>> {
    snapshot
        .read_bytes_bounded(maximum)
        .context("cannot read sealed snapshot")
}

pub(crate) fn snapshot_exact_input_directory(
    input_directory: &Path,
    specifications: &[(&str, &str, u64, &str)],
) -> Result<Vec<SealedArtifact>> {
    ensure!(
        !specifications.is_empty() && specifications.len() <= 8,
        "input specification count is outside the closed bound"
    );
    let directory = open(
        input_directory,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .context("cannot open input directory without following links")?;
    let root_stat = fstat(&directory).context("cannot inspect input directory")?;
    ensure!(
        FileType::from_raw_mode(root_stat.st_mode) == FileType::Directory,
        "input path is not a directory"
    );
    ensure!(
        root_stat.st_uid == getuid().as_raw(),
        "input directory has the wrong owner"
    );
    ensure!(
        root_stat.st_mode & 0o7777 == 0o700,
        "input directory mode is not 0700"
    );
    let names = specifications
        .iter()
        .map(|(_, name, _, _)| *name)
        .collect::<Vec<_>>();
    expected_inventory(&directory, &names)?;
    let mut snapshots = Vec::with_capacity(specifications.len());
    for (role, name, size, sha256) in specifications {
        let snapshot = snapshot_input(&directory, root_stat.st_dev, name, *size)?;
        ensure!(
            snapshot.descriptor().size == *size && snapshot.descriptor().digest.value == *sha256,
            "locked input bytes do not match {}",
            role
        );
        snapshots.push(snapshot);
    }
    expected_inventory(&directory, &names)?;
    let root_after = fstat(&directory).context("cannot re-inspect input directory")?;
    ensure!(
        root_after.st_dev == root_stat.st_dev
            && root_after.st_ino == root_stat.st_ino
            && root_after.st_mode == root_stat.st_mode
            && root_after.st_uid == root_stat.st_uid
            && root_after.st_gid == root_stat.st_gid,
        "input directory identity or permissions changed during snapshotting"
    );
    Ok(snapshots)
}
