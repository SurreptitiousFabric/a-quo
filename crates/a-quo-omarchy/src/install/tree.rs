use std::fs::{self, File};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::limits::{INSTALL_RECEIPT_NAME, MAX_RECEIPT_BYTES};
use crate::archive::{
    ExtractedTreeEntry, ExtractedTreeManifest, MAX_SINGLE_FILE_BYTES, MAX_UNCOMPRESSED_FILE_BYTES,
};
use crate::{OmarchyError, Result};

const MAX_UPDATE_TREE_BYTES: u64 = MAX_UNCOMPRESSED_FILE_BYTES + MAX_RECEIPT_BYTES;
const MAX_UPDATE_TREE_ENTRIES: u64 = 8_192;
const MAX_UPDATE_TREE_DEPTH: usize = 64;
const MAX_UPDATE_TREE_PATH_BYTES: u64 = 32 * 1024 * 1024;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TargetIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UpdateTreeSnapshot {
    pub(super) entries: Vec<UpdateTreeEntry>,
    pub(super) total_file_bytes: u64,
    pub(super) total_path_bytes: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UpdateTreeEntry {
    pub(super) path: Vec<Vec<u8>>,
    pub(super) kind: u8,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) links: u64,
    pub(super) size: u64,
    pub(super) sha256: Option<[u8; 32]>,
}

#[cfg(target_os = "linux")]
pub(super) fn read_update_snapshot_file(
    plugin_directory: &Path,
    snapshot: &UpdateTreeSnapshot,
    relative_name: &str,
    maximum: u64,
) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, open};

    let expected_path = vec![relative_name.as_bytes().to_vec()];
    let expected = snapshot
        .entries
        .iter()
        .find(|entry| entry.path == expected_path && entry.kind == b'f')
        .ok_or_else(|| {
            OmarchyError::UpdateStateIndeterminate(format!(
                "installed {relative_name} is absent from the pinned update baseline"
            ))
        })?;
    if expected.size > maximum || expected.sha256.is_none() {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "installed {relative_name} baseline is not a bounded regular file"
        )));
    }

    let path = plugin_directory.join(relative_name);
    let descriptor = open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "cannot open installed {relative_name} without following links: {error}"
        ))
    })?;
    let mut file = File::from(descriptor);
    let before = file.metadata().map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "cannot inspect installed {relative_name}: {error}"
        ))
    })?;
    if !before.is_file() || before.len() > maximum {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "installed {relative_name} is not a bounded regular file"
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            OmarchyError::UpdateStateIndeterminate(format!(
                "cannot read installed {relative_name}: {error}"
            ))
        })?;
    if bytes.len() as u64 > maximum {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "installed {relative_name} exceeded its read limit"
        )));
    }
    let after = file.metadata().map_err(|error| {
        OmarchyError::UpdateStateIndeterminate(format!(
            "cannot recheck installed {relative_name}: {error}"
        ))
    })?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if !after.is_file()
        || before.len() != after.len()
        || expected.size != bytes.len() as u64
        || expected.sha256 != Some(digest)
    {
        return Err(OmarchyError::UpdateStateIndeterminate(format!(
            "installed {relative_name} bytes did not match the pinned update baseline"
        )));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
pub(super) fn target_identity(path: &Path) -> Result<TargetIdentity> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(OmarchyError::TargetMissing(path.to_path_buf()));
        }
        Err(source) => {
            return Err(OmarchyError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(OmarchyError::SymlinkBoundary(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(OmarchyError::NotManagedInstall(path.to_path_buf()));
    }
    Ok(target_identity_from_metadata(&metadata))
}

#[cfg(target_os = "linux")]
pub(super) fn target_identity_from_metadata(metadata: &fs::Metadata) -> TargetIdentity {
    use std::os::unix::fs::MetadataExt;

    TargetIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn snapshot_update_tree_path(
    path: &Path,
    expected_identity: TargetIdentity,
) -> std::result::Result<UpdateTreeSnapshot, String> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        path,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot pin update tree {}: {error}", path.display()))?;
    if descriptor_identity(&descriptor, "update tree")? != expected_identity {
        return Err(format!(
            "update tree identity changed before it could be snapshotted: {}",
            path.display()
        ));
    }
    let snapshot = snapshot_update_tree_descriptor(&descriptor)?;
    if target_identity(path)
        .map_err(|error| format!("cannot revalidate update-tree path: {error}"))?
        != expected_identity
    {
        return Err(format!(
            "update tree path changed while it was snapshotted: {}",
            path.display()
        ));
    }
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
pub(super) fn verify_update_tree_path(
    path: &Path,
    expected_identity: TargetIdentity,
    expected_snapshot: &UpdateTreeSnapshot,
    phase: &str,
) -> std::result::Result<(), String> {
    let actual = snapshot_update_tree_path(path, expected_identity)?;
    if &actual != expected_snapshot {
        return Err(phase.to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn verify_candidate_matches_extracted_manifest(
    snapshot: &UpdateTreeSnapshot,
    mut expected: ExtractedTreeManifest,
    receipt_size: u64,
    receipt_sha256: [u8; 32],
) -> std::result::Result<(), String> {
    expected.entries.push(ExtractedTreeEntry {
        path: vec![INSTALL_RECEIPT_NAME.as_bytes().to_vec()],
        kind: b'f',
        mode: 0o600,
        size: receipt_size,
        sha256: Some(receipt_sha256),
    });
    expected.entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    let actual = snapshot
        .entries
        .iter()
        .map(|entry| ExtractedTreeEntry {
            path: entry.path.clone(),
            kind: entry.kind,
            mode: entry.mode,
            size: entry.size,
            sha256: entry.sha256,
        })
        .collect::<Vec<_>>();
    if actual != expected.entries {
        return Err(
            "extracted candidate tree does not match the verified package and local receipt"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn verify_update_tree_descriptor(
    descriptor: &OwnedFd,
    expected_snapshot: &UpdateTreeSnapshot,
    phase: &str,
) -> std::result::Result<(), String> {
    let actual = snapshot_update_tree_descriptor(descriptor)?;
    if &actual != expected_snapshot {
        return Err(phase.to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn snapshot_update_tree_descriptor(
    descriptor: &OwnedFd,
) -> std::result::Result<UpdateTreeSnapshot, String> {
    let mut snapshot = UpdateTreeSnapshot {
        entries: Vec::new(),
        total_file_bytes: 0,
        total_path_bytes: 0,
    };
    let mut path = Vec::new();
    snapshot_update_directory(descriptor, &mut path, 0, &mut snapshot)?;
    snapshot
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
fn snapshot_update_directory(
    descriptor: &OwnedFd,
    path: &mut Vec<Vec<u8>>,
    depth: usize,
    snapshot: &mut UpdateTreeSnapshot,
) -> std::result::Result<(), String> {
    use rustix::fs::{Dir, FileType, Mode, OFlags, fstat, openat};

    if depth > MAX_UPDATE_TREE_DEPTH {
        return Err(format!(
            "update tree exceeds the maximum depth of {MAX_UPDATE_TREE_DEPTH}"
        ));
    }
    let before = fstat(descriptor)
        .map_err(|error| format!("cannot inspect update-tree directory: {error}"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::Directory {
        return Err("update-tree directory descriptor changed type".to_owned());
    }
    push_update_tree_entry(
        snapshot,
        UpdateTreeEntry {
            path: path.clone(),
            kind: b'd',
            mode: before.st_mode & 0o7777,
            uid: before.st_uid,
            gid: before.st_gid,
            links: before.st_nlink as u64,
            size: 0,
            sha256: None,
        },
    )?;

    let readable = openat(
        descriptor,
        ".",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open pinned update-tree directory: {error}"))?;
    let directory = Dir::new(readable)
        .map_err(|error| format!("cannot enumerate pinned update-tree directory: {error}"))?;
    for entry in directory {
        let entry = entry.map_err(|error| format!("cannot read update-tree entry: {error}"))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name = name.to_owned();
        let child = openat(
            descriptor,
            name.as_c_str(),
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| format!("cannot pin update-tree entry: {error}"))?;
        let stat = fstat(&child)
            .map_err(|error| format!("cannot inspect pinned update-tree entry: {error}"))?;
        path.push(name.as_bytes().to_vec());
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                snapshot_update_directory(&child, path, depth + 1, snapshot)?;
            }
            FileType::RegularFile => {
                snapshot_update_file(descriptor, name.as_c_str(), &child, path, snapshot)?;
            }
            _ => {
                return Err(
                    "update tree contains a symlink or unsupported special entry".to_owned(),
                );
            }
        }
        path.pop();
    }

    let after = fstat(descriptor)
        .map_err(|error| format!("cannot re-inspect update-tree directory: {error}"))?;
    if !update_scan_stat_is_stable(&before, &after) {
        return Err("update-tree directory changed while it was snapshotted".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn snapshot_update_file(
    parent: &OwnedFd,
    name: &std::ffi::CStr,
    pinned: &OwnedFd,
    path: &[Vec<u8>],
    snapshot: &mut UpdateTreeSnapshot,
) -> std::result::Result<(), String> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, openat};

    let pinned_stat = fstat(pinned)
        .map_err(|error| format!("cannot inspect pinned update-tree file: {error}"))?;
    if pinned_stat.st_nlink != 1 {
        return Err("update tree contains a multiply linked regular file".to_owned());
    }
    if pinned_stat.st_size < 0 || pinned_stat.st_size as u64 > MAX_SINGLE_FILE_BYTES {
        return Err(format!(
            "update-tree file exceeds the maximum size of {MAX_SINGLE_FILE_BYTES} bytes"
        ));
    }
    let readable = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open pinned update-tree file: {error}"))?;
    let before = fstat(&readable)
        .map_err(|error| format!("cannot inspect readable update-tree file: {error}"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_dev != pinned_stat.st_dev
        || before.st_ino != pinned_stat.st_ino
    {
        return Err("update-tree file changed before it could be read".to_owned());
    }

    let mut file = File::from(readable);
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash update-tree file: {error}"))?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or_else(|| "update-tree byte count overflowed".to_owned())?;
        if bytes_read > MAX_SINGLE_FILE_BYTES {
            return Err(format!(
                "update-tree file exceeds the maximum size of {MAX_SINGLE_FILE_BYTES} bytes"
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let after =
        fstat(&file).map_err(|error| format!("cannot re-inspect update-tree file: {error}"))?;
    if !update_scan_stat_is_stable(&before, &after) || bytes_read != before.st_size as u64 {
        return Err("update-tree file changed while it was snapshotted".to_owned());
    }
    snapshot.total_file_bytes = snapshot
        .total_file_bytes
        .checked_add(bytes_read)
        .ok_or_else(|| "update-tree total byte count overflowed".to_owned())?;
    if snapshot.total_file_bytes > MAX_UPDATE_TREE_BYTES {
        return Err(format!(
            "update tree exceeds the maximum total file size of {MAX_UPDATE_TREE_BYTES} bytes"
        ));
    }
    push_update_tree_entry(
        snapshot,
        UpdateTreeEntry {
            path: path.to_vec(),
            kind: b'f',
            mode: before.st_mode & 0o7777,
            uid: before.st_uid,
            gid: before.st_gid,
            links: before.st_nlink as u64,
            size: bytes_read,
            sha256: Some(hasher.finalize().into()),
        },
    )
}

#[cfg(target_os = "linux")]
fn push_update_tree_entry(
    snapshot: &mut UpdateTreeSnapshot,
    entry: UpdateTreeEntry,
) -> std::result::Result<(), String> {
    if snapshot.entries.len() as u64 >= MAX_UPDATE_TREE_ENTRIES {
        return Err(format!(
            "update tree exceeds the maximum entry count of {MAX_UPDATE_TREE_ENTRIES}"
        ));
    }
    let entry_path_bytes = entry.path.iter().try_fold(0_u64, |total, component| {
        total.checked_add(component.len() as u64 + 1)
    });
    snapshot.total_path_bytes = snapshot
        .total_path_bytes
        .checked_add(entry_path_bytes.ok_or_else(|| "update-tree path size overflowed".to_owned())?)
        .ok_or_else(|| "update-tree total path size overflowed".to_owned())?;
    if snapshot.total_path_bytes > MAX_UPDATE_TREE_PATH_BYTES {
        return Err(format!(
            "update tree exceeds the maximum stored path size of {MAX_UPDATE_TREE_PATH_BYTES} bytes"
        ));
    }
    snapshot.entries.push(entry);
    Ok(())
}

#[cfg(target_os = "linux")]
fn update_scan_stat_is_stable(before: &rustix::fs::Stat, after: &rustix::fs::Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_nlink == after.st_nlink
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

#[cfg(target_os = "linux")]
pub(super) fn descriptor_identity(
    descriptor: &OwnedFd,
    label: &str,
) -> std::result::Result<TargetIdentity, String> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|error| format!("cannot inspect pinned {label}: {error}"))?;
    Ok(TargetIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn reject_git_managed_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path.join(".git")) {
        Ok(_) => Err(OmarchyError::NotManagedInstall(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(OmarchyError::Io {
            path: path.join(".git"),
            source,
        }),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn reject_git_managed_update_snapshot(
    path: &Path,
    snapshot: &UpdateTreeSnapshot,
) -> Result<()> {
    if snapshot
        .entries
        .iter()
        .any(|entry| entry.path.as_slice() == [b".git".to_vec()])
    {
        return Err(OmarchyError::NotManagedInstall(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn open_pinned_directory_at(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    label: &str,
) -> std::result::Result<(OwnedFd, TargetIdentity), String> {
    use rustix::fs::{Mode, OFlags, openat};

    let descriptor = openat(
        parent,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| format!("{label} is unavailable: {error}"))?;
    let identity = descriptor_identity(&descriptor, label)?;
    Ok((descriptor, identity))
}

#[cfg(target_os = "linux")]
pub(super) fn pinned_entry_exists(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
) -> std::result::Result<bool, rustix::io::Errno> {
    use rustix::fs::{Mode, OFlags, openat};

    match openat(
        parent,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;
    use crate::OmarchyError;
    use crate::install::command::run_validator_for_descriptor;

    #[cfg(target_os = "linux")]
    #[test]
    fn validator_descriptor_root_survives_candidate_path_replacement() {
        use rustix::fs::{Mode, OFlags, open};

        let directory = tempdir().unwrap();
        let candidate = directory.path().join("candidate");
        let displaced = directory.path().join("displaced");
        fs::create_dir(&candidate).unwrap();
        fs::write(candidate.join("marker"), b"signed\n").unwrap();
        let descriptor = open(
            &candidate,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        fs::rename(&candidate, &displaced).unwrap();
        fs::create_dir(&candidate).unwrap();
        fs::write(candidate.join("marker"), b"replacement\n").unwrap();

        let validator = directory.path().join("validator.sh");
        fs::write(
            &validator,
            b"#!/bin/sh\nset -eu\ntest \"$(cat \"$1/marker\")\" = signed\n",
        )
        .unwrap();
        fs::set_permissions(&validator, fs::Permissions::from_mode(0o755)).unwrap();

        run_validator_for_descriptor(&validator, &descriptor).unwrap();
        assert_eq!(fs::read(displaced.join("marker")).unwrap(), b"signed\n");
        assert_eq!(
            fs::read(candidate.join("marker")).unwrap(),
            b"replacement\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn persistent_validator_mutation_fails_the_pinned_candidate_snapshot() {
        use rustix::fs::{Mode, OFlags, open};

        let directory = tempdir().unwrap();
        let candidate = directory.path().join("candidate");
        fs::create_dir(&candidate).unwrap();
        fs::write(candidate.join("marker"), b"signed\n").unwrap();
        let identity = target_identity(&candidate).unwrap();
        let snapshot = snapshot_update_tree_path(&candidate, identity).unwrap();
        let descriptor = open(
            &candidate,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();

        let validator = directory.path().join("mutating-validator.sh");
        fs::write(
            &validator,
            b"#!/bin/sh\nset -eu\nprintf 'mutated\\n' > \"$1/marker\"\n",
        )
        .unwrap();
        fs::set_permissions(&validator, fs::Permissions::from_mode(0o755)).unwrap();

        run_validator_for_descriptor(&validator, &descriptor).unwrap();
        let error = verify_update_tree_descriptor(
            &descriptor,
            &snapshot,
            "candidate changed during validation",
        )
        .unwrap_err();
        assert_eq!(error, "candidate changed during validation");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_semantic_reads_must_match_the_pinned_tree_digest() {
        let directory = tempdir().unwrap();
        let original = b"baseline manifest bytes\n";
        let path = directory.path().join("manifest.json");
        fs::write(&path, original).unwrap();
        let snapshot = UpdateTreeSnapshot {
            entries: vec![UpdateTreeEntry {
                path: vec![b"manifest.json".to_vec()],
                kind: b'f',
                mode: 0o644,
                uid: 0,
                gid: 0,
                links: 1,
                size: original.len() as u64,
                sha256: Some(Sha256::digest(original).into()),
            }],
            total_file_bytes: original.len() as u64,
            total_path_bytes: b"manifest.json".len() as u64,
        };

        assert_eq!(
            read_update_snapshot_file(directory.path(), &snapshot, "manifest.json", 1_024).unwrap(),
            original
        );
        fs::write(&path, b"forged!! manifest bytes\n").unwrap();
        let error = read_update_snapshot_file(directory.path(), &snapshot, "manifest.json", 1_024)
            .unwrap_err();
        assert!(matches!(error, OmarchyError::UpdateStateIndeterminate(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_snapshot_rejects_git_metadata_restored_after_path_check() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("example.plugin");
        let hidden_git = directory.path().join("hidden-git");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join(".git")).unwrap();

        fs::rename(target.join(".git"), &hidden_git).unwrap();
        reject_git_managed_target(&target).unwrap();
        fs::rename(&hidden_git, target.join(".git")).unwrap();

        let identity = target_identity(&target).unwrap();
        let snapshot = snapshot_update_tree_path(&target, identity).unwrap();
        assert!(matches!(
            reject_git_managed_update_snapshot(&target, &snapshot),
            Err(OmarchyError::NotManagedInstall(path)) if path == target
        ));
    }
}
