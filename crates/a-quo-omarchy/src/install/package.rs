use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

#[cfg(target_os = "linux")]
use a_quo_ipc::{SealedArtifact, snapshot_artifact};

use crate::archive::MAX_COMPRESSED_BYTES;
use crate::{OmarchyError, Result};

pub(super) fn copy_package_once(source: &Path, destination: &Path) -> Result<()> {
    let mut input = open_package_source(source)?;
    let metadata = input.metadata().map_err(|source_error| OmarchyError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if !metadata.is_file() {
        return Err(OmarchyError::InvalidPackage(
            "package source must be a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_COMPRESSED_BYTES {
        return Err(OmarchyError::PackageTooLarge {
            actual: metadata.len(),
            maximum: MAX_COMPRESSED_BYTES,
        });
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|source_error| OmarchyError::Io {
            path: destination.to_path_buf(),
            source: source_error,
        })?;
    let copied =
        copy_at_most(&mut input, &mut output, MAX_COMPRESSED_BYTES).map_err(|source_error| {
            OmarchyError::Io {
                path: destination.to_path_buf(),
                source: source_error,
            }
        })?;
    if copied > MAX_COMPRESSED_BYTES {
        return Err(OmarchyError::PackageTooLarge {
            actual: copied,
            maximum: MAX_COMPRESSED_BYTES,
        });
    }
    if copied != metadata.len() {
        return Err(OmarchyError::InvalidPackage(
            "package changed while it was copied into staging".to_owned(),
        ));
    }
    output.flush().map_err(|source_error| OmarchyError::Io {
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    secure_staged_package(destination)?;
    output.sync_all().map_err(|source_error| OmarchyError::Io {
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_package_source(source: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        source,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            OmarchyError::SymlinkBoundary(source.to_path_buf())
        } else {
            OmarchyError::Io {
                path: source.to_path_buf(),
                source: std::io::Error::from_raw_os_error(error.raw_os_error()),
            }
        }
    })?;
    Ok(File::from(descriptor))
}

#[cfg(not(target_os = "linux"))]
fn open_package_source(source: &Path) -> Result<File> {
    let link_metadata = fs::symlink_metadata(source).map_err(|source_error| OmarchyError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(OmarchyError::SymlinkBoundary(source.to_path_buf()));
    }
    File::open(source).map_err(|source_error| OmarchyError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })
}

fn copy_at_most(
    input: &mut impl Read,
    output: &mut impl Write,
    maximum: u64,
) -> std::io::Result<u64> {
    std::io::copy(&mut input.take(maximum.saturating_add(1)), output)
}

#[cfg(target_os = "linux")]
pub(super) fn snapshot_staged_package(path: &Path) -> Result<SealedArtifact> {
    use rustix::fs::{Mode, OFlags, open};

    let metadata = fs::symlink_metadata(path).map_err(|source| OmarchyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::InvalidPackage(
            "staged package must be a regular, non-symlink file".to_owned(),
        ));
    }
    let source = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| OmarchyError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::from_raw_os_error(error.raw_os_error()),
    })?;
    snapshot_artifact(source, MAX_COMPRESSED_BYTES).map_err(Into::into)
}

#[cfg(unix)]
fn secure_staged_package(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_staged_package(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;
    use crate::OmarchyError;

    #[cfg(target_os = "linux")]
    #[test]
    fn package_copy_rejects_fifo_without_blocking() {
        use rustix::fs::{CWD, FileType, Mode, OFlags, mknodat, open};

        let directory = tempdir().unwrap();
        let source = directory.path().join("package.fifo");
        let destination = directory.path().join("copied.tar.zst");
        mknodat(CWD, &source, FileType::Fifo, Mode::RWXU, 0).unwrap();

        let (sender, receiver) = mpsc::channel();
        let worker_source = source.clone();
        let worker_destination = destination.clone();
        let worker = thread::spawn(move || {
            sender
                .send(copy_package_once(&worker_source, &worker_destination))
                .unwrap();
        });

        let result = match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => result,
            Err(timeout) => {
                let _writer = open(
                    &source,
                    OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .unwrap();
                let _ = receiver.recv_timeout(Duration::from_secs(1));
                worker.join().unwrap();
                panic!("package FIFO open blocked: {timeout}");
            }
        };
        worker.join().unwrap();
        assert!(matches!(result, Err(OmarchyError::InvalidPackage(_))));
        assert!(!destination.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_copy_rejects_sparse_input_over_compressed_limit() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("oversized.tar.zst");
        let destination = directory.path().join("copied.tar.zst");
        fs::File::create(&source)
            .unwrap()
            .set_len(MAX_COMPRESSED_BYTES + 1)
            .unwrap();

        let error = copy_package_once(&source, &destination).unwrap_err();
        assert!(matches!(
            error,
            OmarchyError::PackageTooLarge {
                actual,
                maximum: MAX_COMPRESSED_BYTES
            } if actual == MAX_COMPRESSED_BYTES + 1
        ));
        assert!(!destination.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_copy_reads_at_most_one_byte_beyond_its_limit() {
        let mut input = Cursor::new(b"abcdef".as_slice());
        let mut output = Vec::new();
        let copied = copy_at_most(&mut input, &mut output, 4).unwrap();

        assert_eq!(copied, 5);
        assert_eq!(output, b"abcde");
        assert_eq!(input.position(), 5);
    }
}
