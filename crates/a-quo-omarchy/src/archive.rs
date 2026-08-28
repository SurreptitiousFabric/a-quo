use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

use semver::Version;
use tar::Archive;

use crate::{ArchiveReport, OmarchyError, OmarchyManifest, Result};

pub(crate) const MAX_COMPRESSED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DECOMPRESSED_STREAM_BYTES: u64 = 600 * 1024 * 1024;
const MAX_UNCOMPRESSED_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SINGLE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: u64 = 4_096;
pub(crate) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

pub(crate) fn inspect_archive(path: &Path) -> Result<(OmarchyManifest, ArchiveReport)> {
    process_archive(path, None)
}

pub(crate) fn extract_archive(
    path: &Path,
    destination: &Path,
) -> Result<(OmarchyManifest, ArchiveReport)> {
    fs::create_dir(destination).map_err(|source| OmarchyError::Io {
        path: destination.to_path_buf(),
        source,
    })?;
    set_directory_permissions(destination)?;
    process_archive(path, Some(destination))
}

fn process_archive(
    path: &Path,
    destination: Option<&Path>,
) -> Result<(OmarchyManifest, ArchiveReport)> {
    let metadata = fs::symlink_metadata(path).map_err(|source| OmarchyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OmarchyError::InvalidPackage(
            "package path must be a regular, non-symlink file".to_owned(),
        ));
    }
    if metadata.len() > MAX_COMPRESSED_BYTES {
        return Err(OmarchyError::PackageTooLarge {
            actual: metadata.len(),
            maximum: MAX_COMPRESSED_BYTES,
        });
    }

    let file = File::open(path).map_err(|source| OmarchyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let decoder =
        zstd::stream::read::Decoder::new(BufReader::new(file)).map_err(OmarchyError::ArchiveIo)?;
    let bounded = BoundedReader::new(decoder, MAX_DECOMPRESSED_STREAM_BYTES);
    let mut archive = Archive::new(bounded);
    let entries = archive.entries().map_err(OmarchyError::ArchiveIo)?;

    let mut seen = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut manifest_bytes = None;
    let mut executable_files = Vec::new();
    let mut entry_count = 0_u64;
    let mut file_count = 0_u64;
    let mut directory_count = 0_u64;
    let mut total_file_bytes = 0_u64;

    for entry in entries {
        let mut entry = entry.map_err(OmarchyError::ArchiveIo)?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or(OmarchyError::ArchiveLimit {
                limit_name: "entry count",
                maximum: MAX_ARCHIVE_ENTRIES,
            })?;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(OmarchyError::ArchiveLimit {
                limit_name: "entry count",
                maximum: MAX_ARCHIVE_ENTRIES,
            });
        }

        let raw_path = entry.path().map_err(OmarchyError::ArchiveIo)?;
        let relative = validate_entry_path(&raw_path)?;
        let display = path_string(&relative)?;
        if !seen.insert(relative.clone()) {
            return Err(OmarchyError::DuplicateArchivePath(display));
        }

        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            directory_count += 1;
            if let Some(root) = destination {
                let output = root.join(&relative);
                fs::create_dir_all(&output).map_err(|source| OmarchyError::Io {
                    path: output.clone(),
                    source,
                })?;
                set_directory_permissions(&output)?;
            }
            continue;
        }
        if !entry_type.is_file() {
            return Err(OmarchyError::UnsafeArchiveEntry {
                path: display,
                reason: "only regular files and directories are allowed".to_owned(),
            });
        }

        file_count += 1;
        files.insert(relative.clone());
        let size = entry.size();
        if size > MAX_SINGLE_FILE_BYTES {
            return Err(OmarchyError::ArchiveLimit {
                limit_name: "single-file bytes",
                maximum: MAX_SINGLE_FILE_BYTES,
            });
        }
        total_file_bytes =
            total_file_bytes
                .checked_add(size)
                .ok_or(OmarchyError::ArchiveLimit {
                    limit_name: "uncompressed file bytes",
                    maximum: MAX_UNCOMPRESSED_FILE_BYTES,
                })?;
        if total_file_bytes > MAX_UNCOMPRESSED_FILE_BYTES {
            return Err(OmarchyError::ArchiveLimit {
                limit_name: "uncompressed file bytes",
                maximum: MAX_UNCOMPRESSED_FILE_BYTES,
            });
        }

        let mode = entry.header().mode().map_err(OmarchyError::ArchiveIo)?;
        let executable = mode & 0o111 != 0;
        if executable {
            executable_files.push(path_string(&relative)?);
        }

        if relative == Path::new("manifest.json") {
            if size > MAX_MANIFEST_BYTES {
                return Err(OmarchyError::ArchiveLimit {
                    limit_name: "manifest bytes",
                    maximum: MAX_MANIFEST_BYTES,
                });
            }
            let mut bytes = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut bytes)
                .map_err(OmarchyError::ArchiveIo)?;
            if bytes.len() as u64 != size {
                return Err(OmarchyError::InvalidPackage(
                    "manifest size does not match its tar header".to_owned(),
                ));
            }
            if let Some(root) = destination {
                write_file_new(&root.join(&relative), &bytes[..], executable, size)?;
            }
            manifest_bytes = Some(bytes);
        } else if let Some(root) = destination {
            write_file_new(&root.join(&relative), &mut entry, executable, size)?;
        }
    }

    let mut trailing = archive.into_inner();
    let mut trailing_buffer = [0_u8; 64 * 1024];
    loop {
        let read = trailing
            .read(&mut trailing_buffer)
            .map_err(OmarchyError::ArchiveIo)?;
        if read == 0 {
            break;
        }
        if trailing_buffer[..read].iter().any(|byte| *byte != 0) {
            return Err(OmarchyError::InvalidPackage(
                "archive contains non-zero data after the logical tar end".to_owned(),
            ));
        }
    }

    if entry_count == 0 {
        return Err(OmarchyError::InvalidPackage("archive is empty".to_owned()));
    }
    let manifest_bytes = manifest_bytes.ok_or(OmarchyError::MissingManifest)?;
    let manifest: OmarchyManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest, &files)?;
    executable_files.sort();

    Ok((
        manifest,
        ArchiveReport {
            compressed_bytes: metadata.len(),
            entries: entry_count,
            files: file_count,
            directories: directory_count,
            uncompressed_file_bytes: total_file_bytes,
            executable_files,
        },
    ))
}

fn validate_manifest(manifest: &OmarchyManifest, files: &BTreeSet<PathBuf>) -> Result<()> {
    if manifest.schema_version != 1 {
        return Err(OmarchyError::InvalidManifest(
            "schemaVersion must be exactly 1".to_owned(),
        ));
    }
    validate_plugin_id(&manifest.id)?;
    validate_display_text("name", &manifest.name, 256)?;
    validate_display_text("version", &manifest.version, 128)?;
    parse_semantic_version(&manifest.version)?;
    if let Some(description) = &manifest.description {
        validate_display_text("description", description, 4_096)?;
    }
    if manifest.kinds.is_empty() || manifest.kinds.len() > 16 {
        return Err(OmarchyError::InvalidManifest(
            "kinds must contain between 1 and 16 values".to_owned(),
        ));
    }
    let mut unique_kinds = BTreeSet::new();
    for kind in &manifest.kinds {
        validate_display_text("kind", kind, 64)?;
        if !unique_kinds.insert(kind) {
            return Err(OmarchyError::InvalidManifest(format!(
                "duplicate kind: {kind}"
            )));
        }
    }
    if manifest.entry_points.len() > 32 {
        return Err(OmarchyError::InvalidManifest(
            "entryPoints cannot contain more than 32 values".to_owned(),
        ));
    }
    for (kind, entry_point) in &manifest.entry_points {
        validate_display_text("entry-point kind", kind, 64)?;
        let path = validate_entry_path(Path::new(entry_point))?;
        if !files.contains(&path) {
            return Err(OmarchyError::InvalidManifest(format!(
                "entry point is not a regular archive file: {entry_point}"
            )));
        }
    }
    let required: BTreeMap<&str, &str> = [
        ("bar", "bar"),
        ("bar-widget", "barWidget"),
        ("menu", "menu"),
        ("overlay", "overlay"),
        ("panel", "panel"),
        ("service", "service"),
    ]
    .into_iter()
    .collect();
    for kind in &manifest.kinds {
        if let Some(entry_key) = required.get(kind.as_str())
            && !manifest.entry_points.contains_key(*entry_key)
        {
            return Err(OmarchyError::InvalidManifest(format!(
                "kind '{kind}' requires entryPoints.{entry_key}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_plugin_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 255 {
        return Err(OmarchyError::InvalidManifest(
            "id must contain between 1 and 255 bytes".to_owned(),
        ));
    }
    let mut bytes = id.bytes();
    let Some(first) = bytes.next() else {
        return Err(OmarchyError::InvalidManifest(
            "id must contain between 1 and 255 bytes".to_owned(),
        ));
    };
    if !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        || id.contains("..")
        || id.starts_with("omarchy.")
    {
        return Err(OmarchyError::InvalidManifest(format!(
            "invalid or reserved plugin id: {id}"
        )));
    }
    Ok(())
}

fn validate_entry_path(path: &Path) -> Result<PathBuf> {
    let display = path.to_string_lossy().into_owned();
    if path.as_os_str().is_empty() || path.to_str().is_none() {
        return Err(OmarchyError::UnsafeArchiveEntry {
            path: display,
            reason: "path must be non-empty UTF-8".to_owned(),
        });
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or_else(|| OmarchyError::UnsafeArchiveEntry {
                        path: display.clone(),
                        reason: "path must be UTF-8".to_owned(),
                    })?;
                if value == ".git" {
                    return Err(OmarchyError::UnsafeArchiveEntry {
                        path: display,
                        reason: ".git content is not allowed in release packages".to_owned(),
                    });
                }
                if value == crate::install::INSTALL_RECEIPT_NAME {
                    return Err(OmarchyError::UnsafeArchiveEntry {
                        path: display,
                        reason: "A Quo installation receipts are reserved local metadata"
                            .to_owned(),
                    });
                }
                if value.contains('\\') || value.contains(':') {
                    return Err(OmarchyError::UnsafeArchiveEntry {
                        path: display,
                        reason: "backslashes and colons are not portable path characters"
                            .to_owned(),
                    });
                }
                if value.chars().any(is_unsafe_display_character) {
                    return Err(OmarchyError::UnsafeArchiveEntry {
                        path: display,
                        reason: "control and bidirectional formatting characters are not allowed"
                            .to_owned(),
                    });
                }
                clean.push(value);
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(OmarchyError::UnsafeArchiveEntry {
                    path: display,
                    reason: "path must be a normalized relative path".to_owned(),
                });
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(OmarchyError::UnsafeArchiveEntry {
            path: display,
            reason: "path resolves to empty".to_owned(),
        });
    }
    Ok(clean)
}

pub(crate) fn parse_semantic_version(value: &str) -> Result<Version> {
    Version::parse(value).map_err(|error| OmarchyError::InvalidSemanticVersion {
        version: value.to_owned(),
        reason: error.to_string(),
    })
}

fn validate_display_text(field: &str, value: &str, maximum: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > maximum {
        return Err(OmarchyError::InvalidManifest(format!(
            "{field} must contain between 1 and {maximum} UTF-8 bytes"
        )));
    }
    if value.chars().any(is_unsafe_display_character) {
        return Err(OmarchyError::InvalidManifest(format!(
            "{field} contains a control or bidirectional formatting character"
        )));
    }
    Ok(())
}

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| OmarchyError::UnsafeArchiveEntry {
            path: path.to_string_lossy().into_owned(),
            reason: "path must be UTF-8".to_owned(),
        })
}

fn write_file_new(
    path: &Path,
    mut reader: impl Read,
    executable: bool,
    expected_size: u64,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| OmarchyError::InvalidPackage("output path has no parent".to_owned()))?;
    fs::create_dir_all(parent).map_err(|source| OmarchyError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    set_directory_permissions(parent)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let copied = io::copy(&mut reader, &mut output).map_err(OmarchyError::ArchiveIo)?;
    if copied != expected_size {
        return Err(OmarchyError::InvalidPackage(format!(
            "file size mismatch for {}",
            path.display()
        )));
    }
    output.flush().map_err(|source| OmarchyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    set_file_permissions(path, executable)?;
    output.sync_all().map_err(|source| OmarchyError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| OmarchyError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|source| {
        OmarchyError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
    maximum: u64,
}

impl<R> BoundedReader<R> {
    fn new(inner: R, maximum: u64) -> Self {
        Self {
            inner,
            remaining: maximum,
            maximum,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut byte = [0_u8; 1];
            return match self.inner.read(&mut byte)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("decompressed stream exceeds {} bytes", self.maximum),
                )),
            };
        }
        let allowed = self.remaining.min(buffer.len() as u64) as usize;
        let read = self.inner.read(&mut buffer[..allowed])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}
