use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use a_quo_core::{ArtifactDescriptor, Digest};
use a_quo_ipc::{MAX_ARTIFACT_BYTES, snapshot_artifact, snapshot_stream};
use rustix::fs::{Mode, OFlags, open};

use crate::{
    MAX_MEDIA_BYTES, MediaError, MediaVerificationReport, Result, WorkerResponse,
    normalize_worker_response,
};

const BWRAP: &str = "/usr/bin/bwrap";
const PRLIMIT: &str = "/usr/bin/prlimit";
const SELF_EXE: &str = "/proc/self/exe";
const WORKER_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const _: () = assert!(MAX_MEDIA_BYTES <= MAX_ARTIFACT_BYTES);

pub(super) fn verify_media(path: &Path) -> Result<MediaVerificationReport> {
    let source = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| MediaError::OpenAsset {
        path: path.to_path_buf(),
        source,
    })?;
    let snapshot = snapshot_artifact(source, MAX_MEDIA_BYTES)?;
    let artifact = snapshot.descriptor().clone();
    let extension = safe_extension(path);

    let mut command = Command::new(SELF_EXE);
    command
        .env_clear()
        .process_group(0)
        .arg("__c2pa-launcher")
        .arg("--expected-sha256")
        .arg(&artifact.digest.value)
        .arg("--expected-size")
        .arg(artifact.size.to_string())
        .arg("--extension")
        .arg(&extension)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = command.spawn().map_err(MediaError::WorkerUnavailable)?;
    let captured = wait_bounded(child, snapshot.into_file(), artifact.size)?;
    if !captured.status.success() {
        return Err(MediaError::WorkerFailed(captured.status.to_string()));
    }
    let response: WorkerResponse =
        serde_json::from_slice(&captured.response).map_err(|_| MediaError::InvalidWorkerReport)?;
    normalize_worker_response(artifact, response)
}

pub(super) fn run_launcher(
    expected_sha256: &str,
    expected_size: u64,
    extension: &str,
) -> Result<()> {
    let expected = expected_descriptor(expected_sha256, expected_size)?;
    let asset_destination = sandbox_asset_path(extension)?;
    validate_sandbox_executable(Path::new(BWRAP))?;
    validate_sandbox_executable(Path::new(PRLIMIT))?;

    let stdin = std::io::stdin();
    let snapshot = snapshot_stream(stdin.lock(), MAX_MEDIA_BYTES)?;
    if snapshot.descriptor() != &expected {
        return Err(MediaError::LauncherInputMismatch);
    }
    let executable = File::open(SELF_EXE).map_err(MediaError::CurrentExecutable)?;
    let metadata = executable
        .metadata()
        .map_err(MediaError::CurrentExecutable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(MediaError::CurrentExecutable(std::io::Error::other(
            "the launcher executable is not a regular executable file",
        )));
    }

    let mut command = Command::new(BWRAP);
    command
        .env_clear()
        .stdin(Stdio::from(snapshot.into_file()))
        .stdout(Stdio::from(executable))
        .args([
            "--unshare-all",
            "--unshare-user",
            "--die-with-parent",
            "--new-session",
            "--disable-userns",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--setenv",
            "LANG",
            "C",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/app",
            "--ro-bind-fd",
            "1",
            "/app/a-quo",
            "--dir",
            "/input",
            "--ro-bind-data",
            "0",
        ])
        .arg(&asset_destination)
        .args([
            "--chdir",
            "/",
            "--",
            PRLIMIT,
            "--as=1073741824",
            "--cpu=30",
            "--nofile=64",
            "--nproc=16",
            "--core=0",
            "--",
            "/app/a-quo",
            "__c2pa-worker",
            "--asset",
        ])
        .arg(&asset_destination);

    Err(MediaError::WorkerUnavailable(command.exec()))
}

fn expected_descriptor(sha256: &str, size: u64) -> Result<ArtifactDescriptor> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || size > MAX_MEDIA_BYTES
    {
        return Err(MediaError::InvalidLauncherArgument);
    }
    Ok(ArtifactDescriptor {
        digest: Digest {
            algorithm: "sha256".to_owned(),
            value: sha256.to_owned(),
        },
        size,
    })
}

fn safe_extension(source: &Path) -> String {
    source
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| valid_extension(value))
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "bin".to_owned())
}

fn sandbox_asset_path(extension: &str) -> Result<PathBuf> {
    if !valid_extension(extension) || extension != extension.to_ascii_lowercase() {
        return Err(MediaError::InvalidLauncherArgument);
    }
    Ok(PathBuf::from(format!("/input/asset.{extension}")))
}

fn valid_extension(extension: &str) -> bool {
    !extension.is_empty()
        && extension.len() <= 16
        && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn validate_sandbox_executable(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| MediaError::UnsafeSandboxExecutable(path.to_path_buf()))?;
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || mode & 0o111 == 0
        || mode & 0o022 != 0
        || !matches!(metadata.uid(), 0 | 65_534)
    {
        return Err(MediaError::UnsafeSandboxExecutable(path.to_path_buf()));
    }
    Ok(())
}

struct CapturedOutput {
    status: ExitStatus,
    response: Vec<u8>,
}

struct BoundedBytes {
    bytes: Vec<u8>,
    overflow: bool,
    failed: bool,
}

fn wait_bounded(mut child: Child, input: File, input_size: u64) -> Result<CapturedOutput> {
    let stdin = child.stdin.take().ok_or_else(|| {
        MediaError::WorkerUnavailable(std::io::Error::other("launcher stdin unavailable"))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        MediaError::WorkerUnavailable(std::io::Error::other("worker response unavailable"))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        MediaError::WorkerUnavailable(std::io::Error::other("launcher stderr unavailable"))
    })?;
    let input_thread = thread::spawn(move || write_snapshot(stdin, input, input_size));
    let diagnostics_thread = thread::spawn(move || read_bounded(stdout, MAX_DIAGNOSTIC_BYTES));
    let response_thread = thread::spawn(move || read_bounded(stderr, MAX_RESPONSE_BYTES));
    let deadline = Instant::now() + WORKER_TIMEOUT;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                terminate_worker(&mut child);
                let _ = input_thread.join();
                let _ = diagnostics_thread.join();
                let _ = response_thread.join();
                return Err(MediaError::WorkerTimedOut);
            }
            Err(error) => {
                terminate_worker(&mut child);
                let _ = input_thread.join();
                let _ = diagnostics_thread.join();
                let _ = response_thread.join();
                return Err(MediaError::WorkerUnavailable(error));
            }
        }
    };
    let input_ok = input_thread.join().map_err(|_| MediaError::WorkerInputIo)?;
    let diagnostics = diagnostics_thread
        .join()
        .map_err(|_| MediaError::WorkerOutputIo)?;
    let response = response_thread
        .join()
        .map_err(|_| MediaError::WorkerOutputIo)?;
    if !input_ok {
        return Err(MediaError::WorkerInputIo);
    }
    if diagnostics.failed || response.failed {
        return Err(MediaError::WorkerOutputIo);
    }
    if diagnostics.overflow || response.overflow {
        return Err(MediaError::WorkerOutputTooLarge);
    }
    Ok(CapturedOutput {
        status,
        response: response.bytes,
    })
}

fn write_snapshot(mut destination: impl Write, source: File, size: u64) -> bool {
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while offset < size {
        let remaining = size - offset;
        let requested = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = match source.read_at(&mut buffer[..requested], offset) {
            Ok(0) => return false,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        };
        if destination.write_all(&buffer[..read]).is_err() {
            return false;
        }
        offset += read as u64;
    }
    destination.flush().is_ok()
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> BoundedBytes {
    let mut bytes = Vec::with_capacity(maximum.min(16 * 1024));
    let mut overflow = false;
    let mut failed = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let remaining = maximum.saturating_sub(bytes.len());
                let retained = remaining.min(read);
                bytes.extend_from_slice(&buffer[..retained]);
                overflow |= retained != read;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    BoundedBytes {
        bytes,
        overflow,
        failed,
    }
}

fn terminate_worker(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        if let Some(group) = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_extension_is_bounded_and_inert() {
        assert_eq!(safe_extension(Path::new("Photo.JPEG")), "jpeg");
        assert_eq!(safe_extension(Path::new("photo.jp/g")), "bin");
        assert_eq!(
            safe_extension(Path::new("photo.extension-that-is-too-long")),
            "bin"
        );
        assert!(sandbox_asset_path("../jpg").is_err());
        assert!(sandbox_asset_path("JPG").is_err());
    }

    #[test]
    fn bounded_reader_drains_but_does_not_retain_excess() {
        let output = read_bounded(&b"123456789"[..], 4);
        assert_eq!(output.bytes, b"1234");
        assert!(output.overflow);
        assert!(!output.failed);
    }

    #[test]
    fn launcher_descriptor_is_exact_and_bounded() {
        assert!(expected_descriptor(&"ab".repeat(32), MAX_MEDIA_BYTES).is_ok());
        assert!(expected_descriptor(&"AB".repeat(32), 1).is_err());
        assert!(expected_descriptor(&"ab".repeat(32), MAX_MEDIA_BYTES + 1).is_err());
    }
}
