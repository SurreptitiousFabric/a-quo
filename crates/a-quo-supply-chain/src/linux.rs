use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use a_quo_core::{ArtifactDescriptor, Digest};
use a_quo_ipc::{MAX_ARTIFACT_BYTES, SealedArtifact, snapshot_artifact, snapshot_stream};
use rustix::fs::{Mode, OFlags, open};

use crate::{
    MAX_BUNDLE_BYTES, MAX_FRAME_BYTES, MAX_TRUSTED_ROOT_BYTES, Result, SupplyChainError,
    SupplyChainVerificationReport, WorkerResponse, build_frame, normalize_worker_response,
    valid_sha256, validate_policy,
};

const BWRAP: &str = "/usr/bin/bwrap";
const PRLIMIT: &str = "/usr/bin/prlimit";
const SELF_EXE: &str = "/proc/self/exe";
const WORKER_INPUT: &str = "/input/verification.bin";
const WORKER_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 32 * 1024;

pub(super) fn verify_bundle(
    artifact_path: &Path,
    bundle_path: &Path,
    root_path: &Path,
    expected_identity: &str,
    expected_issuer: &str,
) -> Result<SupplyChainVerificationReport> {
    let artifact_snapshot = snapshot_path(artifact_path, "artifact", MAX_ARTIFACT_BYTES)?;
    let bundle_snapshot = snapshot_path(bundle_path, "bundle", MAX_BUNDLE_BYTES)?;
    let root_snapshot = snapshot_path(root_path, "trusted root", MAX_TRUSTED_ROOT_BYTES)?;

    let artifact = artifact_snapshot.descriptor().clone();
    drop(artifact_snapshot);
    let bundle = bundle_snapshot.descriptor().clone();
    let trusted_root = root_snapshot.descriptor().clone();
    let bundle_bytes = bundle_snapshot.read_bytes_bounded(MAX_BUNDLE_BYTES)?;
    let root_bytes = root_snapshot.read_bytes_bounded(MAX_TRUSTED_ROOT_BYTES)?;
    drop(bundle_snapshot);
    drop(root_snapshot);
    let frame = build_frame(&bundle_bytes, &root_bytes)?;
    let frame_snapshot = snapshot_stream(std::io::Cursor::new(frame), MAX_FRAME_BYTES)?;
    let frame_descriptor = frame_snapshot.descriptor().clone();

    let mut command = Command::new(SELF_EXE);
    command
        .env_clear()
        .process_group(0)
        .arg("__sigstore-launcher")
        .arg("--artifact-sha256")
        .arg(&artifact.digest.value)
        .arg("--artifact-size")
        .arg(artifact.size.to_string())
        .arg("--expected-frame-sha256")
        .arg(&frame_descriptor.digest.value)
        .arg("--expected-frame-size")
        .arg(frame_descriptor.size.to_string())
        .arg("--identity")
        .arg(expected_identity)
        .arg("--issuer")
        .arg(expected_issuer)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = command
        .spawn()
        .map_err(SupplyChainError::WorkerUnavailable)?;
    let captured = wait_bounded(child, frame_snapshot.into_file(), frame_descriptor.size)?;
    if !captured.status.success() {
        return Err(SupplyChainError::WorkerFailed(captured.status.to_string()));
    }
    let response: WorkerResponse = serde_json::from_slice(&captured.response)
        .map_err(|_| SupplyChainError::InvalidWorkerReport)?;
    normalize_worker_response(
        artifact,
        bundle,
        trusted_root,
        expected_identity,
        expected_issuer,
        response,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_launcher(
    artifact_sha256: &str,
    artifact_size: u64,
    expected_frame_sha256: &str,
    expected_frame_size: u64,
    expected_identity: &str,
    expected_issuer: &str,
) -> Result<()> {
    if !valid_sha256(artifact_sha256)
        || artifact_size > MAX_ARTIFACT_BYTES
        || validate_policy(expected_identity, "identity").is_err()
        || validate_policy(expected_issuer, "issuer").is_err()
    {
        return Err(SupplyChainError::InvalidLauncherArgument);
    }
    let expected_frame = expected_descriptor(expected_frame_sha256, expected_frame_size)?;
    validate_sandbox_executable(Path::new(BWRAP))?;
    validate_sandbox_executable(Path::new(PRLIMIT))?;

    let stdin = std::io::stdin();
    let frame = snapshot_stream(stdin.lock(), MAX_FRAME_BYTES)?;
    if frame.descriptor() != &expected_frame {
        return Err(SupplyChainError::LauncherInputMismatch);
    }
    let executable = File::open(SELF_EXE).map_err(SupplyChainError::CurrentExecutable)?;
    let metadata = executable
        .metadata()
        .map_err(SupplyChainError::CurrentExecutable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(SupplyChainError::CurrentExecutable(std::io::Error::other(
            "the launcher executable is not a regular executable file",
        )));
    }

    let mut command = Command::new(BWRAP);
    command
        .env_clear()
        .stdin(Stdio::from(frame.into_file()))
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
            WORKER_INPUT,
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
            "__sigstore-worker",
            "--input",
            WORKER_INPUT,
            "--artifact-sha256",
            artifact_sha256,
            "--artifact-size",
        ])
        .arg(artifact_size.to_string())
        .arg("--identity")
        .arg(expected_identity)
        .arg("--issuer")
        .arg(expected_issuer);

    Err(SupplyChainError::WorkerUnavailable(command.exec()))
}

fn snapshot_path(path: &Path, kind: &'static str, maximum: u64) -> Result<SealedArtifact> {
    let source = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| SupplyChainError::OpenInput {
        kind,
        path: path.to_path_buf(),
        source,
    })?;
    snapshot_artifact(source, maximum).map_err(Into::into)
}

fn expected_descriptor(sha256: &str, size: u64) -> Result<ArtifactDescriptor> {
    if !valid_sha256(sha256) || !(16..=MAX_FRAME_BYTES).contains(&size) {
        return Err(SupplyChainError::InvalidLauncherArgument);
    }
    Ok(ArtifactDescriptor {
        digest: Digest {
            algorithm: "sha256".to_owned(),
            value: sha256.to_owned(),
        },
        size,
    })
}

fn validate_sandbox_executable(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| SupplyChainError::UnsafeSandboxExecutable(path.to_path_buf()))?;
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || mode & 0o111 == 0
        || mode & 0o022 != 0
        || !matches!(metadata.uid(), 0 | 65_534)
    {
        return Err(SupplyChainError::UnsafeSandboxExecutable(
            path.to_path_buf(),
        ));
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
        SupplyChainError::WorkerUnavailable(std::io::Error::other("launcher stdin unavailable"))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        SupplyChainError::WorkerUnavailable(std::io::Error::other("worker response unavailable"))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        SupplyChainError::WorkerUnavailable(std::io::Error::other("launcher stderr unavailable"))
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
                return Err(SupplyChainError::WorkerTimedOut);
            }
            Err(error) => {
                terminate_worker(&mut child);
                let _ = input_thread.join();
                let _ = diagnostics_thread.join();
                let _ = response_thread.join();
                return Err(SupplyChainError::WorkerUnavailable(error));
            }
        }
    };
    let input_ok = input_thread
        .join()
        .map_err(|_| SupplyChainError::WorkerInputIo)?;
    let diagnostics = diagnostics_thread
        .join()
        .map_err(|_| SupplyChainError::WorkerOutputIo)?;
    let response = response_thread
        .join()
        .map_err(|_| SupplyChainError::WorkerOutputIo)?;
    if !input_ok {
        return Err(SupplyChainError::WorkerInputIo);
    }
    if diagnostics.failed || response.failed {
        return Err(SupplyChainError::WorkerOutputIo);
    }
    if diagnostics.overflow || response.overflow {
        return Err(SupplyChainError::WorkerOutputTooLarge);
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
    fn launcher_descriptor_is_exact_and_bounded() {
        assert!(expected_descriptor(&"ab".repeat(32), 16).is_ok());
        assert!(expected_descriptor(&"AB".repeat(32), 16).is_err());
        assert!(expected_descriptor(&"ab".repeat(32), MAX_FRAME_BYTES + 1).is_err());
    }

    #[test]
    fn bounded_reader_drains_but_does_not_retain_excess() {
        let output = read_bounded(&b"123456789"[..], 4);
        assert_eq!(output.bytes, b"1234");
        assert!(output.overflow);
        assert!(!output.failed);
    }
}
