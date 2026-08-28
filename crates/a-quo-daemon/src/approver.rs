use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use a_quo_approval::{
    ApprovalDecision, ApprovalPrompt, MAX_MESSAGE_BYTES, decode_decision, write_prompt,
};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::process::{Pid, Signal, kill_process_group};
use thiserror::Error;

use crate::{ApprovalBackend, ApprovalError};

pub const PACKAGED_APPROVER_PATH: &str = "/usr/lib/a-quo/a-quo-consent";
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(95);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const ALLOWED_ENVIRONMENT: &[&str] = &[
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "LANG",
    "LANGUAGE",
    "LC_ADDRESS",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NAME",
    "LC_NUMERIC",
    "LC_PAPER",
    "LC_TELEPHONE",
    "LC_TIME",
];

#[derive(Debug, Error)]
pub enum ApproverConfigError {
    #[error("trusted approver path must be absolute: {0}")]
    RelativePath(PathBuf),

    #[error("trusted approver path contains an unsafe component: {0}")]
    UnsafeComponent(PathBuf),

    #[error("cannot inspect trusted approver component {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("trusted approver path component is a symbolic link: {0}")]
    SymbolicLink(PathBuf),

    #[error("trusted approver path component is not owned by root: {0}")]
    WrongOwner(PathBuf),

    #[error("trusted approver path component is group- or world-writable: {0}")]
    WritableComponent(PathBuf),

    #[error("trusted approver parent component is not a directory: {0}")]
    NotDirectory(PathBuf),

    #[error("trusted approver is not a regular file: {0}")]
    NotRegularFile(PathBuf),

    #[error("trusted approver is not executable: {0}")]
    NotExecutable(PathBuf),
}

pub struct ProcessApprovalBackend {
    program: PathBuf,
    timeout: Duration,
}

impl ProcessApprovalBackend {
    pub fn packaged() -> Result<Self, ApproverConfigError> {
        let program = PathBuf::from(PACKAGED_APPROVER_PATH);
        validate_packaged_program(&program)?;
        Ok(Self {
            program,
            timeout: APPROVAL_TIMEOUT,
        })
    }

    #[cfg(test)]
    fn for_test(program: PathBuf, timeout: Duration) -> Self {
        Self { program, timeout }
    }

    fn run(&self, prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
        let mut command = Command::new(&self.program);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        copy_allowed_environment(&mut command);
        let mut child = command.spawn().map_err(|_| ApprovalError::Unavailable)?;
        let group = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
        let result = interact(&mut child, prompt, self.timeout);
        if result.is_err() {
            terminate_and_reap(&mut child, group);
        }
        result
    }
}

impl ApprovalBackend for ProcessApprovalBackend {
    fn decide(&mut self, prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
        self.run(prompt)
    }
}

fn interact(
    child: &mut Child,
    prompt: &ApprovalPrompt,
    timeout: Duration,
) -> Result<ApprovalDecision, ApprovalError> {
    let mut input = child.stdin.take().ok_or(ApprovalError::Failed)?;
    write_prompt(&mut input, prompt).map_err(|_| ApprovalError::Failed)?;
    drop(input);

    let mut output = child.stdout.take().ok_or(ApprovalError::Failed)?;
    let flags = fcntl_getfl(&output).map_err(|_| ApprovalError::Failed)?;
    fcntl_setfl(&output, flags | OFlags::NONBLOCK).map_err(|_| ApprovalError::Failed)?;
    let mut response = Vec::new();
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ApprovalError::Failed)?;

    loop {
        let eof = read_available(&mut output, &mut response)?;
        let status = child.try_wait().map_err(|_| ApprovalError::Failed)?;
        if let Some(status) = status {
            let eof = read_available(&mut output, &mut response)? || eof;
            if !status.success() || !eof {
                return Err(ApprovalError::Failed);
            }
            let response = decode_decision(&response).map_err(|_| ApprovalError::Failed)?;
            if response.request_id != prompt.request_id {
                return Err(ApprovalError::Failed);
            }
            return Ok(response.decision);
        }
        if Instant::now() >= deadline {
            return Err(ApprovalError::TimedOut);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn read_available(output: &mut ChildStdout, response: &mut Vec<u8>) -> Result<bool, ApprovalError> {
    let mut chunk = [0_u8; 256];
    loop {
        match output.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(read) => {
                if response.len().saturating_add(read) > MAX_MESSAGE_BYTES {
                    return Err(ApprovalError::Failed);
                }
                response.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err(ApprovalError::Failed),
        }
    }
}

fn terminate_and_reap(child: &mut Child, group: Option<Pid>) {
    if child.try_wait().ok().flatten().is_none() {
        if let Some(group) = group {
            let _ = kill_process_group(group, Signal::KILL);
        } else {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

fn copy_allowed_environment(command: &mut Command) {
    for name in ALLOWED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn validate_packaged_program(path: &Path) -> Result<(), ApproverConfigError> {
    if !path.is_absolute() {
        return Err(ApproverConfigError::RelativePath(path.to_path_buf()));
    }
    let mut current = PathBuf::from(OsStr::new("/"));
    let components = path.components().collect::<Vec<_>>();
    if components.len() == 1 {
        return Err(ApproverConfigError::NotRegularFile(current));
    }
    let root_metadata =
        fs::symlink_metadata(&current).map_err(|source| ApproverConfigError::Inspect {
            path: current.clone(),
            source,
        })?;
    validate_program_component(&current, &root_metadata, false)?;
    let final_index = components.len().saturating_sub(1);
    for (index, component) in components.into_iter().enumerate() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => current.push(part),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ApproverConfigError::UnsafeComponent(path.to_path_buf()));
            }
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|source| ApproverConfigError::Inspect {
                path: current.clone(),
                source,
            })?;
        validate_program_component(&current, &metadata, index == final_index)?;
    }
    Ok(())
}

fn validate_program_component(
    path: &Path,
    metadata: &fs::Metadata,
    is_program: bool,
) -> Result<(), ApproverConfigError> {
    if metadata.file_type().is_symlink() {
        return Err(ApproverConfigError::SymbolicLink(path.to_path_buf()));
    }
    if metadata.uid() != 0 {
        return Err(ApproverConfigError::WrongOwner(path.to_path_buf()));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(ApproverConfigError::WritableComponent(path.to_path_buf()));
    }
    if is_program {
        if !metadata.file_type().is_file() {
            return Err(ApproverConfigError::NotRegularFile(path.to_path_buf()));
        }
        if metadata.mode() & 0o111 == 0 {
            return Err(ApproverConfigError::NotExecutable(path.to_path_buf()));
        }
    } else if !metadata.file_type().is_dir() {
        return Err(ApproverConfigError::NotDirectory(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use a_quo_approval::{ArtifactKind, PeerIdentity, PersonaPurpose};
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn exact_child_decisions_round_trip() {
        for (message_type, expected) in [
            (2, ApprovalDecision::Approve),
            (3, ApprovalDecision::Decline),
            (4, ApprovalDecision::Cancel),
        ] {
            let directory = tempdir().unwrap();
            let helper = directory.path().join("helper");
            write_helper(&helper, &decision_script(message_type));
            let mut backend = ProcessApprovalBackend::for_test(helper, Duration::from_secs(2));
            assert_eq!(decide_after_spawn_retry(&mut backend).unwrap(), expected);
        }
    }

    #[test]
    fn malformed_mismatched_and_timed_out_children_fail_closed() {
        let directory = tempdir().unwrap();

        let malformed = directory.path().join("malformed");
        write_helper(&malformed, "#!/bin/sh\n/usr/bin/printf 'garbage'\n");
        let mut backend = ProcessApprovalBackend::for_test(malformed, Duration::from_secs(2));
        assert_eq!(
            decide_after_spawn_retry(&mut backend),
            Err(ApprovalError::Failed)
        );

        let mismatch = directory.path().join("mismatch");
        write_helper(
            &mismatch,
            "#!/bin/sh\n/usr/bin/printf 'AQUOAPR\\000\\000\\001\\000\\000\\000\\002\\000\\000\\000\\000\\000\\000\\020\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000'\n",
        );
        let mut backend = ProcessApprovalBackend::for_test(mismatch, Duration::from_secs(2));
        assert_eq!(
            decide_after_spawn_retry(&mut backend),
            Err(ApprovalError::Failed)
        );

        let timeout = directory.path().join("timeout");
        write_helper(&timeout, "#!/bin/sh\n/usr/bin/sleep 2\n");
        let mut backend = ProcessApprovalBackend::for_test(timeout, Duration::from_millis(50));
        assert_eq!(
            decide_after_spawn_retry(&mut backend),
            Err(ApprovalError::TimedOut)
        );
    }

    #[test]
    fn packaged_validation_rejects_user_owned_and_symlinked_paths() {
        let directory = tempdir().unwrap();
        let helper = directory.path().join("helper");
        write_helper(&helper, "#!/bin/sh\nexit 0\n");
        assert!(matches!(
            validate_packaged_program(&helper),
            Err(ApproverConfigError::WrongOwner(_))
        ));

        let link = directory.path().join("link");
        symlink(&helper, &link).unwrap();
        let link_metadata = fs::symlink_metadata(&link).unwrap();
        assert!(matches!(
            validate_program_component(&link, &link_metadata, true),
            Err(ApproverConfigError::SymbolicLink(_))
        ));
    }

    #[test]
    fn consent_environment_excludes_buses_and_user_asset_overrides() {
        for forbidden in [
            "DBUS_SESSION_BUS_ADDRESS",
            "DISPLAY",
            "PATH",
            "LD_PRELOAD",
            "XCURSOR_PATH",
            "XCURSOR_SIZE",
            "XCURSOR_THEME",
        ] {
            assert!(!ALLOWED_ENVIRONMENT.contains(&forbidden));
        }
    }

    fn prompt() -> ApprovalPrompt {
        ApprovalPrompt::new(
            Uuid::parse_str("f62e45ae-2a08-411e-b5fb-e3a6c92dd4cf").unwrap(),
            Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap(),
            "A Quo publisher",
            PersonaPurpose::Project,
            "SHA256:9XgBXfKpFQkNWfOqvPq6NKBFe0MPNF34Z2Qv7xw8mXY",
            ArtifactKind::SoftwareRelease,
            "a-quo-0.1.0.tar.zst",
            [0xab; 32],
            1_234_567,
            PeerIdentity {
                pid: 4242,
                uid: 1000,
                gid: 1000,
            },
        )
        .unwrap()
    }

    fn decision_script(message_type: u16) -> String {
        format!(
            "#!/bin/sh\n/usr/bin/printf 'AQUOAPR\\000\\000\\001\\000\\000\\000\\{message_type:03o}\\000\\000\\000\\000\\000\\020'\n/usr/bin/dd bs=1 skip=44 count=16 2>/dev/null\n"
        )
    }

    fn decide_after_spawn_retry(
        backend: &mut ProcessApprovalBackend,
    ) -> Result<ApprovalDecision, ApprovalError> {
        for attempt in 0..3 {
            let result = backend.decide(&prompt());
            if result != Err(ApprovalError::Unavailable) || attempt == 2 {
                return result;
            }
            thread::sleep(Duration::from_millis(25));
        }
        unreachable!("bounded retry loop always returns")
    }

    fn write_helper(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
