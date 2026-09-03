//! Issue #65's fixed, non-executing preparation boundary for the selected
//! AArch64 `gpgv` runtime.
//!
//! This module may execute only the current A Quo verifier in its hidden,
//! fixed probe mode. It never executes an object selected by the runtime lock.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use rustix::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags, Stat, StatVfsMountFlags, StatxAttributes,
    StatxFlags, chmodat, fchmod, fstat, fstatfs, fstatvfs, mkdirat, open, openat, openat2,
    readlinkat, statat, statx, symlinkat, unlinkat,
};
use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, MountFlags, MountPropagationFlags, MoveMountFlags,
    UnmountFlags, fsconfig_create, fsconfig_set_string, fsmount, fsopen, mount_change,
    mount_remount, move_mount, unmount,
};
use rustix::process::{chdir, fchdir, getgid, getuid, pivot_root};
use rustix::system::{sethostname, uname};
use rustix::thread::{
    CapabilitySet, CapabilitySets, UnshareFlags, capabilities, capability_is_in_bounding_set,
    clear_ambient_capability_set, no_new_privs, remove_capability_from_bounding_set,
    set_capabilities, set_no_new_privs,
};

use crate::ExternalLockExpectation;
use crate::MAX_LOCK_BYTES;
use crate::debian::sha256;
use crate::gpgv_runtime::{
    GpgvRuntimeLock, RuntimeMaterialization, RuntimeMaterializationKind,
    load_runtime_materialization, parse_gpgv_runtime_lock, verify_gpgv_runtime,
};
use crate::snapshot::{snapshot_bytes, snapshot_path};

const OPERATION_PREFIX: &str = "a-quo-gpgv-isolation-";
const OPERATION_SUFFIX_MINIMUM: usize = 6;
const OPERATION_SUFFIX_MAXIMUM: usize = 32;
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_OUTPUT_MAXIMUM: u64 = 8 * 1024;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;
const ISOLATED_HOSTNAME: &[u8] = b"a-quo-gpgv-probe";
const PROBE_SUCCESS: &str = concat!(
    "format=a-quo-gpgv-isolation-probe-v1\n",
    "procfs_verified=true\n",
    "numeric_launcher_pid_bound=true\n",
    "runtime_object_count=17\n",
    "runtime_object_bytes_reverified=true\n",
    "symlink_graph_reverified=true\n",
    "host_root_visible=false\n",
    "host_home_visible=false\n",
    "host_gnupg_state_visible=false\n",
    "host_loader_configuration_visible=false\n",
    "host_temporary_directory_visible=false\n",
    "inherited_environment_retained=false\n",
    "isolated_network_egress_available=false\n",
    "private_writable_area_limited_to_selected_locations=true\n",
    "runtime_mount_read_only=true\n",
    "private_work_mount_writable=true\n",
    "no_new_privs_established=true\n",
    "capabilities_dropped=true\n",
);

const CLOSED_ENVIRONMENT: &[(&str, &str)] = &[
    ("HOME", "/work/home"),
    ("GNUPGHOME", "/work/gnupg"),
    ("TMPDIR", "/work/tmp"),
    ("LC_ALL", "C"),
    ("LANG", "C"),
    ("TZ", "UTC0"),
    ("PATH", ""),
];

// The pinned Rustix 1.1.4 safety note for `unshare_unsafe` identifies FILES as
// the flag that can split file-descriptor tables observed by other threads.
// This closed value contains only the four required namespace flags. It is not
// caller-controlled and is used in a dedicated hidden process before A Quo
// creates any application thread.
const FIXED_NAMESPACE_FLAGS: UnshareFlags = UnshareFlags::NEWUSER
    .union(UnshareFlags::NEWNS)
    .union(UnshareFlags::NEWNET)
    .union(UnshareFlags::NEWUTS);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpgvIsolationReport {
    fields: Vec<(&'static str, String)>,
}

impl GpgvIsolationReport {
    pub fn render(&self) -> String {
        let mut keys = BTreeSet::new();
        let mut output = String::new();
        for (key, value) in &self.fields {
            assert!(
                !key.is_empty()
                    && key.bytes().enumerate().all(|(index, byte)| if index == 0 {
                        byte.is_ascii_lowercase()
                    } else {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    }),
                "invalid issue-65 report key"
            );
            assert!(keys.insert(*key), "duplicate issue-65 report key");
            assert!(
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'='),
                "invalid issue-65 report value"
            );
            writeln!(output, "{key}={value}").expect("writing to a String cannot fail");
        }
        output
    }
}

struct PrivateParent {
    descriptor: OwnedFd,
    path: PathBuf,
}

struct OperationRoot {
    parent: PrivateParent,
    name: String,
    device: u64,
    inode: u64,
    cleaned: bool,
}

impl OperationRoot {
    fn create(parent_path: &Path) -> Result<Self> {
        let parent = validate_private_parent(parent_path)?;
        let temporary = tempfile::Builder::new()
            .prefix(OPERATION_PREFIX)
            .tempdir_in(&parent.path)
            .context("cannot create the private issue-65 operation root")?;
        let temporary_path = temporary.keep();
        let name = temporary_path
            .file_name()
            .and_then(OsStr::to_str)
            .context("operation root name is not UTF-8")?
            .to_owned();
        validate_operation_name(&name)?;
        let descriptor = openat2(
            &parent.descriptor,
            &name,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("cannot pin the new operation root")?;
        let mode_descriptor = openat2(
            &parent.descriptor,
            &name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("cannot open the new operation root for mode enforcement")?;
        fchmod(&mode_descriptor, Mode::from_raw_mode(0o700))
            .context("cannot enforce mode 0700 on the new operation root")?;
        let metadata = fstat(&descriptor).context("cannot inspect the new operation root")?;
        ensure_operation_root_metadata(&metadata)?;
        ensure_empty_directory(&parent.descriptor, &name)?;
        Ok(Self {
            parent,
            name,
            device: metadata.st_dev,
            inode: metadata.st_ino,
            cleaned: false,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        let metadata = statat(
            &self.parent.descriptor,
            &self.name,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .context("cannot inspect the operation root before cleanup")?;
        ensure!(
            metadata.st_dev == self.device
                && metadata.st_ino == self.inode
                && FileType::from_raw_mode(metadata.st_mode) == FileType::Directory,
            "operation root was replaced before cleanup"
        );
        unlinkat(&self.parent.descriptor, &self.name, AtFlags::REMOVEDIR)
            .context("cannot remove the empty operation root")?;
        ensure!(
            matches!(
                statat(
                    &self.parent.descriptor,
                    &self.name,
                    AtFlags::SYMLINK_NOFOLLOW
                ),
                Err(rustix::io::Errno::NOENT)
            ),
            "operation-root removal was not confirmed"
        );
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for OperationRoot {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

pub fn prepare_gpgv_isolation(
    runtime_lock_path: &Path,
    expectation: &ExternalLockExpectation,
    profile_path: &Path,
    parent_oci_lock_path: &Path,
    parent_oci_input_directory: &Path,
    private_parent: &Path,
) -> Result<GpgvIsolationReport> {
    reject_unexpected_inherited_descriptors()?;
    let _static_report = verify_gpgv_runtime(
        runtime_lock_path,
        expectation,
        profile_path,
        parent_oci_lock_path,
        parent_oci_input_directory,
    )?;
    let lock_snapshot = snapshot_path(runtime_lock_path, MAX_LOCK_BYTES)?;
    ensure!(
        lock_snapshot.descriptor().digest.value == expectation.sha256,
        "gpgv runtime lock changed after static verification"
    );
    let lock = parse_gpgv_runtime_lock(&snapshot_bytes(&lock_snapshot, MAX_LOCK_BYTES)?)?;
    let mut operation = OperationRoot::create(private_parent)?;
    let probe = run_fixed_probe(
        runtime_lock_path,
        parent_oci_lock_path,
        parent_oci_input_directory,
        &operation,
    );
    finish_preparation(&mut operation, probe)?;
    success_report(expectation, &lock)
}

fn finish_preparation(operation: &mut OperationRoot, probe: Result<()>) -> Result<()> {
    let cleanup = operation.cleanup();
    match (probe, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (probe, cleanup) => {
            let mut evidence = String::new();
            if let Err(error) = probe {
                write_bounded_error(&mut evidence, "probe", &error);
            }
            if let Err(error) = cleanup {
                write_bounded_error(&mut evidence, "cleanup", &error);
            }
            anyhow::bail!("fixed isolation preparation failed: {evidence}");
        }
    }
}

fn write_bounded_error(output: &mut String, label: &str, error: &anyhow::Error) {
    if !output.is_empty() {
        output.push(';');
    }
    let summary = format!("{error:#}");
    let bounded = summary.chars().take(512).collect::<String>();
    let _ = write!(output, "{label}_failure={bounded}");
}

struct ProcfsPin {
    root: OwnedFd,
    pid: OwnedFd,
    pid_text: String,
    mount_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    sha256: String,
}

fn pin_procfs() -> Result<ProcfsPin> {
    let filesystem_root = open(
        "/",
        OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .context("cannot pin the current filesystem root for procfs validation")?;
    let root = openat2(
        &filesystem_root,
        "proc",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot pin /proc without following a substituted path")?;
    ensure!(
        fstatfs(&root)
            .context("cannot inspect the pinned procfs root")?
            .f_type as u64
            == PROC_SUPER_MAGIC,
        "the pinned /proc root is not procfs"
    );
    let root_stat = statx(
        &root,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .context("cannot obtain the pinned procfs mount identity")?;
    ensure!(
        root_stat
            .stx_attributes
            .contains(StatxAttributes::MOUNT_ROOT)
            && (root_stat.stx_mask & StatxFlags::MNT_ID.bits()) != 0,
        "the pinned procfs root is not a confirmed mount root"
    );
    let pid_text = readlinkat(&root, "self", Vec::new())
        .context("cannot inspect procfs self identity")?
        .into_bytes();
    let pid_text = std::str::from_utf8(&pid_text)
        .context("procfs self identity is not UTF-8")?
        .to_owned();
    ensure!(
        !pid_text.is_empty() && pid_text.bytes().all(|byte| byte.is_ascii_digit()),
        "procfs self identity is not a numeric PID"
    );
    let pid = openat2(
        &root,
        &pid_text,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot bind the numeric launcher PID to procfs")?;
    ensure!(
        fstatfs(&pid)
            .context("cannot inspect the numeric procfs PID directory")?
            .f_type as u64
            == PROC_SUPER_MAGIC,
        "the numeric launcher PID is not on the pinned procfs mount"
    );
    let pid_stat = statx(
        &pid,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .context("cannot inspect the numeric procfs PID mount identity")?;
    ensure!(
        pid_stat.stx_mnt_id == root_stat.stx_mnt_id,
        "the numeric launcher PID is on a different procfs mount"
    );
    Ok(ProcfsPin {
        root,
        pid,
        pid_text,
        mount_id: root_stat.stx_mnt_id,
    })
}

fn pin_proc_link(procfs: &ProcfsPin, name: &str) -> Result<OwnedFd> {
    let link = openat2(
        &procfs.pid,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
    )
    .with_context(|| format!("cannot pin procfs link {name}"))?;
    let metadata = fstat(&link).context("cannot inspect a pinned procfs link")?;
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Symlink,
        "procfs {name} is not a magic-link object"
    );
    ensure!(
        fstatfs(&link)
            .context("cannot inspect procfs link filesystem")?
            .f_type as u64
            == PROC_SUPER_MAGIC,
        "procfs {name} is not backed by the pinned procfs filesystem"
    );
    let link_stat = statx(
        &link,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .context("cannot inspect procfs link mount identity")?;
    ensure!(
        link_stat.stx_mnt_id == procfs.mount_id,
        "procfs {name} is not on the pinned procfs mount"
    );
    Ok(link)
}

fn inspect_current_executable(procfs: &ProcfsPin) -> Result<ExecutableIdentity> {
    let _exe_link = pin_proc_link(procfs, "exe")?;
    let executable = openat2(
        &procfs.pid,
        "exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::empty(),
    )
    .context("cannot open the pinned current A Quo executable")?;
    let metadata = fstat(&executable).context("cannot inspect the current A Quo executable")?;
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile,
        "the current A Quo executable is not a regular file"
    );
    ensure!(
        metadata.st_mode & 0o111 != 0,
        "the current A Quo executable is not executable"
    );
    let mut bytes = Vec::new();
    File::from(executable)
        .take(CHILD_OUTPUT_MAXIMUM * 1024)
        .read_to_end(&mut bytes)
        .context("cannot hash the current A Quo executable")?;
    ensure!(
        bytes.len() as u64 <= CHILD_OUTPUT_MAXIMUM * 1024,
        "current A Quo executable is oversized"
    );
    Ok(ExecutableIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        size: metadata.st_size as u64,
        mode: metadata.st_mode,
        sha256: sha256(&bytes),
    })
}

fn reject_unexpected_inherited_descriptors() -> Result<()> {
    // The fixed probe has no descriptor hand-off protocol: every descriptor
    // above stderr is rejected before spawn and therefore cannot survive into
    // the child. The three temporary procfs descriptors used for this audit
    // are CLOEXEC and are dropped when this function returns.
    let procfs = pin_procfs()?;
    let fd_dir = openat2(
        &procfs.pid,
        "fd",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_XDEV
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot enumerate inherited descriptors from pinned procfs")?;
    let mut directory = Dir::new(fd_dir).context("cannot open the pinned descriptor directory")?;
    let directory_fd = directory
        .fd()
        .context("cannot inspect the pinned descriptor directory FD")?
        .as_raw_fd();
    let allowed = [
        procfs.root.as_raw_fd(),
        procfs.pid.as_raw_fd(),
        directory_fd,
        0,
        1,
        2,
    ];
    let mut unexpected = Vec::new();
    for entry in &mut directory {
        let entry = entry.context("cannot enumerate inherited descriptors")?;
        let name = entry.file_name().to_bytes();
        let Ok(fd) = std::str::from_utf8(name).unwrap_or_default().parse::<i32>() else {
            continue;
        };
        if fd > 2 && !allowed.contains(&fd) {
            unexpected.push(fd);
            if unexpected.len() == 16 {
                break;
            }
        }
    }
    ensure!(
        unexpected.is_empty(),
        "unintended inherited descriptors rejected before probe spawn: {unexpected:?}"
    );
    Ok(())
}

fn run_fixed_probe(
    runtime_lock_path: &Path,
    parent_oci_lock_path: &Path,
    parent_oci_input_directory: &Path,
    operation: &OperationRoot,
) -> Result<()> {
    let procfs = pin_procfs()?;
    let identity = inspect_current_executable(&procfs)?;
    let executable_path = format!("/proc/{}/exe", procfs.pid_text);
    let identity_again = inspect_current_executable(&procfs)?;
    ensure!(
        identity == identity_again,
        "current A Quo executable identity changed before spawn"
    );
    // The path is derived only from a descriptor-pinned, genuine procfs mount
    // and its numeric PID entry. The owner-defined threat boundary excludes
    // concurrent authority capable of replacing that mount, the executable,
    // or this process between the identity checks and spawn.
    let mut child = Command::new(executable_path);
    child
        .arg("internal-gpgv-isolation-probe")
        .arg("--lock")
        .arg(runtime_lock_path)
        .arg("--parent-oci-lock")
        .arg(parent_oci_lock_path)
        .arg("--parent-oci-input-directory")
        .arg(parent_oci_input_directory)
        .arg("--private-parent")
        .arg(&operation.parent.path)
        .arg("--operation-name")
        .arg(&operation.name)
        .arg("--expected-device")
        .arg(operation.device.to_string())
        .arg("--expected-inode")
        .arg(operation.inode.to_string())
        .env_clear()
        .envs(CLOSED_ENVIRONMENT.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_probe_child(&mut child)
}

fn run_probe_child(command: &mut Command) -> Result<()> {
    let mut child = command
        .spawn()
        .context("cannot start the fixed A Quo isolation probe")?;
    drop(child.stdin.take());
    let stdout = child
        .stdout
        .take()
        .context("isolation probe stdout is absent")?;
    let stderr = child
        .stderr
        .take()
        .context("isolation probe stderr is absent")?;
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    let stdout_thread = spawn_pipe_drainer(stdout, Arc::clone(&stdout_overflow));
    let stderr_thread = spawn_pipe_drainer(stderr, Arc::clone(&stderr_overflow));
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        if stdout_overflow.load(Ordering::Acquire) || stderr_overflow.load(Ordering::Acquire) {
            let _ = child.kill();
            break child
                .wait()
                .context("cannot reap the overflowing isolation probe")?;
        }
        if let Some(status) = child
            .try_wait()
            .context("cannot inspect the fixed isolation probe")?
        {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break child
                .wait()
                .context("cannot reap the timed-out isolation probe")?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| anyhow::anyhow!("stdout drainer panicked"))??;
    let _stderr = stderr_thread
        .join()
        .map_err(|_| anyhow::anyhow!("stderr drainer panicked"))??;
    if timed_out {
        anyhow::bail!("fixed isolation probe timed out");
    }
    let stdout_overflowed = stdout_overflow.load(Ordering::Acquire);
    let stderr_overflowed = stderr_overflow.load(Ordering::Acquire);
    ensure!(
        !stdout_overflowed && !stderr_overflowed,
        "fixed isolation probe output exceeds its byte bound (stdout_overflow={stdout_overflowed}, stderr_overflow={stderr_overflowed})"
    );
    ensure!(status.success(), "fixed isolation probe failed");
    ensure!(
        stdout == PROBE_SUCCESS.as_bytes(),
        "fixed isolation probe output is incomplete"
    );
    Ok(())
}

fn spawn_pipe_drainer(
    mut pipe: impl Read + Send + 'static,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>>> {
    thread::spawn(move || drain_pipe(&mut pipe, overflow))
}

fn drain_pipe(pipe: &mut impl Read, overflow: Arc<AtomicBool>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = pipe
            .read(&mut buffer)
            .context("cannot read fixed isolation probe output")?;
        if read == 0 {
            break;
        }
        let remaining = CHILD_OUTPUT_MAXIMUM.saturating_sub(bytes.len() as u64) as usize;
        if read <= remaining {
            bytes.extend_from_slice(&buffer[..read]);
        } else {
            bytes.extend_from_slice(&buffer[..remaining]);
            overflow.store(true, Ordering::Release);
        }
    }
    Ok(bytes)
}

#[doc(hidden)]
pub fn run_internal_probe(
    runtime_lock_path: &Path,
    parent_oci_lock_path: &Path,
    parent_oci_input_directory: &Path,
    private_parent_path: &Path,
    operation_name: &str,
    expected_device: u64,
    expected_inode: u64,
) -> Result<&'static str> {
    reject_unexpected_inherited_descriptors()?;
    validate_closed_environment()?;
    validate_operation_name(operation_name)?;
    let parent = validate_private_parent(private_parent_path)?;
    let operation_descriptor = openat2(
        &parent.descriptor,
        operation_name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot pin the requested operation root")?;
    let operation_metadata =
        fstat(&operation_descriptor).context("cannot inspect operation root")?;
    ensure_operation_root_metadata(&operation_metadata)?;
    ensure_empty_directory(&parent.descriptor, operation_name)?;
    ensure!(
        operation_metadata.st_dev == expected_device && operation_metadata.st_ino == expected_inode,
        "operation root identity differs from the parent process"
    );
    let procfs = pin_procfs()?;
    let namespaces_before = namespace_identities(&procfs)?;
    let invoking_uid = getuid().as_raw();
    let invoking_gid = getgid().as_raw();
    enter_fixed_namespaces()?;
    write_identity_maps(invoking_uid, invoking_gid, &procfs)?;
    ensure!(
        getuid().as_raw() == 0 && getgid().as_raw() == 0,
        "isolated identity mapping did not produce namespace uid/gid zero"
    );
    let namespaces_after = namespace_identities(&procfs)?;
    for (name, identity) in &namespaces_before {
        ensure!(
            namespaces_after.get(name) != Some(identity),
            "required {name} namespace was not replaced"
        );
    }
    drop(procfs);
    drop(operation_descriptor);
    drop(parent);
    let parent = validate_private_parent(private_parent_path)?;
    let operation_descriptor = openat2(
        &parent.descriptor,
        operation_name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot repin the operation root inside the new mount namespace")?;
    let repinned =
        fstat(&operation_descriptor).context("cannot inspect the repinned operation root")?;
    ensure!(
        repinned.st_dev == expected_device && repinned.st_ino == expected_inode,
        "operation root changed while namespaces were created"
    );
    sethostname(ISOLATED_HOSTNAME).context("cannot set the private UTS hostname")?;
    ensure!(
        uname().nodename().to_bytes() == ISOLATED_HOSTNAME,
        "private UTS hostname differs from policy"
    );
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .context("cannot make mount propagation private")?;
    attach_private_tmpfs(
        &operation_descriptor,
        [("mode", "0700"), ("size", "16777216"), ("nr_inodes", "128")],
    )
    .context("cannot attach the private tmpfs to the pinned operation root")?;
    let mounted_root = openat2(
        &parent.descriptor,
        operation_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot pin the mounted private runtime root")?;
    verify_mount_flags(&mounted_root)?;
    let (_, _, objects) = load_runtime_materialization(
        runtime_lock_path,
        parent_oci_lock_path,
        parent_oci_input_directory,
    )?;
    ensure!(
        objects.len() == 17,
        "runtime selection is not exactly 17 objects"
    );
    materialize_objects(&mounted_root, &objects)?;
    create_work_mount(&mounted_root)?;
    verify_materialized_objects(&mounted_root, &objects)?;
    mkdirat(&mounted_root, ".old-root", Mode::from_raw_mode(0o700))
        .context("cannot create the private old-root mountpoint")?;
    drop(parent);
    drop(operation_descriptor);
    fchdir(&mounted_root).context("cannot enter the pinned private runtime root")?;
    pivot_root(".", ".old-root").context("cannot close the probe root with pivot_root")?;
    chdir("/").context("cannot enter the closed probe root")?;
    unmount("/.old-root", UnmountFlags::DETACH).context("cannot detach the old host root")?;
    std::fs::remove_dir("/.old-root").context("cannot remove the detached old-root mountpoint")?;
    fchmod(&mounted_root, Mode::from_raw_mode(0o555)).context("cannot lock the isolated root")?;
    mount_remount(
        "/",
        MountFlags::RDONLY | MountFlags::NODEV | MountFlags::NOSUID | MountFlags::NOEXEC,
        "",
    )
    .context("cannot make the selected runtime mount read-only")?;
    verify_materialized_objects(&mounted_root, &objects)?;
    verify_closed_root()?;
    set_no_new_privs(true).context("cannot establish no_new_privs")?;
    drop_all_capabilities()?;
    ensure!(
        no_new_privs().context("cannot read no_new_privs")?,
        "no_new_privs is false"
    );
    verify_no_capabilities()?;
    ensure_no_external_route()?;
    verify_selected_writable_locations()?;
    Ok(PROBE_SUCCESS)
}

#[allow(deprecated)]
fn enter_fixed_namespaces() -> Result<()> {
    // Rustix 1.1.4 deprecates this safe wrapper because FILES can split a file
    // descriptor table shared with another thread. FILES is absent from the
    // compile-time constant, callers cannot provide flags, and this is the
    // first isolation operation in the dedicated single-threaded probe.
    rustix::thread::unshare(FIXED_NAMESPACE_FLAGS)
        .context("cannot create the fixed user/mount/network/UTS namespace set")
}

fn namespace_identities(procfs: &ProcfsPin) -> Result<BTreeMap<&'static str, (u64, u64)>> {
    let mut identities = BTreeMap::new();
    for name in ["user", "mnt", "net", "uts"] {
        let path = format!("ns/{name}");
        let link = openat2(
            &procfs.pid,
            &path,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
        )
        .with_context(|| format!("cannot pin the {name} namespace procfs link"))?;
        let link_metadata = fstat(&link).context("cannot inspect a namespace procfs link")?;
        ensure!(
            FileType::from_raw_mode(link_metadata.st_mode) == FileType::Symlink,
            "procfs namespace entry is not a magic-link object"
        );
        ensure!(
            fstatfs(&link)
                .context("cannot inspect namespace procfs link filesystem")?
                .f_type as u64
                == PROC_SUPER_MAGIC,
            "namespace entry is not backed by the pinned procfs filesystem"
        );
        let link_stat = statx(
            &link,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
        )
        .context("cannot inspect namespace procfs link mount identity")?;
        ensure!(
            link_stat.stx_mnt_id == procfs.mount_id,
            "namespace entry is not on the pinned procfs mount"
        );
        let descriptor = openat2(
            &procfs.pid,
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::empty(),
        )
        .with_context(|| format!("cannot open the {name} namespace identity"))?;
        let metadata = fstat(&descriptor).context("cannot inspect a namespace identity")?;
        identities.insert(
            match name {
                "mnt" => "mount",
                other => other,
            },
            (metadata.st_dev, metadata.st_ino),
        );
    }
    Ok(identities)
}

fn write_identity_maps(uid: u32, gid: u32, procfs: &ProcfsPin) -> Result<()> {
    for (name, contents) in [
        ("setgroups", "deny\n".to_owned()),
        ("uid_map", format!("0 {uid} 1\n")),
        ("gid_map", format!("0 {gid} 1\n")),
    ] {
        let descriptor = openat2(
            &procfs.pid,
            name,
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_XDEV
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS,
        )
        .with_context(|| format!("cannot open procfs {name}"))?;
        File::from(descriptor)
            .write_all(contents.as_bytes())
            .with_context(|| format!("cannot write procfs {name}"))?;
    }
    Ok(())
}

fn verify_mount_flags(root: &OwnedFd) -> Result<()> {
    ensure!(
        fstatfs(root)
            .context("cannot inspect private-root filesystem type")?
            .f_type as u64
            == TMPFS_MAGIC,
        "private runtime filesystem is not tmpfs"
    );
    let flags = fstatvfs(root)
        .context("cannot inspect private-root mount flags")?
        .f_flag;
    for required in [
        StatVfsMountFlags::NODEV,
        StatVfsMountFlags::NOSUID,
        StatVfsMountFlags::NOEXEC,
    ] {
        ensure!(
            flags.contains(required),
            "private runtime root lacks a required mount flag"
        );
    }
    Ok(())
}

fn attach_private_tmpfs<const N: usize>(
    target: &OwnedFd,
    options: [(&str, &str); N],
) -> Result<()> {
    let filesystem = fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC)
        .context("cannot create a private tmpfs context")?;
    for (key, value) in options {
        fsconfig_set_string(&filesystem, key, value)
            .with_context(|| format!("cannot set the fixed tmpfs {key} option"))?;
    }
    fsconfig_create(&filesystem).context("cannot create the configured private tmpfs")?;
    let detached_mount = fsmount(
        &filesystem,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )
    .context("cannot instantiate the private non-executable tmpfs")?;
    move_mount(
        &detached_mount,
        "",
        target,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .context("cannot attach the private tmpfs to its pinned target")
}

fn materialize_objects(root: &OwnedFd, objects: &[RuntimeMaterialization]) -> Result<()> {
    let mut paths = BTreeSet::new();
    for object in objects {
        ensure!(
            paths.insert(object.path.as_str()),
            "runtime materialization repeats a path"
        );
        let (parent, name) = open_parent(root, &object.path, true)?;
        match object.kind {
            RuntimeMaterializationKind::Regular => {
                ensure!(
                    object.bytes.len() as u64 == object.size,
                    "runtime payload size changed"
                );
                ensure!(
                    sha256(&object.bytes) == object.sha256,
                    "runtime payload digest changed"
                );
                let descriptor = openat(
                    &parent,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::CLOEXEC
                        | OFlags::NOFOLLOW,
                    Mode::from_raw_mode(object.mode),
                )
                .context("cannot exclusively create a runtime regular file")?;
                let mut file = File::from(descriptor);
                file.write_all(&object.bytes)
                    .context("cannot write a runtime regular file")?;
                file.sync_all()
                    .context("cannot sync a runtime regular file")?;
                fchmod(&file, Mode::from_raw_mode(object.mode))
                    .context("cannot set the exact runtime regular-file mode")?;
            }
            RuntimeMaterializationKind::Symlink => {
                ensure!(
                    object.bytes.len() as u64 == object.size
                        && sha256(&object.bytes) == object.sha256,
                    "runtime symlink payload identity changed"
                );
                let target = std::str::from_utf8(&object.bytes)
                    .context("locked runtime symlink text is not UTF-8")?;
                symlinkat(target, &parent, name).context("cannot create a runtime symlink")?;
            }
        }
    }
    lock_runtime_directories(root, objects)?;
    Ok(())
}

fn open_parent<'a>(root: &OwnedFd, path: &'a str, create: bool) -> Result<(OwnedFd, &'a str)> {
    let path = Path::new(path);
    ensure!(path.is_relative(), "runtime path is not relative");
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("runtime path lacks a UTF-8 filename")?;
    let mut current = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .context("cannot duplicate the private-root descriptor")?;
    if let Some(parent) = path.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                anyhow::bail!("runtime path contains a forbidden component");
            };
            if create {
                match mkdirat(&current, component, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => {
                        return Err(error).context("cannot create a runtime parent directory");
                    }
                }
            }
            current = openat2(
                &current,
                component,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            )
            .context("cannot traverse a runtime parent directory")?;
        }
    }
    Ok((current, name))
}

fn lock_runtime_directories(root: &OwnedFd, objects: &[RuntimeMaterialization]) -> Result<()> {
    let mut directories = BTreeSet::new();
    for object in objects {
        let mut parent = Path::new(&object.path).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        chmodat(
            root,
            &directory,
            Mode::from_raw_mode(0o555),
            AtFlags::empty(),
        )
        .context("cannot make a runtime directory read-only")?;
    }
    Ok(())
}

fn create_work_mount(root: &OwnedFd) -> Result<()> {
    mkdirat(root, "work", Mode::from_raw_mode(0o755)).context("cannot create /work")?;
    let work_target = openat2(
        root,
        "work",
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .context("cannot pin the private /work mountpoint")?;
    attach_private_tmpfs(
        &work_target,
        [("mode", "0755"), ("size", "1048576"), ("nr_inodes", "16")],
    )
    .context("cannot attach the private writable /work filesystem")?;
    let work = openat2(
        root,
        "work",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot pin the mounted private /work filesystem")?;
    verify_mount_flags(&work)?;
    for name in ["home", "gnupg", "tmp"] {
        mkdirat(&work, name, Mode::from_raw_mode(0o700))
            .with_context(|| format!("cannot create /work/{name}"))?;
    }
    fchmod(&work, Mode::from_raw_mode(0o555)).context("cannot lock /work")?;
    Ok(())
}

fn verify_materialized_objects(root: &OwnedFd, objects: &[RuntimeMaterialization]) -> Result<()> {
    verify_materialized_inventory(root, objects)?;
    for object in objects {
        let (parent, name) = open_parent(root, &object.path, false)?;
        let metadata = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .context("cannot inspect a materialized runtime object")?;
        ensure!(
            metadata.st_mode & 0o7777 == object.mode,
            "materialized runtime object mode changed"
        );
        match object.kind {
            RuntimeMaterializationKind::Regular => {
                ensure!(
                    FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
                        && metadata.st_nlink == 1
                        && metadata.st_size >= 0
                        && metadata.st_size as u64 == object.size,
                    "materialized runtime regular-file identity changed"
                );
                let descriptor = openat2(
                    &parent,
                    name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
                )
                .context("cannot open a materialized runtime regular file")?;
                let mut bytes = Vec::with_capacity(object.size as usize);
                File::from(descriptor)
                    .take(object.size + 1)
                    .read_to_end(&mut bytes)
                    .context("cannot re-read a materialized runtime regular file")?;
                ensure!(
                    bytes.len() as u64 == object.size && sha256(&bytes) == object.sha256,
                    "materialized runtime regular-file bytes changed"
                );
            }
            RuntimeMaterializationKind::Symlink => {
                ensure!(
                    FileType::from_raw_mode(metadata.st_mode) == FileType::Symlink,
                    "materialized runtime symlink type changed"
                );
                let target = readlinkat(&parent, name, Vec::new())
                    .context("cannot re-read a materialized runtime symlink")?;
                ensure!(
                    target.to_bytes() == object.bytes
                        && target.to_bytes().len() as u64 == object.size
                        && sha256(target.to_bytes()) == object.sha256,
                    "materialized runtime symlink target changed"
                );
            }
        }
    }
    Ok(())
}

fn verify_materialized_inventory(root: &OwnedFd, objects: &[RuntimeMaterialization]) -> Result<()> {
    let expected_objects = objects
        .iter()
        .map(|object| object.path.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        expected_objects.len() == objects.len(),
        "runtime inventory repeats an object path"
    );
    let mut expected_directories = BTreeSet::from([
        "work".to_owned(),
        "work/home".to_owned(),
        "work/gnupg".to_owned(),
        "work/tmp".to_owned(),
    ]);
    for object in objects {
        let mut parent = Path::new(&object.path).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            expected_directories.insert(path.to_string_lossy().into_owned());
            parent = path.parent();
        }
    }
    let mut observed_objects = BTreeSet::new();
    let mut observed_directories = BTreeSet::new();
    walk_materialized_inventory(
        root,
        "",
        &expected_objects,
        &expected_directories,
        &mut observed_objects,
        &mut observed_directories,
        0,
    )?;
    ensure!(
        observed_objects == expected_objects && observed_directories == expected_directories,
        "materialized runtime tree differs from the closed inventory"
    );
    Ok(())
}

fn walk_materialized_inventory(
    directory: &OwnedFd,
    prefix: &str,
    expected_objects: &BTreeSet<String>,
    expected_directories: &BTreeSet<String>,
    observed_objects: &mut BTreeSet<String>,
    observed_directories: &mut BTreeSet<String>,
    depth: usize,
) -> Result<()> {
    ensure!(
        depth <= 8,
        "materialized runtime tree exceeds its depth bound"
    );
    let readable = openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .context("cannot enumerate a materialized runtime directory")?;
    let mut count = 0_usize;
    for entry in Dir::new(readable).context("cannot create runtime-tree iterator")? {
        let entry = entry.context("cannot enumerate the materialized runtime tree")?;
        let raw_name = entry.file_name().to_bytes();
        if matches!(raw_name, b"." | b"..") {
            continue;
        }
        count += 1;
        ensure!(
            count <= 64,
            "materialized directory exceeds its entry bound"
        );
        let name = std::str::from_utf8(raw_name).context("runtime-tree name is not UTF-8")?;
        ensure!(
            !name.is_empty() && name.len() <= 128 && !name.contains('/'),
            "runtime-tree name is outside its closed bound"
        );
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let metadata = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .context("cannot inspect a runtime-tree entry")?;
        match FileType::from_raw_mode(metadata.st_mode) {
            FileType::Directory => {
                ensure!(
                    expected_directories.contains(&path)
                        && observed_directories.insert(path.clone()),
                    "materialized tree contains an unexpected or duplicated directory"
                );
                let expected_mode = if path.starts_with("work/") {
                    0o700
                } else {
                    0o555
                };
                ensure!(
                    metadata.st_mode & 0o7777 == expected_mode,
                    "materialized directory has the wrong mode"
                );
                let child = openat2(
                    directory,
                    name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .context("cannot traverse a materialized runtime directory")?;
                walk_materialized_inventory(
                    &child,
                    &path,
                    expected_objects,
                    expected_directories,
                    observed_objects,
                    observed_directories,
                    depth + 1,
                )?;
            }
            FileType::RegularFile | FileType::Symlink => ensure!(
                expected_objects.contains(&path) && observed_objects.insert(path),
                "materialized tree contains an unexpected or duplicated object"
            ),
            _ => anyhow::bail!("materialized tree contains a forbidden object type"),
        }
    }
    Ok(())
}

fn validate_private_parent(path: &Path) -> Result<PrivateParent> {
    ensure!(path.is_absolute(), "private parent is not absolute");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "private parent has a forbidden path component"
    );
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("input-lock crate is inside the repository");
    let home = std::env::var_os("HOME").map(PathBuf::from);
    ensure!(
        ![
            Path::new("/"),
            Path::new("/tmp"),
            Path::new("/var/tmp"),
            Path::new("/dev/shm"),
            repository_root
        ]
        .contains(&path)
            && home.as_deref() != Some(path),
        "private parent is a broad or protected location"
    );
    let root = open(
        "/",
        OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .context("cannot pin filesystem root for private-parent resolution")?;
    let relative = path.strip_prefix("/").expect("absolute path checked");
    let descriptor = openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot open private parent without following path components")?;
    let metadata = fstat(&descriptor).context("cannot inspect private parent")?;
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
            && metadata.st_uid == getuid().as_raw()
            && metadata.st_mode & 0o022 == 0,
        "private parent has unsafe type, ownership, or permissions"
    );
    Ok(PrivateParent {
        descriptor,
        path: path.to_path_buf(),
    })
}

fn validate_operation_name(name: &str) -> Result<()> {
    let suffix = name
        .strip_prefix(OPERATION_PREFIX)
        .context("operation root lacks the fixed prefix")?;
    ensure!(
        (OPERATION_SUFFIX_MINIMUM..=OPERATION_SUFFIX_MAXIMUM).contains(&suffix.len())
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "operation root has an invalid unpredictable suffix"
    );
    Ok(())
}

fn ensure_operation_root_metadata(metadata: &Stat) -> Result<()> {
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
            && metadata.st_uid == getuid().as_raw()
            && metadata.st_mode & 0o7777 == 0o700,
        "operation root has unsafe type, ownership, or mode"
    );
    Ok(())
}

fn ensure_empty_directory(parent: &OwnedFd, name: &str) -> Result<()> {
    let readable = openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .context("cannot enumerate the operation root")?;
    for entry in Dir::new(readable).context("cannot create operation-root iterator")? {
        let entry = entry.context("cannot enumerate the operation root")?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            anyhow::bail!("operation root is not empty");
        }
    }
    Ok(())
}

fn validate_closed_environment() -> Result<()> {
    let expected = CLOSED_ENVIRONMENT
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let observed = std::env::vars().collect::<BTreeMap<_, _>>();
    ensure!(
        observed == expected,
        "fixed probe environment is not closed"
    );
    Ok(())
}

fn verify_closed_root() -> Result<()> {
    for forbidden in [
        "/etc",
        "/home",
        "/root",
        "/tmp",
        "/var",
        "/run",
        "/proc",
        "/etc/ld.so.cache",
        "/root/.gnupg",
    ] {
        ensure!(
            !Path::new(forbidden).exists(),
            "isolated root exposes a forbidden host path"
        );
    }
    ensure!(
        Path::new("/usr/bin/gpgv").is_file(),
        "selected runtime layout is incomplete"
    );
    let root = open(
        "/",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )?;
    verify_mount_flags(&root)?;
    ensure!(
        fstatvfs(&root)
            .context("cannot inspect the isolated root read-only state")?
            .f_flag
            .contains(StatVfsMountFlags::RDONLY),
        "isolated runtime root is not read-only"
    );
    Ok(())
}

fn drop_all_capabilities() -> Result<()> {
    clear_ambient_capability_set().context("cannot clear ambient capabilities")?;
    for bit in 0..64 {
        let capability = CapabilitySet::from_bits_retain(1_u64 << bit);
        match capability_is_in_bounding_set(capability) {
            Ok(true) => remove_capability_from_bounding_set(capability)
                .context("cannot drop a capability from the bounding set")?,
            Ok(false) => {}
            Err(rustix::io::Errno::INVAL) => break,
            Err(error) => return Err(error).context("cannot inspect the capability bounding set"),
        }
    }
    set_capabilities(
        None,
        CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        },
    )
    .context("cannot clear effective, permitted, and inheritable capabilities")?;
    Ok(())
}

fn verify_no_capabilities() -> Result<()> {
    let sets = capabilities(None).context("cannot inspect final capability sets")?;
    ensure!(
        sets.effective.is_empty() && sets.permitted.is_empty() && sets.inheritable.is_empty(),
        "a process capability remained after the drop"
    );
    for bit in 0..64 {
        let capability = CapabilitySet::from_bits_retain(1_u64 << bit);
        match capability_is_in_bounding_set(capability) {
            Ok(false) => {}
            Ok(true) => anyhow::bail!("a bounding-set capability remained after the drop"),
            Err(rustix::io::Errno::INVAL) => break,
            Err(error) => return Err(error).context("cannot verify the final bounding set"),
        }
    }
    Ok(())
}

fn ensure_no_external_route() -> Result<()> {
    let documentation_only = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9);
    let error = TcpStream::connect_timeout(&documentation_only.into(), Duration::from_millis(100))
        .expect_err("private network namespace unexpectedly has an external route");
    ensure!(
        matches!(
            error.kind(),
            std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable
        ),
        "private network probe did not fail locally as unreachable"
    );
    Ok(())
}

fn verify_selected_writable_locations() -> Result<()> {
    for path in ["/work/home", "/work/gnupg", "/work/tmp"] {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("cannot inspect selected writable path {path}"))?;
        ensure!(
            metadata.is_dir(),
            "selected writable path is not a directory"
        );
    }
    for path in ["/", "/work", "/usr", "/usr/bin", "/usr/lib"] {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("cannot inspect read-only path {path}"))?;
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o222 == 0,
            "a non-work path remains writable"
        );
    }
    let work = open(
        "/work",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .context("cannot pin the private writable filesystem")?;
    let work_flags = fstatvfs(&work)
        .context("cannot inspect private writable filesystem flags")?
        .f_flag;
    ensure!(
        !work_flags.contains(StatVfsMountFlags::RDONLY)
            && work_flags.contains(StatVfsMountFlags::NODEV)
            && work_flags.contains(StatVfsMountFlags::NOSUID)
            && work_flags.contains(StatVfsMountFlags::NOEXEC),
        "private writable filesystem has the wrong mount policy"
    );
    Ok(())
}

fn success_report(
    expectation: &ExternalLockExpectation,
    lock: &GpgvRuntimeLock,
) -> Result<GpgvIsolationReport> {
    let text = |value: &str| value.to_owned();
    let boolean = |value: bool| value.to_string();
    Ok(GpgvIsolationReport {
        fields: vec![
            (
                "verification_status",
                text("prepared-exact-gpgv-runtime-isolation-without-execution"),
            ),
            (
                "evidence_kind",
                text("exact-local-retained-runtime-isolation-preparation"),
            ),
            ("runtime_lock_repository", expectation.repository.clone()),
            ("runtime_lock_commit", expectation.commit.clone()),
            ("runtime_lock_path", expectation.path.clone()),
            ("runtime_lock_sha256", expectation.sha256.clone()),
            ("runtime_lock_git_object_authenticated", boolean(false)),
            (
                "parent_oci_lock_sha256",
                text(lock.locked_field("parent_oci_lock_sha256")?),
            ),
            (
                "parent_oci_layer_sha256",
                text(lock.locked_field("parent_oci_layer_sha256")?),
            ),
            ("parent_oci_input_selection_verified", boolean(true)),
            ("parent_oci_git_object_authenticated", boolean(false)),
            (
                "parent_oci_source_to_image_provenance",
                text("not-established"),
            ),
            ("profile_state", text(lock.locked_field("profile_state")?)),
            (
                "profile_armable",
                text(lock.locked_field("profile_armable")?),
            ),
            ("runtime_object_count", text("17")),
            ("runtime_static_verification", boolean(true)),
            ("private_parent_validation", boolean(true)),
            ("fresh_operation_root_created", boolean(true)),
            ("user_namespace_created", boolean(true)),
            ("mount_namespace_created", boolean(true)),
            ("network_namespace_created", boolean(true)),
            ("uts_namespace_created", boolean(true)),
            (
                "uid_gid_mapping",
                text("namespace-zero-to-invoking-user-only"),
            ),
            ("mount_propagation_private", boolean(true)),
            ("isolated_root_nodev", boolean(true)),
            ("isolated_root_nosuid", boolean(true)),
            ("isolated_root_noexec", boolean(true)),
            ("runtime_mount_read_only", boolean(true)),
            ("private_work_mount_writable", boolean(true)),
            (
                "runtime_objects_materialized",
                text("exact-17-selected-objects-only"),
            ),
            (
                "runtime_object_bytes_reverified_after_materialization",
                boolean(true),
            ),
            ("runtime_symlink_graph_reverified", boolean(true)),
            ("host_root_visible", boolean(false)),
            ("host_home_visible", boolean(false)),
            ("host_gnupg_state_visible", boolean(false)),
            ("host_loader_configuration_visible", boolean(false)),
            ("host_temporary_directory_visible", boolean(false)),
            ("inherited_environment_retained", boolean(false)),
            ("isolated_network_egress_available", boolean(false)),
            (
                "verifier_network_activity",
                text("fixed-local-unreachable-route-probe-only"),
            ),
            ("external_network_activity", boolean(false)),
            ("whole_machine_network_silence", text("not-established")),
            (
                "private_writable_area_limited_to_selected_locations",
                boolean(true),
            ),
            ("no_new_privs_established", boolean(true)),
            ("capabilities_dropped", boolean(true)),
            ("fixed_a_quo_probe_execution", boolean(true)),
            ("procfs_verified", boolean(true)),
            ("numeric_launcher_pid_bound", boolean(true)),
            ("fixed_a_quo_executable_identity_verified", boolean(true)),
            (
                "fixed_a_quo_executable_execution_route",
                text("numeric-procfs-pid-exe"),
            ),
            ("host_authority_interference", text("not-in-threat-model")),
            ("temporary_root_cleanup", text("verified")),
            ("durable_retention", text("not-established")),
            ("ubuntu_signature_validity", text("not-established")),
            ("release_to_packages_verification", boolean(false)),
            ("package_archive_verification", boolean(false)),
            ("apt_solver_replay", boolean(false)),
            (
                "apt_dependency_closure_correctness",
                text("not-established"),
            ),
            (
                "archive_equivalence_to_original_ports",
                text("not-established"),
            ),
            ("durable_candidate_retention", text("not-established")),
            ("runtime_option_compatibility", text("not-established")),
            (
                "runtime_configuration_isolation",
                text("prepared-not-runtime-execution-proven"),
            ),
            ("nss_passwd_requirements", text("not-established")),
            ("locale_and_gconv_requirements", text("not-established")),
            ("randomness_requirements", text("not-established")),
            (
                "dev_null_and_proc_self_fd_requirements",
                text("not-established"),
            ),
            ("helper_config_keybox_access", text("not-established")),
            ("status_fd_sequence", text("not-established")),
            ("publisher_authentication", text("not-established")),
            ("current_publisher_authorization", text("not-established")),
            ("current_revocation_status", text("not-established")),
            ("trusted_time", text("not-established")),
            ("freshness", text("not-established")),
            ("source_to_binary_provenance", text("not-established")),
            ("verifier_correctness", text("not-established")),
            ("safety", text("not-established")),
            ("construction_authority", text("not-established")),
            ("build_authorization", text("not-established")),
            ("runnable", boolean(false)),
            ("external_executable_execution", boolean(false)),
            ("retained_runtime_object_execution", boolean(false)),
            ("retained_loader_execution", boolean(false)),
            ("gpgv_execution", boolean(false)),
            ("keyring_materialization", boolean(false)),
            ("inrelease_materialization", boolean(false)),
            ("signature_replay", boolean(false)),
            (
                "archive_filesystem_extraction",
                text("exact-17-selected-runtime-objects-only"),
            ),
            ("network_acquisition", boolean(false)),
            (
                "namespace_creation",
                text("fixed-user-mount-network-uts-only"),
            ),
            ("mount_execution", text("private-preparation-mounts-only")),
            ("package_manager_execution", boolean(false)),
            ("vm_execution", boolean(false)),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CANONICAL_REPOSITORY;
    use std::os::unix::fs::PermissionsExt;

    const REPORT_FIXTURE: &str = include_str!("../tests/fixtures/gpgv-isolation-prepare.report");

    fn expectation() -> ExternalLockExpectation {
        ExternalLockExpectation {
            repository: CANONICAL_REPOSITORY.to_owned(),
            commit: "0000000000000000000000000000000000000000".to_owned(),
            path: "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-gpgv-runtime-v1.lock".to_owned(),
            sha256: "a70ff31f4de6885619887e68f0633b2ddbe904ea910046b6b520df0e25bec925".to_owned(),
        }
    }

    fn create_synthetic_work(root: &Path) {
        for path in ["work/home", "work/gnupg", "work/tmp"] {
            std::fs::create_dir_all(root.join(path)).unwrap();
            std::fs::set_permissions(root.join(path), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        std::fs::set_permissions(root.join("work"), std::fs::Permissions::from_mode(0o555))
            .unwrap();
    }

    #[test]
    fn report_is_byte_exact_and_preserves_execution_nonclaims() {
        let lock = parse_gpgv_runtime_lock(include_bytes!(
            "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-gpgv-runtime-v1.lock"
        ))
        .unwrap();
        let rendered = success_report(&expectation(), &lock).unwrap().render();
        assert_eq!(rendered, REPORT_FIXTURE);
        for required in [
            "isolated_root_noexec=true\n",
            "whole_machine_network_silence=not-established\n",
            "retained_loader_execution=false\n",
            "gpgv_execution=false\n",
            "keyring_materialization=false\n",
            "inrelease_materialization=false\n",
            "signature_replay=false\n",
            "source_to_image_provenance=not-established\n",
            "source_to_binary_provenance=not-established\n",
            "runnable=false\n",
        ] {
            assert!(rendered.contains(required));
        }
    }

    #[test]
    fn namespace_flags_are_closed_and_exclude_files() {
        assert_eq!(
            FIXED_NAMESPACE_FLAGS,
            UnshareFlags::NEWUSER
                | UnshareFlags::NEWNS
                | UnshareFlags::NEWNET
                | UnshareFlags::NEWUTS
        );
        assert!(!FIXED_NAMESPACE_FLAGS.contains(UnshareFlags::FILES));
        assert_eq!(FIXED_NAMESPACE_FLAGS.bits().count_ones(), 4);
    }

    #[test]
    fn procfs_pin_binds_numeric_pid_and_executable_identity() {
        let procfs = pin_procfs().unwrap();
        assert!(!procfs.pid_text.is_empty());
        let identity = inspect_current_executable(&procfs).unwrap();
        assert!(identity.size > 0);
        assert!(!identity.sha256.is_empty());
    }

    #[test]
    fn output_writer_child() {
        let Ok(mode) = std::env::var("A_QUO_TEST_OUTPUT_MODE") else {
            return;
        };
        let bytes = vec![b'x'; CHILD_OUTPUT_MAXIMUM as usize + 4096];
        if mode == "stdout" || mode == "both" {
            std::io::stdout().write_all(&bytes).unwrap();
        }
        if mode == "stderr" || mode == "both" {
            std::io::stderr().write_all(&bytes).unwrap();
        }
    }

    #[test]
    fn descriptor_rejection_child() {
        if std::env::var_os("A_QUO_TEST_DESCRIPTOR_MODE").is_some() {
            let error = reject_unexpected_inherited_descriptors().unwrap_err();
            eprintln!("{error:#}");
        }
    }

    #[test]
    fn non_cloexec_file_directory_and_socket_are_rejected_before_spawn() {
        let regular = tempfile::tempfile().unwrap();
        let directory = File::open(std::env::temp_dir()).unwrap();
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        rustix::io::fcntl_setfd(&regular, rustix::io::FdFlags::empty()).unwrap();
        rustix::io::fcntl_setfd(&directory, rustix::io::FdFlags::empty()).unwrap();
        rustix::io::fcntl_setfd(&stream, rustix::io::FdFlags::empty()).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "gpgv_isolation::tests::descriptor_rejection_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("A_QUO_TEST_DESCRIPTOR_MODE", "reject")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let output = command.output().unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("unintended inherited descriptors rejected before probe spawn"));
    }

    fn assert_output_overflow(mode: &str, expected: &str) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "gpgv_isolation::tests::output_writer_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("A_QUO_TEST_OUTPUT_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let error = run_probe_child(&mut command).unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert!(error.to_string().contains("output exceeds its byte bound"));
    }

    #[test]
    fn stdout_overflow_is_rejected_while_child_runs() {
        assert_output_overflow("stdout", "stdout_overflow=true");
    }

    #[test]
    fn stderr_overflow_is_rejected_while_child_runs() {
        assert_output_overflow("stderr", "stderr_overflow=true");
    }

    #[test]
    fn simultaneous_output_overflow_is_rejected_while_child_runs() {
        assert_output_overflow("both", "stdout_overflow=true, stderr_overflow=true");
    }

    #[test]
    fn member_manifest_enables_only_the_owner_approved_rustix_features() {
        let member = include_str!("../Cargo.toml");
        let declaration =
            "rustix = { workspace = true, features = [\"thread\", \"mount\", \"system\"] }";
        assert_eq!(member.matches(declaration).count(), 1);
        assert!(!member.contains("all-apis"));
        assert!(!member.contains("use-libc"));
    }

    #[test]
    fn operation_names_are_closed() {
        assert!(validate_operation_name("a-quo-gpgv-isolation-A1b2C3").is_ok());
        for invalid in [
            "gpgv-isolation-A1b2C3",
            "a-quo-gpgv-isolation-short",
            "a-quo-gpgv-isolation-../../escape",
            "a-quo-gpgv-isolation-name_with_symbol",
        ] {
            assert!(validate_operation_name(invalid).is_err());
        }
    }

    #[test]
    fn unsafe_private_parents_are_rejected() {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap();
        for path in [
            "/",
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            repository_root.to_str().unwrap(),
        ] {
            assert!(validate_private_parent(Path::new(path)).is_err());
        }
        assert!(validate_private_parent(Path::new("relative-parent")).is_err());

        let writable = tempfile::tempdir().unwrap();
        std::fs::set_permissions(writable.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(validate_private_parent(writable.path()).is_err());

        let target = tempfile::tempdir().unwrap();
        let link_parent = tempfile::tempdir().unwrap();
        let link = link_parent.path().join("linked-parent");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        assert!(validate_private_parent(&link).is_err());
    }

    #[test]
    fn operation_root_is_exclusive_and_cleanup_is_exact() {
        let parent = tempfile::tempdir().unwrap();
        let mut operation = OperationRoot::create(parent.path()).unwrap();
        let operation_path = parent.path().join(&operation.name);
        assert!(operation_path.is_dir());
        assert_eq!(
            std::fs::symlink_metadata(&operation_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        operation.cleanup().unwrap();
        assert!(!operation_path.exists());
    }

    #[test]
    fn cleanup_rejects_root_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let mut operation = OperationRoot::create(parent.path()).unwrap();
        let operation_path = parent.path().join(&operation.name);
        let replacement = parent.path().join("replacement");
        std::fs::create_dir(&replacement).unwrap();
        std::fs::rename(&operation_path, parent.path().join("original")).unwrap();
        std::fs::rename(&replacement, &operation_path).unwrap();
        assert!(operation.cleanup().is_err());
        std::fs::remove_dir(&operation_path).unwrap();
        std::fs::remove_dir(parent.path().join("original")).unwrap();
        operation.cleaned = true;
    }

    #[test]
    fn materializer_rejects_changed_object_and_symlink() {
        let root = tempfile::tempdir().unwrap();
        let descriptor = open(
            root.path(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let regular = RuntimeMaterialization {
            path: "usr/lib/example".to_owned(),
            kind: RuntimeMaterializationKind::Regular,
            mode: 0o644,
            size: 3,
            sha256: sha256(b"one"),
            bytes: b"two".to_vec(),
        };
        assert!(materialize_objects(&descriptor, &[regular]).is_err());
        let symlink = RuntimeMaterialization {
            path: "lib".to_owned(),
            kind: RuntimeMaterializationKind::Symlink,
            mode: 0o777,
            size: 3,
            sha256: sha256(b"usr"),
            bytes: b"usr".to_vec(),
        };
        materialize_objects(&descriptor, std::slice::from_ref(&symlink)).unwrap();
        create_synthetic_work(root.path());
        std::fs::remove_file(root.path().join("lib")).unwrap();
        std::os::unix::fs::symlink("bad", root.path().join("lib")).unwrap();
        assert!(verify_materialized_objects(&descriptor, &[symlink]).is_err());
    }

    #[test]
    fn synthetic_runtime_tree_is_exact_and_rejects_additions() {
        let root = tempfile::tempdir().unwrap();
        let descriptor = open(
            root.path(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let objects = vec![
            RuntimeMaterialization {
                path: "usr/lib/example".to_owned(),
                kind: RuntimeMaterializationKind::Regular,
                mode: 0o644,
                size: 3,
                sha256: sha256(b"one"),
                bytes: b"one".to_vec(),
            },
            RuntimeMaterialization {
                path: "lib".to_owned(),
                kind: RuntimeMaterializationKind::Symlink,
                mode: 0o777,
                size: 3,
                sha256: sha256(b"usr"),
                bytes: b"usr".to_vec(),
            },
        ];
        materialize_objects(&descriptor, &objects).unwrap();
        create_synthetic_work(root.path());
        verify_materialized_objects(&descriptor, &objects).unwrap();
        std::fs::write(root.path().join("unexpected"), b"extra").unwrap();
        assert!(verify_materialized_objects(&descriptor, &objects).is_err());
    }

    #[test]
    fn materializer_rejects_escape_and_duplicate_paths() {
        let root = tempfile::tempdir().unwrap();
        let descriptor = open(
            root.path(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let escaped = RuntimeMaterialization {
            path: "../escape".to_owned(),
            kind: RuntimeMaterializationKind::Regular,
            mode: 0o644,
            size: 3,
            sha256: sha256(b"one"),
            bytes: b"one".to_vec(),
        };
        assert!(materialize_objects(&descriptor, &[escaped]).is_err());
        let duplicate = RuntimeMaterialization {
            path: "same".to_owned(),
            kind: RuntimeMaterializationKind::Regular,
            mode: 0o644,
            size: 3,
            sha256: sha256(b"one"),
            bytes: b"one".to_vec(),
        };
        assert!(materialize_objects(&descriptor, &[duplicate.clone(), duplicate]).is_err());
    }

    #[test]
    fn cleanup_runs_after_failure_reported_from_each_probe_stage() {
        for stage in [
            "namespace creation",
            "identity mapping",
            "private mount setup",
            "runtime input loading",
            "runtime materialization",
            "closed-root transition",
            "fixed probe checks",
            "probe output validation",
        ] {
            let parent = tempfile::tempdir().unwrap();
            let mut operation = OperationRoot::create(parent.path()).unwrap();
            let operation_path = parent.path().join(&operation.name);
            let error = finish_preparation(
                &mut operation,
                Err(anyhow::anyhow!("injected {stage} failure")),
            )
            .unwrap_err();
            assert!(error.to_string().contains(stage));
            assert!(!operation_path.exists());
        }
    }

    #[test]
    fn simultaneous_probe_and_cleanup_failures_are_both_reported() {
        let parent = tempfile::tempdir().unwrap();
        let mut operation = OperationRoot::create(parent.path()).unwrap();
        let operation_path = parent.path().join(&operation.name);
        std::fs::write(operation_path.join("unexpected"), b"retained").unwrap();
        let error = finish_preparation(
            &mut operation,
            Err(anyhow::anyhow!("injected probe failure")),
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("probe_failure=injected probe failure"));
        assert!(text.contains("cleanup_failure="));
        std::fs::remove_file(operation_path.join("unexpected")).unwrap();
        operation.cleanup().unwrap();
    }

    #[test]
    fn closed_environment_has_only_the_fixed_allowlist() {
        let keys = CLOSED_ENVIRONMENT
            .iter()
            .map(|(key, _)| *key)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "HOME",
                "GNUPGHOME",
                "TMPDIR",
                "LC_ALL",
                "LANG",
                "TZ",
                "PATH"
            ])
        );
        assert!(
            CLOSED_ENVIRONMENT
                .iter()
                .all(|(key, _)| !key.starts_with("LD_"))
        );
    }

    #[test]
    fn production_surface_has_only_the_fixed_self_probe() {
        let source = include_str!("gpgv_isolation.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("Command::new(\"/proc/self/exe\")"));
        assert!(production.contains("numeric-procfs-pid-exe"));
        for forbidden in [
            "rustix::thread::unshare_unsafe(",
            "Command::new(\"/usr/bin/gpgv\")",
            "Command::new(\"/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1\")",
            "--version",
            "signature_replay\", boolean(true)",
            "gpgv_execution\", boolean(true)",
            "retained_loader_execution\", boolean(true)",
            "std::process::exit",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production surface: {forbidden}"
            );
        }
    }
}
