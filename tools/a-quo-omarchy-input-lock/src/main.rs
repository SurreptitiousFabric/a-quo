#![forbid(unsafe_code)]

use std::path::PathBuf;

use a_quo_omarchy_input_lock::aavmf::{inspect_aavmf_lock, verify_aavmf_inputs};
use a_quo_omarchy_input_lock::alarm_rootfs::{
    inspect_alarm_rootfs_lock, verify_alarm_rootfs_inputs,
};
use a_quo_omarchy_input_lock::apt::inspect_apt_lock;
#[cfg(target_os = "linux")]
use a_quo_omarchy_input_lock::gpgv_isolation::{prepare_gpgv_isolation, run_internal_probe};
use a_quo_omarchy_input_lock::gpgv_runtime::verify_gpgv_runtime;
use a_quo_omarchy_input_lock::qemu::{inspect_qemu_lock, verify_qemu_inputs};
use a_quo_omarchy_input_lock::{ExternalLockExpectation, inspect_lock, verify_inputs};
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "a-quo-omarchy-input-lock",
    about = "Verify reviewed Omarchy evaluation inputs offline without building or granting runtime authority"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prepare and remove the exact issue-65 runtime in a private noexec namespace.
    #[cfg(target_os = "linux")]
    PrepareGpgvIsolation {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        parent_oci_lock: PathBuf,
        /// Mode-0700 directory containing exactly the four mode-0400 parent OCI objects.
        #[arg(long)]
        parent_oci_input_directory: PathBuf,
        /// Existing private mode-0700 parent for the fresh, disposable operation root.
        #[arg(long)]
        private_parent: PathBuf,
    },
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    InternalGpgvIsolationProbe {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        expected_runtime_lock_sha256: String,
        #[arg(long)]
        parent_oci_lock: PathBuf,
        #[arg(long)]
        parent_oci_input_directory: PathBuf,
        #[arg(long)]
        private_parent: PathBuf,
        #[arg(long)]
        operation_name: String,
        #[arg(long)]
        expected_device: u64,
        #[arg(long)]
        expected_inode: u64,
    },
    /// Statically verify the exact issue-65 gpgv runtime closure from its retained OCI layer.
    VerifyGpgvRuntime {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        parent_oci_lock: PathBuf,
        /// Mode-0700 directory containing exactly the four mode-0400 parent OCI objects.
        #[arg(long)]
        parent_oci_input_directory: PathBuf,
    },
    /// Check the exact non-authoritative Ubuntu APT candidate lock and frozen profile.
    InspectApt {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Check the externally pinned lock and profile; does not claim retained bytes are present.
    Inspect {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Verify exactly four caller-supplied OCI objects from sealed snapshots.
    Verify {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
        /// Mode-0700 directory containing exactly the four mode-0400 locked objects.
        #[arg(long)]
        input_directory: PathBuf,
    },
    /// Check the externally pinned ALARM rootfs lock and profile without claiming input bytes.
    InspectAlarmRootfs {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Verify the exact ALARM rootfs, detached signature, and key from sealed snapshots.
    VerifyAlarmRootfs {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
        /// Mode-0700 directory containing exactly the three mode-0400 locked objects.
        #[arg(long)]
        input_directory: PathBuf,
    },
    /// Check the externally pinned AAVMF package/member lock and frozen profile.
    InspectAavmf {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Verify the APT receipt, manifest, Debian package, and exact AAVMF members.
    VerifyAavmf {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
        /// Mode-0700 directory containing exactly the three mode-0400 locked objects.
        #[arg(long)]
        input_directory: PathBuf,
    },
    /// Check the externally pinned QEMU package/ELF/machine lock and frozen profile.
    InspectQemu {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Verify the APT context, QEMU Debian packages/ELFs, and exact machine script.
    VerifyQemu {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        externally_expected_lock_sha256: String,
        #[arg(long)]
        externally_expected_lock_repository: String,
        #[arg(long)]
        externally_expected_lock_commit: String,
        #[arg(long)]
        externally_expected_lock_path: String,
        #[arg(long)]
        profile: PathBuf,
        /// Mode-0700 directory containing exactly the seven mode-0400 locked objects.
        #[arg(long)]
        input_directory: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        #[cfg(target_os = "linux")]
        Command::PrepareGpgvIsolation {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
            parent_oci_lock,
            parent_oci_input_directory,
            private_parent,
        } => {
            let report = prepare_gpgv_isolation(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
                &parent_oci_lock,
                &parent_oci_input_directory,
                &private_parent,
            )?;
            print!("{}", report.render());
        }
        #[cfg(target_os = "linux")]
        Command::InternalGpgvIsolationProbe {
            lock,
            parent_oci_lock,
            parent_oci_input_directory,
            private_parent,
            operation_name,
            expected_device,
            expected_inode,
            expected_runtime_lock_sha256,
        } => {
            print!(
                "{}",
                run_internal_probe(
                    &lock,
                    &expected_runtime_lock_sha256,
                    &parent_oci_lock,
                    &parent_oci_input_directory,
                    &private_parent,
                    &operation_name,
                    expected_device,
                    expected_inode,
                )?
            );
        }
        Command::VerifyGpgvRuntime {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
            parent_oci_lock,
            parent_oci_input_directory,
        } => {
            let report = verify_gpgv_runtime(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
                &parent_oci_lock,
                &parent_oci_input_directory,
            )?;
            print!("{}", report.render());
        }
        Command::InspectApt {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
        } => {
            let report = inspect_apt_lock(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
            )?;
            print!("{}", report.render());
        }
        Command::Inspect {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
        } => {
            let report = inspect_lock(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
            )?;
            print!("{}", report.render());
        }
        Command::Verify {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
            input_directory,
        } => {
            let report = verify_inputs(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
                &input_directory,
            )?;
            print!("{}", report.render());
        }
        Command::InspectAlarmRootfs {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
        } => {
            let report = inspect_alarm_rootfs_lock(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
            )?;
            print!("{}", report.render());
        }
        Command::VerifyAlarmRootfs {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
            input_directory,
        } => {
            let report = verify_alarm_rootfs_inputs(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
                &input_directory,
            )?;
            print!("{}", report.render());
        }
        Command::InspectAavmf {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
        } => {
            let report = inspect_aavmf_lock(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
            )?;
            print!("{}", report.render());
        }
        Command::VerifyAavmf {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
            input_directory,
        } => {
            let report = verify_aavmf_inputs(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
                &input_directory,
            )?;
            print!("{}", report.render());
        }
        Command::InspectQemu {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
        } => {
            let report = inspect_qemu_lock(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
            )?;
            print!("{}", report.render());
        }
        Command::VerifyQemu {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
            input_directory,
        } => {
            let report = verify_qemu_inputs(
                &lock,
                &ExternalLockExpectation {
                    repository: externally_expected_lock_repository,
                    commit: externally_expected_lock_commit,
                    path: externally_expected_lock_path,
                    sha256: externally_expected_lock_sha256,
                },
                &profile,
                &input_directory,
            )?;
            print!("{}", report.render());
        }
    }
    Ok(())
}
