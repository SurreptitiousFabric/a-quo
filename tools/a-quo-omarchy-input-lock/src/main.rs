#![forbid(unsafe_code)]

use std::path::PathBuf;

use a_quo_omarchy_input_lock::alarm_rootfs::{
    inspect_alarm_rootfs_lock, verify_alarm_rootfs_inputs,
};
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
}

fn main() -> Result<()> {
    match Cli::parse().command {
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
    }
    Ok(())
}
