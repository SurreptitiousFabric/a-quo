#![forbid(unsafe_code)]

use std::path::PathBuf;

use a_quo_omarchy_joined_input_lock::{ExternalLockExpectation, inspect_lock, verify_inputs};
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "a-quo-omarchy-joined-input-lock",
    about = "Verify the frozen AArch64 joined-lifecycle inputs without executing them or arming an evaluator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify the externally pinned lock and frozen profile only.
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
    /// Verify exactly ten caller-supplied inert inputs from sealed snapshots.
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
        /// Mode-0700 directory containing the ten singly linked mode-0400 inputs.
        #[arg(long)]
        input_directory: PathBuf,
    },
}

fn expectation(
    repository: String,
    commit: String,
    path: String,
    sha256: String,
) -> ExternalLockExpectation {
    ExternalLockExpectation {
        repository,
        commit,
        path,
        sha256,
    }
}

fn main() -> Result<()> {
    let report = match Cli::parse().command {
        Command::Inspect {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
        } => inspect_lock(
            &lock,
            &expectation(
                externally_expected_lock_repository,
                externally_expected_lock_commit,
                externally_expected_lock_path,
                externally_expected_lock_sha256,
            ),
            &profile,
        )?,
        Command::Verify {
            lock,
            externally_expected_lock_sha256,
            externally_expected_lock_repository,
            externally_expected_lock_commit,
            externally_expected_lock_path,
            profile,
            input_directory,
        } => verify_inputs(
            &lock,
            &expectation(
                externally_expected_lock_repository,
                externally_expected_lock_commit,
                externally_expected_lock_path,
                externally_expected_lock_sha256,
            ),
            &profile,
            &input_directory,
        )?,
    };
    print!("{}", report.render());
    Ok(())
}
