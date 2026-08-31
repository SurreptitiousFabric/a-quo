#![forbid(unsafe_code)]

use std::path::PathBuf;

use a_quo_omarchy_builder_context_lock::{ExternalLockExpectation, inspect_lock, verify_export};
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "a-quo-omarchy-builder-context-lock",
    about = "Verify an inert Omarchy builder-context selection without Git, network, containers, packages, mounts, or VMs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check the externally pinned lock and profile; does not claim source bytes are present.
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
    /// Verify an inert mode-0700 export containing exactly the ten locked files.
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
        #[arg(long)]
        input_directory: PathBuf,
    },
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
            &ExternalLockExpectation {
                repository: externally_expected_lock_repository,
                commit: externally_expected_lock_commit,
                path: externally_expected_lock_path,
                sha256: externally_expected_lock_sha256,
            },
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
        } => verify_export(
            &lock,
            &ExternalLockExpectation {
                repository: externally_expected_lock_repository,
                commit: externally_expected_lock_commit,
                path: externally_expected_lock_path,
                sha256: externally_expected_lock_sha256,
            },
            &profile,
            &input_directory,
        )?,
    };
    print!("{}", report.render());
    Ok(())
}
