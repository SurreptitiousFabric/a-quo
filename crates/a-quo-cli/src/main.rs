use std::path::PathBuf;

use a_quo_core::{
    create_sshsig_proof, default_proof_path, describe_artifact, inspect_proof, load_proof,
    verify_sshsig_proof, write_proof_new,
};
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "a-quo",
    version,
    about = "Sign and verify exact artifacts without overstating identity or safety"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Calculate the content identity of an artifact.
    Digest {
        artifact: PathBuf,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Sign an artifact statement with an OpenSSH or FIDO-backed SSH key.
    Sign {
        artifact: PathBuf,

        /// Private key or public key stub understood by ssh-keygen/ssh-agent.
        #[arg(long)]
        key: PathBuf,

        /// OpenSSH public key corresponding to --key.
        #[arg(long)]
        public_key: PathBuf,

        /// Persona label to bind into the signed statement.
        #[arg(long)]
        persona: String,

        /// Proof path; defaults to ARTIFACT.a-quo-proof.json.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify exact artifact bytes and their SSHSIG proof.
    Verify {
        artifact: PathBuf,

        #[arg(long)]
        proof: PathBuf,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Inspect signed claims without claiming the artifact was verified.
    Inspect {
        #[arg(long)]
        proof: PathBuf,

        /// Emit compact rather than pretty JSON.
        #[arg(long)]
        compact: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Digest { artifact, json } => {
            let descriptor = describe_artifact(&artifact)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&descriptor)?);
            } else {
                println!(
                    "sha256:{}  {} bytes",
                    descriptor.digest.value, descriptor.size
                );
            }
        }
        Commands::Sign {
            artifact,
            key,
            public_key,
            persona,
            output,
        } => {
            let output = output.unwrap_or_else(|| default_proof_path(&artifact));
            let proof = create_sshsig_proof(&artifact, &key, &public_key, &persona)?;
            write_proof_new(&output, &proof)?;
            let statement = inspect_proof(&proof)?;
            println!("Proof written: {}", output.display());
            println!("Persona claim: {}", statement.signer.persona);
            println!("Key: {}", statement.signer.key_fingerprint);
            println!(
                "Meaning: this key signed the exact artifact digest; legal identity and safety are not established."
            );
        }
        Commands::Verify {
            artifact,
            proof,
            json,
        } => {
            let proof = load_proof(&proof)?;
            let report = verify_sshsig_proof(&artifact, &proof)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("VERIFIED: artifact bytes match and the SSH signature is valid.");
                println!("Persona claim: {}", report.signer.persona);
                println!("Key: {}", report.signer.key_fingerprint);
                println!("Identity binding: self-asserted");
                println!("Not established: {}", report.not_established.join(", "));
            }
        }
        Commands::Inspect { proof, compact } => {
            let proof = load_proof(&proof)?;
            let statement = inspect_proof(&proof)?;
            if compact {
                println!("{}", serde_json::to_string(&statement)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&statement)?);
            }
        }
    }
    Ok(())
}
