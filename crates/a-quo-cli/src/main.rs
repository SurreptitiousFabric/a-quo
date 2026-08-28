use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a_quo_core::{
    DOMAIN_DEFAULT_VALIDITY_SECONDS, DOMAIN_MAX_VALIDITY_SECONDS, ProofBundle,
    canonical_domain_control_statement_bytes, create_sshsig_proof, default_proof_path,
    describe_artifact, describe_open_artifact, inspect_domain_control_proof, inspect_proof,
    load_proof, new_domain_control_statement, public_key_fingerprint,
    review_domain_control_statement, verify_domain_control_proof, verify_sshsig_proof,
    verify_sshsig_proof_for_descriptor, write_proof_new,
};
use a_quo_domain::{
    DnssecStatus, DomainControlStatus, LiveDomainControlVerification, PublicationStatus,
    verify_domain_control_live,
};
#[cfg(target_os = "linux")]
use a_quo_ipc::{
    ArtifactKind as IpcArtifactKind, RejectionCode, SignRequest as IpcSignRequest, SignResponse,
    connect_consent_socket, receive_sign_response, send_sign_request,
};
use a_quo_omarchy::{
    PluginInspection, PublisherRegistryStatus, inspect_signed_package, install_signed_package,
    update_signed_package,
};
use a_quo_store::{
    KeyProvider, KeyStatus, MAX_PERSONA_BACKUP_BYTES, PersonaBackup, PersonaPurpose, PersonaStore,
    RecognizedKey, RotationReason, validate_persona_backup,
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
#[cfg(target_os = "linux")]
use rustix::fs::{Mode, OFlags, open};
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use tempfile::tempfile;

const MAX_PUBLIC_KEY_FILE_BYTES: u64 = 16_384;
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
const DEFAULT_DOMAIN_VALIDITY_DAYS: u16 =
    (DOMAIN_DEFAULT_VALIDITY_SECONDS / SECONDS_PER_DAY) as u16;

#[derive(Debug, Parser)]
#[command(
    name = "a-quo",
    version,
    about = "Sign and verify exact artifacts without overstating identity or safety"
)]
struct Cli {
    /// Persona metadata database. Defaults to the platform data directory.
    #[arg(long, global = true, value_name = "PATH")]
    store: Option<PathBuf>,

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

        /// Self-asserted persona label for an unregistered signing key.
        #[arg(
            long,
            required_unless_present = "persona_id",
            conflicts_with = "persona_id"
        )]
        persona: Option<String>,

        /// Registered persona whose active key must match --public-key.
        #[arg(long, required_unless_present = "persona", conflicts_with = "persona")]
        persona_id: Option<String>,

        /// Proof path; defaults to ARTIFACT.a-quo-proof.json.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Ask the private Linux daemon to sign after an exact-digest consent prompt.
    RequestSign {
        artifact: PathBuf,

        /// Registered local persona selected for this request.
        #[arg(long)]
        persona_id: String,

        /// Display kind: generic, software, article, or image.
        #[arg(long, default_value = "generic")]
        kind: String,

        /// Caller-supplied display label; defaults to the artifact filename.
        #[arg(long)]
        label: Option<String>,

        /// Proof path; defaults to ARTIFACT.a-quo-proof.json.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Private daemon socket; defaults to $XDG_RUNTIME_DIR/a-quo/consent.sock.
        #[arg(long)]
        socket: Option<PathBuf>,
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

    /// Manage separate, non-secret publishing personas and key history.
    Persona {
        #[command(subcommand)]
        command: PersonaCommands,
    },

    /// Inspect, install, or update signed Omarchy release packages.
    Omarchy {
        #[command(subcommand)]
        command: OmarchyCommands,
    },

    /// Create, inspect, and verify short-lived DNS domain-control proofs.
    Domain {
        #[command(subcommand)]
        command: DomainCommands,
    },
}

#[derive(Debug, Subcommand)]
enum DomainCommands {
    /// Ask the private Linux daemon to approve and sign a domain-control statement.
    RequestProof {
        /// Exact DNS name to prove control of; URLs and wildcards are rejected.
        domain: String,

        /// Registered local persona selected for this request.
        #[arg(long)]
        persona_id: String,

        /// Proof lifetime in whole days (1 through 30).
        #[arg(long, default_value_t = DEFAULT_DOMAIN_VALIDITY_DAYS)]
        valid_days: u16,

        /// Proof path; defaults to DOMAIN.a-quo-domain-proof.json.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Private daemon socket; defaults to $XDG_RUNTIME_DIR/a-quo/consent.sock.
        #[arg(long)]
        socket: Option<PathBuf>,
    },

    /// Verify the signature and validity; optionally make an explicit live DNS query.
    Verify {
        #[arg(long)]
        proof: PathBuf,

        /// Query current DNS with DNSSEC validation. Without this, no network is used.
        #[arg(long)]
        live: bool,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Inspect claims without verifying their signature, validity, or DNS publication.
    Inspect {
        #[arg(long)]
        proof: PathBuf,

        /// Emit compact rather than pretty JSON.
        #[arg(long)]
        compact: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PersonaCommands {
    /// Create a persona without generating or importing a private key.
    Create {
        #[arg(long)]
        label: String,

        /// One of: personal, pseudonymous, project, organization, legal-bridge.
        #[arg(long)]
        purpose: String,

        #[arg(long)]
        json: bool,
    },

    /// List personas. Stable IDs remain local unless explicitly exported later.
    List {
        #[arg(long)]
        json: bool,
    },

    /// Enroll public verification material for a persona.
    KeyAdd {
        #[arg(long)]
        persona_id: String,

        #[arg(long)]
        public_key: PathBuf,

        /// One of: openssh-file, ssh-agent, fido2.
        #[arg(long)]
        provider: String,

        #[arg(long)]
        json: bool,
    },

    /// Replace active keys while retaining their history.
    KeyRotate {
        #[arg(long)]
        persona_id: String,

        #[arg(long)]
        public_key: PathBuf,

        /// One of: openssh-file, ssh-agent, fido2.
        #[arg(long)]
        provider: String,

        /// One of: routine, recovery, compromise.
        #[arg(long)]
        reason: String,

        #[arg(long)]
        note: Option<String>,

        #[arg(long)]
        json: bool,
    },

    /// Bind an active public key to a local signer path without importing it.
    KeyBind {
        #[arg(long)]
        fingerprint: String,

        /// Private key, FIDO stub, or SSH-agent public-key stub used by ssh-keygen.
        #[arg(long)]
        signing_key: PathBuf,

        #[arg(long)]
        json: bool,
    },

    /// Remove the current local signer path while retaining its event history.
    KeyUnbind {
        #[arg(long)]
        fingerprint: String,
    },

    /// Show append-only bind, rebind, and unbind events for a key.
    KeyBindingHistory {
        #[arg(long)]
        fingerprint: String,

        #[arg(long)]
        json: bool,
    },

    /// Record who marked a key compromised, when, and under which policy.
    KeyCompromise {
        #[arg(long)]
        fingerprint: String,

        #[arg(long)]
        actor: String,

        #[arg(long)]
        policy: String,

        #[arg(long)]
        note: Option<String>,
    },

    /// Show append-only key lifecycle events for a persona.
    History {
        #[arg(long)]
        persona_id: String,

        #[arg(long)]
        json: bool,
    },

    /// Export non-secret metadata; this never exports signing authority.
    BackupExport {
        #[arg(long)]
        persona_id: String,

        /// New JSON file to create; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Validate and summarize a metadata backup without importing it.
    BackupInspect {
        input: PathBuf,

        /// Emit a machine-readable summary without public-key contents.
        #[arg(long)]
        json: bool,
    },

    /// Restore non-secret metadata without restoring any signer reference.
    BackupImport {
        input: PathBuf,

        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum OmarchyCommands {
    /// Verify and inspect a signed .tar.zst without extracting it.
    Inspect {
        /// Immutable Omarchy plugin release package.
        package: PathBuf,

        /// A Quo proof bundle for the exact package bytes.
        #[arg(long)]
        proof: PathBuf,

        #[arg(long)]
        json: bool,
    },

    /// Install a verified plugin atomically and leave it disabled.
    Install {
        /// Immutable Omarchy plugin release package.
        package: PathBuf,

        /// A Quo proof bundle for the exact package bytes.
        #[arg(long)]
        proof: PathBuf,

        /// Override the Omarchy plugins directory.
        #[arg(long)]
        plugins_directory: Option<PathBuf>,

        /// Confirm installation after reviewing `omarchy inspect` output.
        #[arg(long)]
        yes: bool,
    },

    /// Atomically update an A Quo-managed plugin and roll back on rescan failure.
    Update {
        /// Newer immutable Omarchy plugin release package.
        package: PathBuf,

        /// A Quo proof bundle for the exact package bytes.
        #[arg(long)]
        proof: PathBuf,

        /// Override the Omarchy plugins directory.
        #[arg(long)]
        plugins_directory: Option<PathBuf>,

        /// Confirm update after reviewing `omarchy inspect` output.
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> Result<()> {
    let Cli { store, command } = Cli::parse();
    match command {
        Commands::Digest { artifact, json } => digest(&artifact, json),
        Commands::Sign {
            artifact,
            key,
            public_key,
            persona,
            persona_id,
            output,
        } => sign(
            store.as_deref(),
            &artifact,
            &key,
            &public_key,
            persona,
            persona_id,
            output,
        ),
        Commands::RequestSign {
            artifact,
            persona_id,
            kind,
            label,
            output,
            socket,
        } => request_sign(
            store.as_deref(),
            &artifact,
            &persona_id,
            &kind,
            label,
            output,
            socket.as_deref(),
        ),
        Commands::Verify {
            artifact,
            proof,
            json,
        } => verify(store.as_deref(), &artifact, &proof, json),
        Commands::Inspect { proof, compact } => inspect(&proof, compact),
        Commands::Persona { command } => persona_command(store.as_deref(), command),
        Commands::Omarchy { command } => omarchy_command(store.as_deref(), command),
        Commands::Domain { command } => domain_command(store.as_deref(), command),
    }
}

fn domain_command(store_path: Option<&Path>, command: DomainCommands) -> Result<()> {
    match command {
        DomainCommands::RequestProof {
            domain,
            persona_id,
            valid_days,
            output,
            socket,
        } => request_domain_proof(
            store_path,
            &domain,
            &persona_id,
            valid_days,
            output,
            socket.as_deref(),
        ),
        DomainCommands::Verify { proof, live, json } => {
            verify_domain(store_path, &proof, live, json)
        }
        DomainCommands::Inspect { proof, compact } => inspect_domain(&proof, compact),
    }
}

#[cfg(target_os = "linux")]
fn request_domain_proof(
    store_path: Option<&Path>,
    domain: &str,
    persona_id: &str,
    valid_days: u16,
    output: Option<PathBuf>,
    socket_path: Option<&Path>,
) -> Result<()> {
    let validity_seconds = domain_validity_seconds(valid_days)?;

    let store = require_existing_persona_store(store_path)?;
    let expected = store
        .active_signer_for_persona(persona_id)
        .with_context(|| format!("persona {persona_id} has no unambiguous active signer"))?;
    let issued_at = current_unix_time()?;
    let expires_at = issued_at
        .checked_add(validity_seconds)
        .context("domain proof expiry overflowed")?;
    let statement = new_domain_control_statement(
        domain,
        issued_at,
        expires_at,
        &expected.key.public_key,
        &expected.persona.label,
    )?;
    let canonical_statement = canonical_domain_control_statement_bytes(&statement)?;
    let expected_review = review_domain_control_statement(
        &statement,
        issued_at,
        &expected.key.public_key,
        &expected.persona.label,
    )?;

    let mut input = tempfile().context("cannot create anonymous domain statement file")?;
    input
        .write_all(&canonical_statement)
        .context("cannot write anonymous domain statement file")?;
    let request = IpcSignRequest::new_domain(persona_id)?;
    let socket_path = resolve_consent_socket_path(socket_path)?;
    let socket = connect_consent_socket(&socket_path)
        .with_context(|| format!("cannot connect to daemon socket {}", socket_path.display()))?;
    send_sign_request(&socket, &request, &input)?;
    let received = receive_sign_response(&socket)?;
    let sealed_proof = match received.response {
        SignResponse::Approved => received
            .proof
            .context("daemon approved without a sealed proof descriptor")?,
        SignResponse::Rejected(code) => {
            bail!("domain signing request rejected: {}", rejection_name(code));
        }
    };

    let proof_bytes = sealed_proof.read_bytes()?;
    let proof: ProofBundle =
        serde_json::from_slice(&proof_bytes).context("daemon returned an invalid proof bundle")?;
    let returned_statement =
        inspect_domain_control_proof(&proof).context("daemon returned the wrong proof purpose")?;
    ensure!(
        returned_statement == statement,
        "daemon proof does not contain the exact domain statement submitted for consent"
    );
    let verified_at = current_unix_time()?;
    let report = verify_domain_control_proof(&proof, verified_at)
        .context("daemon returned an invalid domain-control proof")?;
    ensure!(
        report.signer.key_fingerprint == expected.key.fingerprint,
        "daemon proof used key {}, but persona {persona_id} expected {}",
        report.signer.key_fingerprint,
        expected.key.fingerprint
    );
    ensure!(
        report.signer.persona == expected.persona.label,
        "daemon proof persona label does not match the local persona record"
    );
    ensure!(
        report.dns_record_name == expected_review.dns_record_name
            && report.dns_txt_value == expected_review.dns_txt_value,
        "daemon proof changed the reviewed DNS publication"
    );

    let output = output.unwrap_or_else(|| default_domain_proof_path(&statement.domain));
    write_proof_new(&output, &proof)?;
    println!("Proof written: {}", output.display());
    println!("Domain claim: {}", report.domain);
    println!("Persona: {}", report.signer.persona);
    println!("Key: {}", report.signer.key_fingerprint);
    println!("Valid until Unix time: {}", report.expires_at);
    println!("Publish this exact TXT record at:");
    println!("  Name: {}", report.dns_record_name);
    println!("  Value: {}", report.dns_txt_value);
    println!(
        "Current DNS control: NOT CHECKED. Run `a-quo domain verify --proof {} --live` after publishing.",
        output.display()
    );
    println!(
        "Not established: legal ownership, registrant identity, website safety, or control of any parent or subdomain."
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn request_domain_proof(
    _store_path: Option<&Path>,
    _domain: &str,
    _persona_id: &str,
    _valid_days: u16,
    _output: Option<PathBuf>,
    _socket_path: Option<&Path>,
) -> Result<()> {
    bail!("domain request-proof is currently available only on Linux")
}

fn verify_domain(
    store_path: Option<&Path>,
    proof_path: &Path,
    live: bool,
    json_output: bool,
) -> Result<()> {
    let proof = load_proof(proof_path)?;
    let now = current_unix_time()?;
    if live {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("cannot initialize the bounded DNS verifier")?;
        let report = runtime.block_on(verify_domain_control_live(&proof, now))?;
        let local = local_key_evidence(store_path, &report.signer.key_fingerprint)?;
        if json_output {
            let mut value = serde_json::to_value(&report)?;
            value["local_registry"] = local_json(&local, &report.signer.persona);
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            print_live_domain_verification(&report, &local);
        }
    } else {
        let report = verify_domain_control_proof(&proof, now)?;
        let local = local_key_evidence(store_path, &report.signer.key_fingerprint)?;
        if json_output {
            let mut value = serde_json::to_value(&report)?;
            value["local_registry"] = local_json(&local, &report.signer.persona);
            value["network"] = json!({
                "status": "not_checked",
                "meaning": "no DNS query was made; pass --live for a current observation"
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!(
                "SIGNATURE VERIFIED: the domain statement signature and validity window are valid."
            );
            println!("Domain claim: {}", report.domain);
            println!("DNS name: {}", report.dns_record_name);
            println!("Expected TXT: {}", report.dns_txt_value);
            println!("Current DNS control: NOT CHECKED (no network request was made).");
            println!("Persona claim: {}", report.signer.persona);
            println!("Key: {}", report.signer.key_fingerprint);
            print_local_evidence(&local, &report.signer.persona);
            println!("Not established: {}", report.not_established.join(", "));
        }
    }
    Ok(())
}

fn print_live_domain_verification(
    report: &LiveDomainControlVerification,
    local: &LocalKeyEvidence,
) {
    match report.domain_control {
        DomainControlStatus::VerifiedDnssec => println!(
            "DNSSEC DOMAIN CONTROL VERIFIED: the exact signed commitment is currently published at the exact claimed name."
        ),
        DomainControlStatus::ObservedUnsigned => println!(
            "UNSIGNED DNS OBSERVATION: the exact commitment is present, but DNSSEC did not authenticate it."
        ),
        DomainControlStatus::NotEstablished => println!(
            "DOMAIN CONTROL NOT ESTABLISHED: the current DNS evidence does not authenticate the claim."
        ),
    }
    println!("Signature and validity: verified");
    println!("Domain claim: {}", report.domain);
    println!("DNS name: {}", report.dns_record_name);
    println!("Expected TXT: {}", report.dns_txt_value);
    println!(
        "Publication: {}",
        publication_status_name(report.publication)
    );
    println!("DNSSEC: {}", dnssec_status_name(report.dnssec));
    println!("Checked at Unix time: {}", report.checked_at);
    if let Some(ttl) = report.matching_record_ttl_seconds {
        println!("Matching record TTL: {ttl} seconds");
    }
    println!("Persona claim: {}", report.signer.persona);
    println!("Key: {}", report.signer.key_fingerprint);
    print_local_evidence(local, &report.signer.persona);
    println!("Not established: {}", report.not_established.join(", "));
}

fn inspect_domain(proof_path: &Path, compact: bool) -> Result<()> {
    let proof = load_proof(proof_path)?;
    let statement = inspect_domain_control_proof(&proof)?;
    if compact {
        println!("{}", serde_json::to_string(&statement)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&statement)?);
    }
    Ok(())
}

fn default_domain_proof_path(domain: &str) -> PathBuf {
    PathBuf::from(format!("{domain}.a-quo-domain-proof.json"))
}

fn domain_validity_seconds(valid_days: u16) -> Result<i64> {
    ensure!(
        (1..=30).contains(&valid_days),
        "domain proof lifetime must be between 1 and 30 whole days"
    );
    let seconds = i64::from(valid_days)
        .checked_mul(SECONDS_PER_DAY)
        .context("domain proof lifetime overflowed")?;
    ensure!(
        seconds <= DOMAIN_MAX_VALIDITY_SECONDS,
        "domain proof lifetime exceeds the protocol maximum"
    );
    Ok(seconds)
}

fn publication_status_name(status: PublicationStatus) -> &'static str {
    match status {
        PublicationStatus::Matched => "exact TXT matched",
        PublicationStatus::Missing => "exact TXT missing",
    }
}

fn dnssec_status_name(status: DnssecStatus) -> &'static str {
    match status {
        DnssecStatus::Secure => "secure",
        DnssecStatus::Insecure => "insecure (zone is provably unsigned)",
        DnssecStatus::Bogus => "bogus",
        DnssecStatus::Indeterminate => "indeterminate",
    }
}

fn current_unix_time() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("system clock is outside A Quo's supported range")
}

fn omarchy_command(store_path: Option<&Path>, command: OmarchyCommands) -> Result<()> {
    match command {
        OmarchyCommands::Inspect {
            package,
            proof,
            json,
        } => {
            let store = open_existing_persona_store(store_path)?;
            let inspection = inspect_signed_package(&package, &proof, store.as_ref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&inspection)?);
            } else {
                print_omarchy_inspection(&inspection);
            }
        }
        OmarchyCommands::Install {
            package,
            proof,
            plugins_directory,
            yes,
        } => {
            ensure!(
                yes,
                "refusing installation without explicit confirmation; inspect first, then pass --yes"
            );
            let store = require_existing_persona_store(store_path)?;
            let plugins_directory = resolve_plugins_directory(plugins_directory.as_deref())?;
            let outcome = install_signed_package(&package, &proof, &store, &plugins_directory)?;
            println!(
                "Installed disabled: {} {}",
                outcome.plugin_id, outcome.version
            );
            println!(
                "Official Omarchy manifest validation: {}",
                outcome.omarchy_manifest_validation
            );
            println!("Shell rescan: {}", outcome.shell_rescan);
            println!("Runtime safety: {}", outcome.runtime_safety);
            println!(
                "Review with a separate code-risk scanner, then enable explicitly with Omarchy if acceptable."
            );
        }
        OmarchyCommands::Update {
            package,
            proof,
            plugins_directory,
            yes,
        } => {
            ensure!(
                yes,
                "refusing update without explicit confirmation; inspect first, then pass --yes"
            );
            let store = require_existing_persona_store(store_path)?;
            let plugins_directory = resolve_plugins_directory(plugins_directory.as_deref())?;
            let outcome = update_signed_package(&package, &proof, &store, &plugins_directory)?;
            println!(
                "Updated: {} {} -> {}",
                outcome.plugin_id, outcome.previous_version, outcome.version
            );
            println!("Publisher continuity: {}", outcome.publisher_continuity);
            println!(
                "Official Omarchy manifest validation: {}",
                outcome.omarchy_manifest_validation
            );
            println!("Atomic exchange: {}", outcome.atomic_exchange);
            println!("Shell rescan: {}", outcome.shell_rescan);
            println!("Enablement: {}", outcome.enablement);
            println!("Runtime safety: {}", outcome.runtime_safety);
            println!(
                "The signature and publisher continuity identify the release; they do not prove the updated code is safe."
            );
        }
    }
    Ok(())
}

fn print_omarchy_inspection(inspection: &PluginInspection) {
    println!(
        "VERIFIED PACKAGE: exact archive bytes match a valid SSH signature from {}.",
        inspection.artifact_evidence.signer.persona
    );
    println!(
        "Publisher registry: {}",
        publisher_status_name(inspection.publisher_evidence.registry_status)
    );
    if let Some(label) = &inspection.publisher_evidence.local_label {
        println!("Local publisher label: {label}");
    }
    if let Some(agreement) = inspection.publisher_evidence.signed_label_agreement {
        println!(
            "Signed-label agreement: {}",
            if agreement { "yes" } else { "NO" }
        );
    }
    println!(
        "Plugin: {} {} ({})",
        inspection.manifest.name, inspection.manifest.version, inspection.manifest.id
    );
    println!("Kinds: {}", inspection.manifest.kinds.join(", "));
    println!(
        "Archive: {} files, {} directories, {} uncompressed file bytes",
        inspection.archive.files,
        inspection.archive.directories,
        inspection.archive.uncompressed_file_bytes
    );
    if inspection.archive.executable_files.is_empty() {
        println!("Executable archive files: none");
    } else {
        println!(
            "Executable archive files: {}",
            inspection.archive.executable_files.join(", ")
        );
    }
    println!(
        "Official Omarchy manifest validation: {} (runs during installation)",
        inspection.omarchy_manifest_validation
    );
    println!("Runtime safety: {}", inspection.runtime_safety);
    println!("Automatic enablement: {}", inspection.automatic_enablement);
    println!(
        "A valid signature identifies bytes and a key; it does not make this plugin safe to run."
    );
}

fn publisher_status_name(status: PublisherRegistryStatus) -> &'static str {
    match status {
        PublisherRegistryStatus::NotChecked => "not checked",
        PublisherRegistryStatus::Unrecognized => "unrecognized",
        PublisherRegistryStatus::Active => "active",
        PublisherRegistryStatus::Retired => "retired",
        PublisherRegistryStatus::Compromised => "compromised",
    }
}

fn digest(artifact: &Path, json_output: bool) -> Result<()> {
    let descriptor = describe_artifact(artifact)?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&descriptor)?);
    } else {
        println!(
            "sha256:{}  {} bytes",
            descriptor.digest.value, descriptor.size
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign(
    store_path: Option<&Path>,
    artifact: &Path,
    private_key: &Path,
    public_key_path: &Path,
    persona_label: Option<String>,
    persona_id: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    let persona = match (persona_label, persona_id) {
        (Some(label), None) => label,
        (None, Some(persona_id)) => {
            let public_key = read_public_key(public_key_path)?;
            let fingerprint = public_key_fingerprint(&public_key)?;
            let store = open_persona_store(store_path)?;
            let recognized = store
                .lookup_key(&fingerprint)?
                .with_context(|| format!("key {fingerprint} is not registered"))?;
            ensure!(
                recognized.persona.id == persona_id,
                "key {fingerprint} belongs to persona {}, not {persona_id}",
                recognized.persona.id
            );
            ensure!(
                recognized.key.status == KeyStatus::Active,
                "refusing to sign with {} key {fingerprint}",
                status_name(recognized.key.status)
            );
            recognized.persona.label
        }
        _ => bail!("exactly one of --persona or --persona-id is required"),
    };

    let output = output.unwrap_or_else(|| default_proof_path(artifact));
    let proof = create_sshsig_proof(artifact, private_key, public_key_path, &persona)?;
    write_proof_new(&output, &proof)?;
    let statement = inspect_proof(&proof)?;
    println!("Proof written: {}", output.display());
    println!("Persona claim: {}", statement.signer.persona);
    println!("Key: {}", statement.signer.key_fingerprint);
    println!(
        "Meaning: this key signed the exact artifact digest; legal identity and safety are not established."
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn request_sign(
    store_path: Option<&Path>,
    artifact: &Path,
    persona_id: &str,
    kind: &str,
    label: Option<String>,
    output: Option<PathBuf>,
    socket_path: Option<&Path>,
) -> Result<()> {
    let store = require_existing_persona_store(store_path)?;
    let expected = store
        .active_signer_for_persona(persona_id)
        .with_context(|| format!("persona {persona_id} has no unambiguous active signer"))?;
    let artifact_kind = parse_artifact_kind(kind)?;
    let artifact_label = match label {
        Some(label) => label,
        None => artifact
            .file_name()
            .and_then(|name| name.to_str())
            .context("artifact filename is not UTF-8; pass --label")?
            .to_owned(),
    };
    let request = IpcSignRequest::new(persona_id, artifact_kind, artifact_label)?;

    let descriptor = open(
        artifact,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .with_context(|| format!("cannot safely open artifact {}", artifact.display()))?;
    let artifact_file = File::from(descriptor);
    ensure!(
        artifact_file.metadata()?.is_file(),
        "artifact must be a regular file"
    );
    let before = describe_open_artifact(&artifact_file)?;

    let socket_path = resolve_consent_socket_path(socket_path)?;
    let socket = connect_consent_socket(&socket_path)
        .with_context(|| format!("cannot connect to daemon socket {}", socket_path.display()))?;
    send_sign_request(&socket, &request, &artifact_file)?;
    let received = receive_sign_response(&socket)?;
    let sealed_proof = match received.response {
        SignResponse::Approved => received
            .proof
            .context("daemon approved without a sealed proof descriptor")?,
        SignResponse::Rejected(code) => {
            bail!("signing request rejected: {}", rejection_name(code));
        }
    };

    let after = describe_open_artifact(&artifact_file)?;
    ensure!(
        before == after,
        "artifact changed while consent was pending; refusing the returned proof"
    );
    let proof_bytes = sealed_proof.read_bytes()?;
    let proof: ProofBundle =
        serde_json::from_slice(&proof_bytes).context("daemon returned an invalid proof bundle")?;
    let report = verify_sshsig_proof_for_descriptor(&after, &proof)
        .context("daemon proof does not verify for the open artifact")?;
    ensure!(
        report.signer.key_fingerprint == expected.key.fingerprint,
        "daemon proof used key {}, but persona {persona_id} expected {}",
        report.signer.key_fingerprint,
        expected.key.fingerprint
    );
    ensure!(
        report.signer.persona == expected.persona.label,
        "daemon proof persona label does not match the local persona record"
    );

    let output = output.unwrap_or_else(|| default_proof_path(artifact));
    write_proof_new(&output, &proof)?;
    println!("Proof written: {}", output.display());
    println!("Persona: {}", report.signer.persona);
    println!("Key: {}", report.signer.key_fingerprint);
    println!("Consent: approved for the immutable SHA-256 shown by A Quo");
    println!(
        "Meaning: this key signed the exact bytes; legal identity and safety are not established."
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn request_sign(
    _store_path: Option<&Path>,
    _artifact: &Path,
    _persona_id: &str,
    _kind: &str,
    _label: Option<String>,
    _output: Option<PathBuf>,
    _socket_path: Option<&Path>,
) -> Result<()> {
    bail!("request-sign is currently available only on Linux")
}

#[cfg(target_os = "linux")]
fn parse_artifact_kind(value: &str) -> Result<IpcArtifactKind> {
    match value {
        "generic" => Ok(IpcArtifactKind::Generic),
        "software" => Ok(IpcArtifactKind::SoftwareRelease),
        "article" => Ok(IpcArtifactKind::Article),
        "image" => Ok(IpcArtifactKind::Image),
        _ => bail!(
            "unsupported artifact kind {value}; expected generic, software, article, or image"
        ),
    }
}

#[cfg(target_os = "linux")]
fn resolve_consent_socket_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        ensure!(path.is_absolute(), "consent socket path must be absolute");
        return Ok(path.to_path_buf());
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR is required; or pass --socket PATH")?;
    let runtime = PathBuf::from(runtime);
    ensure!(runtime.is_absolute(), "XDG_RUNTIME_DIR must be absolute");
    Ok(runtime.join("a-quo/consent.sock"))
}

#[cfg(target_os = "linux")]
fn rejection_name(code: RejectionCode) -> &'static str {
    match code {
        RejectionCode::UserDeclined => "user declined",
        RejectionCode::Cancelled => "request cancelled",
        RejectionCode::InvalidRequest => "invalid request",
        RejectionCode::PersonaUnavailable => "persona unavailable",
        RejectionCode::SignerUnavailable => "signer unavailable",
        RejectionCode::InternalError => "daemon internal failure",
        RejectionCode::ConsentUnavailable => "trusted consent process unavailable",
    }
}

fn verify(
    store_path: Option<&Path>,
    artifact: &Path,
    proof_path: &Path,
    json_output: bool,
) -> Result<()> {
    let proof = load_proof(proof_path)?;
    let report = verify_sshsig_proof(artifact, &proof)?;
    let local = local_key_evidence(store_path, &report.signer.key_fingerprint)?;

    if json_output {
        let mut value = serde_json::to_value(&report)?;
        value["local_registry"] = local_json(&local, &report.signer.persona);
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("VERIFIED: artifact bytes match and the SSH signature is valid.");
        println!("Persona claim: {}", report.signer.persona);
        println!("Key: {}", report.signer.key_fingerprint);
        println!("Identity binding: self-asserted");
        print_local_evidence(&local, &report.signer.persona);
        println!("Not established: {}", report.not_established.join(", "));
    }
    Ok(())
}

fn inspect(proof_path: &Path, compact: bool) -> Result<()> {
    let proof = load_proof(proof_path)?;
    let statement = inspect_proof(&proof)?;
    if compact {
        println!("{}", serde_json::to_string(&statement)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&statement)?);
    }
    Ok(())
}

fn persona_command(store_path: Option<&Path>, command: PersonaCommands) -> Result<()> {
    match &command {
        PersonaCommands::BackupExport { persona_id, output } => {
            return export_persona_backup_command(store_path, persona_id, output);
        }
        PersonaCommands::BackupInspect { input, json } => {
            return inspect_persona_backup_command(input, *json);
        }
        PersonaCommands::BackupImport { input, json } => {
            return import_persona_backup_command(store_path, input, *json);
        }
        _ => {}
    }

    let mut store = open_persona_store(store_path)?;
    match command {
        PersonaCommands::Create {
            label,
            purpose,
            json,
        } => {
            let purpose: PersonaPurpose = purpose.parse()?;
            let persona = store.create_persona(&label, purpose)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&persona)?);
            } else {
                println!("Created persona: {}", persona.label);
                println!("Local ID: {}", persona.id);
                println!("Purpose: {}", persona.purpose);
                println!("No private key or credential was stored.");
            }
        }
        PersonaCommands::List { json } => {
            let personas = store.list_personas()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&personas)?);
            } else if personas.is_empty() {
                println!("No personas are registered.");
            } else {
                for persona in personas {
                    let state = if persona.archived_at.is_some() {
                        "archived"
                    } else {
                        "active"
                    };
                    println!(
                        "{}  {}  {}  {}",
                        persona.id, persona.purpose, state, persona.label
                    );
                }
            }
        }
        PersonaCommands::KeyAdd {
            persona_id,
            public_key,
            provider,
            json,
        } => {
            let provider: KeyProvider = provider.parse()?;
            let public_key = read_public_key(&public_key)?;
            let key = store.enroll_key(&persona_id, &public_key, provider)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&key)?);
            } else {
                println!("Enrolled active public key: {}", key.fingerprint);
                println!("Provider: {}", key.provider);
                println!("Private key material was not copied or stored.");
            }
        }
        PersonaCommands::KeyRotate {
            persona_id,
            public_key,
            provider,
            reason,
            note,
            json,
        } => {
            let provider: KeyProvider = provider.parse()?;
            let reason: RotationReason = reason.parse()?;
            let public_key = read_public_key(&public_key)?;
            let key =
                store.rotate_key(&persona_id, &public_key, provider, reason, note.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&key)?);
            } else {
                println!("New active key: {}", key.fingerprint);
                println!("Rotation reason: {}", reason.as_str());
                println!("Previous key history was retained.");
            }
        }
        PersonaCommands::KeyBind {
            fingerprint,
            signing_key,
            json,
        } => {
            let reference = store.bind_signing_reference(&fingerprint, &signing_key)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "key_fingerprint": reference.key_fingerprint,
                        "locator": reference.locator,
                        "configured_at": reference.configured_at
                    }))?
                );
            } else {
                println!("Bound signer reference: {}", reference.key_fingerprint);
                println!("Local path: {}", reference.locator.display());
                println!("Only the path was stored; private key bytes were not imported.");
            }
        }
        PersonaCommands::KeyUnbind { fingerprint } => {
            store.unbind_signing_reference(&fingerprint)?;
            println!("Removed signer reference: {fingerprint}");
            println!("The non-secret bind history was retained.");
        }
        PersonaCommands::KeyBindingHistory { fingerprint, json } => {
            let events = store.signing_reference_history(&fingerprint)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else if events.is_empty() {
                println!("No signer-reference events are recorded for key {fingerprint}.");
            } else {
                for event in events {
                    println!(
                        "{}  {}  {}",
                        event.occurred_at, event.event_type, event.key_fingerprint
                    );
                }
            }
        }
        PersonaCommands::KeyCompromise {
            fingerprint,
            actor,
            policy,
            note,
        } => {
            store.mark_key_compromised(&fingerprint, &actor, &policy, note.as_deref())?;
            println!("Recorded compromised key: {fingerprint}");
            println!("Actor: {actor}");
            println!("Policy: {policy}");
            println!(
                "Historical proofs remain inspectable but are not presented as current trust."
            );
        }
        PersonaCommands::History { persona_id, json } => {
            let events = store.key_history(&persona_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else if events.is_empty() {
                println!("No key events are recorded for persona {persona_id}.");
            } else {
                for event in events {
                    println!(
                        "{}  {}  {}  actor={}  policy={}{}",
                        event.occurred_at,
                        event.event_type,
                        event.key_fingerprint,
                        event.actor,
                        event.policy,
                        event
                            .note
                            .as_deref()
                            .map(|note| format!("  note={note}"))
                            .unwrap_or_default()
                    );
                }
            }
        }
        PersonaCommands::BackupExport { .. }
        | PersonaCommands::BackupInspect { .. }
        | PersonaCommands::BackupImport { .. } => {
            unreachable!("backup commands return before opening the ordinary persona store")
        }
    }
    Ok(())
}

fn export_persona_backup_command(
    store_path: Option<&Path>,
    persona_id: &str,
    output: &Path,
) -> Result<()> {
    let mut store = open_existing_persona_store(store_path)?
        .context("metadata export requires an existing persona store")?;
    let backup = store.export_persona_backup(persona_id)?;
    write_persona_backup_new(output, &backup)?;
    println!("Exported persona metadata: {}", backup.persona.label);
    println!("Backup: {}", output.display());
    println!(
        "Contents: {} public key(s), {} lifecycle event(s)",
        backup.keys.len(),
        backup.events.len()
    );
    println!("No private key, signer path, wallet credential, or recovery authority was exported.");
    Ok(())
}

fn inspect_persona_backup_command(input: &Path, emit_json: bool) -> Result<()> {
    let backup = read_persona_backup(input)?;
    let summary = json!({
        "status": "internally_consistent_unsigned_metadata",
        "schema": backup.schema,
        "exported_at": backup.exported_at,
        "persona": {
            "id": backup.persona.id,
            "label": backup.persona.label,
            "purpose": backup.persona.purpose,
            "created_at": backup.persona.created_at,
            "archived_at": backup.persona.archived_at
        },
        "public_key_count": backup.keys.len(),
        "lifecycle_event_count": backup.events.len(),
        "signing_authority": false,
        "cryptographic_continuity": false
    });
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("VALID UNSIGNED METADATA BACKUP");
        println!(
            "Persona: {} ({})",
            backup.persona.label, backup.persona.purpose
        );
        println!("Local ID: {}", backup.persona.id);
        println!(
            "Contents: {} public key(s), {} lifecycle event(s)",
            backup.keys.len(),
            backup.events.len()
        );
        println!("Meaning: internally consistent metadata only; no signing or recovery authority.");
    }
    Ok(())
}

fn import_persona_backup_command(
    store_path: Option<&Path>,
    input: &Path,
    emit_json: bool,
) -> Result<()> {
    let backup = read_persona_backup(input)?;
    let mut store = open_persona_store(store_path)?;
    let persona = store.import_persona_backup(&backup)?;
    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "persona": persona,
                "signer_references_restored": 0,
                "signing_authority": false,
                "cryptographic_continuity": false
            }))?
        );
    } else {
        println!("Imported persona metadata: {}", persona.label);
        println!("Local ID: {}", persona.id);
        println!("Signer references restored: none");
        println!("Bind an available signer explicitly before signing.");
        println!("This import did not establish cryptographic recovery or legal identity.");
    }
    Ok(())
}

enum LocalKeyEvidence {
    NotChecked,
    Unrecognized,
    Recognized {
        record: Box<RecognizedKey>,
        events: Vec<a_quo_store::KeyEvent>,
    },
}

fn local_key_evidence(store_path: Option<&Path>, fingerprint: &str) -> Result<LocalKeyEvidence> {
    let path = resolve_store_path(store_path)?;
    if !path.exists() {
        if store_path.is_some() {
            bail!("persona store does not exist: {}", path.display());
        }
        return Ok(LocalKeyEvidence::NotChecked);
    }

    let store = PersonaStore::open(&path)?;
    match store.lookup_key(fingerprint)? {
        Some(record) => {
            let events = store.key_history(&record.persona.id)?;
            Ok(LocalKeyEvidence::Recognized {
                record: Box::new(record),
                events,
            })
        }
        None => Ok(LocalKeyEvidence::Unrecognized),
    }
}

fn local_json(local: &LocalKeyEvidence, signed_label: &str) -> Value {
    match local {
        LocalKeyEvidence::NotChecked => json!({ "status": "not_checked" }),
        LocalKeyEvidence::Unrecognized => json!({ "status": "unrecognized" }),
        LocalKeyEvidence::Recognized { record, events } => {
            let status_event = relevant_status_event(record, events).map(|event| {
                json!({
                    "event_type": event.event_type,
                    "occurred_at": event.occurred_at,
                    "actor": event.actor,
                    "policy": event.policy,
                    "note": event.note
                })
            });
            json!({
                "status": "recognized",
                "persona": {
                    "label": record.persona.label,
                    "purpose": record.persona.purpose
                },
                "key_status": record.key.status,
                "signed_label_agreement": record.persona.label == signed_label,
                "status_event": status_event,
                "meaning": "local metadata only; no independent legal identity is established"
            })
        }
    }
}

fn print_local_evidence(local: &LocalKeyEvidence, signed_label: &str) {
    match local {
        LocalKeyEvidence::NotChecked => println!("Local persona registry: not configured"),
        LocalKeyEvidence::Unrecognized => println!("Local persona registry: key is unrecognized"),
        LocalKeyEvidence::Recognized { record, events } => {
            println!(
                "Local persona registry: {} key for {} ({})",
                status_name(record.key.status),
                record.persona.label,
                record.persona.purpose
            );
            println!(
                "Signed-label agreement: {}",
                if record.persona.label == signed_label {
                    "yes"
                } else {
                    "NO"
                }
            );
            if let Some(event) = relevant_status_event(record, events)
                && record.key.status != KeyStatus::Active
            {
                println!(
                    "Lifecycle record: event={} actor={} time={} policy={}",
                    event.event_type, event.actor, event.occurred_at, event.policy
                );
            }
            println!("Registry meaning: local metadata, not independent legal identity.");
        }
    }
}

fn relevant_status_event<'a>(
    record: &RecognizedKey,
    events: &'a [a_quo_store::KeyEvent],
) -> Option<&'a a_quo_store::KeyEvent> {
    events.iter().rev().find(|event| {
        if event.key_fingerprint != record.key.fingerprint {
            return false;
        }
        match record.key.status {
            KeyStatus::Active => matches!(event.event_type.as_str(), "rotated_in" | "enrolled"),
            KeyStatus::Retired => event.event_type == "retired",
            KeyStatus::Compromised => event.event_type == "compromised",
        }
    })
}

fn status_name(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::Active => "active",
        KeyStatus::Retired => "retired",
        KeyStatus::Compromised => "compromised",
    }
}

fn open_persona_store(path: Option<&Path>) -> Result<PersonaStore> {
    let path = resolve_store_path(path)?;
    PersonaStore::open(&path)
        .with_context(|| format!("cannot open persona store {}", path.display()))
}

fn open_existing_persona_store(path: Option<&Path>) -> Result<Option<PersonaStore>> {
    let resolved = resolve_store_path(path)?;
    if !resolved.exists() {
        if path.is_some() {
            bail!("persona store does not exist: {}", resolved.display());
        }
        return Ok(None);
    }
    PersonaStore::open(&resolved)
        .map(Some)
        .with_context(|| format!("cannot open persona store {}", resolved.display()))
}

fn require_existing_persona_store(path: Option<&Path>) -> Result<PersonaStore> {
    open_existing_persona_store(path)?.with_context(
        || "this operation requires an existing persona store with the relevant active public key",
    )
}

fn resolve_store_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        let data_home = PathBuf::from(data_home);
        ensure!(
            data_home.is_absolute(),
            "XDG_DATA_HOME must be an absolute path"
        );
        return Ok(data_home.join("a-quo/personas.sqlite3"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".local/share/a-quo/personas.sqlite3"));
    }
    bail!("cannot locate a data directory; pass --store PATH")
}

fn resolve_plugins_directory(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        let config_home = PathBuf::from(config_home);
        ensure!(
            config_home.is_absolute(),
            "XDG_CONFIG_HOME must be an absolute path"
        );
        return Ok(config_home.join("omarchy/plugins"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".config/omarchy/plugins"));
    }
    bail!("cannot locate Omarchy's config directory; pass --plugins-directory PATH")
}

fn read_persona_backup(path: &Path) -> Result<PersonaBackup> {
    let file = open_persona_backup_input(path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect persona backup {}", path.display()))?;
    ensure!(metadata.is_file(), "persona backup must be a regular file");
    ensure!(
        metadata.len() <= MAX_PERSONA_BACKUP_BYTES,
        "persona backup exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
    );

    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_PERSONA_BACKUP_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read persona backup {}", path.display()))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_PERSONA_BACKUP_BYTES,
        "persona backup exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
    );
    let backup: PersonaBackup = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid persona backup JSON in {}", path.display()))?;
    validate_persona_backup(&backup)
        .with_context(|| format!("invalid persona backup {}", path.display()))?;
    Ok(backup)
}

#[cfg(target_os = "linux")]
fn open_persona_backup_input(path: &Path) -> Result<File> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| format!("cannot safely open persona backup {}", path.display()))?;
    Ok(File::from(descriptor))
}

#[cfg(not(target_os = "linux"))]
fn open_persona_backup_input(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect persona backup {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "persona backup cannot be a symbolic link"
    );
    ensure!(metadata.is_file(), "persona backup must be a regular file");
    File::open(path).with_context(|| format!("cannot open persona backup {}", path.display()))
}

fn write_persona_backup_new(path: &Path, backup: &PersonaBackup) -> Result<()> {
    validate_persona_backup(backup)?;
    let mut bytes = serde_json::to_vec_pretty(backup)?;
    bytes.push(b'\n');
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_PERSONA_BACKUP_BYTES,
        "serialized persona backup exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
    );

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).with_context(|| {
        format!(
            "cannot create new persona backup {}; existing paths are never overwritten",
            path.display()
        )
    })?;
    file.write_all(&bytes)
        .with_context(|| format!("cannot write persona backup {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot sync persona backup {}", path.display()))?;
    Ok(())
}

fn read_public_key(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("cannot read public key metadata: {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_PUBLIC_KEY_FILE_BYTES,
        "public key file exceeds {MAX_PUBLIC_KEY_FILE_BYTES} bytes"
    );
    fs::read_to_string(path).with_context(|| format!("cannot read public key: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKUP_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";

    fn test_backup() -> PersonaBackup {
        let mut store = PersonaStore::open_in_memory().unwrap();
        let persona = store
            .create_persona("Backup test", PersonaPurpose::Project)
            .unwrap();
        store
            .enroll_key(&persona.id, BACKUP_KEY, KeyProvider::OpensshFile)
            .unwrap();
        store.export_persona_backup(&persona.id).unwrap()
    }

    #[test]
    fn persona_backup_commands_parse_with_explicit_paths() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "persona",
            "backup-export",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--output",
            "persona.backup.json",
        ])
        .unwrap();
        let Commands::Persona {
            command: PersonaCommands::BackupExport { output, .. },
        } = cli.command
        else {
            panic!("expected persona backup export command");
        };
        assert_eq!(output, PathBuf::from("persona.backup.json"));

        let cli = Cli::try_parse_from(["a-quo", "persona", "backup-import", "persona.backup.json"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Persona {
                command: PersonaCommands::BackupImport { .. }
            }
        ));
    }

    #[test]
    fn backup_file_io_is_private_strict_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("persona.backup.json");
        let backup = test_backup();

        write_persona_backup_new(&path, &backup).unwrap();
        assert_eq!(read_persona_backup(&path).unwrap(), backup);
        assert!(write_persona_backup_new(&path, &backup).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let unknown_path = directory.path().join("unknown-field.json");
        let mut value = serde_json::to_value(&backup).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), Value::Bool(true));
        fs::write(&unknown_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_persona_backup(&unknown_path).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let link = directory.path().join("backup-link.json");
            symlink(&path, &link).unwrap();
            assert!(read_persona_backup(&link).is_err());
        }
    }

    #[test]
    fn invalid_backup_import_does_not_create_a_store() {
        let directory = tempfile::tempdir().unwrap();
        let backup_path = directory.path().join("invalid.json");
        let store_path = directory.path().join("personas.sqlite3");
        fs::write(&backup_path, b"{\"not\":\"a backup\"}").unwrap();

        assert!(import_persona_backup_command(Some(&store_path), &backup_path, false).is_err());
        assert!(!store_path.exists());
    }

    #[test]
    fn domain_verification_is_offline_unless_live_is_explicit() {
        let cli =
            Cli::try_parse_from(["a-quo", "domain", "verify", "--proof", "proof.json"]).unwrap();
        let Commands::Domain {
            command: DomainCommands::Verify { live, json, .. },
        } = cli.command
        else {
            panic!("expected domain verification command");
        };
        assert!(!live);
        assert!(!json);

        let cli = Cli::try_parse_from([
            "a-quo",
            "domain",
            "verify",
            "--proof",
            "proof.json",
            "--live",
        ])
        .unwrap();
        let Commands::Domain {
            command: DomainCommands::Verify { live, .. },
        } = cli.command
        else {
            panic!("expected live domain verification command");
        };
        assert!(live);
    }

    #[test]
    fn domain_request_defaults_to_a_short_lifetime() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "domain",
            "request-proof",
            "a-quo.ch",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
        ])
        .unwrap();
        let Commands::Domain {
            command: DomainCommands::RequestProof { valid_days, .. },
        } = cli.command
        else {
            panic!("expected domain proof request command");
        };
        assert_eq!(valid_days, DEFAULT_DOMAIN_VALIDITY_DAYS);
    }

    #[test]
    fn domain_validity_is_bounded_before_request_processing() {
        assert!(domain_validity_seconds(0).is_err());
        assert_eq!(domain_validity_seconds(1).unwrap(), SECONDS_PER_DAY);
        assert_eq!(
            domain_validity_seconds(30).unwrap(),
            DOMAIN_MAX_VALIDITY_SECONDS
        );
        assert!(domain_validity_seconds(31).is_err());
    }

    #[test]
    fn default_domain_proof_path_is_unambiguous() {
        assert_eq!(
            default_domain_proof_path("a-quo.ch"),
            PathBuf::from("a-quo.ch.a-quo-domain-proof.json")
        );
    }
}
