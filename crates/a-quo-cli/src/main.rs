use std::fs;
use std::path::{Path, PathBuf};

use a_quo_core::{
    create_sshsig_proof, default_proof_path, describe_artifact, inspect_proof, load_proof,
    public_key_fingerprint, verify_sshsig_proof, write_proof_new,
};
use a_quo_store::{
    KeyProvider, KeyStatus, PersonaPurpose, PersonaStore, RecognizedKey, RotationReason,
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

const MAX_PUBLIC_KEY_FILE_BYTES: u64 = 16_384;

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
        Commands::Verify {
            artifact,
            proof,
            json,
        } => verify(store.as_deref(), &artifact, &proof, json),
        Commands::Inspect { proof, compact } => inspect(&proof, compact),
        Commands::Persona { command } => persona_command(store.as_deref(), command),
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

fn read_public_key(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("cannot read public key metadata: {}", path.display()))?;
    ensure!(
        metadata.len() <= MAX_PUBLIC_KEY_FILE_BYTES,
        "public key file exceeds {MAX_PUBLIC_KEY_FILE_BYTES} bytes"
    );
    fs::read_to_string(path).with_context(|| format!("cannot read public key: {}", path.display()))
}
