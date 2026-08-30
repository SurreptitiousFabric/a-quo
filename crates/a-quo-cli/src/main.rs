#[cfg(any(test, not(target_os = "linux")))]
use std::fs;
use std::fs::File;
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::io::{Read, Write};
#[cfg(all(unix, not(target_os = "linux")))]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a_quo_c2pa::{
    CawgIdentityStatus, ClaimSignatureStatus, MediaOutcome, MediaVerificationReport,
    run_launcher as run_c2pa_launcher, run_worker as run_c2pa_worker, verify_media,
};
use a_quo_core::{
    DOMAIN_DEFAULT_VALIDITY_SECONDS, DOMAIN_MAX_VALIDITY_SECONDS, MAX_CONTINUITY_TRANSITIONS,
    MAX_PERSONA_ROOT_CARD_BYTES, MAX_PERSONA_ROOT_PIN_BYTES, MAX_PROOF_BYTES,
    MAX_RECOVERY_AUTHORITIES, MAX_RECOVERY_CEREMONY_REQUEST_BYTES,
    MAX_RECOVERY_CEREMONY_RESPONSE_BYTES, MAX_RECOVERY_CEREMONY_RESPONSES,
    MAX_RECOVERY_CEREMONY_VALIDITY_SECONDS, MAX_RECOVERY_POLICY_VALIDITY_SECONDS,
    MAX_RECOVERY_POLICY_VERSIONS, MAX_TERMINAL_PERSONA_REVOCATION_SEQUENCE,
    MIN_RECOVERY_AUTHORITIES, PersonaContinuityCheckpoint, PersonaContinuityTransitionProof,
    PersonaRootCard, PersonaRootMatchStatus, PersonaRootPin, PersonaRootPinChannel,
    PersonaRootProof, PersonaRootTrustBasis, PersonaTransitionProof, ProofBundle,
    RECOVERY_POLICY_STATEMENT_SCHEMA_V2, RecoveryCeremonyRequest, RecoveryCeremonyResponse,
    RecoveryContinuityCheckpoint, RecoveryPolicyAuthorization, RecoveryPolicyCapability,
    RecoveryPolicyChainReport, RecoveryPolicyProof, RecoveryPolicyTimeStatus, RecoverySigner,
    RecoveryTransitionProof, RecoveryTransitionReason, TerminalPersonaRevocationProof,
    TerminalPersonaRevocationReason, VerifiedPersonaRoot, VerifiedRecoveryPolicy,
    assemble_recovery_ceremony_proof, canonical_domain_control_statement_bytes,
    canonical_persona_root_card_bytes, canonical_persona_root_pin_bytes,
    canonical_persona_root_statement_bytes, canonical_recovery_ceremony_request_bytes,
    canonical_recovery_ceremony_response_bytes, compare_persona_root_distribution,
    create_initial_recovery_policy_proof, create_persona_root_proof,
    create_recovery_policy_update_proof, create_recovery_transition_proof,
    create_routine_transition_proof, create_sshsig_proof, create_terminal_persona_revocation_proof,
    default_proof_path, describe_artifact, describe_open_artifact, inspect_domain_control_proof,
    inspect_proof, inspect_recovery_transition_proof, inspect_terminal_persona_revocation_proof,
    load_proof, new_domain_control_statement, new_initial_recovery_policy_statement,
    new_initial_recovery_policy_statement_with_capabilities, new_persona_root_pin,
    new_persona_root_statement, new_recovery_ceremony_request,
    new_recovery_policy_update_statement, new_recovery_policy_update_statement_with_capabilities,
    new_recovery_transition_ceremony_statement, new_recovery_transition_statement,
    new_routine_transition_statement, parse_persona_continuity_transition_proof_bytes,
    parse_persona_root_card_bytes, parse_persona_root_pin_bytes, parse_persona_root_pin_uri,
    parse_persona_root_proof_bytes, parse_persona_transition_proof_bytes,
    parse_recovery_ceremony_request_bytes, parse_recovery_ceremony_response_bytes,
    parse_recovery_policy_proof_bytes, parse_recovery_transition_proof_bytes,
    parse_terminal_persona_revocation_proof_bytes, persona_root_card_from_proof,
    public_key_fingerprint, review_domain_control_statement, review_persona_root_statement,
    review_persona_transition_statement, validate_persona_root_pin, verify_domain_control_proof,
    verify_initial_recovery_policy_proof, verify_persona_continuity_chain,
    verify_persona_continuity_chain_at_checkpoint, verify_persona_continuity_chain_with_recovery,
    verify_persona_continuity_chain_with_recovery_at_checkpoint, verify_persona_root_proof,
    verify_persona_transition_proof, verify_recovery_ceremony_request,
    verify_recovery_ceremony_response, verify_recovery_policy_chain_with_verified_sequence,
    verify_recovery_policy_update_proof, verify_recovery_transition_proof, verify_sshsig_proof,
    verify_sshsig_proof_for_descriptor, verify_terminal_persona_revocation_proof, write_proof_new,
};
use a_quo_domain::{
    DnssecStatus, DomainControlStatus, LiveDomainControlVerification, PublicationStatus,
    verify_domain_control_live,
};
#[cfg(target_os = "linux")]
use a_quo_ipc::{
    ArtifactKind as IpcArtifactKind, MAX_RECOVERY_PARTICIPATION_REQUEST_BYTES,
    RecoveryParticipantKeyProvider, RejectionCode, SignRequest as IpcSignRequest, SignResponse,
    TransitionKeyProvider, connect_consent_socket, receive_sign_response, send_sign_request,
    snapshot_stream,
};
use a_quo_omarchy::{
    PluginInspection, PublisherRegistryStatus, inspect_signed_package, install_signed_package,
    uninstall_managed_plugin, update_signed_package,
};
use a_quo_root_card::{
    MAX_ROOT_CARD_HTML_BYTES, MAX_ROOT_CARD_TEXT_BYTES, render_root_card_html,
    render_root_card_text,
};
use a_quo_store::{
    BackupContinuityArchive, BackupContinuityExpectedPins, BackupContinuityHeadRelation,
    BackupContinuityVerificationReport, BackupPersonaRootEvidence, BackupRecoveryPolicyEvidence,
    BackupTerminalPersonaRevocationEvidence, BackupTransitionEvidence,
    DirectArchiveActivationRequest, DirectArchiveSignerBinding, ExpectedBackupContinuityPolicy,
    KeyProvider, KeyStatus, MAX_PERSONA_BACKUP_BYTES, MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS,
    MAX_PERSONA_BACKUP_RECOVERY_POLICIES, PERSONA_BACKUP_V1_SCHEMA, PersonaAuthorityDisposition,
    PersonaBackup, PersonaListingAuthorityDisposition, PersonaPurpose, PersonaStore, RecognizedKey,
    RecoveryArchiveActivationRequest, RecoveryArchiveSignerBinding, RecoveryTransitionIntent,
    RotationReason, RoutineTransitionIntent, TerminalArchiveHydrationRequest,
    compare_persona_backup_continuity, parse_persona_backup_bytes, validate_persona_backup,
    verify_persona_backup_continuity, verify_persona_backup_for_import,
};
use a_quo_supply_chain::{
    AttestationKind, SupplyChainOutcome, SupplyChainVerificationReport,
    run_launcher as run_sigstore_launcher, run_worker as run_sigstore_worker,
    verify_bundle as verify_sigstore_bundle,
};
use anyhow::{Context, Result, bail, ensure};
use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
#[cfg(target_os = "linux")]
use rustix::fs::{Mode, OFlags, open};
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use tempfile::tempfile;

const MAX_PUBLIC_KEY_FILE_BYTES: u64 = 16_384;
/// Aggregate raw proof and public-key bytes accepted by one continuity command.
///
/// 64 MiB accommodates thousands of ordinary compact proofs while preventing the
/// independent per-file and count ceilings from composing into multi-gigabyte input.
const MAX_CONTINUITY_COMMAND_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Operational ceiling on cryptographic signature checks performed by one
/// continuity command. This is a local work bound, not a protocol-validity
/// limit; valid larger histories must be verified in bounded segments.
const MAX_CONTINUITY_COMMAND_SIGNATURE_VERIFICATIONS: usize = 2_048;
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

    /// Create and verify persona-specific key-continuity evidence.
    Continuity {
        #[command(subcommand)]
        command: ContinuityCommands,
    },

    /// Verify embedded C2PA media provenance without network access.
    Media {
        #[command(subcommand)]
        command: MediaCommands,
    },

    /// Verify offline Sigstore bundles and authenticated supply-chain attestations.
    SupplyChain {
        #[command(subcommand)]
        command: SupplyChainCommands,
    },

    #[command(name = "__c2pa-worker", hide = true)]
    C2paWorker {
        #[arg(long)]
        asset: PathBuf,
    },

    #[command(name = "__c2pa-launcher", hide = true)]
    C2paLauncher {
        #[arg(long)]
        expected_sha256: String,

        #[arg(long)]
        expected_size: u64,

        #[arg(long)]
        extension: String,
    },

    #[command(name = "__sigstore-worker", hide = true)]
    SigstoreWorker {
        #[arg(long)]
        input: PathBuf,

        #[arg(long)]
        artifact_sha256: String,

        #[arg(long)]
        artifact_size: u64,

        #[arg(long)]
        identity: String,

        #[arg(long)]
        issuer: String,
    },

    #[command(name = "__sigstore-launcher", hide = true)]
    SigstoreLauncher {
        #[arg(long)]
        artifact_sha256: String,

        #[arg(long)]
        artifact_size: u64,

        #[arg(long)]
        expected_frame_sha256: String,

        #[arg(long)]
        expected_frame_size: u64,

        #[arg(long)]
        identity: String,

        #[arg(long)]
        issuer: String,
    },
}

#[derive(Debug, Subcommand)]
enum MediaCommands {
    /// Verify an embedded local C2PA manifest in an isolated worker.
    Verify {
        asset: PathBuf,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SupplyChainCommands {
    /// Verify a standard Sigstore v0.3 bundle with an explicit local trust root.
    VerifyBundle {
        artifact: PathBuf,

        /// Standardized Sigstore v0.3 JSON bundle.
        #[arg(long)]
        bundle: PathBuf,

        /// Explicit local Sigstore trusted-root JSON snapshot.
        #[arg(long)]
        trusted_root: PathBuf,

        /// Exact certificate subject identity required by policy.
        #[arg(long)]
        identity: String,

        /// Exact Fulcio OIDC issuer required by policy.
        #[arg(long)]
        issuer: String,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
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
enum ContinuityCommands {
    /// Ask the private Linux daemon to approve and sign a new persona root.
    RootRequest {
        /// Registered local persona whose active key will create the root.
        #[arg(long)]
        persona_id: String,

        /// New root-proof file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,

        /// Private daemon socket; defaults to $XDG_RUNTIME_DIR/a-quo/consent.sock.
        #[arg(long)]
        socket: Option<PathBuf>,
    },

    /// Low-level direct signing of a new self-asserted persona root.
    RootCreate {
        #[arg(long)]
        persona: String,

        /// Initial private key or SSH-agent/FIDO stub understood by ssh-keygen.
        #[arg(long)]
        key: PathBuf,

        /// OpenSSH public key corresponding to --key.
        #[arg(long)]
        public_key: PathBuf,

        /// New root-proof file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify a self-signed root and print the digest others must pin separately.
    RootVerify {
        proof: PathBuf,

        #[arg(long)]
        json: bool,
    },

    /// Export a verified self-asserted root as a portable public card.
    RootCardExport {
        /// Verified persona-root proof to summarize.
        #[arg(long)]
        root: PathBuf,

        /// One of: json, text, html. HTML is a standalone printable QR card.
        #[arg(long, value_enum)]
        format: RootCardFormatArgument,

        /// New card file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Record a portable root pin and how the user says it was obtained.
    #[command(group(
        ArgGroup::new("root_pin_source")
            .required(true)
            .multiple(false)
            .args(["from_root", "pin_uri"])
    ))]
    RootPinCreate {
        /// Verified root proof used for TOFU or an explicitly same-channel copy.
        #[arg(long)]
        from_root: Option<PathBuf>,

        /// Full digest-only pin URI obtained separately from the candidate proof.
        #[arg(long)]
        pin_uri: Option<String>,

        /// How this pin was obtained; this is user-recorded provenance, not a credential.
        #[arg(long, value_enum)]
        basis: RootPinBasisArgument,

        /// Carrier used for the observation; A Quo does not infer independence from it.
        #[arg(long, value_enum)]
        channel: RootPinChannelArgument,

        /// Record at this Unix time; defaults to the current clock.
        #[arg(long)]
        at_unix: Option<i64>,

        /// Exact reviewed digest required to publish a --from-root pin.
        #[arg(long)]
        accept_root_sha256: Option<String>,

        /// New pin-record file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Inspect an unsigned local pin record without checking a root proof.
    RootPinInspect {
        pin: PathBuf,

        #[arg(long)]
        json: bool,
    },

    /// Verify a root proof and compare it with a retained portable pin.
    RootPinCompare {
        #[arg(long)]
        root: PathBuf,

        #[arg(long)]
        pin: PathBuf,

        /// Optional public card whose copied root fields must all match the proof.
        #[arg(long)]
        card: Option<PathBuf>,

        /// Evaluate observation age at this Unix time; defaults to the current clock.
        #[arg(long)]
        at_unix: Option<i64>,

        #[arg(long)]
        json: bool,
    },

    /// Ask the private Linux daemon to approve and atomically journal a routine key rotation.
    TransitionRequest {
        /// Registered continuity-managed persona whose current and next keys must both sign.
        #[arg(long)]
        persona_id: String,

        /// Persona-root statement SHA-256 obtained through a separate trusted channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Proposed private key, FIDO stub, or SSH-agent public-key stub used by ssh-keygen.
        #[arg(long)]
        next_key: PathBuf,

        /// Matching proposed OpenSSH public key; passed to the daemon as a bounded descriptor.
        #[arg(long)]
        next_public_key: PathBuf,

        /// One of: openssh-file, ssh-agent, fido2.
        #[arg(long)]
        next_provider: String,

        /// New transition-proof file; an exact prior result is accepted on retry.
        #[arg(short, long)]
        output: PathBuf,

        /// Private daemon socket; defaults to $XDG_RUNTIME_DIR/a-quo/consent.sock.
        #[arg(long)]
        socket: Option<PathBuf>,
    },

    /// Low-level direct dual-signing of the next routine key transition.
    TransitionCreate {
        /// Verified persona root proof.
        #[arg(long)]
        root: PathBuf,

        /// Existing transition proof, repeated in sequence order.
        #[arg(long = "prior-transition")]
        prior_transitions: Vec<PathBuf>,

        /// Recovery policy proof, repeated in version order when prior history contains recovery.
        #[arg(long = "policy")]
        recovery_policies: Vec<PathBuf>,

        /// Independently obtained latest-policy digest; required with recovery history.
        #[arg(long)]
        expected_policy_sha256: Option<String>,

        /// Current private key or SSH-agent/FIDO stub.
        #[arg(long)]
        previous_key: PathBuf,

        /// Current OpenSSH public key.
        #[arg(long)]
        previous_public_key: PathBuf,

        /// Proposed private key or SSH-agent/FIDO stub.
        #[arg(long)]
        next_key: PathBuf,

        /// Proposed OpenSSH public key.
        #[arg(long)]
        next_public_key: PathBuf,

        /// New transition-proof file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify both signatures on one transition without claiming chain continuity.
    TransitionVerify {
        proof: PathBuf,

        #[arg(long)]
        json: bool,
    },

    /// Verify an ordered chain against an independently obtained root digest.
    ChainVerify {
        #[arg(long)]
        root: PathBuf,

        /// Transition proof, repeated in sequence order.
        #[arg(long = "transition")]
        transitions: Vec<PathBuf>,

        /// Expected root-statement SHA-256 from a separate trusted channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Expected transition sequence from a separate trusted channel; zero names the root.
        #[arg(long)]
        expected_head_sequence: Option<u32>,

        /// Expected transition-statement SHA-256; required for a nonzero expected head.
        #[arg(long)]
        expected_head_sha256: Option<String>,

        #[arg(long)]
        json: bool,
    },

    /// Create a recovery policy; terminal revocation requires an explicit capability opt-in.
    RecoveryPolicyCreate {
        #[arg(long)]
        root: PathBuf,

        /// Existing routine transition, repeated in sequence order, to anchor at enrollment.
        #[arg(long = "prior-transition")]
        prior_transitions: Vec<PathBuf>,

        /// Required number of distinct recovery authority signatures (minimum 2).
        #[arg(long)]
        threshold: u32,

        /// Explicit policy lifetime in days; there is deliberately no hidden default.
        #[arg(long)]
        valid_days: u16,

        /// Explicitly authorize threshold terminal persona revocation in this policy.
        #[arg(long)]
        authorize_terminal_revocation: bool,

        /// Recovery-only private key or SSH-agent/FIDO stub; repeat once per authority.
        #[arg(long = "authority-key", required = true)]
        authority_keys: Vec<PathBuf>,

        /// Matching OpenSSH public key; repeat in the same order as --authority-key.
        #[arg(long = "authority-public-key", required = true)]
        authority_public_keys: Vec<PathBuf>,

        /// New policy-proof file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Replace a recovery policy using the old threshold and all newly listed keys.
    RecoveryPolicyUpdate {
        #[arg(long)]
        root: PathBuf,

        /// Existing policy proof, repeated from version 1 through the current version.
        #[arg(long = "policy", required = true)]
        policies: Vec<PathBuf>,

        /// Independently obtained persona-root statement SHA-256.
        #[arg(long)]
        expected_root_sha256: String,

        /// Independently obtained digest of the current recovery policy.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Existing routine or recovery transition, repeated in sequence order.
        #[arg(long = "transition")]
        transitions: Vec<PathBuf>,

        /// Threshold declared by the new policy (minimum 2).
        #[arg(long)]
        threshold: u32,

        /// Explicit new policy lifetime in days; there is no hidden default.
        #[arg(long)]
        valid_days: u16,

        /// Include terminal revocation in the new policy; omission removes it (v2 stays v2).
        #[arg(long)]
        authorize_terminal_revocation: bool,

        /// Old-policy authority key approving the update; repeat to meet its threshold.
        #[arg(long = "previous-authority-key", required = true)]
        previous_authority_keys: Vec<PathBuf>,

        /// Matching old-policy public key, in the same order.
        #[arg(long = "previous-authority-public-key", required = true)]
        previous_authority_public_keys: Vec<PathBuf>,

        /// Newly listed authority key; every new authority must prove possession.
        #[arg(long = "current-authority-key", required = true)]
        current_authority_keys: Vec<PathBuf>,

        /// Matching new-policy public key, in the same order.
        #[arg(long = "current-authority-public-key", required = true)]
        current_authority_public_keys: Vec<PathBuf>,

        /// New policy-proof file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify a policy chain against independently supplied root and latest-policy pins.
    RecoveryPolicyVerify {
        #[arg(long)]
        root: PathBuf,

        #[arg(long = "policy", required = true)]
        policies: Vec<PathBuf>,

        #[arg(long)]
        expected_root_sha256: String,

        #[arg(long)]
        expected_policy_sha256: String,

        /// Evaluate policy activity at this Unix time; defaults to the current clock.
        #[arg(long)]
        at_unix: Option<i64>,

        #[arg(long)]
        json: bool,
    },

    /// Record an already-signed recovery-policy chain in an existing persona journal.
    RecoveryPolicyRecord {
        /// Existing operational persona that owns the continuity journal.
        #[arg(long)]
        persona_id: String,

        /// Complete recovery-policy proof chain, repeated in version order.
        #[arg(long = "policy", required = true)]
        policies: Vec<PathBuf>,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Latest recovery-policy statement SHA-256 obtained independently.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Exact current transition sequence independently expected before recording.
        #[arg(long)]
        expected_head_sequence: u32,

        /// Exact current transition digest; required for a nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_head_sha256: Option<String>,
    },

    /// Replace an unavailable/compromised online key using an active policy threshold.
    RecoveryTransitionCreate {
        #[arg(long)]
        root: PathBuf,

        #[arg(long = "policy", required = true)]
        policies: Vec<PathBuf>,

        #[arg(long)]
        expected_root_sha256: String,

        #[arg(long)]
        expected_policy_sha256: String,

        /// Existing routine or recovery transition, repeated in sequence order.
        #[arg(long = "prior-transition")]
        prior_transitions: Vec<PathBuf>,

        /// Explicit reason shown in the signed statement.
        #[arg(long)]
        reason: RecoveryReasonArgument,

        /// Authorized recovery key; repeat to meet the active threshold.
        #[arg(long = "authority-key", required = true)]
        authority_keys: Vec<PathBuf>,

        /// Matching authority public key, in the same order.
        #[arg(long = "authority-public-key", required = true)]
        authority_public_keys: Vec<PathBuf>,

        /// Proposed new online signing key or SSH-agent/FIDO stub.
        #[arg(long)]
        next_key: PathBuf,

        /// Matching proposed OpenSSH public key.
        #[arg(long)]
        next_public_key: PathBuf,

        /// New recovery-transition proof; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Start a short-lived, portable multi-party recovery-transition ceremony.
    RecoveryTransitionCeremonyStart {
        /// Existing operational persona whose reverified public journal becomes the request.
        #[arg(long)]
        persona_id: String,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Latest recovery-policy statement SHA-256 obtained independently.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Exact current transition sequence independently expected before starting.
        #[arg(long)]
        expected_previous_head_sequence: u32,

        /// Exact prior transition digest; required for a nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_previous_head_sha256: Option<String>,

        /// Explicit reason covered by every participant signature.
        #[arg(long)]
        reason: RecoveryReasonArgument,

        /// Proposed successor OpenSSH public key.
        #[arg(long)]
        next_public_key: PathBuf,

        /// Signed response deadline in minutes; maximum seven days and no later than policy expiry.
        #[arg(long)]
        valid_minutes: u16,

        /// New canonical ceremony-request file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Independently verify and consent to one role in a recovery ceremony.
    RecoveryTransitionCeremonyRespond {
        /// Canonical portable ceremony request received from the coordinator.
        #[arg(long)]
        request: PathBuf,

        /// Persona-root statement SHA-256 obtained independently by this participant.
        #[arg(long)]
        expected_root_sha256: String,

        /// Latest recovery-policy statement SHA-256 obtained independently by this participant.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Exact prior transition sequence independently expected by this participant.
        #[arg(long)]
        expected_previous_head_sequence: u32,

        /// Exact prior transition digest; required for a nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_previous_head_sha256: Option<String>,

        /// One of: openssh-file, ssh-agent, fido2.
        #[arg(long)]
        participant_provider: String,

        /// Local participant signer locator; this is never included in the portable response.
        #[arg(long)]
        participant_signing_locator: PathBuf,

        /// OpenSSH public key for the local participant signer.
        #[arg(long)]
        participant_public_key: PathBuf,

        /// New canonical participant-response file; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,

        /// Private daemon socket; defaults to $XDG_RUNTIME_DIR/a-quo/consent.sock.
        #[arg(long)]
        socket: Option<PathBuf>,
    },

    /// Verify participant responses and assemble the existing recovery-transition proof.
    RecoveryTransitionCeremonyAssemble {
        /// Exact canonical request to which every response must bind.
        #[arg(long)]
        request: PathBuf,

        /// Participant response; repeat for the threshold authorities and exact successor key.
        #[arg(long = "response", required = true)]
        responses: Vec<PathBuf>,

        /// Persona-root statement SHA-256 independently expected by the assembler.
        #[arg(long)]
        expected_root_sha256: String,

        /// Latest recovery-policy statement SHA-256 independently expected by the assembler.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Exact prior transition sequence independently expected by the assembler.
        #[arg(long)]
        expected_previous_head_sequence: u32,

        /// Exact prior transition digest; required for a nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_previous_head_sha256: Option<String>,

        /// New recovery-transition proof; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify one recovery transition and its policy authority, but not its chain position.
    RecoveryTransitionVerify {
        proof: PathBuf,

        #[arg(long)]
        root: PathBuf,

        #[arg(long = "policy", required = true)]
        policies: Vec<PathBuf>,

        #[arg(long)]
        expected_root_sha256: String,

        #[arg(long)]
        expected_policy_sha256: String,

        #[arg(long)]
        json: bool,
    },

    /// Commit an already-signed threshold recovery transition to an existing journal.
    RecoveryTransitionCommit {
        /// Existing operational persona whose live continuity head will advance.
        #[arg(long)]
        persona_id: String,

        /// Already-signed recovery-transition proof to verify and commit.
        #[arg(long)]
        proof: PathBuf,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Latest recovery-policy statement SHA-256 obtained independently.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Exact transition sequence independently expected immediately before this commit.
        #[arg(long)]
        expected_previous_head_sequence: u32,

        /// Exact prior transition digest; required for a nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_previous_head_sha256: Option<String>,

        /// One of: openssh-file, ssh-agent, fido2. Supply with locator for a first commit.
        #[arg(long, requires = "next_signing_locator")]
        next_provider: Option<String>,

        /// Local signer locator. Omit both binding options only for an exact current-head replay.
        #[arg(long, requires = "next_provider")]
        next_signing_locator: Option<PathBuf>,
    },

    /// Create a threshold-authorized, no-successor terminal persona revocation.
    TerminalRevocationCreate {
        #[arg(long)]
        root: PathBuf,

        #[arg(long = "policy", required = true)]
        policies: Vec<PathBuf>,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Latest recovery-policy statement SHA-256 obtained independently.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Existing routine or recovery transition, repeated in sequence order.
        #[arg(long = "prior-transition")]
        prior_transitions: Vec<PathBuf>,

        /// Exact independently expected head sequence immediately before revocation.
        #[arg(long)]
        expected_previous_head_sequence: u32,

        /// Exact prior transition digest; required for nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_previous_head_sha256: Option<String>,

        /// Why the persona is ending: compromise or cessation.
        #[arg(long)]
        reason: TerminalRevocationReasonArgument,

        /// Authorized recovery key; repeat to meet the active threshold.
        #[arg(long = "authority-key", required = true)]
        authority_keys: Vec<PathBuf>,

        /// Matching authority public key, in the same order.
        #[arg(long = "authority-public-key", required = true)]
        authority_public_keys: Vec<PathBuf>,

        /// New terminal-revocation proof; existing paths are never overwritten.
        #[arg(short, long)]
        output: PathBuf,

        /// Emit machine-readable JSON after the proof is safely written.
        #[arg(long)]
        json: bool,
    },

    /// Verify threshold authority for one terminal revocation, but not its chain position.
    TerminalRevocationVerify {
        proof: PathBuf,

        #[arg(long)]
        root: PathBuf,

        #[arg(long = "policy", required = true)]
        policies: Vec<PathBuf>,

        #[arg(long)]
        expected_root_sha256: String,

        #[arg(long)]
        expected_policy_sha256: String,

        #[arg(long)]
        json: bool,
    },

    /// Commit an already-signed terminal revocation and permanently end a live persona.
    TerminalRevocationCommit {
        #[arg(long)]
        persona_id: String,

        #[arg(long)]
        proof: PathBuf,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Latest recovery-policy statement SHA-256 obtained independently.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Exact independently expected head sequence immediately before revocation.
        #[arg(long)]
        expected_previous_head_sequence: u32,

        /// Exact prior transition digest; required for nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_previous_head_sha256: Option<String>,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Verify an ordered mixed routine/recovery chain and its pinned policy chain.
    RecoveryChainVerify {
        #[arg(long)]
        root: PathBuf,

        #[arg(long = "policy", required = true)]
        policies: Vec<PathBuf>,

        #[arg(long = "transition")]
        transitions: Vec<PathBuf>,

        /// Optional terminal-revocation proof; it is always the final continuity event.
        #[arg(long)]
        terminal_revocation: Option<PathBuf>,

        #[arg(long)]
        expected_root_sha256: String,

        #[arg(long)]
        expected_policy_sha256: String,

        /// Expected transition sequence from a separate trusted channel; zero names the root.
        #[arg(long)]
        expected_head_sequence: Option<u32>,

        /// Expected transition-statement SHA-256; required for a nonzero expected head.
        #[arg(long)]
        expected_head_sha256: Option<String>,

        /// Report latest-policy activity at this Unix time; defaults to current clock.
        #[arg(long)]
        at_unix: Option<i64>,

        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RootCardFormatArgument {
    Json,
    Text,
    Html,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RootPinBasisArgument {
    TrustOnFirstUse,
    SameChannelCopy,
    OutOfBandUserConfirmed,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RootPinChannelArgument {
    InPerson,
    Paper,
    Qr,
    Voice,
    File,
    Other,
}

impl From<RootPinBasisArgument> for PersonaRootTrustBasis {
    fn from(value: RootPinBasisArgument) -> Self {
        match value {
            RootPinBasisArgument::TrustOnFirstUse => Self::TrustOnFirstUse,
            RootPinBasisArgument::SameChannelCopy => Self::SameChannelCopy,
            RootPinBasisArgument::OutOfBandUserConfirmed => Self::OutOfBandUserConfirmed,
        }
    }
}

impl From<RootPinChannelArgument> for PersonaRootPinChannel {
    fn from(value: RootPinChannelArgument) -> Self {
        match value {
            RootPinChannelArgument::InPerson => Self::InPerson,
            RootPinChannelArgument::Paper => Self::Paper,
            RootPinChannelArgument::Qr => Self::Qr,
            RootPinChannelArgument::Voice => Self::Voice,
            RootPinChannelArgument::File => Self::File,
            RootPinChannelArgument::Other => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RecoveryReasonArgument {
    Recovery,
    Compromise,
}

impl From<RecoveryReasonArgument> for RecoveryTransitionReason {
    fn from(value: RecoveryReasonArgument) -> Self {
        match value {
            RecoveryReasonArgument::Recovery => Self::Recovery,
            RecoveryReasonArgument::Compromise => Self::Compromise,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TerminalRevocationReasonArgument {
    Compromise,
    Cessation,
}

impl From<TerminalRevocationReasonArgument> for TerminalPersonaRevocationReason {
    fn from(value: TerminalRevocationReasonArgument) -> Self {
        match value {
            TerminalRevocationReasonArgument::Compromise => Self::Compromise,
            TerminalRevocationReasonArgument::Cessation => Self::Cessation,
        }
    }
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
    /// Bulk listing does not cryptographically verify operational authority;
    /// unarchived authority is `not_checked` and is reverified on use.
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

        /// Persona-root proof to include with externally supplied continuity evidence.
        #[arg(long, value_name = "ROOT_PROOF")]
        root: Option<PathBuf>,

        /// Recovery-policy proof to include, repeated in version order.
        #[arg(
            long = "recovery-policy",
            value_name = "POLICY_PROOF",
            requires = "root"
        )]
        recovery_policies: Vec<PathBuf>,

        /// Routine or recovery transition proof to include, repeated in sequence order.
        #[arg(
            long = "transition",
            value_name = "ROUTINE_OR_RECOVERY_PROOF",
            requires = "root"
        )]
        transitions: Vec<PathBuf>,

        /// Final terminal-revocation proof; it cannot appear in --transition.
        #[arg(long, value_name = "TERMINAL_REVOCATION_PROOF", requires = "root")]
        terminal_revocation: Option<PathBuf>,

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

    /// Compare a verified evidence archive with independently obtained pins.
    #[command(group(
        ArgGroup::new("policy_expectation")
            .required(true)
            .multiple(false)
            .args(["expect_no_recovery_policy", "expected_policy_version"])
    ))]
    BackupCompare {
        input: PathBuf,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Exact independently expected effective-head sequence; zero names the root.
        #[arg(long)]
        expected_head_sequence: u32,

        /// Exact effective-head digest; required for a nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_head_sha256: Option<String>,

        /// Explicitly require the archive to contain no recovery-policy chain.
        #[arg(long)]
        expect_no_recovery_policy: bool,

        /// Exact independently expected latest recovery-policy version.
        #[arg(long, requires = "expected_policy_sha256")]
        expected_policy_version: Option<u32>,

        /// Exact independently expected latest recovery-policy statement SHA-256.
        #[arg(long, requires = "expected_policy_version")]
        expected_policy_sha256: Option<String>,

        /// Emit a machine-readable comparison report without public-key contents.
        #[arg(long)]
        json: bool,
    },

    /// Activate an imported continuity archive after exact pin and signer-custody checks.
    #[command(group(
        ArgGroup::new("activation_policy_expectation")
            .required(true)
            .multiple(false)
            .args(["expect_no_recovery_policy", "expected_policy_version"])
    ))]
    BackupActivateDirect {
        /// Local ID of the already-imported, quarantined persona archive.
        #[arg(long)]
        persona_id: String,

        /// Exact archive SHA-256 reported by inspection/comparison and checked independently.
        #[arg(long)]
        expected_archive_sha256: String,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Exact independently expected effective-head sequence; zero names the root.
        #[arg(long)]
        expected_head_sequence: u32,

        /// Exact effective-head digest; required for a nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_head_sha256: Option<String>,

        /// Explicitly require the archive to contain no recovery-policy chain.
        #[arg(long)]
        expect_no_recovery_policy: bool,

        /// Exact independently expected latest recovery-policy version.
        #[arg(long, requires = "expected_policy_sha256")]
        expected_policy_version: Option<u32>,

        /// Exact independently expected latest recovery-policy statement SHA-256.
        #[arg(long, requires = "expected_policy_version")]
        expected_policy_sha256: Option<String>,

        /// Exact fingerprint of the key that must be current at the pinned head.
        #[arg(long)]
        expected_current_key_fingerprint: String,

        /// Explicit signer provider for first activation; omit only for exact sealed replay.
        #[arg(long, requires = "current_signing_locator")]
        current_provider: Option<String>,

        /// Private key, FIDO stub, or agent public-key stub; paired with --current-provider.
        #[arg(long, value_name = "PATH", requires = "current_provider")]
        current_signing_locator: Option<PathBuf>,

        /// Emit the sealed activation receipt and its precise evidence as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Recover an imported archive into one exact signed successor head.
    BackupActivateRecovery {
        /// Local ID of the already-imported, quarantined persona archive.
        #[arg(long)]
        persona_id: String,

        /// Recovery transition that must extend the exact pinned source head.
        #[arg(long, value_name = "RECOVERY_PROOF")]
        proof: PathBuf,

        /// Exact archive SHA-256 reported by comparison and checked independently.
        #[arg(long)]
        expected_archive_sha256: String,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Exact independently expected source-head sequence; zero names the root.
        #[arg(long)]
        expected_head_sequence: u32,

        /// Exact source-head digest; required for a nonzero sequence and forbidden for zero.
        #[arg(long)]
        expected_head_sha256: Option<String>,

        /// Exact independently expected latest recovery-policy version.
        #[arg(long, requires = "expected_policy_sha256")]
        expected_policy_version: u32,

        /// Exact independently expected latest recovery-policy statement SHA-256.
        #[arg(long, requires = "expected_policy_version")]
        expected_policy_sha256: String,

        /// Explicit successor signer provider for first activation; omit on exact sealed replay.
        #[arg(long, requires = "next_signing_locator")]
        next_provider: Option<String>,

        /// Successor private key, FIDO stub, or agent public-key stub; paired with --next-provider.
        #[arg(long, value_name = "PATH", requires = "next_provider")]
        next_signing_locator: Option<PathBuf>,

        /// Emit the sealed recovery-activation receipt and its precise evidence as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Hydrate an exact terminal archive as frozen, inspectable zero-authority state.
    BackupHydrateTerminal {
        /// Local ID of the already-imported, quarantined terminal persona archive.
        #[arg(long)]
        persona_id: String,

        /// Exact archive SHA-256 reported by comparison and checked independently.
        #[arg(long)]
        expected_archive_sha256: String,

        /// Persona-root statement SHA-256 obtained through an independent channel.
        #[arg(long)]
        expected_root_sha256: String,

        /// Exact final terminal-leaf sequence, never the preterminal SQL-head sequence.
        #[arg(long)]
        expected_head_sequence: u32,

        /// Exact final terminal-revocation statement SHA-256.
        #[arg(long)]
        expected_head_sha256: String,

        /// Exact independently expected latest recovery-policy version.
        #[arg(long)]
        expected_policy_version: u32,

        /// Exact independently expected latest recovery-policy statement SHA-256.
        #[arg(long)]
        expected_policy_sha256: String,

        /// Emit the sealed zero-authority hydration receipt as JSON.
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

    /// Install a verified plugin atomically without asking Omarchy to enable it.
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

        /// Accept that no behavioural reviewer analysed what the plugin may do.
        #[arg(long)]
        accept_behavioral_analysis_not_run: bool,
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

        /// Accept that no behavioural reviewer analysed what the plugin may do.
        #[arg(long)]
        accept_behavioral_analysis_not_run: bool,
    },

    /// Remove an unreferenced managed plugin and retain a recovery quarantine.
    Uninstall {
        /// Exact Omarchy plugin ID to remove.
        plugin_id: String,

        /// Override the Omarchy plugins directory.
        #[arg(long)]
        plugins_directory: Option<PathBuf>,

        /// Confirm removal after disabling and unreferencing the plugin in Omarchy.
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
        Commands::Continuity { command } => continuity_command(store.as_deref(), command),
        Commands::Media { command } => media_command(command),
        Commands::SupplyChain { command } => supply_chain_command(command),
        Commands::C2paWorker { asset } => run_c2pa_worker(&asset).map_err(Into::into),
        Commands::C2paLauncher {
            expected_sha256,
            expected_size,
            extension,
        } => run_c2pa_launcher(&expected_sha256, expected_size, &extension).map_err(Into::into),
        Commands::SigstoreWorker {
            input,
            artifact_sha256,
            artifact_size,
            identity,
            issuer,
        } => run_sigstore_worker(&input, &artifact_sha256, artifact_size, &identity, &issuer)
            .map_err(Into::into),
        Commands::SigstoreLauncher {
            artifact_sha256,
            artifact_size,
            expected_frame_sha256,
            expected_frame_size,
            identity,
            issuer,
        } => run_sigstore_launcher(
            &artifact_sha256,
            artifact_size,
            &expected_frame_sha256,
            expected_frame_size,
            &identity,
            &issuer,
        )
        .map_err(Into::into),
    }
}

fn supply_chain_command(command: SupplyChainCommands) -> Result<()> {
    match command {
        SupplyChainCommands::VerifyBundle {
            artifact,
            bundle,
            trusted_root,
            identity,
            issuer,
            json,
        } => {
            verify_supply_chain_bundle(&artifact, &bundle, &trusted_root, &identity, &issuer, json)
        }
    }
}

fn verify_supply_chain_bundle(
    artifact: &Path,
    bundle: &Path,
    trusted_root: &Path,
    identity: &str,
    issuer: &str,
    emit_json: bool,
) -> Result<()> {
    let report = verify_sigstore_bundle(artifact, bundle, trusted_root, identity, issuer)?;
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_supply_chain_report(&report);
    }
    ensure!(
        report.is_verified(),
        "Sigstore verification did not satisfy every required cryptographic and identity check"
    );
    Ok(())
}

fn print_supply_chain_report(report: &SupplyChainVerificationReport) {
    let outcome = match report.outcome {
        SupplyChainOutcome::Verified => "VERIFIED SIGSTORE SUPPLY-CHAIN EVIDENCE",
        SupplyChainOutcome::Invalid => "INVALID SIGSTORE SUPPLY-CHAIN EVIDENCE",
    };
    println!("{outcome}");
    println!("Artifact SHA-256: {}", report.artifact.digest.value);
    println!("Artifact size: {} bytes", report.artifact.size);
    println!("Bundle SHA-256: {}", report.bundle.digest.value);
    println!("Trusted-root SHA-256: {}", report.trusted_root.digest.value);
    if let Some(failure) = report.failure {
        println!("Failure code: {failure:?}");
    }
    println!(
        "Expected signer: {} (issuer {})",
        report.signer_policy.expected_identity, report.signer_policy.expected_issuer
    );
    if let Some(identity) = &report.signer_policy.actual_identity {
        println!("Verified certificate identity: {identity}");
    }
    if let Some(issuer) = &report.signer_policy.actual_issuer {
        println!("Verified certificate issuer: {issuer}");
    }
    println!(
        "Transparency entries verified: {}",
        report.evidence.verified_transparency_entries
    );
    println!(
        "RFC 3161 timestamps verified: {}",
        report.evidence.verified_rfc3161_timestamps
    );
    if let Some(integrated_time) = report.evidence.integrated_time_unix {
        println!("Rekor integrated time (Unix): {integrated_time}");
    }
    if let Some(attestation) = &report.attestation {
        match attestation.kind {
            AttestationKind::BlobSignature => println!("Attestation: signed blob"),
            AttestationKind::InTotoStatement => println!("Attestation: in-toto Statement v1"),
        }
        if let Some(predicate_type) = &attestation.predicate_type {
            println!("Authenticated predicate type: {predicate_type}");
        }
        if let Some(slsa) = &attestation.slsa_provenance {
            println!("Claimed builder ID: {}", slsa.builder_id);
            println!("Claimed build type: {}", slsa.build_type);
            println!("SLSA expectations: not evaluated");
            println!("SLSA Build level: not established");
        }
    }
    println!("Network: blocked by Linux namespaces");
    println!("Trust-root freshness: not established");
    println!("A Quo persona link: not established");
    println!(
        "Not established: build expectations, reproducibility, review, runtime safety, quality, or legal identity."
    );
}

fn media_command(command: MediaCommands) -> Result<()> {
    match command {
        MediaCommands::Verify { asset, json } => verify_media_command(&asset, json),
    }
}

fn verify_media_command(asset: &Path, emit_json: bool) -> Result<()> {
    let report = verify_media(asset)?;
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_media_report(&report);
    }
    ensure!(
        report.is_valid(),
        "local C2PA validation did not establish valid embedded provenance"
    );
    Ok(())
}

fn print_media_report(report: &MediaVerificationReport) {
    let outcome = match report.outcome {
        MediaOutcome::Valid => "VALID LOCAL C2PA CONTENT BINDING",
        MediaOutcome::Invalid => "INVALID C2PA CONTENT BINDING",
        MediaOutcome::Unavailable => "C2PA PROVENANCE NOT AVAILABLE",
    };
    println!("{outcome}");
    println!("SHA-256: {}", report.artifact.digest.value);
    println!("Size: {} bytes", report.artifact.size);
    let signature = match report.claim_signature.status {
        ClaimSignatureStatus::ValidatedAsPartOfManifest => "validated as part of the C2PA manifest",
        ClaimSignatureStatus::PresentButManifestInvalid => {
            "present, but the overall C2PA manifest is invalid"
        }
        ClaimSignatureStatus::NotAvailable => "not available",
    };
    println!("Claim signature: {signature}");
    if let Some(generator) = &report.claim_generator {
        println!("Claim generator: {generator}");
    }
    if let Some(issuer) = &report.claim_signature.certificate_issuer {
        println!("Certificate issuer: {issuer}");
    }
    if let Some(common_name) = &report.claim_signature.certificate_common_name {
        println!("Certificate name: {common_name}");
    }
    let cawg = match report.cawg_identity {
        CawgIdentityStatus::Absent => "absent",
        CawgIdentityStatus::PresentUnassessed => "present, but not identity-trusted by A Quo",
        CawgIdentityStatus::NotAvailable => "not available",
    };
    println!("CAWG identity assertion: {cawg}");
    println!("Certificate trust: not checked");
    println!("Network: blocked; remote manifests were not fetched");
    println!("A Quo persona link: not established");
    if !report.validation_failures.is_empty() {
        println!(
            "Validation failure codes: {}",
            report.validation_failures.join(", ")
        );
    }
    println!("Not established: creator legal identity, truth, originality, safety, or quality.");
}

fn continuity_command(store_path: Option<&Path>, command: ContinuityCommands) -> Result<()> {
    match command {
        ContinuityCommands::RootRequest {
            persona_id,
            output,
            socket,
        } => request_continuity_root(store_path, &persona_id, &output, socket.as_deref()),
        ContinuityCommands::RootCreate {
            persona,
            key,
            public_key,
            output,
        } => create_continuity_root(&persona, &key, &public_key, &output),
        ContinuityCommands::RootVerify { proof, json } => verify_continuity_root(&proof, json),
        ContinuityCommands::RootCardExport {
            root,
            format,
            output,
        } => export_continuity_root_card(&root, format, &output),
        ContinuityCommands::RootPinCreate {
            from_root,
            pin_uri,
            basis,
            channel,
            at_unix,
            accept_root_sha256,
            output,
        } => create_continuity_root_pin(
            from_root.as_deref(),
            pin_uri.as_deref(),
            basis,
            channel,
            at_unix,
            accept_root_sha256.as_deref(),
            &output,
        ),
        ContinuityCommands::RootPinInspect { pin, json } => inspect_continuity_root_pin(&pin, json),
        ContinuityCommands::RootPinCompare {
            root,
            pin,
            card,
            at_unix,
            json,
        } => compare_continuity_root_pin(&root, &pin, card.as_deref(), at_unix, json),
        ContinuityCommands::TransitionRequest {
            persona_id,
            expected_root_sha256,
            next_key,
            next_public_key,
            next_provider,
            output,
            socket,
        } => request_continuity_transition(
            store_path,
            &persona_id,
            &expected_root_sha256,
            &next_key,
            &next_public_key,
            &next_provider,
            &output,
            socket.as_deref(),
        ),
        ContinuityCommands::TransitionCreate {
            root,
            prior_transitions,
            recovery_policies,
            expected_policy_sha256,
            previous_key,
            previous_public_key,
            next_key,
            next_public_key,
            output,
        } => create_continuity_transition(
            &root,
            &prior_transitions,
            &recovery_policies,
            expected_policy_sha256.as_deref(),
            &previous_key,
            &previous_public_key,
            &next_key,
            &next_public_key,
            &output,
        ),
        ContinuityCommands::TransitionVerify { proof, json } => {
            verify_continuity_transition(&proof, json)
        }
        ContinuityCommands::ChainVerify {
            root,
            transitions,
            expected_root_sha256,
            expected_head_sequence,
            expected_head_sha256,
            json,
        } => verify_continuity_chain(
            &root,
            &transitions,
            &expected_root_sha256,
            expected_head_sequence,
            expected_head_sha256.as_deref(),
            json,
        ),
        ContinuityCommands::RecoveryPolicyCreate {
            root,
            prior_transitions,
            threshold,
            valid_days,
            authorize_terminal_revocation,
            authority_keys,
            authority_public_keys,
            output,
        } => create_recovery_policy(
            &root,
            &prior_transitions,
            threshold,
            valid_days,
            authorize_terminal_revocation,
            &authority_keys,
            &authority_public_keys,
            &output,
        ),
        ContinuityCommands::RecoveryPolicyUpdate {
            root,
            policies,
            expected_root_sha256,
            expected_policy_sha256,
            transitions,
            threshold,
            valid_days,
            authorize_terminal_revocation,
            previous_authority_keys,
            previous_authority_public_keys,
            current_authority_keys,
            current_authority_public_keys,
            output,
        } => update_recovery_policy(
            &root,
            &policies,
            &expected_root_sha256,
            &expected_policy_sha256,
            &transitions,
            threshold,
            valid_days,
            authorize_terminal_revocation,
            &previous_authority_keys,
            &previous_authority_public_keys,
            &current_authority_keys,
            &current_authority_public_keys,
            &output,
        ),
        ContinuityCommands::RecoveryPolicyVerify {
            root,
            policies,
            expected_root_sha256,
            expected_policy_sha256,
            at_unix,
            json,
        } => verify_recovery_policy_command(
            &root,
            &policies,
            &expected_root_sha256,
            &expected_policy_sha256,
            at_unix,
            json,
        ),
        ContinuityCommands::RecoveryPolicyRecord {
            persona_id,
            policies,
            expected_root_sha256,
            expected_policy_sha256,
            expected_head_sequence,
            expected_head_sha256,
        } => record_recovery_policy_command(
            store_path,
            &persona_id,
            &policies,
            &expected_root_sha256,
            &expected_policy_sha256,
            expected_head_sequence,
            expected_head_sha256.as_deref(),
        ),
        ContinuityCommands::RecoveryTransitionCreate {
            root,
            policies,
            expected_root_sha256,
            expected_policy_sha256,
            prior_transitions,
            reason,
            authority_keys,
            authority_public_keys,
            next_key,
            next_public_key,
            output,
        } => create_recovery_transition_command(
            &root,
            &policies,
            &expected_root_sha256,
            &expected_policy_sha256,
            &prior_transitions,
            reason.into(),
            &authority_keys,
            &authority_public_keys,
            &next_key,
            &next_public_key,
            &output,
        ),
        ContinuityCommands::RecoveryTransitionCeremonyStart {
            persona_id,
            expected_root_sha256,
            expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256,
            reason,
            next_public_key,
            valid_minutes,
            output,
        } => start_recovery_transition_ceremony(
            store_path,
            &persona_id,
            &expected_root_sha256,
            &expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256.as_deref(),
            reason.into(),
            &next_public_key,
            valid_minutes,
            &output,
        ),
        ContinuityCommands::RecoveryTransitionCeremonyRespond {
            request,
            expected_root_sha256,
            expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256,
            participant_provider,
            participant_signing_locator,
            participant_public_key,
            output,
            socket,
        } => respond_to_recovery_transition_ceremony(
            &request,
            &expected_root_sha256,
            &expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256.as_deref(),
            &participant_provider,
            &participant_signing_locator,
            &participant_public_key,
            &output,
            socket.as_deref(),
        ),
        ContinuityCommands::RecoveryTransitionCeremonyAssemble {
            request,
            responses,
            expected_root_sha256,
            expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256,
            output,
        } => assemble_recovery_transition_ceremony(
            &request,
            &responses,
            &expected_root_sha256,
            &expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256.as_deref(),
            &output,
        ),
        ContinuityCommands::RecoveryTransitionVerify {
            proof,
            root,
            policies,
            expected_root_sha256,
            expected_policy_sha256,
            json,
        } => verify_recovery_transition_command(
            &proof,
            &root,
            &policies,
            &expected_root_sha256,
            &expected_policy_sha256,
            json,
        ),
        ContinuityCommands::RecoveryTransitionCommit {
            persona_id,
            proof,
            expected_root_sha256,
            expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256,
            next_provider,
            next_signing_locator,
        } => commit_recovery_transition_command(
            store_path,
            &persona_id,
            &proof,
            &expected_root_sha256,
            &expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256.as_deref(),
            next_provider.as_deref(),
            next_signing_locator.as_deref(),
        ),
        ContinuityCommands::TerminalRevocationCreate {
            root,
            policies,
            expected_root_sha256,
            expected_policy_sha256,
            prior_transitions,
            expected_previous_head_sequence,
            expected_previous_head_sha256,
            reason,
            authority_keys,
            authority_public_keys,
            output,
            json,
        } => create_terminal_revocation_command(
            &root,
            &policies,
            &expected_root_sha256,
            &expected_policy_sha256,
            &prior_transitions,
            expected_previous_head_sequence,
            expected_previous_head_sha256.as_deref(),
            reason.into(),
            &authority_keys,
            &authority_public_keys,
            &output,
            json,
        ),
        ContinuityCommands::TerminalRevocationVerify {
            proof,
            root,
            policies,
            expected_root_sha256,
            expected_policy_sha256,
            json,
        } => verify_terminal_revocation_command(
            &proof,
            &root,
            &policies,
            &expected_root_sha256,
            &expected_policy_sha256,
            json,
        ),
        ContinuityCommands::TerminalRevocationCommit {
            persona_id,
            proof,
            expected_root_sha256,
            expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256,
            json,
        } => commit_terminal_revocation_command(
            store_path,
            &persona_id,
            &proof,
            &expected_root_sha256,
            &expected_policy_sha256,
            expected_previous_head_sequence,
            expected_previous_head_sha256.as_deref(),
            json,
        ),
        ContinuityCommands::RecoveryChainVerify {
            root,
            policies,
            transitions,
            terminal_revocation,
            expected_root_sha256,
            expected_policy_sha256,
            expected_head_sequence,
            expected_head_sha256,
            at_unix,
            json,
        } => verify_recovery_chain_command(
            &root,
            &policies,
            &transitions,
            terminal_revocation.as_deref(),
            RecoveryChainExpectations {
                root_sha256: &expected_root_sha256,
                policy_sha256: &expected_policy_sha256,
                head_sequence: expected_head_sequence,
                head_sha256: expected_head_sha256.as_deref(),
            },
            at_unix,
            json,
        ),
    }
}

#[cfg(target_os = "linux")]
fn request_continuity_root(
    store_path: Option<&Path>,
    persona_id: &str,
    output: &Path,
    socket_path: Option<&Path>,
) -> Result<()> {
    let store = require_existing_persona_store(store_path)?;
    if let Some(recorded) = store.recorded_continuity_root(persona_id)? {
        let verified = verify_persona_root_proof(&recorded.proof)
            .context("stored persona-root journal entry failed reverification")?;
        ensure!(
            verified.root_statement_sha256 == recorded.root_statement_sha256,
            "stored persona-root journal digest does not match its proof"
        );
        let created = write_or_confirm_persona_root_proof(output, &recorded.proof)?;
        print_requested_continuity_root(&verified, output, !created);
        return Ok(());
    }
    require_new_output_path(output, "persona root proof")?;
    let expected = store
        .active_signer_for_persona(persona_id)
        .with_context(|| format!("persona {persona_id} has no unambiguous active signer"))?;
    let issued_at = current_unix_time()?;
    let statement =
        new_persona_root_statement(&expected.persona.label, issued_at, &expected.key.public_key)?;
    let canonical_statement = canonical_persona_root_statement_bytes(&statement)?;
    let expected_review = review_persona_root_statement(
        &statement,
        issued_at,
        &expected.key.public_key,
        &expected.persona.label,
    )?;

    let mut input = tempfile().context("cannot create anonymous persona-root statement file")?;
    input
        .write_all(&canonical_statement)
        .context("cannot write anonymous persona-root statement file")?;
    let request = IpcSignRequest::new_persona_root(persona_id)?;
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
            bail!(
                "persona-root signing request rejected: {}",
                rejection_name(code)
            );
        }
    };

    let proof_bytes = sealed_proof.read_bytes()?;
    let proof = parse_persona_root_proof_bytes(&proof_bytes)
        .context("daemon returned an invalid persona-root proof")?;
    let verified = verify_persona_root_proof(&proof)
        .context("daemon returned an invalid persona-root signature")?;
    ensure!(
        verified.statement == statement,
        "daemon proof does not contain the exact persona-root statement submitted for consent"
    );
    let returned_review = review_persona_root_statement(
        &verified.statement,
        current_unix_time()?,
        &expected.key.public_key,
        &expected.persona.label,
    )
    .context("daemon returned a stale or locally mismatched persona root")?;
    ensure!(
        returned_review == expected_review
            && verified.root_statement_sha256 == expected_review.root_statement_sha256,
        "daemon proof changed the reviewed persona-root digest"
    );
    ensure!(
        verified.statement.initial_key_fingerprint == expected.key.fingerprint,
        "daemon proof used key {}, but persona {persona_id} expected {}",
        verified.statement.initial_key_fingerprint,
        expected.key.fingerprint
    );
    ensure!(
        verified.statement.persona == expected.persona.label,
        "daemon proof persona label does not match the local persona record"
    );
    let recorded = store
        .recorded_continuity_root(persona_id)?
        .context("daemon returned a persona root without atomically journaling it")?;
    ensure!(
        recorded.proof == proof && recorded.root_statement_sha256 == verified.root_statement_sha256,
        "daemon journal does not contain the exact returned persona-root proof"
    );
    write_or_confirm_persona_root_proof(output, &proof)?;
    print_requested_continuity_root(&verified, output, false);
    Ok(())
}

fn print_requested_continuity_root(verified: &VerifiedPersonaRoot, output: &Path, recovered: bool) {
    println!("VERIFIED SELF-ASSERTED PERSONA ROOT");
    if recovered {
        println!("Journal recovery: exported the exact previously approved root proof");
    } else {
        println!("Trusted local consent: approved exact root statement");
    }
    println!("Persona: {}", verified.statement.persona);
    println!("Persona anchor: {}", verified.statement.persona_anchor);
    println!(
        "Initial key: {}",
        verified.statement.initial_key_fingerprint
    );
    println!("Root statement SHA-256: {}", verified.root_statement_sha256);
    println!("Proof: {}", output.display());
    println!(
        "Trust step still required: pin that digest through a separate trusted channel before relying on continuity."
    );
    println!(
        "Not established: legal identity, recovery authority, current authorization, or safety."
    );
}

#[cfg(not(target_os = "linux"))]
fn request_continuity_root(
    _store_path: Option<&Path>,
    _persona_id: &str,
    _output: &Path,
    _socket_path: Option<&Path>,
) -> Result<()> {
    bail!("continuity root-request is currently available only on Linux")
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn request_continuity_transition(
    store_path: Option<&Path>,
    persona_id: &str,
    expected_root_sha256: &str,
    next_key_path: &Path,
    next_public_key_path: &Path,
    next_provider: &str,
    output: &Path,
    socket_path: Option<&Path>,
) -> Result<()> {
    let expected_root_digest = decode_sha256(expected_root_sha256)
        .map_err(|()| anyhow::anyhow!("--expected-root-sha256 must be 64 lowercase hex digits"))?;
    let store = require_existing_persona_store(store_path)?;
    let snapshot = store
        .continuity_snapshot(persona_id)
        .with_context(|| format!("persona {persona_id} has no valid live continuity journal"))?;
    ensure!(
        snapshot.terminal_revocation.is_none(),
        "persona {persona_id} is PERMANENTLY DEAUTHORIZED and cannot request a successor transition"
    );
    ensure!(
        snapshot.root.root_statement_sha256 == expected_root_sha256,
        "independently supplied root digest does not match the persona journal"
    );

    let next_public_key = read_public_key(next_public_key_path)?;
    let next_key_fingerprint = public_key_fingerprint(&next_public_key)?;
    let next_public_key = normalized_public_key_text(&next_public_key)?;
    let next_provider: KeyProvider = next_provider.parse()?;

    if snapshot.head.current_key_fingerprint == next_key_fingerprint {
        ensure!(
            snapshot.head.transition_sequence > 0,
            "the proposed next key is already the persona root key; no rotation proof exists"
        );
        let proof = match snapshot.transitions.last() {
            Some(PersonaContinuityTransitionProof::Routine(proof)) => proof,
            Some(PersonaContinuityTransitionProof::Recovery(_)) => bail!(
                "the current continuity head is a recovery transition; routine transition-request cannot replay it"
            ),
            Some(PersonaContinuityTransitionProof::TerminalRevocation(_)) => {
                bail!("persona is terminally revoked and cannot request a successor transition")
            }
            None => bail!("continuity head claims a transition that is absent from the journal"),
        };
        let verified = verify_persona_transition_proof(proof)?;
        let retry_intent = RoutineTransitionIntent {
            persona_id: persona_id.to_owned(),
            sequence: verified.statement.sequence,
            root_statement_sha256: verified.statement.root_statement_sha256.clone(),
            previous_transition_sha256: verified.statement.previous_transition_sha256.clone(),
            previous_key_fingerprint: verified.statement.previous_key_fingerprint.clone(),
            next_key_fingerprint: verified.statement.next_key_fingerprint.clone(),
            issued_at: verified.statement.issued_at,
        };
        let retry_metadata = store
            .committed_routine_transition_retry_metadata(&retry_intent)?
            .context("committed transition is not the current, fully verified continuity head")?;
        let locator_matches = retry_locator_matches(
            next_key_path,
            &retry_metadata.signing_locator,
            "next signing key",
        )?;
        ensure!(
            verified.statement.root_statement_sha256 == expected_root_sha256
                && verified.statement.sequence == snapshot.head.transition_sequence
                && verified.transition_statement_sha256
                    == snapshot
                        .head
                        .last_transition_sha256
                        .as_deref()
                        .context("non-root continuity head has no transition digest")?
                && verified.statement.next_key_fingerprint == next_key_fingerprint
                && verified.next_public_key == next_public_key
                && retry_metadata.persona_id == persona_id
                && retry_metadata.current_key_fingerprint == next_key_fingerprint
                && retry_metadata.provider == next_provider
                && locator_matches,
            "the proposed retry does not exactly match the committed continuity head"
        );
        write_or_confirm_persona_transition_proof(output, proof)?;
        print_requested_continuity_transition(&verified, output, true);
        return Ok(());
    }

    require_new_output_path(output, "persona transition proof")?;
    let candidate = store
        .validate_routine_rotation_candidate(
            persona_id,
            &next_public_key,
            next_provider,
            next_key_path,
        )
        .context("proposed next signer is not safe and usable for routine rotation")?;
    ensure!(
        candidate.intent.root_statement_sha256 == expected_root_sha256
            && candidate.intent.previous_key_fingerprint == snapshot.head.current_key_fingerprint
            && candidate.intent.previous_transition_sha256 == snapshot.head.last_transition_sha256,
        "continuity journal changed while preparing the rotation"
    );
    let previous_key = store
        .lookup_key(&snapshot.head.current_key_fingerprint)?
        .context("current continuity-head key is absent from the persona store")?;
    ensure!(
        previous_key.persona.id == persona_id
            && previous_key.key.persona_id == persona_id
            && previous_key.key.status == KeyStatus::Active
            && previous_key.key.fingerprint == snapshot.head.current_key_fingerprint,
        "current continuity-head key is not the active key for this persona"
    );
    let expected_sequence = candidate.intent.sequence;
    let expected_previous_transition_sha256 = candidate
        .intent
        .previous_transition_sha256
        .as_deref()
        .map(decode_sha256)
        .transpose()
        .map_err(|()| anyhow::anyhow!("journal contains a malformed transition digest"))?;
    let next_signing_reference = candidate
        .signing_reference
        .locator
        .to_str()
        .context("validated next signing reference is not UTF-8")?;

    let request = IpcSignRequest::new_persona_transition(
        persona_id,
        expected_sequence,
        expected_root_digest,
        expected_previous_transition_sha256,
        ipc_transition_key_provider(next_provider),
        next_signing_reference,
    )?;
    let mut input = tempfile().context("cannot create anonymous next-public-key file")?;
    input
        .write_all(next_public_key.as_bytes())
        .context("cannot write anonymous next-public-key file")?;

    let socket_path = resolve_consent_socket_path(socket_path)?;
    let socket = connect_consent_socket(&socket_path)
        .with_context(|| format!("cannot connect to daemon socket {}", socket_path.display()))?;
    send_sign_request(&socket, &request, &input)?;
    let received = receive_sign_response(&socket)?;
    let sealed_proof = match received.response {
        SignResponse::Approved => received
            .proof
            .context("daemon approved without a sealed transition proof descriptor")?,
        SignResponse::Rejected(code) => {
            bail!(
                "persona-transition request rejected: {}",
                rejection_name(code)
            );
        }
    };
    let proof_bytes = sealed_proof.read_bytes()?;
    let proof = parse_persona_transition_proof_bytes(&proof_bytes)
        .context("daemon returned an invalid persona-transition proof")?;
    let verified = verify_persona_transition_proof(&proof)
        .context("daemon returned an invalid dual-signed persona transition")?;
    let root = verify_persona_root_proof(&snapshot.root.proof)?;
    let review = review_persona_transition_statement(
        &verified.statement,
        current_unix_time()?,
        &root,
        expected_sequence,
        snapshot.head.last_transition_sha256.as_deref(),
        &previous_key.key.public_key,
        &next_public_key,
    )
    .context("daemon returned a stale or locally mismatched transition")?;
    ensure!(
        review.transition_statement_sha256 == verified.transition_statement_sha256
            && review.root_statement_sha256 == expected_root_sha256
            && review.next_key_fingerprint == next_key_fingerprint,
        "daemon proof differs from the exact transition reviewed by the client"
    );

    let committed = store
        .continuity_snapshot(persona_id)
        .context("daemon returned a transition without a valid committed journal")?;
    ensure!(
        committed.head.transition_sequence == expected_sequence
            && committed.head.current_key_fingerprint == next_key_fingerprint
            && committed.head.last_transition_sha256.as_deref()
                == Some(verified.transition_statement_sha256.as_str())
            && matches!(
                committed.transitions.last(),
                Some(PersonaContinuityTransitionProof::Routine(committed_proof))
                    if committed_proof == &proof
            ),
        "daemon journal does not contain the exact returned transition proof"
    );
    write_or_confirm_persona_transition_proof(output, &proof)?;
    print_requested_continuity_transition(&verified, output, false);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn request_continuity_transition(
    _store_path: Option<&Path>,
    _persona_id: &str,
    _expected_root_sha256: &str,
    _next_key_path: &Path,
    _next_public_key_path: &Path,
    _next_provider: &str,
    _output: &Path,
    _socket_path: Option<&Path>,
) -> Result<()> {
    bail!("continuity transition-request is currently available only on Linux")
}

fn print_requested_continuity_transition(
    verified: &a_quo_core::VerifiedPersonaTransition,
    output: &Path,
    recovered: bool,
) {
    println!("VERIFIED DUAL-SIGNED ROUTINE TRANSITION");
    if recovered {
        println!("Journal recovery: exported the exact previously committed transition proof");
    } else {
        println!("Trusted local consent: approved the exact two-key transition");
    }
    println!("Persona: {}", verified.statement.persona);
    println!("Sequence: {}", verified.statement.sequence);
    println!("Pinned root: {}", verified.statement.root_statement_sha256);
    println!(
        "Previous key: {}",
        verified.statement.previous_key_fingerprint
    );
    println!("Next key: {}", verified.statement.next_key_fingerprint);
    println!(
        "Transition statement SHA-256: {}",
        verified.transition_statement_sha256
    );
    println!("Proof: {}", output.display());
    println!("External root pin: matched the explicitly supplied digest.");
    println!(
        "Not established: legal identity, truth, safety, or current third-party authorization."
    );
}

#[cfg(target_os = "linux")]
fn ipc_transition_key_provider(provider: KeyProvider) -> TransitionKeyProvider {
    match provider {
        KeyProvider::OpensshFile => TransitionKeyProvider::OpensshFile,
        KeyProvider::SshAgent => TransitionKeyProvider::SshAgent,
        KeyProvider::Fido2 => TransitionKeyProvider::Fido2,
    }
}

#[cfg(target_os = "linux")]
fn ipc_recovery_participant_key_provider(provider: KeyProvider) -> RecoveryParticipantKeyProvider {
    match provider {
        KeyProvider::OpensshFile => RecoveryParticipantKeyProvider::OpensshFile,
        KeyProvider::SshAgent => RecoveryParticipantKeyProvider::SshAgent,
        KeyProvider::Fido2 => RecoveryParticipantKeyProvider::Fido2,
    }
}

fn create_continuity_root(
    persona: &str,
    key: &Path,
    public_key_path: &Path,
    output: &Path,
) -> Result<()> {
    require_continuity_command_verification_work(&[(1, 2)])?;
    require_new_output_path(output, "persona root proof")?;
    let public_key = read_public_key(public_key_path)?;
    let statement = new_persona_root_statement(persona, current_unix_time()?, &public_key)?;
    let proof = create_persona_root_proof(statement, key, &public_key)?;
    let verified = verify_persona_root_proof(&proof)?;
    write_private_json_new(
        output,
        serde_json::to_vec_pretty(&proof)?,
        MAX_PROOF_BYTES,
        "persona root proof",
    )?;

    println!("VERIFIED SELF-ASSERTED PERSONA ROOT");
    println!("Persona: {}", verified.statement.persona);
    println!("Persona anchor: {}", verified.statement.persona_anchor);
    println!(
        "Initial key: {}",
        verified.statement.initial_key_fingerprint
    );
    println!("Root statement SHA-256: {}", verified.root_statement_sha256);
    println!("Proof: {}", output.display());
    println!(
        "Trust step still required: pin that digest through a separate trusted channel before relying on continuity."
    );
    println!("Signing path: low-level direct signing; no trusted A Quo consent ceremony was used.");
    Ok(())
}

fn verify_continuity_root(proof_path: &Path, emit_json: bool) -> Result<()> {
    require_continuity_command_verification_work(&[(1, 1)])?;
    let proof = read_persona_root_proof(proof_path)?;
    let verified = verify_persona_root_proof(&proof)?;
    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "signature": "verified",
                "statement": verified.statement,
                "root_statement_sha256": verified.root_statement_sha256,
                "external_root_pin": "not_checked",
                "legal_identity": "not_established"
            }))?
        );
    } else {
        println!("VERIFIED SELF-ASSERTED ROOT SIGNATURE");
        println!("Persona: {}", verified.statement.persona);
        println!("Persona anchor: {}", verified.statement.persona_anchor);
        println!(
            "Initial key: {}",
            verified.statement.initial_key_fingerprint
        );
        println!("Root statement SHA-256: {}", verified.root_statement_sha256);
        println!("External root pin: not checked");
        println!("Legal identity: not established");
    }
    Ok(())
}

fn export_continuity_root_card(
    root_path: &Path,
    format: RootCardFormatArgument,
    output: &Path,
) -> Result<()> {
    require_new_output_path(output, "persona root card")?;
    require_continuity_command_verification_work(&[(1, 1)])?;
    let proof = read_persona_root_proof(root_path)?;
    let card = persona_root_card_from_proof(&proof)?;
    let (bytes, maximum, format_label) = match format {
        RootCardFormatArgument::Json => (
            canonical_persona_root_card_bytes(&card)?,
            MAX_PERSONA_ROOT_CARD_BYTES,
            "canonical JSON",
        ),
        RootCardFormatArgument::Text => (
            render_root_card_text(&card)?.into_bytes(),
            MAX_ROOT_CARD_TEXT_BYTES,
            "accessible text",
        ),
        RootCardFormatArgument::Html => (
            render_root_card_html(&card)?.into_bytes(),
            MAX_ROOT_CARD_HTML_BYTES,
            "standalone printable HTML with a digest-only QR",
        ),
    };
    write_private_bytes_new(
        output,
        &bytes,
        u64::try_from(maximum).expect("root card output bound fits in u64"),
        "persona root card",
    )?;

    println!("EXPORTED VERIFIED SELF-ASSERTED PERSONA ROOT CARD");
    println!("Persona: {}", card.persona);
    println!("Root statement SHA-256: {}", card.root_statement_sha256);
    println!("Pin URI: {}", card.pin_uri);
    println!("Format: {format_label}");
    println!("Card: {}", output.display());
    println!("External root pin: not checked");
    println!(
        "Not established: legal identity, trusted time, current continuity head, channel independence, signing authority, truth, or safety."
    );
    Ok(())
}

fn create_continuity_root_pin(
    from_root: Option<&Path>,
    pin_uri: Option<&str>,
    basis: RootPinBasisArgument,
    channel: RootPinChannelArgument,
    at_unix: Option<i64>,
    accept_root_sha256: Option<&str>,
    output: &Path,
) -> Result<()> {
    let recorded_at = at_unix.map_or_else(current_unix_time, Ok)?;
    let trust_basis = PersonaRootTrustBasis::from(basis);
    let root_statement_sha256 = match (from_root, pin_uri, trust_basis) {
        (Some(_), None, PersonaRootTrustBasis::OutOfBandUserConfirmed) => {
            bail!(
                "--from-root cannot create an out-of-band pin: use the complete --pin-uri obtained through the separately trusted route"
            )
        }
        (Some(root_path), None, _) => {
            require_continuity_command_verification_work(&[(1, 1)])?;
            let proof = read_persona_root_proof(root_path)?;
            let verified = verify_persona_root_proof(&proof)?;
            require_new_output_path(output, "persona root pin")?;

            println!("PERSONA ROOT PIN REVIEW — NOTHING WRITTEN YET");
            println!("Identity basis: self-asserted");
            println!("Persona: {}", verified.statement.persona);
            println!(
                "Initial key fingerprint: {}",
                verified.statement.initial_key_fingerprint
            );
            println!(
                "Self-signed issuance time: {}",
                verified.statement.issued_at
            );
            println!("Root statement SHA-256: {}", verified.root_statement_sha256);
            println!("Root signature: verified");
            println!(
                "Requested trust basis: {}",
                root_pin_basis_label(trust_basis)
            );
            println!(
                "Requested channel: {}",
                root_pin_channel_label(channel.into())
            );
            println!(
                "Channel independence: {}",
                root_pin_independence_label(trust_basis)
            );
            println!("Existing pin at requested output: none");
            println!("Trusted time: not established");
            println!("Current continuity history: not established");
            println!("Current signing authority: not established");
            println!("Current recovery authority: not established");
            println!("Legal identity: not established");
            println!("Artifact truth or safety: not established");
            match trust_basis {
                PersonaRootTrustBasis::TrustOnFirstUse => println!(
                    "Warning: this first contact has not been independently authenticated."
                ),
                PersonaRootTrustBasis::SameChannelCopy => println!(
                    "Warning: the root and confirmation came through the same route; coherent substitution remains possible."
                ),
                PersonaRootTrustBasis::OutOfBandUserConfirmed => unreachable!(),
            }

            ensure!(
                accept_root_sha256 == Some(verified.root_statement_sha256.as_str()),
                "no pin was written; after reviewing these facts, rerun with --accept-root-sha256 {}",
                verified.root_statement_sha256
            );
            verified.root_statement_sha256
        }
        (None, Some(uri), PersonaRootTrustBasis::OutOfBandUserConfirmed) => {
            ensure!(
                accept_root_sha256.is_none(),
                "--accept-root-sha256 is only valid with --from-root"
            );
            parse_persona_root_pin_uri(uri)?
        }
        (None, Some(_), _) => {
            bail!(
                "--pin-uri is reserved for --basis out-of-band-user-confirmed; use --from-root for TOFU or a same-channel copy"
            )
        }
        _ => bail!("provide exactly one of --from-root or --pin-uri"),
    };

    let pin = new_persona_root_pin(
        &root_statement_sha256,
        recorded_at,
        trust_basis,
        channel.into(),
        None,
    )?;
    let bytes = canonical_persona_root_pin_bytes(&pin)?;
    write_private_bytes_new(
        output,
        &bytes,
        u64::try_from(MAX_PERSONA_ROOT_PIN_BYTES).expect("persona root pin bound fits in u64"),
        "persona root pin",
    )?;

    let report = validate_persona_root_pin(&pin)?;
    println!("RECORDED UNSIGNED PERSONA ROOT PIN");
    println!("Root statement SHA-256: {}", report.root_statement_sha256);
    println!("Trust basis: {}", root_pin_basis_label(report.trust_basis));
    println!("Channel: {}", root_pin_channel_label(report.channel));
    println!(
        "Channel independence: {}",
        root_pin_independence_label(report.trust_basis)
    );
    println!("Pin record: {}", output.display());
    println!(
        "Provenance: user-recorded metadata; A Quo has not cryptographically verified the route."
    );
    println!(
        "Not established: legal identity, trusted time, current continuity head, signing authority, truth, or safety."
    );
    Ok(())
}

fn inspect_continuity_root_pin(pin_path: &Path, emit_json: bool) -> Result<()> {
    let pin = read_persona_root_pin(pin_path)?;
    let report = validate_persona_root_pin(&pin)?;
    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "pin_record": "valid_unsigned_user_metadata",
                "root_statement_sha256": report.root_statement_sha256,
                "recorded_at": report.recorded_at,
                "trust_basis": report.trust_basis,
                "trust_basis_source": report.trust_basis_source,
                "channel": report.channel,
                "channel_independence": report.channel_independence,
                "provenance_assurance": report.provenance_assurance,
                "source_artifact_sha256": report.source_artifact_sha256,
                "root_signature": "not_checked",
                "current_history_freshness": "not_established",
                "legal_identity": "not_established",
                "current_signing_authority": "not_established",
                "current_recovery_authority": "not_established",
                "artifact_truth_or_safety": "not_established",
                "root_card_possession_grants_authority": false
            }))?
        );
    } else {
        println!("VALID UNSIGNED PERSONA ROOT PIN RECORD");
        println!("Root statement SHA-256: {}", report.root_statement_sha256);
        println!("Recorded at: {}", report.recorded_at);
        println!("Trust basis: {}", root_pin_basis_label(report.trust_basis));
        println!("Channel: {}", root_pin_channel_label(report.channel));
        println!(
            "Channel independence: {}",
            root_pin_independence_label(report.trust_basis)
        );
        println!("Root signature: not checked");
        println!("Current history freshness: not established");
        println!("Current signing authority: not established");
        println!("Current recovery authority: not established");
        println!("Artifact truth or safety: not established");
        println!("Root-card possession grants authority: false");
        println!("Legal identity: not established");
        println!(
            "Warning: this portable record is unsigned user metadata; protect retained copies from replacement."
        );
    }
    Ok(())
}

fn compare_continuity_root_pin(
    root_path: &Path,
    pin_path: &Path,
    card_path: Option<&Path>,
    at_unix: Option<i64>,
    emit_json: bool,
) -> Result<()> {
    require_continuity_command_verification_work(&[(1, 1)])?;
    let proof = read_persona_root_proof(root_path)?;
    let pin = read_persona_root_pin(pin_path)?;
    let card = card_path.map(read_persona_root_card).transpose()?;
    let checked_at = at_unix.map_or_else(current_unix_time, Ok)?;
    let report = compare_persona_root_distribution(&proof, card.as_ref(), &pin, checked_at)?;

    if emit_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("PERSONA ROOT EVIDENCE COMPARISON");
        println!("Root identity basis: self-asserted");
        println!("Root signature: verified");
        println!("Pin relationship: {}", root_match_label(report.pin_match));
        println!("Card relationship: {}", root_match_label(report.card_match));
        println!(
            "Candidate root statement SHA-256: {}",
            report.candidate_root_statement_sha256
        );
        println!(
            "Retained pin root statement SHA-256: {}",
            report.pinned_root_statement_sha256
        );
        println!(
            "Candidate root card SHA-256: {}",
            report.candidate_card_sha256
        );
        if let Some(supplied_card_sha256) = &report.supplied_card_sha256 {
            println!("Supplied root card SHA-256: {supplied_card_sha256}");
        }
        println!("Trust basis: {}", root_pin_basis_label(report.trust_basis));
        println!("Channel: {}", root_pin_channel_label(report.channel));
        println!(
            "Channel independence: {}",
            root_pin_independence_label(report.trust_basis)
        );
        if let Some(delay) = report.first_contact_delay_seconds {
            println!("First-contact delay: {delay} seconds");
        }
        if report.root_issued_after_local_observation {
            println!(
                "Warning: the root's self-signed issuance time is later than the local observation; neither timestamp is trusted."
            );
        } else if report.late_first_contact == Some(true) {
            println!(
                "Warning: first contact was more than 30 days after the root's self-signed issuance time; this is not retroactive trust."
            );
        }
        println!(
            "Pin observation age: {} seconds",
            report.pin_observation_age_seconds
        );
        if report.pin_observation_review_due {
            println!(
                "Warning: the retained observation is more than one year old; re-check current continuity through an appropriate route."
            );
        }
        match report.trust_basis {
            PersonaRootTrustBasis::TrustOnFirstUse => {
                println!("Warning: the original first contact was not independently authenticated.")
            }
            PersonaRootTrustBasis::SameChannelCopy => println!(
                "Warning: matching values from the same route are a consistency check, not independent pinning."
            ),
            PersonaRootTrustBasis::OutOfBandUserConfirmed => {
                println!("Warning: channel separation is user-reported and is not proven by A Quo.")
            }
        }
        println!("Trusted time: not established");
        println!("Current continuity history: not established");
        println!("Current signing authority: not established");
        println!("Current recovery authority: not established");
        println!("Artifact truth or safety: not established");
        println!("Root-card possession grants authority: false");
        println!("Legal identity: not established");
    }

    ensure!(
        report.pin_match == PersonaRootMatchStatus::Matched,
        "retained root pin conflicts with the verified persona root; the pin was not changed"
    );
    ensure!(
        matches!(
            report.card_match,
            PersonaRootMatchStatus::Matched | PersonaRootMatchStatus::NotChecked
        ),
        "supplied root card conflicts with the verified persona root; no material was changed"
    );
    Ok(())
}

fn root_pin_basis_label(basis: PersonaRootTrustBasis) -> &'static str {
    match basis {
        PersonaRootTrustBasis::TrustOnFirstUse => "trust on first use (TOFU)",
        PersonaRootTrustBasis::SameChannelCopy => "same-channel copy",
        PersonaRootTrustBasis::OutOfBandUserConfirmed => "user-confirmed out of band",
    }
}

fn root_pin_channel_label(channel: PersonaRootPinChannel) -> &'static str {
    match channel {
        PersonaRootPinChannel::InPerson => "in person",
        PersonaRootPinChannel::Paper => "paper",
        PersonaRootPinChannel::Qr => "QR",
        PersonaRootPinChannel::Voice => "voice",
        PersonaRootPinChannel::File => "file",
        PersonaRootPinChannel::Other => "other",
    }
}

fn root_pin_independence_label(basis: PersonaRootTrustBasis) -> &'static str {
    match basis {
        PersonaRootTrustBasis::TrustOnFirstUse | PersonaRootTrustBasis::SameChannelCopy => {
            "not established"
        }
        PersonaRootTrustBasis::OutOfBandUserConfirmed => {
            "user reported a separate route; A Quo cannot prove it"
        }
    }
}

fn root_match_label(status: PersonaRootMatchStatus) -> &'static str {
    match status {
        PersonaRootMatchStatus::NotChecked => "not checked",
        PersonaRootMatchStatus::Matched => "exact match",
        PersonaRootMatchStatus::Mismatched => "conflict",
    }
}

fn ensure_continuity_transition_path_count(
    transition_paths: &[PathBuf],
    appending: bool,
) -> Result<()> {
    if appending {
        ensure!(
            transition_paths.len() < MAX_CONTINUITY_TRANSITIONS,
            "cannot append beyond {MAX_CONTINUITY_TRANSITIONS} continuity transitions"
        );
    } else {
        ensure!(
            transition_paths.len() <= MAX_CONTINUITY_TRANSITIONS,
            "chain cannot contain more than {MAX_CONTINUITY_TRANSITIONS} transitions"
        );
    }
    Ok(())
}

fn ensure_terminal_revocation_prior_path_count(transition_paths: &[PathBuf]) -> Result<()> {
    let maximum = usize::try_from(MAX_TERMINAL_PERSONA_REVOCATION_SEQUENCE - 1)
        .expect("terminal revocation sequence bound fits in usize");
    ensure!(
        transition_paths.len() <= maximum,
        "cannot append a terminal revocation beyond sequence {MAX_TERMINAL_PERSONA_REVOCATION_SEQUENCE}"
    );
    Ok(())
}

fn ensure_recovery_policy_path_count(
    policy_paths: &[PathBuf],
    required: bool,
    appending: bool,
) -> Result<()> {
    if required {
        ensure!(
            !policy_paths.is_empty(),
            "recovery policy chain must contain 1 through {MAX_RECOVERY_POLICY_VERSIONS} proofs"
        );
    }
    if appending {
        ensure!(
            policy_paths.len() < MAX_RECOVERY_POLICY_VERSIONS,
            "cannot append beyond {MAX_RECOVERY_POLICY_VERSIONS} recovery policy versions"
        );
    } else {
        ensure!(
            policy_paths.len() <= MAX_RECOVERY_POLICY_VERSIONS,
            "recovery policy chain cannot contain more than {MAX_RECOVERY_POLICY_VERSIONS} proofs"
        );
    }
    Ok(())
}

fn ensure_recovery_signer_path_counts(
    private_key_paths: &[PathBuf],
    public_key_paths: &[PathBuf],
    description: &str,
) -> Result<()> {
    ensure!(
        private_key_paths.len() <= MAX_RECOVERY_AUTHORITIES
            && public_key_paths.len() <= MAX_RECOVERY_AUTHORITIES,
        "{description} cannot contain more than {MAX_RECOVERY_AUTHORITIES} key pairs"
    );
    ensure!(
        !private_key_paths.is_empty(),
        "{description} requires at least one key pair"
    );
    ensure!(
        private_key_paths.len() == public_key_paths.len(),
        "{description} requires one public-key path for each private-key path"
    );
    Ok(())
}

fn minimum_recovery_policy_signature_count(policy_count: usize) -> usize {
    match policy_count {
        0 => 0,
        // Enrollment has at least two signatures. Every later update has at
        // least two previous-policy and two current-policy signatures.
        count => MIN_RECOVERY_AUTHORITIES.saturating_add(
            count
                .saturating_sub(1)
                .saturating_mul(MIN_RECOVERY_AUTHORITIES.saturating_mul(2)),
        ),
    }
}

fn minimum_continuity_transition_signature_count(transition_count: usize) -> usize {
    // Routine transitions have two signatures. Recovery transitions have at
    // least two authority signatures plus the next-key signature.
    transition_count.saturating_mul(2)
}

fn recovery_policy_signature_count(proof: &RecoveryPolicyProof) -> usize {
    match &proof.authorization {
        RecoveryPolicyAuthorization::Enrollment { signatures } => signatures.len(),
        RecoveryPolicyAuthorization::Update {
            previous_policy_signatures,
            current_policy_signatures,
        } => previous_policy_signatures
            .len()
            .saturating_add(current_policy_signatures.len()),
    }
}

fn recovery_policy_signature_count_sum(proofs: &[RecoveryPolicyProof]) -> usize {
    proofs.iter().fold(0usize, |total, proof| {
        total.saturating_add(recovery_policy_signature_count(proof))
    })
}

fn continuity_transition_signature_count(proof: &PersonaContinuityTransitionProof) -> usize {
    match proof {
        PersonaContinuityTransitionProof::Routine(proof) => proof.signatures.len(),
        PersonaContinuityTransitionProof::Recovery(proof) => {
            proof.recovery_signatures.len().saturating_add(1)
        }
        PersonaContinuityTransitionProof::TerminalRevocation(proof) => {
            proof.recovery_signatures.len()
        }
    }
}

fn continuity_transition_signature_count_sum(proofs: &[PersonaContinuityTransitionProof]) -> usize {
    proofs.iter().fold(0usize, |total, proof| {
        total.saturating_add(continuity_transition_signature_count(proof))
    })
}

fn recovery_ceremony_request_signature_count(request: &RecoveryCeremonyRequest) -> usize {
    1_usize
        .saturating_add(recovery_policy_signature_count_sum(
            &request.recovery_policies,
        ))
        .saturating_add(continuity_transition_signature_count_sum(
            &request.prior_transitions,
        ))
}

fn routine_transition_signature_count_sum(proofs: &[PersonaTransitionProof]) -> usize {
    proofs.iter().fold(0usize, |total, proof| {
        total.saturating_add(proof.signatures.len())
    })
}

fn continuity_command_verification_work(terms: &[(usize, usize)]) -> Result<usize> {
    terms
        .iter()
        .try_fold(0usize, |total, (signatures, passes)| {
            let term = signatures
                .checked_mul(*passes)
                .context("continuity signature verification work count overflowed")?;
            total
                .checked_add(term)
                .context("continuity signature verification work count overflowed")
        })
}

fn require_continuity_command_verification_work(terms: &[(usize, usize)]) -> Result<()> {
    let work = continuity_command_verification_work(terms)?;
    ensure!(
        work <= MAX_CONTINUITY_COMMAND_SIGNATURE_VERIFICATIONS,
        "continuity command would require {work} signature verifications; the operational limit is {MAX_CONTINUITY_COMMAND_SIGNATURE_VERIFICATIONS}"
    );
    Ok(())
}

fn preflight_recovery_policy_parameters(
    threshold: u32,
    authority_count: usize,
    valid_days: u16,
) -> Result<i64> {
    let threshold =
        usize::try_from(threshold).context("recovery threshold does not fit this platform")?;
    ensure!(
        (MIN_RECOVERY_AUTHORITIES..=authority_count).contains(&threshold),
        "recovery threshold must be at least {MIN_RECOVERY_AUTHORITIES} and no greater than the authority count"
    );
    recovery_policy_validity_seconds(valid_days)
}

#[allow(clippy::too_many_arguments)]
fn create_continuity_transition(
    root_path: &Path,
    prior_transition_paths: &[PathBuf],
    recovery_policy_paths: &[PathBuf],
    expected_policy_sha256: Option<&str>,
    previous_key_path: &Path,
    previous_public_key_path: &Path,
    next_key_path: &Path,
    next_public_key_path: &Path,
    output: &Path,
) -> Result<()> {
    ensure_continuity_transition_path_count(prior_transition_paths, true)?;
    ensure_recovery_policy_path_count(recovery_policy_paths, false, false)?;
    require_continuity_command_verification_work(&[
        (1, 3),
        (
            minimum_continuity_transition_signature_count(prior_transition_paths.len()),
            2,
        ),
        (
            minimum_recovery_policy_signature_count(recovery_policy_paths.len()),
            2,
        ),
        (2, 3),
    ])?;
    require_new_output_path(output, "persona transition proof")?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let root_proof = read_persona_root_proof_with_command_budget(root_path, &mut input_budget)?;
    let mut prior_transitions = prior_transition_paths
        .iter()
        .map(|path| read_continuity_transition_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        prior_transitions.iter().all(|proof| !matches!(
            proof,
            PersonaContinuityTransitionProof::TerminalRevocation(_)
        )),
        "a terminally revoked persona cannot accept a successor transition"
    );
    let recovery_policy_proofs = recovery_policy_paths
        .iter()
        .map(|path| read_recovery_policy_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    let previous_public_key =
        read_public_key_with_command_budget(previous_public_key_path, &mut input_budget)?;
    let next_public_key =
        read_public_key_with_command_budget(next_public_key_path, &mut input_budget)?;
    let contains_recovery = prior_transitions
        .iter()
        .any(|proof| matches!(proof, PersonaContinuityTransitionProof::Recovery(_)));
    let recovery_context_requested =
        contains_recovery || !recovery_policy_paths.is_empty() || expected_policy_sha256.is_some();
    let expected_recovery_policy_sha256 = if recovery_context_requested {
        ensure!(
            !recovery_policy_proofs.is_empty(),
            "--policy is required when routine rotation follows recovery history"
        );
        Some(expected_policy_sha256.context(
            "--expected-policy-sha256 is required when routine rotation follows recovery history",
        )?)
    } else {
        None
    };
    require_continuity_command_verification_work(&[
        (1, 3),
        (
            continuity_transition_signature_count_sum(&prior_transitions),
            2,
        ),
        (
            recovery_policy_signature_count_sum(&recovery_policy_proofs),
            2,
        ),
        (2, 3),
    ])?;
    let root = verify_persona_root_proof(&root_proof)?;
    let issued_at = current_unix_time()?;
    let (current_key_fingerprint, last_transition_sha256, last_issued_at, policy_proofs) =
        if recovery_context_requested {
            let expected_policy_sha256 = expected_recovery_policy_sha256
                .expect("recovery context has an expected policy digest");
            let report = verify_persona_continuity_chain_with_recovery(
                &root_proof,
                &prior_transitions,
                &recovery_policy_proofs,
                &root.root_statement_sha256,
                expected_policy_sha256,
                issued_at,
            )?;
            ensure!(
                !report.terminally_revoked,
                "a terminally revoked persona cannot accept a successor transition"
            );
            (
                report
                    .current_key_fingerprint
                    .context("verified continuity history has no current online key")?,
                report.last_transition_sha256,
                report.last_issued_at,
                Some(recovery_policy_proofs),
            )
        } else {
            let routine_transitions = prior_transitions
                .iter()
                .map(|proof| match proof {
                    PersonaContinuityTransitionProof::Routine(proof) => Ok(proof.clone()),
                    PersonaContinuityTransitionProof::Recovery(_) => Err(anyhow::anyhow!(
                        "recovery history requires recovery-policy verification context"
                    )),
                    PersonaContinuityTransitionProof::TerminalRevocation(_) => {
                        Err(anyhow::anyhow!(
                            "a terminally revoked persona cannot accept a successor transition"
                        ))
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            let report = verify_persona_continuity_chain(
                &root_proof,
                &routine_transitions,
                &root.root_statement_sha256,
            )?;
            (
                report.chain_tip_key_fingerprint,
                report.last_transition_sha256,
                report.last_issued_at,
                None,
            )
        };
    ensure!(
        public_key_fingerprint(previous_public_key.trim())? == current_key_fingerprint,
        "--previous-public-key is not the current key at the end of the supplied chain"
    );
    ensure!(
        issued_at >= last_issued_at,
        "system clock precedes the last verified continuity statement; refusing to sign"
    );
    let sequence = u32::try_from(prior_transitions.len() + 1)
        .context("continuity transition count overflowed")?;
    let statement = new_routine_transition_statement(
        &root,
        sequence,
        last_transition_sha256.as_deref(),
        &previous_public_key,
        &next_public_key,
        issued_at,
    )?;
    let proof = create_routine_transition_proof(
        statement,
        previous_key_path,
        &previous_public_key,
        next_key_path,
        &next_public_key,
    )?;
    let verified = verify_persona_transition_proof(&proof)?;
    prior_transitions.push(PersonaContinuityTransitionProof::Routine(proof.clone()));
    if let Some(policy_proofs) = policy_proofs {
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &prior_transitions,
            &policy_proofs,
            &root.root_statement_sha256,
            expected_recovery_policy_sha256
                .expect("recovery context requires an expected policy digest"),
            issued_at,
        )?;
    } else {
        let resulting_chain = prior_transitions
            .iter()
            .map(|proof| match proof {
                PersonaContinuityTransitionProof::Routine(proof) => proof.clone(),
                PersonaContinuityTransitionProof::Recovery(_) => {
                    unreachable!("recovery proof requires policy context")
                }
                PersonaContinuityTransitionProof::TerminalRevocation(_) => {
                    unreachable!("terminal proof was rejected before successor creation")
                }
            })
            .collect::<Vec<_>>();
        verify_persona_continuity_chain(
            &root_proof,
            &resulting_chain,
            &root.root_statement_sha256,
        )?;
    }
    write_private_json_new(
        output,
        serde_json::to_vec_pretty(&proof)?,
        MAX_PROOF_BYTES,
        "persona transition proof",
    )?;

    println!("VERIFIED DUAL-SIGNED ROUTINE TRANSITION");
    println!("Persona: {}", verified.statement.persona);
    println!("Sequence: {}", verified.statement.sequence);
    println!(
        "Previous key: {}",
        verified.statement.previous_key_fingerprint
    );
    println!("Next key: {}", verified.statement.next_key_fingerprint);
    println!(
        "Transition statement SHA-256: {}",
        verified.transition_statement_sha256
    );
    println!("Proof: {}", output.display());
    println!("Root trust: not independently checked by this creation command.");
    if recovery_context_requested {
        println!("Recovery history and supplied latest-policy digest: verified.");
    }
    println!("Signing path: low-level direct signing; no trusted multi-key ceremony was used.");
    Ok(())
}

fn verify_continuity_transition(proof_path: &Path, emit_json: bool) -> Result<()> {
    require_continuity_command_verification_work(&[(2, 1)])?;
    let proof = read_persona_transition_proof(proof_path)?;
    let verified = verify_persona_transition_proof(&proof)?;
    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "previous_key_signature": "verified",
                "next_key_signature": "verified",
                "statement": verified.statement,
                "transition_statement_sha256": verified.transition_statement_sha256,
                "root_digest_match": "not_checked",
                "ordered_chain": "not_checked",
                "legal_identity": "not_established"
            }))?
        );
    } else {
        println!("VERIFIED BOTH TRANSITION SIGNATURES");
        println!("Persona claim: {}", verified.statement.persona);
        println!("Sequence claim: {}", verified.statement.sequence);
        println!(
            "Previous key: {}",
            verified.statement.previous_key_fingerprint
        );
        println!("Next key: {}", verified.statement.next_key_fingerprint);
        println!(
            "Transition statement SHA-256: {}",
            verified.transition_statement_sha256
        );
        println!("Root digest and ordered chain: not checked");
        println!("Legal identity and current authorization: not established");
    }
    Ok(())
}

fn verify_continuity_chain(
    root_path: &Path,
    transition_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_head_sequence: Option<u32>,
    expected_head_sha256: Option<&str>,
    emit_json: bool,
) -> Result<()> {
    ensure_continuity_transition_path_count(transition_paths, false)?;
    require_continuity_command_verification_work(&[
        (1, 1),
        (
            minimum_continuity_transition_signature_count(transition_paths.len()),
            1,
        ),
    ])?;
    let expected_head =
        expected_continuity_checkpoint(expected_head_sequence, expected_head_sha256)?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let root_proof = read_persona_root_proof_with_command_budget(root_path, &mut input_budget)?;
    let transitions = transition_paths
        .iter()
        .map(|path| read_persona_transition_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    require_continuity_command_verification_work(&[
        (1, 1),
        (routine_transition_signature_count_sum(&transitions), 1),
    ])?;
    let report = if let Some(expected_head) = &expected_head {
        verify_persona_continuity_chain_at_checkpoint(
            &root_proof,
            &transitions,
            expected_root_sha256,
            expected_head,
        )?
    } else {
        verify_persona_continuity_chain(&root_proof, &transitions, expected_root_sha256)?
    };
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("VERIFIED PERSONA CONTINUITY CHAIN");
        println!("Persona: {}", report.persona);
        println!("Persona anchor: {}", report.persona_anchor);
        println!("Expected root digest: matched");
        println!(
            "Expected head checkpoint: {}",
            if expected_head.is_some() {
                "matched"
            } else {
                "not supplied"
            }
        );
        println!("Transitions verified: {}", report.transition_count);
        println!("Initial key: {}", report.initial_key_fingerprint);
        println!(
            "Key at {} chain tip: {}",
            if expected_head.is_some() {
                "expected"
            } else {
                "supplied"
            },
            report.chain_tip_key_fingerprint
        );
        println!("Not established: {}", report.not_established.join(", "));
    }
    Ok(())
}

fn expected_continuity_checkpoint(
    sequence: Option<u32>,
    transition_sha256: Option<&str>,
) -> Result<Option<PersonaContinuityCheckpoint>> {
    match (sequence, transition_sha256) {
        (None, None) => Ok(None),
        (None, Some(_)) => bail!("--expected-head-sha256 requires --expected-head-sequence"),
        (Some(0), None) => Ok(Some(PersonaContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        })),
        (Some(0), Some(_)) => {
            bail!("--expected-head-sequence 0 cannot have --expected-head-sha256")
        }
        (Some(_), None) => {
            bail!("a nonzero --expected-head-sequence requires --expected-head-sha256")
        }
        (Some(transition_sequence), Some(transition_sha256)) => {
            Ok(Some(PersonaContinuityCheckpoint {
                transition_sequence,
                transition_sha256: Some(transition_sha256.to_owned()),
            }))
        }
    }
}

fn required_continuity_checkpoint(
    transition_sequence: u32,
    transition_sha256: Option<&str>,
    sequence_option: &str,
    digest_option: &str,
) -> Result<PersonaContinuityCheckpoint> {
    match (transition_sequence, transition_sha256) {
        (0, None) => Ok(PersonaContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        }),
        (0, Some(_)) => bail!("{sequence_option} 0 cannot have {digest_option}"),
        (_, None) => bail!("a nonzero {sequence_option} requires {digest_option}"),
        (transition_sequence, Some(transition_sha256)) => {
            require_sha256_pin(transition_sha256, digest_option)?;
            Ok(PersonaContinuityCheckpoint {
                transition_sequence,
                transition_sha256: Some(transition_sha256.to_owned()),
            })
        }
    }
}

fn require_sha256_pin(value: &str, option: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "{option} must be 64 lowercase hex digits"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_recovery_policy(
    root_path: &Path,
    prior_transition_paths: &[PathBuf],
    threshold: u32,
    valid_days: u16,
    authorize_terminal_revocation: bool,
    authority_key_paths: &[PathBuf],
    authority_public_key_paths: &[PathBuf],
    output: &Path,
) -> Result<()> {
    ensure_continuity_transition_path_count(prior_transition_paths, false)?;
    ensure_recovery_signer_path_counts(
        authority_key_paths,
        authority_public_key_paths,
        "recovery policy enrollment",
    )?;
    let validity_seconds = preflight_recovery_policy_parameters(
        threshold,
        authority_public_key_paths.len(),
        valid_days,
    )?;
    require_continuity_command_verification_work(&[
        (1, 3),
        (
            minimum_continuity_transition_signature_count(prior_transition_paths.len()),
            2,
        ),
        (authority_public_key_paths.len(), 3),
    ])?;
    require_new_output_path(output, "recovery policy proof")?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let root_proof = read_persona_root_proof_with_command_budget(root_path, &mut input_budget)?;
    let prior_transitions = prior_transition_paths
        .iter()
        .map(|path| read_persona_transition_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    let signers = read_recovery_signers(
        authority_key_paths,
        authority_public_key_paths,
        "recovery policy enrollment",
        &mut input_budget,
    )?;
    require_continuity_command_verification_work(&[
        (1, 3),
        (
            routine_transition_signature_count_sum(&prior_transitions),
            2,
        ),
        (signers.len(), 3),
    ])?;
    let root = verify_persona_root_proof(&root_proof)?;
    let continuity_report = verify_persona_continuity_chain(
        &root_proof,
        &prior_transitions,
        &root.root_statement_sha256,
    )?;
    let authority_public_keys = signers
        .iter()
        .map(|signer| signer.public_key.clone())
        .collect::<Vec<_>>();
    let issued_at = current_unix_time()?;
    ensure!(
        issued_at >= continuity_report.last_issued_at,
        "system clock precedes the last verified continuity statement; refusing to enroll recovery"
    );
    let expires_at = issued_at
        .checked_add(validity_seconds)
        .context("recovery policy expiry overflowed")?;
    let checkpoint = RecoveryContinuityCheckpoint {
        transition_sequence: continuity_report.transition_count,
        transition_sha256: continuity_report.last_transition_sha256.clone(),
    };
    let statement = if authorize_terminal_revocation {
        new_initial_recovery_policy_statement_with_capabilities(
            &root,
            &authority_public_keys,
            threshold,
            &[
                RecoveryPolicyCapability::KeyRecovery,
                RecoveryPolicyCapability::TerminalRevocation,
            ],
            checkpoint,
            issued_at,
            expires_at,
        )?
    } else {
        new_initial_recovery_policy_statement(
            &root,
            &authority_public_keys,
            threshold,
            checkpoint,
            issued_at,
            expires_at,
        )?
    };
    let proof = create_initial_recovery_policy_proof(statement, &signers)?;
    let verified = verify_initial_recovery_policy_proof(&root, &proof)?;
    let mixed_transitions = prior_transitions
        .into_iter()
        .map(PersonaContinuityTransitionProof::Routine)
        .collect::<Vec<_>>();
    verify_persona_continuity_chain_with_recovery(
        &root_proof,
        &mixed_transitions,
        std::slice::from_ref(&proof),
        &root.root_statement_sha256,
        &verified.policy_statement_sha256,
        issued_at,
    )?;
    write_private_json_new(
        output,
        serde_json::to_vec_pretty(&proof)?,
        MAX_PROOF_BYTES,
        "recovery policy proof",
    )?;

    println!("VERIFIED SELF-ASSERTED RECOVERY POLICY ENROLLMENT");
    println!("Persona: {}", verified.statement.persona);
    println!("Policy version: {}", verified.statement.policy_version);
    println!("Policy statement schema: {}", verified.statement.schema);
    println!("Threshold: {}", verified.statement.threshold);
    println!(
        "Recovery authorities: {} distinct public keys",
        verified.statement.recovery_key_fingerprints.len()
    );
    println!("Issued at (Unix): {}", verified.statement.issued_at);
    println!("Expires at (Unix): {}", verified.statement.expires_at);
    println!(
        "Terminal persona revocation authorized: {}",
        if verified
            .statement
            .authorizes(RecoveryPolicyCapability::TerminalRevocation)
        {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "Continuity checkpoint: transition {} {}",
        verified.statement.continuity_checkpoint.transition_sequence,
        verified
            .statement
            .continuity_checkpoint
            .transition_sha256
            .as_deref()
            .unwrap_or("none")
    );
    println!(
        "Recovery policy SHA-256: {}",
        verified.policy_statement_sha256
    );
    println!("Proof: {}", output.display());
    println!("Every listed recovery key proved possession under the enrollment namespace.");
    println!(
        "Trust step still required: pin the root and policy digests through a separate trusted channel before relying on recovery."
    );
    println!(
        "Signing path: low-level sequential signing; no trusted multi-party ceremony was used."
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn update_recovery_policy(
    root_path: &Path,
    policy_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    transition_paths: &[PathBuf],
    threshold: u32,
    valid_days: u16,
    authorize_terminal_revocation: bool,
    previous_authority_key_paths: &[PathBuf],
    previous_authority_public_key_paths: &[PathBuf],
    current_authority_key_paths: &[PathBuf],
    current_authority_public_key_paths: &[PathBuf],
    output: &Path,
) -> Result<()> {
    ensure_recovery_policy_path_count(policy_paths, true, true)?;
    ensure_continuity_transition_path_count(transition_paths, false)?;
    ensure_recovery_signer_path_counts(
        previous_authority_key_paths,
        previous_authority_public_key_paths,
        "previous recovery policy approval",
    )?;
    ensure_recovery_signer_path_counts(
        current_authority_key_paths,
        current_authority_public_key_paths,
        "current recovery policy enrollment",
    )?;
    let validity_seconds = preflight_recovery_policy_parameters(
        threshold,
        current_authority_public_key_paths.len(),
        valid_days,
    )?;
    let new_policy_signature_count = previous_authority_public_key_paths
        .len()
        .saturating_add(current_authority_public_key_paths.len());
    require_continuity_command_verification_work(&[
        (1, 3),
        (
            minimum_recovery_policy_signature_count(policy_paths.len()),
            3,
        ),
        (
            minimum_continuity_transition_signature_count(transition_paths.len()),
            2,
        ),
        (new_policy_signature_count, 3),
    ])?;
    require_new_output_path(output, "recovery policy proof")?;
    let issued_at = current_unix_time()?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let transitions = transition_paths
        .iter()
        .map(|path| read_continuity_transition_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    let previous_signers = read_recovery_signers(
        previous_authority_key_paths,
        previous_authority_public_key_paths,
        "previous recovery policy approval",
        &mut input_budget,
    )?;
    let current_signers = read_recovery_signers(
        current_authority_key_paths,
        current_authority_public_key_paths,
        "current recovery policy enrollment",
        &mut input_budget,
    )?;
    let additional_verifications = continuity_command_verification_work(&[
        (continuity_transition_signature_count_sum(&transitions), 2),
        (
            previous_signers.len().saturating_add(current_signers.len()),
            3,
        ),
    ])?;
    let context = load_recovery_context(
        root_path,
        policy_paths,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
        &mut input_budget,
        RecoveryContextVerificationWork {
            root_passes: 3,
            policy_passes: 3,
            additional_verifications,
        },
    )?;
    let previous = context
        .policies
        .last()
        .context("verified recovery policy chain is empty")?;
    let continuity_report = verify_persona_continuity_chain_with_recovery(
        &context.root_proof,
        &transitions,
        &context.policy_proofs,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
    )?;
    ensure!(
        !continuity_report.terminally_revoked,
        "a terminally revoked persona cannot update its recovery policy"
    );
    ensure!(
        issued_at >= previous.statement.issued_at && issued_at >= continuity_report.last_issued_at,
        "system clock precedes the current recovery policy or continuity history; refusing to sign an update"
    );
    let current_public_keys = current_signers
        .iter()
        .map(|signer| signer.public_key.clone())
        .collect::<Vec<_>>();
    let expires_at = issued_at
        .checked_add(validity_seconds)
        .context("recovery policy expiry overflowed")?;
    let checkpoint = RecoveryContinuityCheckpoint {
        transition_sequence: continuity_report.transition_count,
        transition_sha256: continuity_report.last_transition_sha256.clone(),
    };
    let statement = if authorize_terminal_revocation
        || previous.statement.schema == RECOVERY_POLICY_STATEMENT_SCHEMA_V2
    {
        let capabilities = if authorize_terminal_revocation {
            &[
                RecoveryPolicyCapability::KeyRecovery,
                RecoveryPolicyCapability::TerminalRevocation,
            ][..]
        } else {
            &[RecoveryPolicyCapability::KeyRecovery][..]
        };
        new_recovery_policy_update_statement_with_capabilities(
            previous,
            &current_public_keys,
            threshold,
            capabilities,
            checkpoint,
            issued_at,
            expires_at,
        )?
    } else {
        new_recovery_policy_update_statement(
            previous,
            &current_public_keys,
            threshold,
            checkpoint,
            issued_at,
            expires_at,
        )?
    };
    let proof = create_recovery_policy_update_proof(
        statement,
        previous,
        &previous_signers,
        &current_signers,
    )?;
    let verified = verify_recovery_policy_update_proof(&context.root, previous, &proof)?;
    let mut resulting_policies = context.policy_proofs;
    resulting_policies.push(proof.clone());
    verify_persona_continuity_chain_with_recovery(
        &context.root_proof,
        &transitions,
        &resulting_policies,
        expected_root_sha256,
        &verified.policy_statement_sha256,
        issued_at,
    )?;
    write_private_json_new(
        output,
        serde_json::to_vec_pretty(&proof)?,
        MAX_PROOF_BYTES,
        "recovery policy proof",
    )?;

    println!("VERIFIED DUAL-THRESHOLD RECOVERY POLICY UPDATE");
    println!("Persona: {}", verified.statement.persona);
    println!("Policy version: {}", verified.statement.policy_version);
    println!("Policy statement schema: {}", verified.statement.schema);
    println!("New threshold: {}", verified.statement.threshold);
    println!(
        "New recovery authorities: {} distinct public keys",
        verified.statement.recovery_key_fingerprints.len()
    );
    println!("Issued at (Unix): {}", verified.statement.issued_at);
    println!("Expires at (Unix): {}", verified.statement.expires_at);
    println!(
        "Terminal persona revocation authorized: {}",
        if verified
            .statement
            .authorizes(RecoveryPolicyCapability::TerminalRevocation)
        {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "Continuity checkpoint: transition {} {}",
        verified.statement.continuity_checkpoint.transition_sequence,
        verified
            .statement
            .continuity_checkpoint
            .transition_sha256
            .as_deref()
            .unwrap_or("none")
    );
    println!(
        "New recovery policy SHA-256: {}",
        verified.policy_statement_sha256
    );
    println!("Proof: {}", output.display());
    println!(
        "Previous-policy time status at update: {} (expiry does not erase valid old-threshold update authority).",
        recovery_policy_time_name(context.report.time_status)
    );
    println!(
        "Trust step still required: distribute and independently pin the new latest-policy digest."
    );
    println!(
        "Signing path: low-level sequential signing; no trusted multi-party ceremony was used."
    );
    Ok(())
}

fn verify_recovery_policy_command(
    root_path: &Path,
    policy_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    at_unix: Option<i64>,
    emit_json: bool,
) -> Result<()> {
    ensure_recovery_policy_path_count(policy_paths, true, false)?;
    require_continuity_command_verification_work(&[
        (1, 1),
        (
            minimum_recovery_policy_signature_count(policy_paths.len()),
            1,
        ),
    ])?;
    let checked_at = at_unix.map_or_else(current_unix_time, Ok)?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let context = load_recovery_context(
        root_path,
        policy_paths,
        expected_root_sha256,
        expected_policy_sha256,
        checked_at,
        &mut input_budget,
        RecoveryContextVerificationWork {
            root_passes: 1,
            policy_passes: 1,
            additional_verifications: 0,
        },
    )?;
    let latest_policy = context
        .policies
        .last()
        .context("verified recovery policy chain is empty")?;
    let terminal_revocation_authorized = latest_policy
        .statement
        .authorizes(RecoveryPolicyCapability::TerminalRevocation);
    if emit_json {
        let mut machine_report = serde_json::to_value(&context.report)?;
        let object = machine_report
            .as_object_mut()
            .context("recovery-policy report did not serialize as an object")?;
        object.insert(
            "latest_policy_capabilities".to_owned(),
            serde_json::to_value(latest_policy.statement.effective_capabilities())?,
        );
        object.insert(
            "terminal_revocation_authorized".to_owned(),
            Value::Bool(terminal_revocation_authorized),
        );
        println!("{}", serde_json::to_string_pretty(&machine_report)?);
    } else {
        print_recovery_policy_report(&context.report);
        println!(
            "Terminal persona revocation authorized: {}",
            if terminal_revocation_authorized {
                "yes"
            } else {
                "no"
            }
        );
    }
    ensure!(
        context.report.time_status == RecoveryPolicyTimeStatus::Active,
        "the cryptographically verified latest recovery policy is not active at the checked time"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_recovery_policy_command(
    store_path: Option<&Path>,
    persona_id: &str,
    policy_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    expected_head_sequence: u32,
    expected_head_sha256: Option<&str>,
) -> Result<()> {
    ensure_recovery_policy_path_count(policy_paths, true, false)?;
    require_sha256_pin(expected_root_sha256, "--expected-root-sha256")?;
    require_sha256_pin(expected_policy_sha256, "--expected-policy-sha256")?;
    let expected_head = required_continuity_checkpoint(
        expected_head_sequence,
        expected_head_sha256,
        "--expected-head-sequence",
        "--expected-head-sha256",
    )?;
    require_continuity_command_verification_work(&[(
        minimum_recovery_policy_signature_count(policy_paths.len()),
        1,
    )])?;

    let mut input_budget = ContinuityCommandInputBudget::new();
    let policies = policy_paths
        .iter()
        .map(|path| read_recovery_policy_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    require_continuity_command_verification_work(&[(
        recovery_policy_signature_count_sum(&policies),
        1,
    )])?;

    let mut store = require_existing_persona_store(store_path)?;
    let recorded = store.record_recovery_policy_chain(
        persona_id,
        &policies,
        expected_root_sha256,
        expected_policy_sha256,
        &expected_head,
    )?;

    println!("RECORDED RECOVERY POLICY EVIDENCE");
    println!("Persona ID: {persona_id}");
    println!("Policy versions recorded: {}", recorded.policies.len());
    println!(
        "Latest policy version: {}",
        recorded.head.latest_policy_version
    );
    println!(
        "Recovery policy statement SHA-256: {}",
        recorded.head.latest_policy_sha256
    );
    println!(
        "Store status: {}",
        if recorded.replayed {
            "already recorded; exact chain replay"
        } else {
            "new policy evidence recorded"
        }
    );
    print_recovery_recording_caveats();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_recovery_transition_command(
    root_path: &Path,
    policy_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    prior_transition_paths: &[PathBuf],
    reason: RecoveryTransitionReason,
    authority_key_paths: &[PathBuf],
    authority_public_key_paths: &[PathBuf],
    next_key_path: &Path,
    next_public_key_path: &Path,
    output: &Path,
) -> Result<()> {
    ensure_recovery_policy_path_count(policy_paths, true, false)?;
    ensure_continuity_transition_path_count(prior_transition_paths, true)?;
    ensure_recovery_signer_path_counts(
        authority_key_paths,
        authority_public_key_paths,
        "recovery transition approval",
    )?;
    let new_transition_signature_count = authority_public_key_paths.len().saturating_add(1);
    require_continuity_command_verification_work(&[
        (1, 3),
        (
            minimum_recovery_policy_signature_count(policy_paths.len()),
            3,
        ),
        (
            minimum_continuity_transition_signature_count(prior_transition_paths.len()),
            2,
        ),
        (new_transition_signature_count, 3),
    ])?;
    require_new_output_path(output, "recovery transition proof")?;
    let issued_at = current_unix_time()?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let prior_transitions = prior_transition_paths
        .iter()
        .map(|path| read_continuity_transition_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        prior_transitions.iter().all(|proof| !matches!(
            proof,
            PersonaContinuityTransitionProof::TerminalRevocation(_)
        )),
        "a terminally revoked persona cannot accept a successor recovery transition"
    );
    let authority_signers = read_recovery_signers(
        authority_key_paths,
        authority_public_key_paths,
        "recovery transition approval",
        &mut input_budget,
    )?;
    let next_public_key =
        read_public_key_with_command_budget(next_public_key_path, &mut input_budget)?;
    let additional_verifications = continuity_command_verification_work(&[
        (
            continuity_transition_signature_count_sum(&prior_transitions),
            2,
        ),
        (authority_signers.len().saturating_add(1), 3),
    ])?;
    let context = load_recovery_context(
        root_path,
        policy_paths,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
        &mut input_budget,
        RecoveryContextVerificationWork {
            root_passes: 3,
            policy_passes: 3,
            additional_verifications,
        },
    )?;
    ensure!(
        context.report.time_status == RecoveryPolicyTimeStatus::Active,
        "the independently pinned latest recovery policy is not active"
    );
    let prior_report = verify_persona_continuity_chain_with_recovery(
        &context.root_proof,
        &prior_transitions,
        &context.policy_proofs,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
    )?;
    ensure!(
        issued_at >= prior_report.last_issued_at,
        "system clock precedes the last verified continuity statement; refusing to sign"
    );
    let previous_key_fingerprint = prior_report
        .current_key_fingerprint
        .as_deref()
        .context("verified continuity history has no current online key")?;
    let latest_policy = context
        .policies
        .last()
        .context("verified recovery policy chain is empty")?;
    let sequence = u32::try_from(prior_transitions.len() + 1)
        .context("continuity transition count overflowed")?;
    let statement = new_recovery_transition_statement(
        &context.root,
        sequence,
        prior_report.last_transition_sha256.as_deref(),
        previous_key_fingerprint,
        &next_public_key,
        latest_policy,
        issued_at,
        reason,
    )?;
    let proof = create_recovery_transition_proof(
        statement,
        latest_policy,
        &authority_signers,
        next_key_path,
        &next_public_key,
    )?;
    let verified = verify_recovery_transition_proof(&context.root, latest_policy, &proof)?;
    let mut resulting_transitions = prior_transitions;
    resulting_transitions.push(PersonaContinuityTransitionProof::Recovery(proof.clone()));
    verify_persona_continuity_chain_with_recovery(
        &context.root_proof,
        &resulting_transitions,
        &context.policy_proofs,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
    )?;
    write_private_json_new(
        output,
        serde_json::to_vec_pretty(&proof)?,
        MAX_PROOF_BYTES,
        "recovery transition proof",
    )?;

    println!("VERIFIED THRESHOLD-AUTHORIZED RECOVERY TRANSITION");
    println!("Persona: {}", verified.statement.persona);
    println!("Sequence: {}", verified.statement.sequence);
    println!("Reason: {:?}", verified.statement.reason);
    println!(
        "Replaced key: {}",
        verified.statement.previous_key_fingerprint
    );
    println!("New key: {}", verified.statement.next_key_fingerprint);
    println!(
        "Recovery policy: v{} {}",
        verified.statement.recovery_policy_version, verified.statement.recovery_policy_sha256
    );
    println!(
        "Distinct recovery signatures verified: {}",
        verified.recovery_signer_fingerprints.len()
    );
    println!(
        "Transition statement SHA-256: {}",
        verified.transition_statement_sha256
    );
    println!("Proof: {}", output.display());
    println!("Expected root and latest-policy pins: matched supplied values.");
    println!(
        "Signing path: low-level sequential signing; no trusted multi-party ceremony was used."
    );
    println!(
        "Not established: trusted issuance time, legal identity, guardian independence, or safety."
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn start_recovery_transition_ceremony(
    store_path: Option<&Path>,
    persona_id: &str,
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<&str>,
    reason: RecoveryTransitionReason,
    next_public_key_path: &Path,
    valid_minutes: u16,
    output: &Path,
) -> Result<()> {
    require_new_output_path(output, "recovery ceremony request")?;
    require_sha256_pin(expected_root_sha256, "--expected-root-sha256")?;
    require_sha256_pin(expected_policy_sha256, "--expected-policy-sha256")?;
    let expected_head = required_continuity_checkpoint(
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        "--expected-previous-head-sequence",
        "--expected-previous-head-sha256",
    )?;
    ensure!(
        valid_minutes > 0,
        "--valid-minutes must be at least one minute"
    );
    let validity_seconds = i64::from(valid_minutes)
        .checked_mul(60)
        .context("recovery ceremony validity overflowed")?;
    ensure!(
        validity_seconds <= MAX_RECOVERY_CEREMONY_VALIDITY_SECONDS,
        "--valid-minutes cannot exceed {} minutes",
        MAX_RECOVERY_CEREMONY_VALIDITY_SECONDS / 60
    );

    let mut input_budget = ContinuityCommandInputBudget::new();
    let next_public_key = normalized_public_key_text(&read_public_key_with_command_budget(
        next_public_key_path,
        &mut input_budget,
    )?)?;
    let store = require_existing_persona_store(store_path)?;
    let snapshot = store
        .continuity_snapshot(persona_id)
        .with_context(|| format!("persona {persona_id} has no valid live continuity journal"))?;
    ensure!(
        snapshot.terminal_revocation.is_none(),
        "persona {persona_id} is PERMANENTLY DEAUTHORIZED and cannot start a recovery ceremony"
    );
    ensure!(
        snapshot.root.root_statement_sha256 == expected_root_sha256,
        "independently supplied root digest does not match the live persona journal"
    );
    let policy_head = snapshot
        .recovery_policy_head
        .as_ref()
        .context("persona has no recorded recovery-policy chain")?;
    ensure!(
        policy_head.latest_policy_sha256 == expected_policy_sha256,
        "independently supplied latest-policy digest does not match the live persona journal"
    );
    ensure!(
        snapshot.head.transition_sequence == expected_head.transition_sequence
            && snapshot.head.last_transition_sha256 == expected_head.transition_sha256,
        "independently supplied previous-head pin does not match the live persona journal"
    );

    let policy_proofs = snapshot
        .recovery_policies
        .iter()
        .map(|recorded| recorded.proof.clone())
        .collect::<Vec<_>>();
    ensure!(
        !policy_proofs.is_empty() && policy_proofs.len() <= MAX_RECOVERY_POLICY_VERSIONS,
        "live recovery policy chain must contain 1 through {MAX_RECOVERY_POLICY_VERSIONS} proofs"
    );
    require_continuity_command_verification_work(&[
        (1, 3),
        (recovery_policy_signature_count_sum(&policy_proofs), 3),
        (
            continuity_transition_signature_count_sum(&snapshot.transitions),
            2,
        ),
    ])?;

    let issued_at = current_unix_time()?;
    let policy_chain = verify_recovery_policy_chain_with_verified_sequence(
        &snapshot.root.proof,
        &policy_proofs,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
    )?;
    ensure!(
        policy_chain.report().time_status == RecoveryPolicyTimeStatus::Active,
        "the independently pinned latest recovery policy is not active"
    );
    let latest_policy = policy_chain
        .policies()
        .last()
        .context("verified recovery policy chain is empty")?;
    let expires_at = issued_at
        .checked_add(validity_seconds)
        .context("recovery ceremony expiry overflowed")?;
    let sequence = expected_previous_head_sequence
        .checked_add(1)
        .context("recovery transition sequence overflowed")?;
    let statement = new_recovery_transition_ceremony_statement(
        policy_chain.root(),
        sequence,
        expected_head.transition_sha256.as_deref(),
        &snapshot.head.current_key_fingerprint,
        &next_public_key,
        latest_policy,
        issued_at,
        expires_at,
        reason,
    )?;
    let request = new_recovery_ceremony_request(
        snapshot.root.proof,
        policy_proofs,
        snapshot.transitions,
        expected_root_sha256.to_owned(),
        expected_policy_sha256.to_owned(),
        expected_head,
        statement,
        next_public_key,
    )?;
    let verified = verify_recovery_ceremony_request_with_expectations(
        &request,
        expected_root_sha256,
        expected_policy_sha256,
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        issued_at,
    )?;
    let request_bytes = canonical_recovery_ceremony_request_bytes(&request)?;
    write_private_bytes_new(
        output,
        &request_bytes,
        u64::try_from(MAX_RECOVERY_CEREMONY_REQUEST_BYTES)
            .expect("recovery ceremony request bound fits in u64"),
        "recovery ceremony request",
    )?;

    println!("CREATED VERIFIED RECOVERY CEREMONY REQUEST");
    println!("Persona: {}", verified.statement().persona);
    println!(
        "Ceremony ID: {}",
        verified
            .statement()
            .ceremony_id
            .as_deref()
            .expect("verified ceremony has an ID")
    );
    println!("Request SHA-256: {}", verified.request_sha256());
    println!("Sequence: {}", verified.statement().sequence);
    println!(
        "Previous head: {}",
        continuity_checkpoint_label(&request.expected_head)
    );
    println!("Next key: {}", verified.statement().next_key_fingerprint);
    println!("Expires at Unix time: {expires_at}");
    println!("Request: {}", output.display());
    println!("Live persona state: not changed; responses and commit are separate operations.");
    println!(
        "Each participant must independently verify the root, latest-policy, and previous-head pins."
    );
    println!(
        "Not established: distinct people or devices, trusted wall-clock time, legal identity, or safety."
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn respond_to_recovery_transition_ceremony(
    request_path: &Path,
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<&str>,
    participant_provider: &str,
    participant_signing_locator: &Path,
    participant_public_key_path: &Path,
    output: &Path,
    socket_path: Option<&Path>,
) -> Result<()> {
    require_new_output_path(output, "recovery ceremony response")?;
    let checked_at = current_unix_time()?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let (request, request_bytes) =
        read_recovery_ceremony_request_with_command_budget(request_path, &mut input_budget)?;
    require_continuity_command_verification_work(&[(
        recovery_ceremony_request_signature_count(&request),
        1,
    )])?;
    let verified = verify_recovery_ceremony_request_with_expectations(
        &request,
        expected_root_sha256,
        expected_policy_sha256,
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        checked_at,
    )?;
    let participant_public_key = normalized_public_key_text(&read_public_key_with_command_budget(
        participant_public_key_path,
        &mut input_budget,
    )?)?;
    let expected_review = a_quo_core::review_recovery_ceremony_participant(
        &verified,
        &participant_public_key,
        checked_at,
    )?;
    let provider = participant_provider.parse::<KeyProvider>()?;
    let signing_reference = participant_signing_locator
        .to_str()
        .context("participant signing locator is not UTF-8")?;
    ensure!(
        !signing_reference.is_empty(),
        "participant signing locator cannot be empty"
    );
    let request_packet = IpcSignRequest::new_recovery_participation(
        ipc_recovery_participant_key_provider(provider),
        signing_reference,
        &participant_public_key,
        decode_sha256(expected_root_sha256).map_err(|()| {
            anyhow::anyhow!("--expected-root-sha256 must be 64 lowercase hex digits")
        })?,
        verified.selected_policy().statement.policy_version,
        decode_sha256(expected_policy_sha256).map_err(|()| {
            anyhow::anyhow!("--expected-policy-sha256 must be 64 lowercase hex digits")
        })?,
        verified.selected_policy().statement.threshold,
        request.expected_head.transition_sequence,
        request
            .expected_head
            .transition_sha256
            .as_deref()
            .map(decode_sha256)
            .transpose()
            .map_err(|()| anyhow::anyhow!("request contains a malformed previous-head digest"))?,
    )?;
    let sealed_request = snapshot_stream(
        request_bytes.as_slice(),
        MAX_RECOVERY_PARTICIPATION_REQUEST_BYTES,
    )?;
    let socket_path = resolve_consent_socket_path(socket_path)?;
    let socket = connect_consent_socket(&socket_path)
        .with_context(|| format!("cannot connect to daemon socket {}", socket_path.display()))?;
    send_sign_request(&socket, &request_packet, sealed_request.file())?;
    let received = receive_sign_response(&socket)?;
    let sealed_response = match received.response {
        SignResponse::Approved => received
            .proof
            .context("daemon approved without a sealed recovery response descriptor")?,
        SignResponse::Rejected(code) => {
            bail!(
                "recovery ceremony participation rejected: {}",
                rejection_name(code)
            );
        }
    };
    let response_bytes = sealed_response.read_bytes()?;
    let response = parse_recovery_ceremony_response_bytes(&response_bytes)
        .context("daemon returned an invalid recovery ceremony response")?;
    let verified_at = current_unix_time()?;
    let verified_response = verify_recovery_ceremony_response(&verified, &response, verified_at)
        .context("daemon returned an unauthorized or stale recovery ceremony response")?;
    ensure!(
        verified_response.participant_fingerprint() == expected_review.participant_fingerprint,
        "daemon response was signed by a different participant key"
    );
    let canonical_response = canonical_recovery_ceremony_response_bytes(&response)?;
    ensure!(
        canonical_response == response_bytes,
        "daemon response changed during canonical verification"
    );
    write_private_bytes_new(
        output,
        &canonical_response,
        u64::try_from(MAX_RECOVERY_CEREMONY_RESPONSE_BYTES)
            .expect("recovery ceremony response bound fits in u64"),
        "recovery ceremony response",
    )?;

    println!("CREATED VERIFIED RECOVERY CEREMONY RESPONSE");
    println!("Persona: {}", expected_review.persona);
    println!("Ceremony ID: {}", expected_review.ceremony_id);
    println!("Request SHA-256: {}", expected_review.request_sha256);
    println!("Role: {:?}", expected_review.role);
    println!(
        "Participant key: {}",
        expected_review.participant_fingerprint
    );
    println!("Response: {}", output.display());
    println!("Portable response contains no local signer locator or persona UUID.");
    println!("Not established: participant independence, legal identity, truth, or safety.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn respond_to_recovery_transition_ceremony(
    _request_path: &Path,
    _expected_root_sha256: &str,
    _expected_policy_sha256: &str,
    _expected_previous_head_sequence: u32,
    _expected_previous_head_sha256: Option<&str>,
    _participant_provider: &str,
    _participant_signing_locator: &Path,
    _participant_public_key_path: &Path,
    _output: &Path,
    _socket_path: Option<&Path>,
) -> Result<()> {
    bail!("recovery ceremony participation is currently available only on Linux")
}

#[allow(clippy::too_many_arguments)]
fn assemble_recovery_transition_ceremony(
    request_path: &Path,
    response_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<&str>,
    output: &Path,
) -> Result<()> {
    ensure!(
        !response_paths.is_empty() && response_paths.len() <= MAX_RECOVERY_CEREMONY_RESPONSES,
        "--response must be repeated 1 through {MAX_RECOVERY_CEREMONY_RESPONSES} times"
    );
    require_new_output_path(output, "recovery transition proof")?;
    let checked_at = current_unix_time()?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let (request, _) =
        read_recovery_ceremony_request_with_command_budget(request_path, &mut input_budget)?;
    require_continuity_command_verification_work(&[
        (recovery_ceremony_request_signature_count(&request), 1),
        (response_paths.len(), 3),
    ])?;
    let verified = verify_recovery_ceremony_request_with_expectations(
        &request,
        expected_root_sha256,
        expected_policy_sha256,
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        checked_at,
    )?;
    let responses = response_paths
        .iter()
        .map(|path| read_recovery_ceremony_response_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    let proof = assemble_recovery_ceremony_proof(&verified, &responses, checked_at)?;
    let inspected = inspect_recovery_transition_proof(&proof)?;
    ensure!(
        inspected == *verified.statement(),
        "assembled proof does not contain the exact ceremony statement"
    );
    write_private_json_new(
        output,
        serde_json::to_vec_pretty(&proof)?,
        MAX_PROOF_BYTES,
        "recovery transition proof",
    )?;

    println!("ASSEMBLED VERIFIED RECOVERY TRANSITION PROOF");
    println!("Persona: {}", verified.statement().persona);
    println!(
        "Ceremony ID: {}",
        verified
            .statement()
            .ceremony_id
            .as_deref()
            .expect("verified ceremony has an ID")
    );
    println!("Request SHA-256: {}", verified.request_sha256());
    println!("Sequence: {}", verified.statement().sequence);
    println!(
        "Distinct authority responses: {}",
        proof.recovery_signatures.len()
    );
    println!("Exact successor response: verified");
    println!("Proof: {}", output.display());
    println!("Live persona state: not changed; commit remains a separate atomic operation.");
    println!("Not established: participant independence, legal identity, truth, or safety.");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_recovery_ceremony_request_with_expectations(
    request: &RecoveryCeremonyRequest,
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<&str>,
    checked_at: i64,
) -> Result<a_quo_core::VerifiedRecoveryCeremonyRequest> {
    require_sha256_pin(expected_root_sha256, "--expected-root-sha256")?;
    require_sha256_pin(expected_policy_sha256, "--expected-policy-sha256")?;
    let expected_head = required_continuity_checkpoint(
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        "--expected-previous-head-sequence",
        "--expected-previous-head-sha256",
    )?;
    ensure!(
        request.expected_root_statement_sha256 == expected_root_sha256,
        "ceremony request does not match the independently supplied root digest"
    );
    ensure!(
        request.expected_latest_policy_sha256 == expected_policy_sha256,
        "ceremony request does not match the independently supplied latest-policy digest"
    );
    ensure!(
        request.expected_head == expected_head,
        "ceremony request does not match the independently supplied previous-head pin"
    );
    verify_recovery_ceremony_request(request, checked_at)
        .context("recovery ceremony request failed complete evidence verification")
}

fn continuity_checkpoint_label(checkpoint: &PersonaContinuityCheckpoint) -> String {
    match checkpoint.transition_sha256.as_deref() {
        Some(digest) => format!("sequence {} {digest}", checkpoint.transition_sequence),
        None => format!("root (sequence {})", checkpoint.transition_sequence),
    }
}

fn verify_recovery_transition_command(
    proof_path: &Path,
    root_path: &Path,
    policy_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    emit_json: bool,
) -> Result<()> {
    ensure_recovery_policy_path_count(policy_paths, true, false)?;
    require_continuity_command_verification_work(&[
        (1, 1),
        (
            minimum_recovery_policy_signature_count(policy_paths.len()),
            1,
        ),
        (MIN_RECOVERY_AUTHORITIES.saturating_add(1), 1),
    ])?;
    let checked_at = current_unix_time()?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let proof = read_recovery_transition_proof_with_command_budget(proof_path, &mut input_budget)?;
    let supplied_transition_signature_count = proof.recovery_signatures.len().saturating_add(1);
    let context = load_recovery_context(
        root_path,
        policy_paths,
        expected_root_sha256,
        expected_policy_sha256,
        checked_at,
        &mut input_budget,
        RecoveryContextVerificationWork {
            root_passes: 1,
            policy_passes: 1,
            additional_verifications: supplied_transition_signature_count,
        },
    )?;
    let statement = inspect_recovery_transition_proof(&proof)?;
    let selected_policy = context
        .policies
        .iter()
        .find(|policy| {
            policy.statement.policy_version == statement.recovery_policy_version
                && policy.policy_statement_sha256 == statement.recovery_policy_sha256
        })
        .context("recovery transition references a policy outside the verified policy chain")?;
    let verified = verify_recovery_transition_proof(&context.root, selected_policy, &proof)?;
    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "root_digest_match": "verified",
                "latest_policy_digest_match": "verified",
                "policy_chain": "verified",
                "recovery_threshold": "verified",
                "new_key_custody": "verified",
                "statement": verified.statement,
                "transition_statement_sha256": verified.transition_statement_sha256,
                "recovery_signer_fingerprints": verified.recovery_signer_fingerprints,
                "ordered_transition_chain": "not_checked",
                "trusted_issuance_time": "not_established",
                "legal_identity": "not_established"
            }))?
        );
    } else {
        println!("VERIFIED RECOVERY AUTHORITY AND NEW-KEY CUSTODY");
        println!("Persona claim: {}", verified.statement.persona);
        println!("Sequence claim: {}", verified.statement.sequence);
        println!(
            "Recovery policy: v{} {}",
            verified.statement.recovery_policy_version, verified.statement.recovery_policy_sha256
        );
        println!(
            "Distinct recovery signatures: {}",
            verified.recovery_signer_fingerprints.len()
        );
        println!("New key: {}", verified.statement.next_key_fingerprint);
        println!(
            "Transition statement SHA-256: {}",
            verified.transition_statement_sha256
        );
        println!("Expected root and latest-policy pins: matched");
        println!("Ordered transition chain: not checked");
        println!("Trusted issuance time and legal identity: not established");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn commit_recovery_transition_command(
    store_path: Option<&Path>,
    persona_id: &str,
    proof_path: &Path,
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<&str>,
    next_provider: Option<&str>,
    next_signing_locator: Option<&Path>,
) -> Result<()> {
    let supplied_binding = match (next_provider, next_signing_locator) {
        (Some(provider), Some(locator)) => {
            Some((provider.parse::<KeyProvider>()?, locator.to_path_buf()))
        }
        (None, None) => None,
        _ => bail!("--next-provider and --next-signing-locator must be supplied together"),
    };
    require_sha256_pin(expected_root_sha256, "--expected-root-sha256")?;
    require_sha256_pin(expected_policy_sha256, "--expected-policy-sha256")?;
    let expected_previous_head = required_continuity_checkpoint(
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        "--expected-previous-head-sequence",
        "--expected-previous-head-sha256",
    )?;
    require_continuity_command_verification_work(&[(
        MIN_RECOVERY_AUTHORITIES.saturating_add(1),
        1,
    )])?;

    let mut input_budget = ContinuityCommandInputBudget::new();
    let proof = read_recovery_transition_proof_with_command_budget(proof_path, &mut input_budget)?;
    require_continuity_command_verification_work(&[(
        proof.recovery_signatures.len().saturating_add(1),
        1,
    )])?;
    let statement = inspect_recovery_transition_proof(&proof)?;
    let intent = RecoveryTransitionIntent {
        persona_id: persona_id.to_owned(),
        sequence: statement.sequence,
        root_statement_sha256: statement.root_statement_sha256,
        previous_transition_sha256: statement.previous_transition_sha256,
        previous_key_fingerprint: statement.previous_key_fingerprint,
        next_key_fingerprint: statement.next_key_fingerprint,
        recovery_policy_sha256: statement.recovery_policy_sha256,
        recovery_policy_version: statement.recovery_policy_version,
        reason: statement.reason,
        issued_at: statement.issued_at,
        ceremony_id: statement.ceremony_id,
        expires_at: statement.expires_at,
    };

    let mut store = require_existing_persona_store(store_path)?;
    let binding_was_supplied = supplied_binding.is_some();
    let (next_provider, next_signing_locator, expected_committed) = match supplied_binding {
        Some((provider, locator)) => (provider, locator, None),
        None => {
            let committed = store
                .lookup_committed_recovery_transition(&intent)?
                .context(
                    "--next-provider and --next-signing-locator are required for a first recovery transition commit; omission is allowed only for an exact current-head replay",
                )?;
            let metadata = store
                .committed_recovery_transition_retry_metadata(&intent)?
                .context("committed recovery transition has no current-head signer metadata")?;
            ensure!(
                metadata.persona_id == persona_id
                    && metadata.current_key_fingerprint == intent.next_key_fingerprint,
                "stored recovery retry metadata does not match the exact committed intent"
            );
            (metadata.provider, metadata.signing_locator, Some(committed))
        }
    };
    let committed = store.commit_recovery_transition(
        persona_id,
        &proof,
        expected_root_sha256,
        expected_policy_sha256,
        &expected_previous_head,
        next_provider,
        &next_signing_locator,
    )?;
    if let Some(expected_committed) = expected_committed {
        ensure!(
            committed == expected_committed,
            "recovery retry did not return the authoritative first committed proof wrapper"
        );
    } else if committed.replayed {
        let metadata = store
            .committed_recovery_transition_retry_metadata(&committed.intent)?
            .context("committed recovery transition is not the current verified head")?;
        let locator_matches = retry_locator_matches(
            &next_signing_locator,
            &metadata.signing_locator,
            "next signing locator",
        )?;
        ensure!(
            metadata.persona_id == persona_id
                && metadata.current_key_fingerprint == committed.intent.next_key_fingerprint
                && metadata.provider == next_provider
                && locator_matches,
            "the proposed retry provider or signer locator does not match the committed recovery head"
        );
    }

    println!("COMMITTED RECOVERY TRANSITION EVIDENCE");
    println!("Persona ID: {persona_id}");
    println!("Sequence: {}", committed.intent.sequence);
    println!("Reason: {:?}", committed.intent.reason);
    println!(
        "Recovery policy: v{} {}",
        committed.intent.recovery_policy_version, committed.intent.recovery_policy_sha256
    );
    println!("Next key: {}", committed.intent.next_key_fingerprint);
    println!(
        "Transition statement SHA-256: {}",
        committed.transition_statement_sha256
    );
    println!(
        "Store status: {}",
        if committed.replayed {
            "already committed; statement replay"
        } else {
            "new transition committed"
        }
    );
    println!(
        "Signer binding: {}",
        if binding_was_supplied {
            "explicitly supplied"
        } else {
            "reused from verified current-head metadata for replay"
        }
    );
    print_recovery_recording_caveats();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_terminal_revocation_command(
    root_path: &Path,
    policy_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    prior_transition_paths: &[PathBuf],
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<&str>,
    reason: TerminalPersonaRevocationReason,
    authority_key_paths: &[PathBuf],
    authority_public_key_paths: &[PathBuf],
    output: &Path,
    emit_json: bool,
) -> Result<()> {
    ensure_recovery_policy_path_count(policy_paths, true, false)?;
    ensure_terminal_revocation_prior_path_count(prior_transition_paths)?;
    ensure_recovery_signer_path_counts(
        authority_key_paths,
        authority_public_key_paths,
        "terminal persona revocation approval",
    )?;
    require_sha256_pin(expected_root_sha256, "--expected-root-sha256")?;
    require_sha256_pin(expected_policy_sha256, "--expected-policy-sha256")?;
    let expected_previous_head = required_continuity_checkpoint(
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        "--expected-previous-head-sequence",
        "--expected-previous-head-sha256",
    )?;
    ensure!(
        usize::try_from(expected_previous_head_sequence).ok() == Some(prior_transition_paths.len()),
        "--expected-previous-head-sequence must equal the supplied prior-transition count"
    );
    require_continuity_command_verification_work(&[
        (1, 3),
        (
            minimum_recovery_policy_signature_count(policy_paths.len()),
            3,
        ),
        (
            minimum_continuity_transition_signature_count(prior_transition_paths.len()),
            2,
        ),
        (authority_public_key_paths.len(), 3),
    ])?;
    require_new_output_path(output, "terminal persona revocation proof")?;

    let issued_at = current_unix_time()?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let prior_transitions = prior_transition_paths
        .iter()
        .map(|path| read_continuity_transition_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        prior_transitions.iter().all(|proof| !matches!(
            proof,
            PersonaContinuityTransitionProof::TerminalRevocation(_)
        )),
        "a terminal revocation cannot appear in --prior-transition; it must be the final event"
    );
    let authority_signers = read_recovery_signers(
        authority_key_paths,
        authority_public_key_paths,
        "terminal persona revocation approval",
        &mut input_budget,
    )?;
    let additional_verifications = continuity_command_verification_work(&[
        (
            continuity_transition_signature_count_sum(&prior_transitions),
            2,
        ),
        (authority_signers.len(), 3),
    ])?;
    let context = load_recovery_context(
        root_path,
        policy_paths,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
        &mut input_budget,
        RecoveryContextVerificationWork {
            root_passes: 3,
            policy_passes: 3,
            additional_verifications,
        },
    )?;
    ensure!(
        context.report.time_status == RecoveryPolicyTimeStatus::Active,
        "the independently pinned latest recovery policy is not active"
    );
    let latest_policy = context
        .policies
        .last()
        .context("verified recovery policy chain is empty")?;
    ensure!(
        latest_policy
            .statement
            .authorizes(RecoveryPolicyCapability::TerminalRevocation),
        "the independently pinned latest policy does not explicitly authorize terminal persona revocation"
    );
    let prior_report = verify_persona_continuity_chain_with_recovery(
        &context.root_proof,
        &prior_transitions,
        &context.policy_proofs,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
    )?;
    ensure!(
        prior_report.transition_count == expected_previous_head.transition_sequence
            && prior_report.last_transition_sha256 == expected_previous_head.transition_sha256,
        "supplied prior transition chain does not match the independently expected previous head"
    );
    ensure!(
        !prior_report.terminally_revoked,
        "a terminally revoked persona cannot accept another continuity event"
    );
    ensure!(
        issued_at >= prior_report.last_issued_at,
        "system clock precedes the last verified continuity statement; refusing to sign"
    );
    let previous_key_fingerprint = prior_report
        .current_key_fingerprint
        .as_deref()
        .context("verified pre-revocation history has no current online key")?;
    let sequence = expected_previous_head_sequence
        .checked_add(1)
        .context("terminal revocation sequence overflowed")?;
    let statement = a_quo_core::new_terminal_persona_revocation_statement(
        &context.root,
        sequence,
        prior_report.last_transition_sha256.as_deref(),
        previous_key_fingerprint,
        latest_policy,
        issued_at,
        reason,
    )?;
    let proof =
        create_terminal_persona_revocation_proof(statement, latest_policy, &authority_signers)?;
    let verified = verify_terminal_persona_revocation_proof(&context.root, latest_policy, &proof)?;
    let mut resulting_transitions = prior_transitions;
    resulting_transitions.push(PersonaContinuityTransitionProof::TerminalRevocation(
        proof.clone(),
    ));
    let resulting_report = verify_persona_continuity_chain_with_recovery(
        &context.root_proof,
        &resulting_transitions,
        &context.policy_proofs,
        expected_root_sha256,
        expected_policy_sha256,
        issued_at,
    )?;
    ensure!(
        resulting_report.terminally_revoked
            && resulting_report.current_key_fingerprint.is_none()
            && resulting_report
                .terminal_revocation_statement_sha256
                .as_deref()
                == Some(verified.revocation_statement_sha256.as_str()),
        "resulting continuity chain did not end in the exact terminal revocation"
    );
    write_private_json_new(
        output,
        serde_json::to_vec_pretty(&proof)?,
        MAX_PROOF_BYTES,
        "terminal persona revocation proof",
    )?;

    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "verified_threshold_authorized_terminal_revocation",
                "persona": verified.statement.persona,
                "persona_anchor": verified.statement.persona_anchor,
                "sequence": verified.statement.sequence,
                "reason": verified.statement.reason,
                "signed_effect": "persona_permanently_deauthorized",
                "revoked_key_fingerprint": verified.statement.previous_key_fingerprint,
                "successor_key_fingerprint": Value::Null,
                "recovery_policy_version": verified.statement.recovery_policy_version,
                "recovery_policy_sha256": verified.statement.recovery_policy_sha256,
                "distinct_recovery_signatures_verified": verified.recovery_signer_fingerprints.len(),
                "revocation_statement_sha256": verified.revocation_statement_sha256,
                "expected_root_pin": "matched",
                "expected_latest_policy_pin": "matched",
                "expected_previous_head": "matched",
                "proof": output,
                "live_store_changed": false,
                "trusted_multi_party_consent": false,
                "not_established": [
                    "trusted_issuance_time",
                    "guardian_independence",
                    "legal_identity",
                    "external_publication_or_freshness",
                    "artifact_or_software_safety"
                ]
            }))?
        );
    } else {
        println!("VERIFIED THRESHOLD-AUTHORIZED TERMINAL REVOCATION");
        println!("Persona: {}", verified.statement.persona);
        println!("Sequence: {}", verified.statement.sequence);
        println!(
            "Reason: {}",
            terminal_revocation_reason_name(verified.statement.reason)
        );
        println!("Signed effect: PERSONA PERMANENTLY DEAUTHORIZED");
        println!(
            "Revoked current key: {}",
            verified.statement.previous_key_fingerprint
        );
        println!("Successor key: none");
        println!(
            "Recovery policy: v{} {}",
            verified.statement.recovery_policy_version, verified.statement.recovery_policy_sha256
        );
        println!(
            "Distinct recovery signatures verified: {}",
            verified.recovery_signer_fingerprints.len()
        );
        println!(
            "Revocation statement SHA-256: {}",
            verified.revocation_statement_sha256
        );
        println!("Proof: {}", output.display());
        println!("Expected root, latest-policy, and previous-head pins: matched.");
        println!("Live persona store: not changed; commit is a separate operation.");
        println!(
            "Signing path: low-level sequential signing; no trusted multi-party ceremony was used."
        );
        println!(
            "Not established: trusted issuance time, guardian independence, legal identity, external publication/freshness, or safety."
        );
    }
    Ok(())
}

fn verify_terminal_revocation_command(
    proof_path: &Path,
    root_path: &Path,
    policy_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    emit_json: bool,
) -> Result<()> {
    ensure_recovery_policy_path_count(policy_paths, true, false)?;
    require_sha256_pin(expected_root_sha256, "--expected-root-sha256")?;
    require_sha256_pin(expected_policy_sha256, "--expected-policy-sha256")?;
    require_continuity_command_verification_work(&[
        (1, 1),
        (
            minimum_recovery_policy_signature_count(policy_paths.len()),
            1,
        ),
        (MIN_RECOVERY_AUTHORITIES, 1),
    ])?;
    let checked_at = current_unix_time()?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let proof = read_terminal_revocation_proof_with_command_budget(proof_path, &mut input_budget)?;
    let context = load_recovery_context(
        root_path,
        policy_paths,
        expected_root_sha256,
        expected_policy_sha256,
        checked_at,
        &mut input_budget,
        RecoveryContextVerificationWork {
            root_passes: 1,
            policy_passes: 1,
            additional_verifications: proof.recovery_signatures.len(),
        },
    )?;
    let statement = inspect_terminal_persona_revocation_proof(&proof)?;
    let selected_policy = context
        .policies
        .last()
        .context("verified recovery policy chain is empty")?;
    ensure!(
        selected_policy.statement.policy_version == statement.recovery_policy_version
            && selected_policy.policy_statement_sha256 == statement.recovery_policy_sha256,
        "terminal revocation does not reference the independently pinned latest policy"
    );
    let verified =
        verify_terminal_persona_revocation_proof(&context.root, selected_policy, &proof)?;

    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "verified_terminal_revocation_authority",
                "root_digest_match": "verified",
                "latest_policy_digest_match": "verified",
                "policy_chain": "verified",
                "recovery_threshold": "verified",
                "signed_effect": "persona_permanently_deauthorized",
                "successor_key_fingerprint": Value::Null,
                "statement": verified.statement,
                "revocation_statement_sha256": verified.revocation_statement_sha256,
                "recovery_signer_fingerprints": verified.recovery_signer_fingerprints,
                "ordered_transition_chain": "not_checked",
                "current_head_position": "not_checked",
                "live_store_authorization": "not_checked",
                "trusted_multi_party_consent": false,
                "trusted_issuance_time": "not_established",
                "legal_identity": "not_established"
            }))?
        );
    } else {
        println!("VERIFIED TERMINAL-REVOCATION AUTHORITY");
        println!("Persona claim: {}", verified.statement.persona);
        println!("Sequence claim: {}", verified.statement.sequence);
        println!(
            "Reason: {}",
            terminal_revocation_reason_name(verified.statement.reason)
        );
        println!("Signed effect: PERSONA PERMANENTLY DEAUTHORIZED");
        println!(
            "Revoked-key claim: {}",
            verified.statement.previous_key_fingerprint
        );
        println!("Successor key: none");
        println!(
            "Recovery policy: v{} {}",
            verified.statement.recovery_policy_version, verified.statement.recovery_policy_sha256
        );
        println!(
            "Distinct recovery signatures: {}",
            verified.recovery_signer_fingerprints.len()
        );
        println!(
            "Revocation statement SHA-256: {}",
            verified.revocation_statement_sha256
        );
        println!("Expected root and latest-policy pins: matched");
        println!("Ordered transition chain and current-head position: not checked");
        println!("Live store authorization: not checked");
        println!("Trusted issuance time and legal identity: not established");
        println!("No trusted multi-party consent ceremony was established.");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn commit_terminal_revocation_command(
    store_path: Option<&Path>,
    persona_id: &str,
    proof_path: &Path,
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<&str>,
    emit_json: bool,
) -> Result<()> {
    require_sha256_pin(expected_root_sha256, "--expected-root-sha256")?;
    require_sha256_pin(expected_policy_sha256, "--expected-policy-sha256")?;
    let expected_previous_head = required_continuity_checkpoint(
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        "--expected-previous-head-sequence",
        "--expected-previous-head-sha256",
    )?;
    require_continuity_command_verification_work(&[(MIN_RECOVERY_AUTHORITIES, 1)])?;

    let mut input_budget = ContinuityCommandInputBudget::new();
    let proof = read_terminal_revocation_proof_with_command_budget(proof_path, &mut input_budget)?;
    require_continuity_command_verification_work(&[(proof.recovery_signatures.len(), 1)])?;
    let statement = inspect_terminal_persona_revocation_proof(&proof)?;
    let expected_sequence = expected_previous_head_sequence
        .checked_add(1)
        .context("terminal revocation sequence overflowed")?;
    ensure!(
        statement.sequence == expected_sequence
            && statement.previous_transition_sha256 == expected_previous_head.transition_sha256,
        "terminal revocation does not name the explicitly expected previous head"
    );

    let mut store = require_existing_persona_store(store_path)?;
    let committed = store.commit_terminal_persona_revocation(
        persona_id,
        &proof,
        expected_root_sha256,
        expected_policy_sha256,
        &expected_previous_head,
    )?;

    if emit_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "persona_permanently_deauthorized",
                "persona_id": persona_id,
                "persona_authorization": "permanently_deauthorized",
                "terminal": true,
                "sequence": committed.intent.sequence,
                "reason": committed.intent.reason,
                "revoked_key_fingerprint": committed.intent.previous_key_fingerprint,
                "successor_key_fingerprint": Value::Null,
                "recovery_policy_version": committed.intent.recovery_policy_version,
                "recovery_policy_sha256": committed.intent.recovery_policy_sha256,
                "revocation_statement_sha256": committed.revocation_statement_sha256,
                "store_status": if committed.replayed {
                    "already_committed_statement_replay"
                } else {
                    "new_terminal_revocation_committed"
                },
                "state_changed": !committed.replayed,
                "proof_wrapper": "first_committed",
                "committed_at": committed.committed_at,
                "future_authority_changes": "forbidden",
                "historical_verification": "retained",
                "trusted_multi_party_consent": false,
                "legal_identity": "not_established",
                "artifact_or_software_safety": "not_established"
            }))?
        );
    } else {
        println!("PERSONA PERMANENTLY DEAUTHORIZED");
        println!("Persona ID: {persona_id}");
        println!("Sequence: {}", committed.intent.sequence);
        println!(
            "Reason: {}",
            terminal_revocation_reason_name(committed.intent.reason)
        );
        println!(
            "Revoked current key: {}",
            committed.intent.previous_key_fingerprint
        );
        println!("Successor key: none");
        println!(
            "Recovery policy: v{} {}",
            committed.intent.recovery_policy_version, committed.intent.recovery_policy_sha256
        );
        println!(
            "Revocation statement SHA-256: {}",
            committed.revocation_statement_sha256
        );
        println!(
            "Store status: {}",
            if committed.replayed {
                "already committed; statement replay"
            } else {
                "new terminal revocation committed"
            }
        );
        println!("Proof wrapper: first committed wrapper retained by the journal");
        println!(
            "Future signing, key recovery, policy changes, and reactivation for this persona: forbidden."
        );
        println!("Historical proofs remain retained and inspectable.");
        println!("This records already-signed threshold evidence.");
        println!("It does not claim independent people/devices or trusted multi-party consent.");
        println!("Signed does not mean safe and does not establish legal identity.");
    }
    Ok(())
}

fn terminal_revocation_reason_name(reason: TerminalPersonaRevocationReason) -> &'static str {
    match reason {
        TerminalPersonaRevocationReason::Compromise => "compromise",
        TerminalPersonaRevocationReason::Cessation => "cessation",
    }
}

fn print_recovery_recording_caveats() {
    println!("This records already-signed threshold evidence.");
    println!("It does not claim independent people/devices or trusted multi-party consent.");
    println!("Signed does not mean safe and does not establish legal identity.");
}

struct RecoveryChainExpectations<'a> {
    root_sha256: &'a str,
    policy_sha256: &'a str,
    head_sequence: Option<u32>,
    head_sha256: Option<&'a str>,
}

fn verify_recovery_chain_command(
    root_path: &Path,
    policy_paths: &[PathBuf],
    transition_paths: &[PathBuf],
    terminal_revocation_path: Option<&Path>,
    expectations: RecoveryChainExpectations<'_>,
    at_unix: Option<i64>,
    emit_json: bool,
) -> Result<()> {
    ensure_recovery_policy_path_count(policy_paths, true, false)?;
    if terminal_revocation_path.is_some() {
        ensure_terminal_revocation_prior_path_count(transition_paths)?;
    } else {
        ensure_continuity_transition_path_count(transition_paths, false)?;
    }
    require_continuity_command_verification_work(&[
        (1, 1),
        (
            minimum_recovery_policy_signature_count(policy_paths.len()),
            1,
        ),
        (
            minimum_continuity_transition_signature_count(transition_paths.len()),
            1,
        ),
        (
            if terminal_revocation_path.is_some() {
                MIN_RECOVERY_AUTHORITIES
            } else {
                0
            },
            1,
        ),
    ])?;
    let checked_at = at_unix.map_or_else(current_unix_time, Ok)?;
    let expected_head =
        expected_continuity_checkpoint(expectations.head_sequence, expectations.head_sha256)?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let root_proof = read_persona_root_proof_with_command_budget(root_path, &mut input_budget)?;
    let policies = policy_paths
        .iter()
        .map(|path| read_recovery_policy_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    let mut transitions = transition_paths
        .iter()
        .map(|path| read_continuity_transition_proof_with_command_budget(path, &mut input_budget))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        transitions.iter().all(|proof| !matches!(
            proof,
            PersonaContinuityTransitionProof::TerminalRevocation(_)
        )),
        "terminal revocation proofs must use --terminal-revocation and must be final"
    );
    if let Some(path) = terminal_revocation_path {
        transitions.push(PersonaContinuityTransitionProof::TerminalRevocation(
            read_terminal_revocation_proof_with_command_budget(path, &mut input_budget)?,
        ));
    }
    require_continuity_command_verification_work(&[
        (1, 1),
        (recovery_policy_signature_count_sum(&policies), 1),
        (continuity_transition_signature_count_sum(&transitions), 1),
    ])?;
    let report = if let Some(expected_head) = &expected_head {
        verify_persona_continuity_chain_with_recovery_at_checkpoint(
            &root_proof,
            &transitions,
            &policies,
            expectations.root_sha256,
            expectations.policy_sha256,
            checked_at,
            expected_head,
        )?
    } else {
        verify_persona_continuity_chain_with_recovery(
            &root_proof,
            &transitions,
            &policies,
            expectations.root_sha256,
            expectations.policy_sha256,
            checked_at,
        )?
    };
    if emit_json {
        let mut machine_report = serde_json::to_value(&report)?;
        let object = machine_report
            .as_object_mut()
            .context("recovery-aware chain report did not serialize as an object")?;
        object.insert(
            "persona_authorization".to_owned(),
            Value::String(if report.terminally_revoked {
                if expected_head.is_some() {
                    "permanently_deauthorized".to_owned()
                } else {
                    "permanently_deauthorized_in_supplied_evidence".to_owned()
                }
            } else {
                "online_key_at_chain_tip".to_owned()
            }),
        );
        if report.terminally_revoked {
            object.insert("successor_key_fingerprint".to_owned(), Value::Null);
        }
        println!("{}", serde_json::to_string_pretty(&machine_report)?);
    } else {
        println!("VERIFIED RECOVERY-AWARE PERSONA CONTINUITY CHAIN");
        println!("Persona: {}", report.persona);
        println!("Persona anchor: {}", report.persona_anchor);
        println!("Expected root and latest-policy digests: matched");
        println!(
            "Expected head checkpoint: {}",
            if expected_head.is_some() {
                "matched"
            } else {
                "not supplied"
            }
        );
        println!("Transitions verified: {}", report.transition_count);
        println!("Routine transitions: {}", report.routine_transition_count);
        println!("Recovery transitions: {}", report.recovery_transition_count);
        println!("Terminal revocations: {}", report.terminal_revocation_count);
        if report.terminally_revoked {
            if expected_head.is_some() {
                println!("Persona authorization at expected chain tip: PERMANENTLY DEAUTHORIZED");
            } else {
                println!(
                    "Signed effect at supplied evidence tip: PERSONA PERMANENTLY DEAUTHORIZED"
                );
                println!("Externally pinned current authorization: not established");
            }
            println!(
                "Revoked current key: {}",
                report
                    .terminal_revoked_key_fingerprint
                    .as_deref()
                    .unwrap_or("not_reported")
            );
            println!("Current key: none");
            println!("Successor key: none");
            println!(
                "Terminal revocation SHA-256: {}",
                report
                    .terminal_revocation_statement_sha256
                    .as_deref()
                    .unwrap_or("not_reported")
            );
        } else {
            println!(
                "Key at {} chain tip: {}",
                if expected_head.is_some() {
                    "expected"
                } else {
                    "supplied"
                },
                report.chain_tip_key_fingerprint
            );
        }
        println!(
            "Latest policy: v{} {} ({})",
            report.latest_policy_version,
            report.latest_policy_sha256,
            recovery_policy_time_name(report.latest_policy_time_status)
        );
        println!("Not established: {}", report.not_established.join(", "));
    }
    Ok(())
}

struct RecoveryContext {
    root_proof: PersonaRootProof,
    root: VerifiedPersonaRoot,
    policy_proofs: Vec<RecoveryPolicyProof>,
    policies: Vec<VerifiedRecoveryPolicy>,
    report: RecoveryPolicyChainReport,
}

#[derive(Clone, Copy, Debug)]
struct RecoveryContextVerificationWork {
    root_passes: usize,
    policy_passes: usize,
    additional_verifications: usize,
}

fn load_recovery_context(
    root_path: &Path,
    policy_paths: &[PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    checked_at: i64,
    input_budget: &mut ContinuityCommandInputBudget,
    work: RecoveryContextVerificationWork,
) -> Result<RecoveryContext> {
    ensure_recovery_policy_path_count(policy_paths, true, false)?;
    let root_proof = read_persona_root_proof_with_command_budget(root_path, input_budget)?;
    let policy_proofs = policy_paths
        .iter()
        .map(|path| read_recovery_policy_proof_with_command_budget(path, input_budget))
        .collect::<Result<Vec<_>>>()?;
    require_continuity_command_verification_work(&[
        (1, work.root_passes),
        (
            recovery_policy_signature_count_sum(&policy_proofs),
            work.policy_passes,
        ),
        (work.additional_verifications, 1),
    ])?;
    let verified = verify_recovery_policy_chain_with_verified_sequence(
        &root_proof,
        &policy_proofs,
        expected_root_sha256,
        expected_policy_sha256,
        checked_at,
    )?;
    let (root, policies, report) = verified.into_parts();
    Ok(RecoveryContext {
        root_proof,
        root,
        policy_proofs,
        policies,
        report,
    })
}

fn read_recovery_signers(
    private_key_paths: &[PathBuf],
    public_key_paths: &[PathBuf],
    description: &str,
    input_budget: &mut ContinuityCommandInputBudget,
) -> Result<Vec<RecoverySigner>> {
    ensure_recovery_signer_path_counts(private_key_paths, public_key_paths, description)?;
    private_key_paths
        .iter()
        .zip(public_key_paths)
        .map(|(private_key_path, public_key_path)| {
            Ok(RecoverySigner {
                private_key_path: private_key_path.clone(),
                public_key: read_public_key_with_command_budget(public_key_path, input_budget)?,
            })
        })
        .collect()
}

fn recovery_policy_validity_seconds(valid_days: u16) -> Result<i64> {
    let maximum_days = u16::try_from(MAX_RECOVERY_POLICY_VALIDITY_SECONDS / SECONDS_PER_DAY)
        .expect("recovery validity bound fits in u16 days");
    ensure!(
        (1..=maximum_days).contains(&valid_days),
        "recovery policy validity must be between 1 and {maximum_days} days"
    );
    i64::from(valid_days)
        .checked_mul(SECONDS_PER_DAY)
        .context("recovery policy validity overflowed")
}

fn recovery_policy_time_name(status: RecoveryPolicyTimeStatus) -> &'static str {
    match status {
        RecoveryPolicyTimeStatus::Active => "active",
        RecoveryPolicyTimeStatus::NotYetValid => "not_yet_valid",
        RecoveryPolicyTimeStatus::Expired => "expired",
    }
}

fn print_recovery_policy_report(report: &RecoveryPolicyChainReport) {
    println!("VERIFIED RECOVERY POLICY SIGNATURE CHAIN");
    println!("Persona: {}", report.persona);
    println!("Persona anchor: {}", report.persona_anchor);
    println!("Expected root and latest-policy digests: matched");
    println!("Latest policy version: {}", report.latest_policy_version);
    println!("Latest policy SHA-256: {}", report.latest_policy_sha256);
    println!(
        "Continuity checkpoint: transition {} {} ({})",
        report.latest_checkpoint_sequence,
        report.latest_checkpoint_sha256.as_deref().unwrap_or("none"),
        report.checkpoint_against_transition_chain
    );
    println!(
        "Threshold: {} of {}",
        report.threshold, report.authority_count
    );
    println!("Issued at (Unix): {}", report.issued_at);
    println!("Expires at (Unix): {}", report.expires_at);
    println!("Checked at (Unix): {}", report.checked_at);
    println!(
        "Time status: {}",
        recovery_policy_time_name(report.time_status)
    );
    println!("Not established: {}", report.not_established.join(", "));
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
            accept_behavioral_analysis_not_run,
        } => {
            require_omarchy_cli_acknowledgements(
                "installation",
                yes,
                accept_behavioral_analysis_not_run,
            )?;
            let mut store = require_existing_persona_store(store_path)?;
            let plugins_directory = resolve_plugins_directory(plugins_directory.as_deref())?;
            let outcome = install_signed_package(&package, &proof, &mut store, &plugins_directory)?;
            println!("Installed: {} {}", outcome.plugin_id, outcome.version);
            println!(
                "A Quo enablement action: {}",
                outcome.a_quo_enablement_action
            );
            println!(
                "Official Omarchy manifest validation: {}",
                outcome.omarchy_manifest_validation
            );
            println!("Shell rescan: {}", outcome.shell_rescan);
            println!("Behavioural analysis: not_run (explicitly acknowledged)");
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
            accept_behavioral_analysis_not_run,
        } => {
            require_omarchy_cli_acknowledgements(
                "update",
                yes,
                accept_behavioral_analysis_not_run,
            )?;
            let mut store = require_existing_persona_store(store_path)?;
            let plugins_directory = resolve_plugins_directory(plugins_directory.as_deref())?;
            let outcome = update_signed_package(&package, &proof, &mut store, &plugins_directory)?;
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
            println!(
                "A Quo enablement action: {}",
                outcome.a_quo_enablement_action
            );
            println!("Behavioural analysis: not_run (explicitly acknowledged)");
            println!("Runtime safety: {}", outcome.runtime_safety);
            println!(
                "The signature and publisher continuity identify the release; they do not prove the updated code is safe."
            );
        }
        OmarchyCommands::Uninstall {
            plugin_id,
            plugins_directory,
            yes,
        } => {
            require_omarchy_uninstall_confirmation(yes)?;
            let plugins_directory = resolve_plugins_directory(plugins_directory.as_deref())?;
            let outcome = uninstall_managed_plugin(&plugin_id, &plugins_directory)?;
            println!(
                "Removed from live Omarchy plugin-ID path: {} {}",
                outcome.plugin_id, outcome.version
            );
            println!(
                "Observed Omarchy reference state: {}",
                outcome.observed_reference_state
            );
            println!("Atomic quarantine: {}", outcome.atomic_quarantine);
            println!("Shell rescan: {}", outcome.shell_rescan);
            println!(
                "Recovery quarantine retained: {}",
                outcome.recovery_quarantine.display()
            );
            println!("Disk purge: {}", outcome.disk_purge);
            println!(
                "A Quo enablement action: {}",
                outcome.a_quo_enablement_action
            );
            println!("Runtime safety: {}", outcome.runtime_safety);
            println!(
                "A Quo observed the plugin as unreferenced before removal; this does not prove that Omarchy never loaded it or that no concurrent reference race occurred."
            );
        }
    }
    Ok(())
}

fn require_omarchy_cli_acknowledgements(
    action: &str,
    confirmed: bool,
    accept_behavioral_analysis_not_run: bool,
) -> Result<()> {
    ensure!(
        confirmed,
        "refusing {action} without explicit confirmation; inspect first, then pass --yes"
    );
    ensure!(
        accept_behavioral_analysis_not_run,
        "refusing {action} because behavioural analysis did not run; pass --accept-behavioral-analysis-not-run only after accepting that A Quo verified the exact package signature, recognized publisher persona, and package structure—not likely behaviour or safety"
    );
    Ok(())
}

fn require_omarchy_uninstall_confirmation(confirmed: bool) -> Result<()> {
    ensure!(
        confirmed,
        "refusing uninstall without explicit confirmation; first disable and unreference the plugin in Omarchy, then pass --yes"
    );
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
    println!(
        "A Quo enablement action: {}",
        inspection.a_quo_enablement_action
    );
    println!(
        "A valid signature identifies bytes and a key; it does not make this plugin safe to run."
    );
}

fn publisher_status_name(status: PublisherRegistryStatus) -> &'static str {
    match status {
        PublisherRegistryStatus::NotChecked => "not checked",
        PublisherRegistryStatus::Unrecognized => "unrecognized",
        PublisherRegistryStatus::EvidenceOnly => "evidence-only/quarantined",
        PublisherRegistryStatus::Archived => "archived/non-operational",
        PublisherRegistryStatus::Active => "active",
        PublisherRegistryStatus::Retired => "retired",
        PublisherRegistryStatus::Compromised => "compromised",
        PublisherRegistryStatus::TerminallyRevoked => "terminally_revoked",
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
    let output = output.unwrap_or_else(|| default_proof_path(artifact));
    let proof = match (persona_label, persona_id) {
        (Some(label), None) => {
            let proof = create_sshsig_proof(artifact, private_key, public_key_path, &label)?;
            write_proof_new(&output, &proof)?;
            proof
        }
        (None, Some(persona_id)) => {
            let public_key = read_public_key(public_key_path)?;
            let fingerprint = public_key_fingerprint(&public_key)?;
            let mut store = open_persona_store(store_path)?;
            let recognized = store
                .lookup_key(&fingerprint)?
                .with_context(|| format!("key {fingerprint} is not registered"))?;
            ensure!(
                recognized.persona.id == persona_id,
                "key {fingerprint} belongs to persona {}, not {persona_id}",
                recognized.persona.id
            );
            match recognized.authority_disposition {
                PersonaAuthorityDisposition::Operational => {}
                PersonaAuthorityDisposition::EvidenceOnly => bail!(
                    "refusing to sign: key {fingerprint} is evidence-only/quarantined imported continuity evidence, not signing authority"
                ),
                PersonaAuthorityDisposition::Archived => bail!(
                    "refusing to sign: persona {persona_id} is archived and cannot authorize key {fingerprint}"
                ),
                PersonaAuthorityDisposition::TerminallyRevoked => bail!(
                    "refusing to sign: persona {persona_id} is PERMANENTLY DEAUTHORIZED and has no successor signing key"
                ),
            }
            ensure!(
                recognized.key.status == KeyStatus::Active,
                "refusing to sign with {} key {fingerprint}",
                status_name(recognized.key.status)
            );
            let signed_label = recognized.persona.label;
            store.with_active_key_authorization::<_, anyhow::Error>(
                &fingerprint,
                &signed_label,
                |current| {
                    ensure!(
                        current.persona.id == persona_id,
                        "key {fingerprint} belongs to persona {}, not {persona_id}",
                        current.persona.id
                    );
                    ensure!(
                        current.persona.label == signed_label,
                        "registered persona label changed before signing"
                    );
                    let proof =
                        create_sshsig_proof(artifact, private_key, public_key_path, &signed_label)?;
                    let statement = inspect_proof(&proof)?;
                    ensure!(
                        statement.signer.key_fingerprint == current.key.fingerprint,
                        "signer key changed after registered-persona authorization"
                    );
                    ensure!(
                        statement.signer.persona == current.persona.label,
                        "signed persona label changed after registered-persona authorization"
                    );
                    write_proof_new(&output, &proof)?;
                    Ok(proof)
                },
            )?
        }
        _ => bail!("exactly one of --persona or --persona-id is required"),
    };

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
        PersonaCommands::BackupExport {
            persona_id,
            root,
            recovery_policies,
            transitions,
            terminal_revocation,
            output,
        } => {
            return export_persona_backup_command(
                store_path,
                persona_id,
                root.as_deref(),
                recovery_policies,
                transitions,
                terminal_revocation.as_deref(),
                output,
            );
        }
        PersonaCommands::BackupInspect { input, json } => {
            return inspect_persona_backup_command(input, *json);
        }
        PersonaCommands::BackupCompare {
            input,
            expected_root_sha256,
            expected_head_sequence,
            expected_head_sha256,
            expect_no_recovery_policy,
            expected_policy_version,
            expected_policy_sha256,
            json,
        } => {
            return compare_persona_backup_command(
                input,
                expected_root_sha256,
                *expected_head_sequence,
                expected_head_sha256.as_deref(),
                *expect_no_recovery_policy,
                *expected_policy_version,
                expected_policy_sha256.as_deref(),
                *json,
            );
        }
        PersonaCommands::BackupActivateDirect {
            persona_id,
            expected_archive_sha256,
            expected_root_sha256,
            expected_head_sequence,
            expected_head_sha256,
            expect_no_recovery_policy,
            expected_policy_version,
            expected_policy_sha256,
            expected_current_key_fingerprint,
            current_provider,
            current_signing_locator,
            json,
        } => {
            return activate_persona_backup_direct_command(
                store_path,
                persona_id,
                expected_archive_sha256,
                expected_root_sha256,
                *expected_head_sequence,
                expected_head_sha256.as_deref(),
                *expect_no_recovery_policy,
                *expected_policy_version,
                expected_policy_sha256.as_deref(),
                expected_current_key_fingerprint,
                current_provider.as_deref(),
                current_signing_locator.as_deref(),
                *json,
            );
        }
        PersonaCommands::BackupActivateRecovery {
            persona_id,
            proof,
            expected_archive_sha256,
            expected_root_sha256,
            expected_head_sequence,
            expected_head_sha256,
            expected_policy_version,
            expected_policy_sha256,
            next_provider,
            next_signing_locator,
            json,
        } => {
            return activate_persona_backup_recovery_command(
                store_path,
                persona_id,
                proof,
                expected_archive_sha256,
                expected_root_sha256,
                *expected_head_sequence,
                expected_head_sha256.as_deref(),
                *expected_policy_version,
                expected_policy_sha256,
                next_provider.as_deref(),
                next_signing_locator.as_deref(),
                *json,
            );
        }
        PersonaCommands::BackupHydrateTerminal {
            persona_id,
            expected_archive_sha256,
            expected_root_sha256,
            expected_head_sequence,
            expected_head_sha256,
            expected_policy_version,
            expected_policy_sha256,
            json,
        } => {
            return hydrate_terminal_persona_backup_command(
                store_path,
                persona_id,
                expected_archive_sha256,
                expected_root_sha256,
                *expected_head_sequence,
                expected_head_sha256,
                *expected_policy_version,
                expected_policy_sha256,
                *json,
            );
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
            let personas = store.list_personas_with_listing_authority()?;
            if json {
                let personas = personas
                    .iter()
                    .map(|entry| {
                        let persona = &entry.persona;
                        json!({
                            "id": persona.id,
                            "label": persona.label,
                            "purpose": persona.purpose,
                            "created_at": persona.created_at,
                            "archived_at": persona.archived_at,
                            "lifecycle_status": if entry.authority_disposition
                                == PersonaListingAuthorityDisposition::TerminallyRevoked
                            {
                                "permanently_deauthorized"
                            } else if persona.archived_at.is_some() {
                                "archived"
                            } else {
                                "active"
                            },
                            "authority_disposition": entry.authority_disposition,
                            "persona_authorization": if entry.authority_disposition
                                == PersonaListingAuthorityDisposition::TerminallyRevoked
                            {
                                "permanently_deauthorized"
                            } else {
                                "not_checked_by_listing"
                            },
                            "quarantined": entry.authority_disposition
                                == PersonaListingAuthorityDisposition::EvidenceOnly
                        })
                    })
                    .collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&personas)?);
            } else if personas.is_empty() {
                println!("No personas are registered.");
            } else {
                for entry in personas {
                    let persona = entry.persona;
                    let lifecycle = if entry.authority_disposition
                        == PersonaListingAuthorityDisposition::TerminallyRevoked
                    {
                        "permanently-deauthorized"
                    } else if persona.archived_at.is_some() {
                        "archived"
                    } else {
                        "active"
                    };
                    let authority = match entry.authority_disposition {
                        PersonaListingAuthorityDisposition::NotChecked => "not-checked",
                        PersonaListingAuthorityDisposition::Archived => "archived/non-operational",
                        PersonaListingAuthorityDisposition::EvidenceOnly => {
                            "evidence-only/quarantined"
                        }
                        PersonaListingAuthorityDisposition::TerminallyRevoked => {
                            "terminally-revoked/permanently-deauthorized"
                        }
                    };
                    println!(
                        "{}  {}  lifecycle={}  authority={}  {}",
                        persona.id, persona.purpose, lifecycle, authority, persona.label
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
        | PersonaCommands::BackupCompare { .. }
        | PersonaCommands::BackupActivateDirect { .. }
        | PersonaCommands::BackupActivateRecovery { .. }
        | PersonaCommands::BackupHydrateTerminal { .. }
        | PersonaCommands::BackupImport { .. } => {
            unreachable!("backup commands return before opening the ordinary persona store")
        }
    }
    Ok(())
}

fn export_persona_backup_command(
    store_path: Option<&Path>,
    persona_id: &str,
    root_path: Option<&Path>,
    recovery_policy_paths: &[PathBuf],
    transition_paths: &[PathBuf],
    terminal_revocation_path: Option<&Path>,
    output: &Path,
) -> Result<()> {
    ensure!(
        recovery_policy_paths.len() <= MAX_PERSONA_BACKUP_RECOVERY_POLICIES,
        "continuity archive cannot contain more than {MAX_PERSONA_BACKUP_RECOVERY_POLICIES} recovery policies"
    );
    ensure!(
        transition_paths.len() <= MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS,
        "continuity archive cannot contain more than {MAX_PERSONA_BACKUP_CONTINUITY_TRANSITIONS} transitions"
    );
    ensure!(
        root_path.is_some()
            || (recovery_policy_paths.is_empty()
                && transition_paths.is_empty()
                && terminal_revocation_path.is_none()),
        "--recovery-policy, --transition, and --terminal-revocation require --root"
    );
    let archive = if let Some(root_path) = root_path {
        let mut remaining_input_bytes = MAX_PERSONA_BACKUP_BYTES;
        let root = BackupPersonaRootEvidence {
            proof: read_persona_root_proof_with_budget(root_path, &mut remaining_input_bytes)?,
            observed_at: None,
        };
        let mut recovery_policies = Vec::with_capacity(recovery_policy_paths.len());
        for path in recovery_policy_paths {
            recovery_policies.push(BackupRecoveryPolicyEvidence {
                proof: read_recovery_policy_proof_with_budget(path, &mut remaining_input_bytes)?,
                observed_at: None,
            });
        }
        let mut transitions = Vec::with_capacity(transition_paths.len());
        for path in transition_paths {
            let proof =
                read_continuity_transition_proof_with_budget(path, &mut remaining_input_bytes)?;
            ensure!(
                !matches!(
                    proof,
                    PersonaContinuityTransitionProof::TerminalRevocation(_)
                ),
                "terminal revocation proofs must use --terminal-revocation and must be final"
            );
            transitions.push(BackupTransitionEvidence {
                proof,
                observed_at: None,
            });
        }
        let terminal_revocation = if let Some(path) = terminal_revocation_path {
            Some(BackupTerminalPersonaRevocationEvidence {
                proof: read_terminal_revocation_proof_with_budget(
                    path,
                    &mut remaining_input_bytes,
                )?,
                observed_at: None,
            })
        } else {
            None
        };
        Some(BackupContinuityArchive {
            root,
            recovery_policies,
            transitions,
            terminal_revocation,
        })
    } else {
        None
    };
    let mut store = open_existing_persona_store(store_path)?
        .context("metadata export requires an existing persona store")?;
    let (backup, continuity) =
        store.export_persona_backup_with_archive_and_report(persona_id, archive)?;
    write_persona_backup_new(output, &backup)?;
    println!(
        "Exported persona {}: {}",
        if continuity.is_some() {
            "continuity evidence"
        } else {
            "metadata"
        },
        backup.persona.label
    );
    println!("Backup: {}", output.display());
    println!(
        "Contents: {} public key(s), {} lifecycle event(s)",
        backup.keys.len(),
        backup.events.len()
    );
    if let Some(report) = continuity {
        println!(
            "Root signature: {}",
            verification_name(report.root_signature_verified)
        );
        println!(
            "Transition chain: {} ({} transition(s))",
            verification_name(report.transition_chain_verified),
            report.transition_count
        );
        if report.terminally_revoked {
            println!("Signed effect in exported evidence: PERSONA PERMANENTLY DEAUTHORIZED");
            println!("Current key: none");
            println!("Successor key: none");
        }
        println!("External root/head-checkpoint/latest-policy pins: not checked");
        println!("Meaning: public evidence only; no signing authority was exported.");
    } else {
        println!("Cryptographic continuity: not present");
    }
    println!("No private key, signer path, wallet credential, or recovery secret was exported.");
    Ok(())
}

fn inspect_persona_backup_command(input: &Path, emit_json: bool) -> Result<()> {
    let backup = read_persona_backup(input)?;
    let continuity = verify_persona_backup_continuity(&backup)?;
    let summary = persona_backup_summary(&backup, continuity.as_ref());
    if emit_json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else if let Some(report) = &continuity {
        println!("VERIFIED UNPINNED CONTINUITY EVIDENCE ARCHIVE");
        print_persona_backup_identity(&backup);
        print_continuity_archive_report(report);
        println!("Disposition: evidence-only/quarantined");
    } else {
        println!("VALID UNSIGNED METADATA BACKUP");
        print_persona_backup_identity(&backup);
        println!("Root signature: not present");
        println!("Transition chain: not present");
        println!("Recovery policy/checkpoints: not present");
        println!("External root/head-checkpoint/latest-policy pins: not checked");
        println!("Signing authority: false");
        println!("Current authorization/non-revocation: not established");
        println!("Persona label binding: not_present");
        println!("Persona label/UUID/purpose/lifecycle timestamps: unsigned_local_metadata");
        println!("Meaning: internally consistent unsigned metadata only.");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compare_persona_backup_command(
    input: &Path,
    expected_root_sha256: &str,
    expected_head_sequence: u32,
    expected_head_sha256: Option<&str>,
    expect_no_recovery_policy: bool,
    expected_policy_version: Option<u32>,
    expected_policy_sha256: Option<&str>,
    emit_json: bool,
) -> Result<()> {
    let expected = backup_continuity_expected_pins(
        expected_root_sha256,
        expected_head_sequence,
        expected_head_sha256,
        expect_no_recovery_policy,
        expected_policy_version,
        expected_policy_sha256,
    )?;
    let backup = read_persona_backup(input)?;
    let report = compare_persona_backup_continuity(&backup, &expected)?;
    ensure!(
        report.external_root_pin_matched && report.external_latest_policy_pin_matched,
        "backup comparison returned without matching required root and policy expectations"
    );
    ensure!(
        !report.signing_authority && !report.signer_custody_established,
        "backup comparison must never establish signing authority or signer custody"
    );

    let effective_head_kind = if report.terminally_revoked {
        "terminal_revocation"
    } else if report.effective_head.transition_sequence == 0 {
        "root"
    } else {
        "continuity_transition"
    };
    let (status, head_relation) = match &report.head_relation {
        BackupContinuityHeadRelation::Exact => (
            if report.terminally_revoked {
                "verified_exact_terminal_revocation_evidence"
            } else {
                "verified_exact_continuity_evidence"
            },
            "exact",
        ),
        BackupContinuityHeadRelation::ExtensionBeyondPin => (
            "verified_candidate_extension_beyond_pin",
            "extension_beyond_pin",
        ),
        BackupContinuityHeadRelation::DivergentAtOrBeforePin => (
            "verified_candidate_divergent_at_or_before_pin",
            "divergent_at_or_before_pin",
        ),
        BackupContinuityHeadRelation::ShorterThanExpectedInconclusive => (
            "verified_candidate_shorter_than_expected_inconclusive",
            "shorter_than_expected_inconclusive",
        ),
    };
    if emit_json {
        let output = json!({
            "status": status,
            "archive_sha256": report.archive_sha256,
            "checked_at": report.checked_at,
            "root_statement_sha256": report.root_statement_sha256,
            "expected_effective_head": expected.effective_head,
            "effective_head": report.effective_head,
            "effective_head_kind": effective_head_kind,
            "head_relation": head_relation,
            "exact_head_match": report.external_head_pin_matched,
            "latest_policy": report.latest_policy,
            "latest_policy_time_status": report.latest_policy_time_status,
            "chain_tip_key_fingerprint": report.chain_tip_key_fingerprint,
            "current_key_fingerprint": report.current_key_fingerprint,
            "terminally_revoked": report.terminally_revoked,
            "terminal_revocation_reason": report.terminal_revocation_reason,
            "cryptographic_continuity": report.cryptographic_continuity,
            "external_root_pin": "matched",
            "external_head_pin": if report.external_head_pin_matched {
                "matched"
            } else {
                "not_matched"
            },
            "external_latest_policy_pin": "matched",
            "current_signer_custody": false,
            "signing_authority": false,
            "signer_references_restored": 0,
            "authority_disposition": "evidence_only",
            "disposition": "evidence_only_quarantined",
            "quarantined": true,
            "not_established": report.not_established,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("VERIFIED CONTINUITY EVIDENCE COMPARISON");
        println!("Archive SHA-256: {}", report.archive_sha256);
        println!("External root pin: matched");
        println!(
            "Expected head: sequence {} ({})",
            expected.effective_head.transition_sequence,
            expected
                .effective_head
                .transition_sha256
                .as_deref()
                .unwrap_or("root; no transition digest")
        );
        println!(
            "Candidate effective head: {} sequence {} ({})",
            effective_head_kind,
            report.effective_head.transition_sequence,
            report
                .effective_head
                .transition_sha256
                .as_deref()
                .unwrap_or("root; no transition digest")
        );
        println!("Head relation: {head_relation}");
        println!(
            "External head-checkpoint exact match: {}",
            report.external_head_pin_matched
        );
        match &expected.latest_policy {
            ExpectedBackupContinuityPolicy::None => {
                println!("External latest-policy expectation: matched (none)");
            }
            ExpectedBackupContinuityPolicy::Pinned {
                version,
                statement_sha256,
            } => {
                println!("External latest-policy pin: matched (v{version} {statement_sha256})");
            }
        }
        if let Some(status) = report.latest_policy_time_status {
            println!(
                "Latest recovery-policy time status: {}",
                recovery_policy_time_status_name(status)
            );
            println!(
                "Policy-time verifier checked_at (Unix): {}",
                report.checked_at
            );
        }
        if report.terminally_revoked {
            println!("Signed effect: PERSONA PERMANENTLY DEAUTHORIZED");
            println!("Current key: none");
            println!("Successor key: none");
        } else {
            println!(
                "Current key in supplied evidence: {}",
                report.current_key_fingerprint.as_deref().unwrap_or("none")
            );
        }
        println!("Current signer custody: false");
        println!("Signing authority: false");
        println!("Disposition: evidence-only/quarantined");
        println!("Not established: {}", report.not_established.join(", "));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn activate_persona_backup_direct_command(
    store_path: Option<&Path>,
    persona_id: &str,
    expected_archive_sha256: &str,
    expected_root_sha256: &str,
    expected_head_sequence: u32,
    expected_head_sha256: Option<&str>,
    expect_no_recovery_policy: bool,
    expected_policy_version: Option<u32>,
    expected_policy_sha256: Option<&str>,
    expected_current_key_fingerprint: &str,
    current_provider: Option<&str>,
    current_signing_locator: Option<&Path>,
    emit_json: bool,
) -> Result<()> {
    require_sha256_pin(expected_archive_sha256, "--expected-archive-sha256")?;
    let expected_pins = backup_continuity_expected_pins(
        expected_root_sha256,
        expected_head_sequence,
        expected_head_sha256,
        expect_no_recovery_policy,
        expected_policy_version,
        expected_policy_sha256,
    )?;
    let signer = match (current_provider, current_signing_locator) {
        (Some(provider), Some(signing_locator)) => Some(DirectArchiveSignerBinding {
            provider: provider.parse()?,
            signing_locator: signing_locator.to_path_buf(),
        }),
        (None, None) => None,
        _ => bail!("--current-provider and --current-signing-locator must be supplied together"),
    };
    let request = DirectArchiveActivationRequest {
        persona_id: persona_id.to_owned(),
        expected_archive_sha256: expected_archive_sha256.to_owned(),
        expected_pins,
        expected_current_key_fingerprint: expected_current_key_fingerprint.to_owned(),
        signer,
    };
    let mut store = open_existing_persona_store(store_path)?.context(
        "direct archive activation requires an existing persona store containing the imported continuity archive",
    )?;
    let receipt = store.activate_persona_continuity_archive_direct(&request)?;

    if emit_json {
        let mut output = serde_json::to_value(&receipt)?;
        let object = output
            .as_object_mut()
            .context("direct archive activation receipt must serialize as an object")?;
        let provider = object
            .remove("provider")
            .context("direct archive activation receipt must contain its signer provider")?;
        object.insert("signer_provider_at_materialization".to_owned(), provider);
        let signing_locator = object
            .remove("signing_locator")
            .context("direct archive activation receipt must contain its signer locator")?;
        object.insert(
            "signing_locator_at_materialization".to_owned(),
            signing_locator,
        );
        object.insert(
            "status".to_owned(),
            if receipt.replayed {
                "sealed_direct_archive_activation_replayed".into()
            } else {
                "direct_archive_activated".into()
            },
        );
        object.insert("archive_pin".to_owned(), "matched".into());
        object.insert("external_root_pin".to_owned(), "matched".into());
        object.insert("external_head_pin".to_owned(), "matched".into());
        object.insert("external_latest_policy_pin".to_owned(), "matched".into());
        object.insert("current_key_pin".to_owned(), "matched".into());
        object.insert("cryptographic_continuity".to_owned(), "verified".into());
        object.insert(
            "signer_custody_this_invocation".to_owned(),
            if receipt.signer_challenge_performed_this_invocation {
                "proved_by_challenge".into()
            } else {
                "not_checked_exact_replay".into()
            },
        );
        let authority_disposition = object
            .remove("current_authority_disposition")
            .context("direct archive activation receipt must contain its authority disposition")?;
        object.insert(
            "authority_disposition_at_report".to_owned(),
            authority_disposition,
        );
        object.insert(
            "artifact_or_software_safety".to_owned(),
            "not_established".into(),
        );
        object.insert(
            "legal_or_government_identity".to_owned(),
            "not_established".into(),
        );
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if receipt.replayed {
            println!("REPLAYED SEALED DIRECT ARCHIVE ACTIVATION");
        } else {
            println!("ACTIVATED VERIFIED PERSONA CONTINUITY ARCHIVE");
        }
        println!(
            "Persona: {} ({})",
            receipt.persona_label, receipt.persona_id
        );
        println!("Archive SHA-256 pin: matched ({})", receipt.archive_sha256);
        println!(
            "External root pin: matched ({})",
            receipt.root_statement_sha256
        );
        println!(
            "External head pin: matched (sequence {}{})",
            receipt.source_head.transition_sequence,
            receipt
                .source_head
                .transition_sha256
                .as_deref()
                .map(|digest| format!(" {digest}"))
                .unwrap_or_default()
        );
        match &receipt.latest_policy {
            ExpectedBackupContinuityPolicy::None => {
                println!("External latest-policy expectation: matched (none)");
            }
            ExpectedBackupContinuityPolicy::Pinned {
                version,
                statement_sha256,
            } => {
                println!("External latest-policy pin: matched (v{version} {statement_sha256})");
            }
        }
        if let Some(status) = receipt.latest_policy_time_status_at_materialization {
            println!(
                "Latest recovery-policy time status at materialization: {}",
                recovery_policy_time_status_name(status)
            );
        }
        println!(
            "Current key pin: matched ({})",
            receipt.current_key_fingerprint
        );
        println!("Cryptographic continuity: verified");
        println!(
            "Signer challenge this invocation: {}",
            if receipt.signer_challenge_performed_this_invocation {
                "performed; current-key custody proved"
            } else {
                "not performed; exact sealed replay makes no current signer-availability claim"
            }
        );
        println!(
            "Signer custody at materialization: {}",
            receipt.signer_custody_established_at_materialization
        );
        println!(
            "Signing authority granted at materialization: {}",
            receipt.signing_authority_granted_at_materialization
        );
        println!(
            "Authority disposition at report time: {}",
            persona_authority_disposition_name(receipt.current_authority_disposition)
        );
        println!("Signer provider at materialization: {}", receipt.provider);
        println!(
            "Local signer reference recorded at materialization: {}",
            receipt.signing_locator.display()
        );
        println!(
            "Source evidence archive retained: {}",
            receipt.source_archive_retained
        );
        println!(
            "Imported lifecycle metadata remains unsigned: {}",
            receipt.imported_metadata_is_unsigned
        );
        println!("Signed does not mean safe.");
        println!("Not established: {}", receipt.not_established.join(", "));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn activate_persona_backup_recovery_command(
    store_path: Option<&Path>,
    persona_id: &str,
    proof_path: &Path,
    expected_archive_sha256: &str,
    expected_root_sha256: &str,
    expected_head_sequence: u32,
    expected_head_sha256: Option<&str>,
    expected_policy_version: u32,
    expected_policy_sha256: &str,
    next_provider: Option<&str>,
    next_signing_locator: Option<&Path>,
    emit_json: bool,
) -> Result<()> {
    require_sha256_pin(expected_archive_sha256, "--expected-archive-sha256")?;
    let expected_pins = backup_continuity_expected_pins(
        expected_root_sha256,
        expected_head_sequence,
        expected_head_sha256,
        false,
        Some(expected_policy_version),
        Some(expected_policy_sha256),
    )?;
    let successor_signer = match (next_provider, next_signing_locator) {
        (Some(provider), Some(signing_locator)) => Some(RecoveryArchiveSignerBinding {
            provider: provider.parse()?,
            signing_locator: signing_locator.to_path_buf(),
        }),
        (None, None) => None,
        _ => bail!("--next-provider and --next-signing-locator must be supplied together"),
    };

    require_continuity_command_verification_work(&[(
        MIN_RECOVERY_AUTHORITIES.saturating_add(1),
        1,
    )])?;
    let mut input_budget = ContinuityCommandInputBudget::new();
    let recovery_proof =
        read_recovery_transition_proof_with_command_budget(proof_path, &mut input_budget)?;
    require_continuity_command_verification_work(&[(
        recovery_proof.recovery_signatures.len().saturating_add(1),
        1,
    )])?;

    let request = RecoveryArchiveActivationRequest {
        persona_id: persona_id.to_owned(),
        expected_archive_sha256: expected_archive_sha256.to_owned(),
        expected_pins,
        recovery_proof,
        successor_signer,
    };
    let mut store = open_existing_persona_store(store_path)?.context(
        "recovery archive activation requires an existing persona store containing the imported continuity archive",
    )?;
    let receipt = store.activate_persona_continuity_archive_recovery(&request)?;

    if emit_json {
        let mut output = serde_json::to_value(&receipt)?;
        let object = output
            .as_object_mut()
            .context("recovery archive activation receipt must serialize as an object")?;
        let provider = object
            .remove("provider")
            .context("recovery archive activation receipt must contain its successor provider")?;
        object.insert(
            "successor_signer_provider_at_materialization".to_owned(),
            provider,
        );
        let signing_locator = object
            .remove("signing_locator")
            .context("recovery archive activation receipt must contain its successor locator")?;
        object.insert(
            "successor_signing_locator_at_materialization".to_owned(),
            signing_locator,
        );
        object.insert(
            "status".to_owned(),
            if receipt.replayed {
                "sealed_recovery_archive_activation_replayed".into()
            } else {
                "recovery_archive_activated".into()
            },
        );
        object.insert("archive_pin".to_owned(), "matched".into());
        object.insert("external_root_pin".to_owned(), "matched".into());
        object.insert("external_source_head_pin".to_owned(), "matched".into());
        object.insert("external_latest_policy_pin".to_owned(), "matched".into());
        object.insert("cryptographic_continuity".to_owned(), "verified".into());
        object.insert(
            "successor_signer_custody_this_invocation".to_owned(),
            if receipt.signer_challenge_performed_this_invocation {
                "proved_by_challenge".into()
            } else {
                "not_checked_exact_replay".into()
            },
        );
        let signer_custody = object
            .remove("signer_custody_established_at_materialization")
            .context("recovery archive activation receipt has no successor custody fact")?;
        object.insert(
            "successor_signer_custody_established_at_materialization".to_owned(),
            signer_custody,
        );
        let signing_authority = object
            .remove("signing_authority_granted_at_materialization")
            .context("recovery archive activation receipt has no successor authority fact")?;
        object.insert(
            "successor_signing_authority_granted_at_materialization".to_owned(),
            signing_authority,
        );
        let authority_disposition = object
            .remove("current_authority_disposition")
            .context("recovery archive activation receipt has no authority disposition")?;
        object.insert(
            "authority_disposition_at_report".to_owned(),
            authority_disposition,
        );
        object.insert(
            "artifact_or_software_safety".to_owned(),
            "not_established".into(),
        );
        object.insert(
            "legal_or_government_identity".to_owned(),
            "not_established".into(),
        );
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if receipt.replayed {
            println!("REPLAYED SEALED RECOVERY ARCHIVE ACTIVATION");
        } else {
            println!("ACTIVATED VERIFIED PERSONA ARCHIVE BY RECOVERY");
        }
        println!(
            "Persona: {} ({})",
            receipt.persona_label, receipt.persona_id
        );
        println!("Archive SHA-256 pin: matched ({})", receipt.archive_sha256);
        println!(
            "External root pin: matched ({})",
            receipt.root_statement_sha256
        );
        println!(
            "Pinned source head: sequence {}{}",
            receipt.source_head.transition_sequence,
            receipt
                .source_head
                .transition_sha256
                .as_deref()
                .map(|digest| format!(" {digest}"))
                .unwrap_or_else(|| " (root; no transition digest)".to_owned())
        );
        println!(
            "Recovery result head: sequence {} {}",
            receipt.result_head.transition_sequence,
            receipt
                .result_head
                .transition_sha256
                .as_deref()
                .expect("recovery activation receipt has a result-head digest")
        );
        let ExpectedBackupContinuityPolicy::Pinned {
            version,
            statement_sha256,
        } = &receipt.latest_policy
        else {
            unreachable!("validated recovery activation has an exact recovery-policy pin")
        };
        println!("External latest-policy pin: matched (v{version} {statement_sha256})");
        println!(
            "Latest recovery-policy status at activation: {}",
            recovery_policy_time_status_name(receipt.latest_policy_time_status_at_materialization)
        );
        println!(
            "Recovery transition: verified ({}; {})",
            recovery_transition_reason_name(receipt.recovery_reason),
            receipt.recovery_transition_statement_sha256
        );
        println!("Previous key: {}", receipt.previous_key_fingerprint);
        println!("Successor key: {}", receipt.successor_key_fingerprint);
        println!(
            "Successor signer challenge this invocation: {}",
            if receipt.signer_challenge_performed_this_invocation {
                "performed; successor-key custody proved"
            } else {
                "not performed; exact sealed replay makes no current signer-availability claim"
            }
        );
        println!(
            "Successor signer custody at materialization: {}",
            receipt.signer_custody_established_at_materialization
        );
        println!(
            "Successor signing authority granted at materialization: {}",
            receipt.signing_authority_granted_at_materialization
        );
        println!(
            "Recovery authority exercised at materialization: {}",
            receipt.recovery_authority_exercised
        );
        println!(
            "Authority disposition at report time: {}",
            persona_authority_disposition_name(receipt.current_authority_disposition)
        );
        println!(
            "Successor signer provider at materialization: {}",
            receipt.provider
        );
        println!(
            "Successor signer reference recorded at materialization: {}",
            receipt.signing_locator.display()
        );
        println!(
            "Source evidence archive retained: {}",
            receipt.source_archive_retained
        );
        println!(
            "Imported lifecycle metadata remains unsigned: {}",
            receipt.imported_metadata_is_unsigned
        );
        println!("Signed does not mean safe.");
        println!("Not established: {}", receipt.not_established.join(", "));
    }
    Ok(())
}

fn recovery_transition_reason_name(reason: RecoveryTransitionReason) -> &'static str {
    match reason {
        RecoveryTransitionReason::Recovery => "recovery",
        RecoveryTransitionReason::Compromise => "compromise",
    }
}

#[allow(clippy::too_many_arguments)]
fn hydrate_terminal_persona_backup_command(
    store_path: Option<&Path>,
    persona_id: &str,
    expected_archive_sha256: &str,
    expected_root_sha256: &str,
    expected_head_sequence: u32,
    expected_head_sha256: &str,
    expected_policy_version: u32,
    expected_policy_sha256: &str,
    emit_json: bool,
) -> Result<()> {
    require_sha256_pin(expected_archive_sha256, "--expected-archive-sha256")?;
    ensure!(
        expected_head_sequence > 0,
        "--expected-head-sequence must name the nonzero final terminal leaf"
    );
    ensure!(
        expected_policy_version > 0,
        "--expected-policy-version must be greater than zero"
    );
    let expected_pins = backup_continuity_expected_pins(
        expected_root_sha256,
        expected_head_sequence,
        Some(expected_head_sha256),
        false,
        Some(expected_policy_version),
        Some(expected_policy_sha256),
    )?;
    let request = TerminalArchiveHydrationRequest {
        persona_id: persona_id.to_owned(),
        expected_archive_sha256: expected_archive_sha256.to_owned(),
        expected_pins,
    };
    let mut store = open_existing_persona_store(store_path)?.context(
        "terminal archive hydration requires an existing persona store containing the imported terminal continuity archive",
    )?;
    let receipt = store.hydrate_terminal_persona_continuity_archive(&request)?;

    if emit_json {
        let mut output = serde_json::to_value(&receipt)?;
        let object = output
            .as_object_mut()
            .context("terminal archive hydration receipt must serialize as an object")?;
        object.insert(
            "status".to_owned(),
            if receipt.replayed {
                "sealed_terminal_archive_hydration_replayed".into()
            } else {
                "terminal_archive_hydrated".into()
            },
        );
        object.insert("archive_pin".to_owned(), "matched".into());
        object.insert("external_root_pin".to_owned(), "matched".into());
        object.insert("external_terminal_head_pin".to_owned(), "matched".into());
        object.insert("external_latest_policy_pin".to_owned(), "matched".into());
        object.insert("cryptographic_continuity".to_owned(), "verified".into());
        let authority_disposition = object
            .remove("current_authority_disposition")
            .context("terminal hydration receipt has no authority disposition")?;
        object.insert(
            "authority_disposition_at_report".to_owned(),
            authority_disposition,
        );
        object.insert(
            "artifact_or_software_safety".to_owned(),
            "not_established".into(),
        );
        object.insert(
            "legal_or_government_identity".to_owned(),
            "not_established".into(),
        );
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if receipt.replayed {
            println!("REPLAYED SEALED TERMINAL ARCHIVE HYDRATION");
        } else {
            println!("HYDRATED VERIFIED TERMINAL PERSONA ARCHIVE");
        }
        println!(
            "Persona: {} ({})",
            receipt.persona_label, receipt.persona_id
        );
        println!("Archive SHA-256 pin: matched ({})", receipt.archive_sha256);
        println!(
            "External root pin: matched ({})",
            receipt.root_statement_sha256
        );
        println!(
            "External terminal-head pin: matched (sequence {} {})",
            receipt.result_head.transition_sequence,
            receipt
                .result_head
                .transition_sha256
                .as_deref()
                .expect("terminal receipt has a final digest")
        );
        println!(
            "Preterminal SQL head (not the effective terminal head): sequence {}{}",
            receipt.preterminal_head.transition_sequence,
            receipt
                .preterminal_head
                .transition_sha256
                .as_deref()
                .map(|digest| format!(" {digest}"))
                .unwrap_or_default()
        );
        let ExpectedBackupContinuityPolicy::Pinned {
            version,
            statement_sha256,
        } = &receipt.latest_policy
        else {
            unreachable!("validated terminal receipt has an exact policy pin")
        };
        println!("External latest-policy pin: matched (v{version} {statement_sha256})");
        println!(
            "Latest recovery-policy status at hydration: {}",
            recovery_policy_time_status_name(receipt.latest_policy_time_status_at_materialization)
        );
        println!(
            "Terminal revocation: verified ({}; key {})",
            terminal_revocation_reason_name(receipt.terminal_revocation_reason),
            receipt.terminal_revoked_key_fingerprint
        );
        println!("Current or successor signing key: none");
        println!("Active keys: {}", receipt.active_key_count);
        println!("Signer references: {}", receipt.signer_reference_count);
        println!("Signer custody established by hydration: false");
        println!("Signing authority granted by hydration: false");
        println!("Recovery authority exercised by hydration: false");
        println!("Reactivation path created: false");
        println!(
            "Authority disposition at report time: {}",
            persona_authority_disposition_name(receipt.current_authority_disposition)
        );
        println!(
            "Historical verification material retained: {}",
            receipt.historical_verification_material_retained
        );
        println!(
            "Source evidence archive retained: {}",
            receipt.source_archive_retained
        );
        println!("Signed does not mean safe.");
        println!("Not established: {}", receipt.not_established.join(", "));
    }
    Ok(())
}

fn backup_continuity_expected_pins(
    expected_root_sha256: &str,
    expected_head_sequence: u32,
    expected_head_sha256: Option<&str>,
    expect_no_recovery_policy: bool,
    expected_policy_version: Option<u32>,
    expected_policy_sha256: Option<&str>,
) -> Result<BackupContinuityExpectedPins> {
    require_sha256_pin(expected_root_sha256, "--expected-root-sha256")?;
    let effective_head = required_continuity_checkpoint(
        expected_head_sequence,
        expected_head_sha256,
        "--expected-head-sequence",
        "--expected-head-sha256",
    )?;
    let latest_policy = match (
        expect_no_recovery_policy,
        expected_policy_version,
        expected_policy_sha256,
    ) {
        (true, None, None) => ExpectedBackupContinuityPolicy::None,
        (false, Some(version), Some(statement_sha256)) => {
            ensure!(
                version > 0,
                "--expected-policy-version must be greater than zero"
            );
            require_sha256_pin(statement_sha256, "--expected-policy-sha256")?;
            ExpectedBackupContinuityPolicy::Pinned {
                version,
                statement_sha256: statement_sha256.to_owned(),
            }
        }
        _ => bail!(
            "supply either --expect-no-recovery-policy or both --expected-policy-version and --expected-policy-sha256"
        ),
    };
    Ok(BackupContinuityExpectedPins {
        root_statement_sha256: expected_root_sha256.to_owned(),
        effective_head,
        latest_policy,
    })
}

fn persona_authority_disposition_name(disposition: PersonaAuthorityDisposition) -> &'static str {
    match disposition {
        PersonaAuthorityDisposition::Operational => "operational",
        PersonaAuthorityDisposition::TerminallyRevoked => "terminally-revoked",
        PersonaAuthorityDisposition::Archived => "archived/non-operational",
        PersonaAuthorityDisposition::EvidenceOnly => "evidence-only/quarantined",
    }
}

fn import_persona_backup_command(
    store_path: Option<&Path>,
    input: &Path,
    emit_json: bool,
) -> Result<()> {
    let backup = read_persona_backup(input)?;
    let verified = verify_persona_backup_for_import(&backup)?;
    let mut store = open_persona_store(store_path)?;
    let (persona, continuity) = store.import_verified_persona_backup(verified)?;
    // The verified import result already tells us whether immutable continuity
    // evidence was installed. Derive the displayed disposition from that
    // result so importing an archive performs its bounded cryptographic work
    // exactly once.
    let authority_disposition = if continuity.is_some() {
        PersonaAuthorityDisposition::EvidenceOnly
    } else if persona.archived_at.is_some() {
        PersonaAuthorityDisposition::Archived
    } else {
        PersonaAuthorityDisposition::Operational
    };
    let lifecycle_status = if persona.archived_at.is_some() {
        "archived"
    } else {
        "active"
    };
    if emit_json {
        let mut summary = persona_backup_summary(&backup, continuity.as_ref());
        summary["persona"] = serde_json::to_value(&persona)?;
        summary["lifecycle_status"] = lifecycle_status.into();
        summary["authority_disposition"] = serde_json::to_value(authority_disposition)?;
        summary["quarantined"] =
            (authority_disposition == PersonaAuthorityDisposition::EvidenceOnly).into();
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else if let Some(report) = &continuity {
        println!("Imported persona continuity evidence: {}", persona.label);
        println!("Local ID: {}", persona.id);
        println!("Persona lifecycle: {lifecycle_status}");
        print_continuity_archive_report(report);
        println!("Signer references restored: 0");
        println!("Disposition: evidence-only/quarantined");
        println!("Current local authorization/non-revocation: not established");
    } else if authority_disposition == PersonaAuthorityDisposition::Archived {
        println!("Imported archived persona metadata: {}", persona.label);
        println!("Local ID: {}", persona.id);
        println!("Persona lifecycle: archived");
        println!("Signer references restored: none");
        println!("Disposition: archived/non-operational");
        println!("Historical verification remains inspectable; signing is disabled.");
        println!("This import did not establish cryptographic recovery or legal identity.");
    } else {
        println!("Imported persona metadata: {}", persona.label);
        println!("Local ID: {}", persona.id);
        println!("Signer references restored: none");
        println!("Bind an available signer explicitly before signing.");
        println!("This import did not establish cryptographic recovery or legal identity.");
    }
    Ok(())
}

fn persona_backup_summary(
    backup: &PersonaBackup,
    continuity: Option<&BackupContinuityVerificationReport>,
) -> Value {
    let Some(report) = continuity else {
        return json!({
            "status": "internally_consistent_unsigned_metadata",
            "schema": backup.schema,
            "exported_at": backup.exported_at,
            "persona": backup.persona,
            "public_key_count": backup.keys.len(),
            "lifecycle_event_count": backup.events.len(),
            "metadata_consistency": "verified",
            "root_signature": "not_present",
            "persona_label_binding": "not_present",
            "persona_metadata": {
                "id": "unsigned_local_metadata",
                "label": "unsigned_local_metadata",
                "purpose": "unsigned_local_metadata",
                "lifecycle_timestamps": "unsigned_local_metadata"
            },
            "transition_chain": "not_present",
            "recovery_policy_chain": "not_present",
            "policy_transition_checkpoints": "not_present",
            "external_root_pin": "not_checked",
            "external_head_pin": "not_checked",
            "external_latest_policy_pin": "not_checked",
            "signer_references_restored": 0,
            "signing_authority": false,
            "cryptographic_continuity": false,
            "current_authorization_or_non_revocation": "not_established",
            "disposition": if backup.schema == PERSONA_BACKUP_V1_SCHEMA {
                "unsigned_metadata_v1"
            } else {
                "unsigned_metadata_only"
            }
        });
    };

    json!({
        "status": if report.terminally_revoked {
            "verified_unpinned_terminal_revocation_evidence"
        } else {
            "verified_unpinned_continuity_evidence"
        },
        "schema": backup.schema,
        "exported_at": backup.exported_at,
        "persona": backup.persona,
        "public_key_count": backup.keys.len(),
        "lifecycle_event_count": backup.events.len(),
        "metadata_consistency": verification_name(report.lifecycle_metadata_consistent),
        "root_signature": verification_name(report.root_signature_verified),
        "persona_label_binding": verification_name(report.persona_label_binding_verified),
        "persona_metadata": {
            "id": "unsigned_local_metadata",
            "purpose": "unsigned_local_metadata",
            "lifecycle_timestamps": "unsigned_local_metadata"
        },
        "transition_chain": verification_name(report.transition_chain_verified),
        "recovery_policy_chain": optional_verification_name(report.recovery_policy_chain_verified),
        "policy_transition_checkpoints": optional_verification_name(
            report.policy_transition_checkpoints_verified
        ),
        "cryptographic_continuity": report.cryptographic_continuity,
        "root_statement_sha256": report.root_statement_sha256,
        "chain_tip_key_fingerprint": report.chain_tip_key_fingerprint,
        "current_key_fingerprint": report.current_key_fingerprint,
        "terminally_revoked": report.terminally_revoked,
        "terminal_revocation_count": report.terminal_revocation_count,
        "terminal_revocation_statement_sha256": report.terminal_revocation_statement_sha256,
        "terminal_revoked_key_fingerprint": report.terminal_revoked_key_fingerprint,
        "terminal_revocation_reason": report.terminal_revocation_reason,
        "persona_authorization": if report.terminally_revoked {
            "permanently_deauthorized_in_supplied_evidence"
        } else {
            "not_established"
        },
        "successor_key_fingerprint": if report.terminally_revoked {
            Value::Null
        } else {
            Value::String("not_established".to_owned())
        },
        "transition_count": report.transition_count,
        "routine_transition_count": report.routine_transition_count,
        "recovery_transition_count": report.recovery_transition_count,
        "latest_policy_sha256": report.latest_policy_sha256,
        "latest_policy_version": report.latest_policy_version,
        "latest_policy_time_status": report.latest_policy_time_status,
        "checked_at": report.checked_at,
        "external_root_pin": checked_name(report.external_root_pin_checked),
        "external_head_pin": checked_name(report.external_head_pin_checked),
        "external_latest_policy_pin": checked_name(report.external_policy_pin_checked),
        "signer_references_restored": 0,
        "signing_authority": report.signing_authority,
        "current_authorization_or_non_revocation": if report.terminally_revoked {
            "permanently_deauthorized_in_supplied_evidence"
        } else {
            "not_established"
        },
        "disposition": "evidence_only_quarantined",
        "not_established": report.not_established
    })
}

fn print_persona_backup_identity(backup: &PersonaBackup) {
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
}

fn print_continuity_archive_report(report: &BackupContinuityVerificationReport) {
    println!(
        "Metadata consistency: {}",
        verification_name(report.lifecycle_metadata_consistent)
    );
    println!(
        "Root signature: {}",
        verification_name(report.root_signature_verified)
    );
    println!(
        "Persona label binding: {}",
        verification_name(report.persona_label_binding_verified)
    );
    println!("Persona UUID/purpose/lifecycle timestamps: unsigned_local_metadata");
    println!(
        "Transition chain: {} ({} transition(s))",
        verification_name(report.transition_chain_verified),
        report.transition_count
    );
    println!(
        "Recovery policy chain: {}",
        optional_verification_name(report.recovery_policy_chain_verified)
    );
    println!(
        "Policy transition checkpoints: {}",
        optional_verification_name(report.policy_transition_checkpoints_verified)
    );
    println!("Terminal revocations: {}", report.terminal_revocation_count);
    if report.terminally_revoked {
        println!("Signed effect in supplied evidence: PERSONA PERMANENTLY DEAUTHORIZED");
        println!(
            "Terminal revocation SHA-256: {}",
            report
                .terminal_revocation_statement_sha256
                .as_deref()
                .unwrap_or("not_reported")
        );
        println!(
            "Revoked current key: {}",
            report
                .terminal_revoked_key_fingerprint
                .as_deref()
                .unwrap_or("not_reported")
        );
        println!("Current key: none");
        println!("Successor key: none");
    }
    if let Some(status) = report.latest_policy_time_status {
        println!(
            "Latest recovery-policy time status: {}",
            recovery_policy_time_status_name(status)
        );
        println!(
            "Policy-time verifier checked_at (Unix): {}",
            report.checked_at
        );
    }
    println!(
        "External root pin: {}",
        checked_name(report.external_root_pin_checked)
    );
    println!(
        "External head-checkpoint pin: {}",
        checked_name(report.external_head_pin_checked)
    );
    println!(
        "External latest-policy pin: {}",
        checked_name(report.external_policy_pin_checked)
    );
    println!("Signing authority: {}", report.signing_authority);
    if report.terminally_revoked {
        println!("Live store state: not established by this unpinned evidence report");
    } else {
        println!("Current authorization/non-revocation: not established");
    }
}

fn verification_name(verified: bool) -> &'static str {
    if verified { "verified" } else { "not_verified" }
}

fn optional_verification_name(verified: Option<bool>) -> &'static str {
    verified.map_or("not_present", verification_name)
}

fn checked_name(checked: bool) -> &'static str {
    if checked { "checked" } else { "not_checked" }
}

fn recovery_policy_time_status_name(status: RecoveryPolicyTimeStatus) -> &'static str {
    match status {
        RecoveryPolicyTimeStatus::Active => "active",
        RecoveryPolicyTimeStatus::NotYetValid => "not_yet_valid",
        RecoveryPolicyTimeStatus::Expired => "expired",
    }
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
    match store.lookup_key_with_history(fingerprint)? {
        Some((record, events)) => Ok(LocalKeyEvidence::Recognized {
            record: Box::new(record),
            events,
        }),
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
            let (status, disposition, meaning) = match record.authority_disposition {
                PersonaAuthorityDisposition::Operational => (
                    "recognized",
                    "operational",
                    "local metadata only; no independent legal identity is established",
                ),
                PersonaAuthorityDisposition::Archived => (
                    "archived",
                    "archived_non_operational",
                    "archived local persona metadata only; current signing authority is not established",
                ),
                PersonaAuthorityDisposition::EvidenceOnly => (
                    "evidence_only",
                    "evidence_only_quarantined",
                    "imported continuity evidence only; current authorization, non-revocation, and signing authority are not established",
                ),
                PersonaAuthorityDisposition::TerminallyRevoked => (
                    "terminally_revoked",
                    "permanently_deauthorized",
                    "signed terminal revocation is recorded; this persona has no current or successor signing authority",
                ),
            };
            json!({
                "status": status,
                "disposition": disposition,
                "persona": {
                    "label": record.persona.label,
                    "purpose": record.persona.purpose,
                    "lifecycle_status": if record.authority_disposition
                        == PersonaAuthorityDisposition::TerminallyRevoked
                    {
                        "permanently_deauthorized"
                    } else if record.persona.archived_at.is_some() {
                        "archived"
                    } else {
                        "active"
                    }
                },
                "key_status": record.key.status,
                "signed_label_agreement": record.persona.label == signed_label,
                "status_event": status_event,
                "meaning": meaning
            })
        }
    }
}

fn print_local_evidence(local: &LocalKeyEvidence, signed_label: &str) {
    match local {
        LocalKeyEvidence::NotChecked => println!("Local persona registry: not configured"),
        LocalKeyEvidence::Unrecognized => println!("Local persona registry: key is unrecognized"),
        LocalKeyEvidence::Recognized { record, events } => {
            match record.authority_disposition {
                PersonaAuthorityDisposition::Operational => println!(
                    "Local persona registry: {} key for {} ({})",
                    status_name(record.key.status),
                    record.persona.label,
                    record.persona.purpose
                ),
                PersonaAuthorityDisposition::Archived => {
                    println!(
                        "Local persona registry: archived/non-operational persona key for {} ({})",
                        record.persona.label, record.persona.purpose
                    );
                    println!("Recorded key status: {}", status_name(record.key.status));
                }
                PersonaAuthorityDisposition::EvidenceOnly => {
                    println!(
                        "Local persona registry: evidence-only/quarantined key for {} ({})",
                        record.persona.label, record.persona.purpose
                    );
                    println!("Recorded key status: {}", status_name(record.key.status));
                }
                PersonaAuthorityDisposition::TerminallyRevoked => {
                    println!(
                        "Local persona registry: PERSONA PERMANENTLY DEAUTHORIZED; historical key for {} ({})",
                        record.persona.label, record.persona.purpose
                    );
                    println!("Recorded key status: {}", status_name(record.key.status));
                    println!("Successor key: none");
                }
            }
            println!(
                "Persona lifecycle: {}",
                if record.authority_disposition == PersonaAuthorityDisposition::TerminallyRevoked {
                    "permanently_deauthorized"
                } else if record.persona.archived_at.is_some() {
                    "archived"
                } else {
                    "active"
                }
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
            match record.authority_disposition {
                PersonaAuthorityDisposition::Operational => {
                    println!("Registry meaning: local metadata, not independent legal identity.");
                }
                PersonaAuthorityDisposition::Archived => println!(
                    "Registry meaning: archived local persona metadata only; current signing authority is not established."
                ),
                PersonaAuthorityDisposition::EvidenceOnly => println!(
                    "Registry meaning: imported continuity evidence only; current authorization/non-revocation and signing authority are not established."
                ),
                PersonaAuthorityDisposition::TerminallyRevoked => println!(
                    "Registry meaning: terminal revocation is recorded; this persona is PERMANENTLY DEAUTHORIZED and has no successor signing key."
                ),
            }
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
    let bytes = read_regular_file_bounded(path, MAX_PERSONA_BACKUP_BYTES, "persona backup")?;
    parse_persona_backup_bytes(&bytes)
        .with_context(|| format!("invalid persona backup {}", path.display()))
}

#[derive(Debug)]
struct ContinuityCommandInputBudget {
    remaining: u64,
}

impl ContinuityCommandInputBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_CONTINUITY_COMMAND_INPUT_BYTES,
        }
    }
}

fn read_persona_root_proof(path: &Path) -> Result<PersonaRootProof> {
    let bytes = read_regular_file_bounded(path, MAX_PROOF_BYTES, "persona root proof")?;
    parse_persona_root_proof_bytes(&bytes)
        .with_context(|| format!("invalid persona root proof JSON in {}", path.display()))
}

fn read_persona_root_card(path: &Path) -> Result<PersonaRootCard> {
    let maximum =
        u64::try_from(MAX_PERSONA_ROOT_CARD_BYTES).expect("persona root card bound fits in u64");
    let bytes = read_regular_file_bounded(path, maximum, "persona root card")?;
    parse_persona_root_card_bytes(&bytes)
        .with_context(|| format!("invalid persona root card JSON in {}", path.display()))
}

fn read_persona_root_pin(path: &Path) -> Result<PersonaRootPin> {
    let maximum =
        u64::try_from(MAX_PERSONA_ROOT_PIN_BYTES).expect("persona root pin bound fits in u64");
    let bytes = read_regular_file_bounded(path, maximum, "persona root pin")?;
    parse_persona_root_pin_bytes(&bytes)
        .with_context(|| format!("invalid persona root pin JSON in {}", path.display()))
}

fn read_persona_root_proof_with_budget(
    path: &Path,
    remaining: &mut u64,
) -> Result<PersonaRootProof> {
    let bytes = read_regular_file_bounded_and_account(
        path,
        MAX_PROOF_BYTES,
        remaining,
        "persona root proof",
    )?;
    parse_persona_root_proof_bytes(&bytes)
        .with_context(|| format!("invalid persona root proof JSON in {}", path.display()))
}

fn read_persona_root_proof_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<PersonaRootProof> {
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        MAX_PROOF_BYTES,
        budget,
        "persona root proof",
    )?;
    parse_persona_root_proof_bytes(&bytes)
        .with_context(|| format!("invalid persona root proof JSON in {}", path.display()))
}

fn read_persona_transition_proof(path: &Path) -> Result<PersonaTransitionProof> {
    let bytes = read_regular_file_bounded(path, MAX_PROOF_BYTES, "persona transition proof")?;
    parse_persona_transition_proof_bytes(&bytes).with_context(|| {
        format!(
            "invalid persona transition proof JSON in {}",
            path.display()
        )
    })
}

fn read_persona_transition_proof_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<PersonaTransitionProof> {
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        MAX_PROOF_BYTES,
        budget,
        "persona transition proof",
    )?;
    parse_persona_transition_proof_bytes(&bytes).with_context(|| {
        format!(
            "invalid persona transition proof JSON in {}",
            path.display()
        )
    })
}

fn read_recovery_policy_proof_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<RecoveryPolicyProof> {
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        MAX_PROOF_BYTES,
        budget,
        "recovery policy proof",
    )?;
    parse_recovery_policy_proof_bytes(&bytes)
        .with_context(|| format!("invalid recovery policy proof JSON in {}", path.display()))
}

fn read_recovery_policy_proof_with_budget(
    path: &Path,
    remaining: &mut u64,
) -> Result<RecoveryPolicyProof> {
    let bytes = read_regular_file_bounded_and_account(
        path,
        MAX_PROOF_BYTES,
        remaining,
        "recovery policy proof",
    )?;
    parse_recovery_policy_proof_bytes(&bytes)
        .with_context(|| format!("invalid recovery policy proof JSON in {}", path.display()))
}

fn read_recovery_transition_proof_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<RecoveryTransitionProof> {
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        MAX_PROOF_BYTES,
        budget,
        "recovery transition proof",
    )?;
    parse_recovery_transition_proof_bytes(&bytes).with_context(|| {
        format!(
            "invalid recovery transition proof JSON in {}",
            path.display()
        )
    })
}

fn read_recovery_ceremony_request_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<(RecoveryCeremonyRequest, Vec<u8>)> {
    let maximum = u64::try_from(MAX_RECOVERY_CEREMONY_REQUEST_BYTES)
        .expect("recovery ceremony request bound fits in u64");
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        maximum,
        budget,
        "recovery ceremony request",
    )?;
    let request = parse_recovery_ceremony_request_bytes(&bytes).with_context(|| {
        format!(
            "invalid canonical recovery ceremony request in {}",
            path.display()
        )
    })?;
    Ok((request, bytes))
}

fn read_recovery_ceremony_response_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<RecoveryCeremonyResponse> {
    let maximum = u64::try_from(MAX_RECOVERY_CEREMONY_RESPONSE_BYTES)
        .expect("recovery ceremony response bound fits in u64");
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        maximum,
        budget,
        "recovery ceremony response",
    )?;
    parse_recovery_ceremony_response_bytes(&bytes).with_context(|| {
        format!(
            "invalid canonical recovery ceremony response in {}",
            path.display()
        )
    })
}

fn read_terminal_revocation_proof_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<TerminalPersonaRevocationProof> {
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        MAX_PROOF_BYTES,
        budget,
        "terminal persona revocation proof",
    )?;
    parse_terminal_persona_revocation_proof_bytes(&bytes).with_context(|| {
        format!(
            "invalid terminal persona revocation proof JSON in {}",
            path.display()
        )
    })
}

fn read_continuity_transition_proof_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<PersonaContinuityTransitionProof> {
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        MAX_PROOF_BYTES,
        budget,
        "continuity transition proof",
    )?;
    parse_persona_continuity_transition_proof_bytes(&bytes).with_context(|| {
        format!(
            "invalid routine or recovery transition proof JSON in {}",
            path.display()
        )
    })
}

fn read_continuity_transition_proof_with_budget(
    path: &Path,
    remaining: &mut u64,
) -> Result<PersonaContinuityTransitionProof> {
    let bytes = read_regular_file_bounded_and_account(
        path,
        MAX_PROOF_BYTES,
        remaining,
        "continuity transition proof",
    )?;
    parse_persona_continuity_transition_proof_bytes(&bytes).with_context(|| {
        format!(
            "invalid routine or recovery transition proof JSON in {}",
            path.display()
        )
    })
}

fn read_terminal_revocation_proof_with_budget(
    path: &Path,
    remaining: &mut u64,
) -> Result<TerminalPersonaRevocationProof> {
    let bytes = read_regular_file_bounded_and_account(
        path,
        MAX_PROOF_BYTES,
        remaining,
        "terminal persona revocation proof",
    )?;
    parse_terminal_persona_revocation_proof_bytes(&bytes).with_context(|| {
        format!(
            "invalid terminal persona revocation proof JSON in {}",
            path.display()
        )
    })
}

fn read_regular_file_bounded_and_account(
    path: &Path,
    maximum: u64,
    remaining: &mut u64,
    description: &str,
) -> Result<Vec<u8>> {
    ensure!(
        *remaining > 0,
        "aggregate continuity evidence input exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
    );
    let file = open_untrusted_input(path, description)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect {description} {}", path.display()))?;
    ensure!(metadata.is_file(), "{description} must be a regular file");
    ensure!(
        metadata.len() <= maximum,
        "{description} exceeds {maximum} bytes"
    );
    ensure!(
        metadata.len() <= *remaining,
        "aggregate continuity evidence input exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
    );

    let read_limit = maximum.min(*remaining);
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(read_limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {description} {}", path.display()))?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    ensure!(actual <= maximum, "{description} exceeds {maximum} bytes");
    ensure!(
        actual <= *remaining,
        "aggregate continuity evidence input exceeds {MAX_PERSONA_BACKUP_BYTES} bytes"
    );
    *remaining -= actual;
    Ok(bytes)
}

fn read_regular_file_bounded_with_command_budget(
    path: &Path,
    maximum: u64,
    budget: &mut ContinuityCommandInputBudget,
    description: &str,
) -> Result<Vec<u8>> {
    ensure!(
        budget.remaining > 0,
        "aggregate continuity proof/public-key input exceeds {MAX_CONTINUITY_COMMAND_INPUT_BYTES} bytes"
    );
    let file = open_untrusted_input(path, description)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect {description} {}", path.display()))?;
    ensure!(metadata.is_file(), "{description} must be a regular file");
    ensure!(
        metadata.len() <= maximum,
        "{description} exceeds {maximum} bytes"
    );
    ensure!(
        metadata.len() <= budget.remaining,
        "aggregate continuity proof/public-key input exceeds {MAX_CONTINUITY_COMMAND_INPUT_BYTES} bytes"
    );

    let read_limit = maximum.min(budget.remaining);
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(read_limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {description} {}", path.display()))?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    ensure!(actual <= maximum, "{description} exceeds {maximum} bytes");
    ensure!(
        actual <= budget.remaining,
        "aggregate continuity proof/public-key input exceeds {MAX_CONTINUITY_COMMAND_INPUT_BYTES} bytes"
    );
    budget.remaining -= actual;
    Ok(bytes)
}

fn read_regular_file_bounded(path: &Path, maximum: u64, description: &str) -> Result<Vec<u8>> {
    let file = open_untrusted_input(path, description)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect {description} {}", path.display()))?;
    ensure!(metadata.is_file(), "{description} must be a regular file");
    ensure!(
        metadata.len() <= maximum,
        "{description} exceeds {maximum} bytes"
    );

    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {description} {}", path.display()))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= maximum,
        "{description} exceeds {maximum} bytes"
    );
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn open_untrusted_input(path: &Path, description: &str) -> Result<File> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| format!("cannot safely open {description} {}", path.display()))?;
    Ok(File::from(descriptor))
}

#[cfg(not(target_os = "linux"))]
fn open_untrusted_input(path: &Path, description: &str) -> Result<File> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {description} {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "{description} cannot be a symbolic link"
    );
    ensure!(metadata.is_file(), "{description} must be a regular file");
    File::open(path).with_context(|| format!("cannot open {description} {}", path.display()))
}

fn write_persona_backup_new(path: &Path, backup: &PersonaBackup) -> Result<()> {
    validate_persona_backup(backup)?;
    write_private_json_new(
        path,
        serde_json::to_vec_pretty(backup)?,
        MAX_PERSONA_BACKUP_BYTES,
        "persona backup",
    )
}

#[cfg(target_os = "linux")]
fn write_private_json_new(
    path: &Path,
    mut bytes: Vec<u8>,
    maximum: u64,
    description: &str,
) -> Result<()> {
    bytes.push(b'\n');
    write_private_bytes_new(path, &bytes, maximum, description)
}

#[cfg(target_os = "linux")]
fn write_private_bytes_new(
    path: &Path,
    bytes: &[u8],
    maximum: u64,
    description: &str,
) -> Result<()> {
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= maximum,
        "serialized {description} exceeds {maximum} bytes"
    );
    require_new_output_path(path, description)?;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".a-quo-write-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "cannot create temporary {description} beside {}",
                path.display()
            )
        })?;
    temporary.as_file_mut().write_all(bytes).with_context(|| {
        format!(
            "cannot write temporary {description} for {}",
            path.display()
        )
    })?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("cannot sync temporary {description} for {}", path.display()))?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "cannot create new {description} {}; existing paths are never overwritten",
                path.display()
            )
        })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("cannot sync {description} directory {}", parent.display()))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_private_json_new(
    path: &Path,
    mut bytes: Vec<u8>,
    maximum: u64,
    description: &str,
) -> Result<()> {
    bytes.push(b'\n');
    write_private_bytes_new(path, &bytes, maximum, description)
}

#[cfg(not(target_os = "linux"))]
fn write_private_bytes_new(
    path: &Path,
    bytes: &[u8],
    maximum: u64,
    description: &str,
) -> Result<()> {
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= maximum,
        "serialized {description} exceeds {maximum} bytes"
    );

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).with_context(|| {
        format!(
            "cannot create new {description} {}; existing paths are never overwritten",
            path.display()
        )
    })?;
    file.write_all(&bytes)
        .with_context(|| format!("cannot write {description} {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot sync {description} {}", path.display()))?;
    Ok(())
}

fn require_new_output_path(path: &Path, description: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "refusing to overwrite existing {description}: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("cannot inspect {description} path {}", path.display())),
    }
}

fn read_public_key(path: &Path) -> Result<String> {
    let bytes = read_regular_file_bounded(path, MAX_PUBLIC_KEY_FILE_BYTES, "public key file")?;
    String::from_utf8(bytes)
        .with_context(|| format!("public key file is not UTF-8: {}", path.display()))
}

fn read_public_key_with_command_budget(
    path: &Path,
    budget: &mut ContinuityCommandInputBudget,
) -> Result<String> {
    let bytes = read_regular_file_bounded_with_command_budget(
        path,
        MAX_PUBLIC_KEY_FILE_BYTES,
        budget,
        "public key file",
    )?;
    String::from_utf8(bytes)
        .with_context(|| format!("public key file is not UTF-8: {}", path.display()))
}

fn retry_locator_matches(path: &Path, stored: &Path, description: &str) -> Result<bool> {
    ensure!(path.is_absolute(), "{description} path must be absolute");
    if path == stored {
        return Ok(true);
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect {description} {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    Ok(std::fs::canonicalize(path)
        .with_context(|| format!("cannot canonicalize {description} {}", path.display()))?
        == stored)
}

fn normalized_public_key_text(public_key: &str) -> Result<String> {
    public_key_fingerprint(public_key)?;
    let mut fields = public_key.split_whitespace();
    let algorithm = fields
        .next()
        .context("public key is missing its algorithm")?;
    let encoded = fields
        .next()
        .context("public key is missing its key data")?;
    Ok(format!("{algorithm} {encoded}"))
}

#[cfg(target_os = "linux")]
fn decode_sha256(value: &str) -> std::result::Result<[u8; 32], ()> {
    if value.len() != 64 {
        return Err(());
    }
    let mut digest = [0_u8; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(());
    }
    for (index, pair) in pairs.iter().enumerate() {
        let high = decode_lower_hex_digit(pair[0]).ok_or(())?;
        let low = decode_lower_hex_digit(pair[1]).ok_or(())?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

#[cfg(target_os = "linux")]
fn decode_lower_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn write_or_confirm_persona_root_proof(path: &Path, proof: &PersonaRootProof) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_private_json_new(
                path,
                serde_json::to_vec_pretty(proof)?,
                MAX_PROOF_BYTES,
                "persona root proof",
            )?;
            Ok(true)
        }
        Ok(_) => {
            let existing = read_persona_root_proof(path)
                .context("existing root-proof output is not the journaled proof")?;
            ensure!(
                existing == *proof,
                "refusing to overwrite an existing root-proof output that differs from the journal"
            );
            Ok(false)
        }
        Err(error) => Err(error)
            .with_context(|| format!("cannot inspect persona root proof path {}", path.display())),
    }
}

fn write_or_confirm_persona_transition_proof(
    path: &Path,
    proof: &PersonaTransitionProof,
) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_private_json_new(
                path,
                serde_json::to_vec_pretty(proof)?,
                MAX_PROOF_BYTES,
                "persona transition proof",
            )?;
            Ok(true)
        }
        Ok(_) => {
            let existing = read_persona_transition_proof(path)
                .context("existing transition-proof output is not the journaled proof")?;
            ensure!(
                existing == *proof,
                "refusing to overwrite an existing transition-proof output that differs from the journal"
            );
            Ok(false)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "cannot inspect persona transition proof path {}",
                path.display()
            )
        }),
    }
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

    fn assert_count_preflight_error(result: Result<()>, expected: &str, unopened: &Path) {
        let error = result
            .expect_err("oversized repeated input must fail")
            .to_string();
        assert!(
            error.contains(expected),
            "unexpected preflight error: {error}"
        );
        assert!(
            !error.contains(&unopened.display().to_string()),
            "input file was inspected before the count preflight: {error}"
        );
    }

    #[test]
    fn continuity_signature_verification_work_boundary_is_fail_closed() {
        // Root creation self-verifies the new signature, then the command
        // verifies the returned proof once more.
        assert_eq!(continuity_command_verification_work(&[(1, 2)]).unwrap(), 2);
        assert_eq!(
            continuity_command_verification_work(&[(1_024, 2)]).unwrap(),
            MAX_CONTINUITY_COMMAND_SIGNATURE_VERIFICATIONS
        );
        require_continuity_command_verification_work(&[(1_024, 2)]).unwrap();

        let over_limit = require_continuity_command_verification_work(&[(1_024, 2), (1, 1)])
            .expect_err("one verification beyond the operational limit must fail");
        assert!(
            over_limit
                .to_string()
                .contains("would require 2049 signature verifications")
        );
        let overflow = require_continuity_command_verification_work(&[(usize::MAX, 2)])
            .expect_err("verification-work arithmetic must fail closed on overflow");
        assert!(
            overflow
                .to_string()
                .contains("verification work count overflowed")
        );

        assert_eq!(minimum_recovery_policy_signature_count(0), 0);
        assert_eq!(minimum_recovery_policy_signature_count(1), 2);
        assert_eq!(minimum_recovery_policy_signature_count(2), 6);
    }

    #[test]
    fn continuity_signature_work_counts_fail_before_file_io_or_crypto() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("must-not-be-opened");
        let output = directory.path().join("new-proof.json");
        let one = vec![missing.clone()];
        let two = vec![missing.clone(), missing.clone()];
        // Creation self-verifies each new signature before the command's
        // explicit and resulting-chain passes. These are the first routine
        // history sizes that cross the limit with that third pass included.
        let transition_create_over = vec![missing.clone(); 510];
        let chain_verify_over = vec![missing.clone(); 1_024];
        let policy_update_over = vec![missing.clone(); 170];
        let recovery_create_over = vec![missing.clone(); 165];
        let policy_verify_over = vec![missing.clone(); 513];
        let recovery_transition_verify_over = vec![missing.clone(); 512];
        let recovery_chain_transition_over = vec![missing.clone(); 1_023];
        let thirty_two = vec![missing.clone(); MAX_RECOVERY_AUTHORITIES];

        assert_count_preflight_error(
            create_continuity_transition(
                &missing,
                &transition_create_over,
                &[],
                None,
                &missing,
                &missing,
                &missing,
                &missing,
                &output,
            ),
            "operational limit is 2048",
            &missing,
        );
        assert_count_preflight_error(
            verify_continuity_chain(&missing, &chain_verify_over, "root-pin", None, None, false),
            "operational limit is 2048",
            &missing,
        );
        assert_count_preflight_error(
            create_recovery_policy(
                &missing,
                &transition_create_over,
                2,
                1,
                false,
                &two,
                &two,
                &output,
            ),
            "operational limit is 2048",
            &missing,
        );
        assert_count_preflight_error(
            update_recovery_policy(
                &missing,
                &policy_update_over,
                "root-pin",
                "policy-pin",
                &[],
                2,
                1,
                false,
                &two,
                &two,
                &two,
                &two,
                &output,
            ),
            "operational limit is 2048",
            &missing,
        );
        assert_count_preflight_error(
            verify_recovery_policy_command(
                &missing,
                &policy_verify_over,
                "root-pin",
                "policy-pin",
                None,
                false,
            ),
            "operational limit is 2048",
            &missing,
        );
        assert_count_preflight_error(
            create_recovery_transition_command(
                &missing,
                &recovery_create_over,
                "root-pin",
                "policy-pin",
                &[],
                RecoveryTransitionReason::Recovery,
                &thirty_two,
                &thirty_two,
                &missing,
                &missing,
                &output,
            ),
            "operational limit is 2048",
            &missing,
        );
        assert_count_preflight_error(
            verify_recovery_transition_command(
                &missing,
                &missing,
                &recovery_transition_verify_over,
                "root-pin",
                "policy-pin",
                false,
            ),
            "operational limit is 2048",
            &missing,
        );
        assert_count_preflight_error(
            verify_recovery_chain_command(
                &missing,
                &one,
                &recovery_chain_transition_over,
                None,
                RecoveryChainExpectations {
                    root_sha256: "root-pin",
                    policy_sha256: "policy-pin",
                    head_sequence: None,
                    head_sha256: None,
                },
                None,
                false,
            ),
            "operational limit is 2048",
            &missing,
        );
    }

    #[test]
    fn continuity_repeated_input_counts_fail_before_file_io_or_crypto() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("must-not-be-opened");
        let output = directory.path().join("new-proof.json");
        let too_many_transitions = vec![missing.clone(); MAX_CONTINUITY_TRANSITIONS + 1];
        let too_many_policies = vec![missing.clone(); MAX_RECOVERY_POLICY_VERSIONS + 1];
        let too_many_authorities = vec![missing.clone(); MAX_RECOVERY_AUTHORITIES + 1];
        let one = vec![missing.clone()];
        let two = vec![missing.clone(), missing.clone()];

        assert_count_preflight_error(
            create_continuity_transition(
                &missing,
                &[],
                &too_many_policies,
                None,
                &missing,
                &missing,
                &missing,
                &missing,
                &output,
            ),
            "recovery policy chain cannot contain more than 1024 proofs",
            &missing,
        );
        assert_count_preflight_error(
            verify_continuity_chain(
                &missing,
                &too_many_transitions,
                "root-pin",
                None,
                None,
                false,
            ),
            "chain cannot contain more than 4096 transitions",
            &missing,
        );
        assert_count_preflight_error(
            create_recovery_policy(
                &missing,
                &too_many_transitions,
                2,
                1,
                false,
                &one,
                &one,
                &output,
            ),
            "chain cannot contain more than 4096 transitions",
            &missing,
        );
        assert_count_preflight_error(
            create_recovery_policy(
                &missing,
                &[],
                2,
                1,
                false,
                &too_many_authorities,
                &too_many_authorities,
                &output,
            ),
            "recovery policy enrollment cannot contain more than 32 key pairs",
            &missing,
        );
        assert_count_preflight_error(
            create_recovery_policy(&missing, &[], 1, 1, false, &one, &one, &output),
            "recovery threshold must be at least 2 and no greater than the authority count",
            &missing,
        );
        assert_count_preflight_error(
            update_recovery_policy(
                &missing,
                &one,
                "root-pin",
                "policy-pin",
                &[],
                2,
                0,
                false,
                &two,
                &two,
                &two,
                &two,
                &output,
            ),
            "recovery policy validity must be between 1 and",
            &missing,
        );
        assert_count_preflight_error(
            update_recovery_policy(
                &missing,
                &too_many_policies,
                "root-pin",
                "policy-pin",
                &[],
                2,
                1,
                false,
                &one,
                &one,
                &one,
                &one,
                &output,
            ),
            "cannot append beyond 1024 recovery policy versions",
            &missing,
        );
        assert_count_preflight_error(
            verify_recovery_policy_command(
                &missing,
                &too_many_policies,
                "root-pin",
                "policy-pin",
                None,
                false,
            ),
            "recovery policy chain cannot contain more than 1024 proofs",
            &missing,
        );
        assert_count_preflight_error(
            create_recovery_transition_command(
                &missing,
                &one,
                "root-pin",
                "policy-pin",
                &too_many_transitions,
                RecoveryTransitionReason::Recovery,
                &one,
                &one,
                &missing,
                &missing,
                &output,
            ),
            "cannot append beyond 4096 continuity transitions",
            &missing,
        );
        assert_count_preflight_error(
            verify_recovery_transition_command(
                &missing,
                &missing,
                &too_many_policies,
                "root-pin",
                "policy-pin",
                false,
            ),
            "recovery policy chain cannot contain more than 1024 proofs",
            &missing,
        );
        assert_count_preflight_error(
            verify_recovery_chain_command(
                &missing,
                &one,
                &too_many_transitions,
                None,
                RecoveryChainExpectations {
                    root_sha256: "root-pin",
                    policy_sha256: "policy-pin",
                    head_sequence: None,
                    head_sha256: None,
                },
                None,
                false,
            ),
            "chain cannot contain more than 4096 transitions",
            &missing,
        );
    }

    #[test]
    fn allowed_repeated_proof_count_still_obeys_command_byte_budget() {
        let directory = tempfile::tempdir().unwrap();
        let large_proof = directory.path().join("large-proof.json");
        fs::write(
            &large_proof,
            vec![b' '; usize::try_from(MAX_PROOF_BYTES).unwrap()],
        )
        .unwrap();
        let repetitions =
            usize::try_from(MAX_CONTINUITY_COMMAND_INPUT_BYTES / MAX_PROOF_BYTES).unwrap() + 1;
        assert!(repetitions <= MAX_CONTINUITY_TRANSITIONS);

        let mut budget = ContinuityCommandInputBudget::new();
        for index in 0..repetitions {
            let result = read_regular_file_bounded_with_command_budget(
                &large_proof,
                MAX_PROOF_BYTES,
                &mut budget,
                "continuity proof",
            );
            if index + 1 == repetitions {
                let error = result.expect_err("aggregate budget must reject the final proof");
                assert!(
                    error.to_string().contains(
                        "aggregate continuity proof/public-key input exceeds 67108864 bytes"
                    ),
                    "unexpected aggregate-budget error: {error}"
                );
            } else {
                assert_eq!(
                    u64::try_from(result.unwrap().len()).unwrap(),
                    MAX_PROOF_BYTES
                );
            }
        }
    }

    #[test]
    fn backup_evidence_loader_has_its_distinct_four_mib_budget() {
        let directory = tempfile::tempdir().unwrap();
        let large_proof = directory.path().join("large-backup-proof.json");
        fs::write(
            &large_proof,
            vec![b' '; usize::try_from(MAX_PROOF_BYTES).unwrap()],
        )
        .unwrap();

        let mut remaining = MAX_PERSONA_BACKUP_BYTES;
        for index in 0..5 {
            let result = read_regular_file_bounded_and_account(
                &large_proof,
                MAX_PROOF_BYTES,
                &mut remaining,
                "continuity proof",
            );
            if index == 4 {
                let error = result.expect_err("fifth proof must exceed backup evidence budget");
                assert!(
                    error
                        .to_string()
                        .contains("aggregate continuity evidence input exceeds 4194304 bytes"),
                    "unexpected backup aggregate-budget error: {error}"
                );
            } else {
                assert_eq!(
                    u64::try_from(result.unwrap().len()).unwrap(),
                    MAX_PROOF_BYTES
                );
            }
        }
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

        let cli = Cli::try_parse_from([
            "a-quo",
            "persona",
            "backup-export",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--root",
            "root.json",
            "--recovery-policy",
            "policy-v1.json",
            "--recovery-policy",
            "policy-v2.json",
            "--transition",
            "routine.json",
            "--transition",
            "recovery.json",
            "--terminal-revocation",
            "terminal.json",
            "--output",
            "persona.archive.json",
        ])
        .unwrap();
        let Commands::Persona {
            command:
                PersonaCommands::BackupExport {
                    root,
                    recovery_policies,
                    transitions,
                    terminal_revocation,
                    ..
                },
        } = cli.command
        else {
            panic!("expected persona archive export command");
        };
        assert_eq!(root, Some(PathBuf::from("root.json")));
        assert_eq!(
            recovery_policies,
            [
                PathBuf::from("policy-v1.json"),
                PathBuf::from("policy-v2.json")
            ]
        );
        assert_eq!(
            transitions,
            [
                PathBuf::from("routine.json"),
                PathBuf::from("recovery.json")
            ]
        );
        assert_eq!(terminal_revocation, Some(PathBuf::from("terminal.json")));

        for evidence_flag in ["--recovery-policy", "--transition", "--terminal-revocation"] {
            assert!(
                Cli::try_parse_from([
                    "a-quo",
                    "persona",
                    "backup-export",
                    "--persona-id",
                    "02cc60fd-a039-4af7-bb51-e96f0591f910",
                    evidence_flag,
                    "evidence.json",
                    "--output",
                    "persona.archive.json",
                ])
                .is_err(),
                "{evidence_flag} must require --root"
            );
        }

        let cli = Cli::try_parse_from(["a-quo", "persona", "backup-import", "persona.backup.json"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Persona {
                command: PersonaCommands::BackupImport { .. }
            }
        ));

        let root_pin = "a".repeat(64);
        let head_pin = "b".repeat(64);
        let policy_pin = "c".repeat(64);
        let exact_policy = Cli::try_parse_from([
            "a-quo",
            "persona",
            "backup-compare",
            "persona.archive.json",
            "--expected-root-sha256",
            &root_pin,
            "--expected-head-sequence",
            "2",
            "--expected-head-sha256",
            &head_pin,
            "--expected-policy-version",
            "1",
            "--expected-policy-sha256",
            &policy_pin,
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            exact_policy.command,
            Commands::Persona {
                command: PersonaCommands::BackupCompare {
                    expected_policy_version: Some(1),
                    json: true,
                    ..
                }
            }
        ));

        Cli::try_parse_from([
            "a-quo",
            "persona",
            "backup-compare",
            "persona.archive.json",
            "--expected-root-sha256",
            &root_pin,
            "--expected-head-sequence",
            "0",
            "--expect-no-recovery-policy",
        ])
        .unwrap();

        let required = [
            "a-quo",
            "persona",
            "backup-compare",
            "persona.archive.json",
            "--expected-root-sha256",
            root_pin.as_str(),
            "--expected-head-sequence",
            "2",
            "--expected-head-sha256",
            head_pin.as_str(),
        ];
        assert!(Cli::try_parse_from(required).is_err());
        assert!(
            Cli::try_parse_from(
                required
                    .into_iter()
                    .chain(["--expected-policy-version", "1"])
            )
            .is_err()
        );
        assert!(
            Cli::try_parse_from(
                required
                    .into_iter()
                    .chain(["--expected-policy-sha256", policy_pin.as_str()])
            )
            .is_err()
        );
        assert!(
            Cli::try_parse_from(required.into_iter().chain([
                "--expect-no-recovery-policy",
                "--expected-policy-version",
                "1",
                "--expected-policy-sha256",
                policy_pin.as_str(),
            ]))
            .is_err()
        );

        let archive_pin = "d".repeat(64);
        let activation = Cli::try_parse_from([
            "a-quo",
            "persona",
            "backup-activate-direct",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--expected-archive-sha256",
            archive_pin.as_str(),
            "--expected-root-sha256",
            root_pin.as_str(),
            "--expected-head-sequence",
            "0",
            "--expect-no-recovery-policy",
            "--expected-current-key-fingerprint",
            "SHA256:current-key",
            "--current-provider",
            "openssh-file",
            "--current-signing-locator",
            "/private/signer",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            activation.command,
            Commands::Persona {
                command: PersonaCommands::BackupActivateDirect {
                    current_provider: Some(_),
                    current_signing_locator: Some(_),
                    json: true,
                    ..
                }
            }
        ));

        Cli::try_parse_from([
            "a-quo",
            "persona",
            "backup-activate-direct",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--expected-archive-sha256",
            archive_pin.as_str(),
            "--expected-root-sha256",
            root_pin.as_str(),
            "--expected-head-sequence",
            "0",
            "--expect-no-recovery-policy",
            "--expected-current-key-fingerprint",
            "SHA256:current-key",
        ])
        .expect("exact sealed replay may omit both signer arguments");

        for invalid_tail in [
            ["--current-provider", "openssh-file"],
            ["--current-signing-locator", "/private/signer"],
            ["--force", "true"],
            ["--latest", "true"],
        ] {
            assert!(
                Cli::try_parse_from(
                    [
                        "a-quo",
                        "persona",
                        "backup-activate-direct",
                        "--persona-id",
                        "02cc60fd-a039-4af7-bb51-e96f0591f910",
                        "--expected-archive-sha256",
                        archive_pin.as_str(),
                        "--expected-root-sha256",
                        root_pin.as_str(),
                        "--expected-head-sequence",
                        "0",
                        "--expect-no-recovery-policy",
                        "--expected-current-key-fingerprint",
                        "SHA256:current-key",
                    ]
                    .into_iter()
                    .chain(invalid_tail),
                )
                .is_err(),
                "unsupported or incomplete activation arguments unexpectedly parsed: {invalid_tail:?}"
            );
        }
        assert!(
            Cli::try_parse_from([
                "a-quo",
                "persona",
                "backup-activate-direct",
                "persona.archive.json",
                "--persona-id",
                "02cc60fd-a039-4af7-bb51-e96f0591f910",
                "--expected-archive-sha256",
                archive_pin.as_str(),
                "--expected-root-sha256",
                root_pin.as_str(),
                "--expected-head-sequence",
                "0",
                "--expect-no-recovery-policy",
                "--expected-current-key-fingerprint",
                "SHA256:current-key",
            ])
            .is_err(),
            "direct activation must not accept an ambiguous archive path"
        );

        let recovery_activation = Cli::try_parse_from([
            "a-quo",
            "persona",
            "backup-activate-recovery",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--proof",
            "recovery.json",
            "--expected-archive-sha256",
            archive_pin.as_str(),
            "--expected-root-sha256",
            root_pin.as_str(),
            "--expected-head-sequence",
            "2",
            "--expected-head-sha256",
            head_pin.as_str(),
            "--expected-policy-version",
            "1",
            "--expected-policy-sha256",
            policy_pin.as_str(),
            "--next-provider",
            "openssh-file",
            "--next-signing-locator",
            "/private/successor",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            recovery_activation.command,
            Commands::Persona {
                command: PersonaCommands::BackupActivateRecovery {
                    expected_head_sequence: 2,
                    expected_policy_version: 1,
                    next_provider: Some(_),
                    next_signing_locator: Some(_),
                    json: true,
                    ..
                }
            }
        ));

        let recovery_replay = [
            "a-quo",
            "persona",
            "backup-activate-recovery",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--proof",
            "recovery.json",
            "--expected-archive-sha256",
            archive_pin.as_str(),
            "--expected-root-sha256",
            root_pin.as_str(),
            "--expected-head-sequence",
            "2",
            "--expected-head-sha256",
            head_pin.as_str(),
            "--expected-policy-version",
            "1",
            "--expected-policy-sha256",
            policy_pin.as_str(),
        ];
        Cli::try_parse_from(recovery_replay)
            .expect("exact sealed recovery activation replay may omit both signer arguments");
        assert!(
            Cli::try_parse_from(
                recovery_replay
                    .into_iter()
                    .filter(|argument| !matches!(*argument, "--proof" | "recovery.json"))
            )
            .is_err(),
            "recovery activation must require exactly one recovery proof path"
        );
        assert!(
            backup_continuity_expected_pins(
                root_pin.as_str(),
                2,
                None,
                false,
                Some(1),
                Some(policy_pin.as_str()),
            )
            .is_err(),
            "a nonzero recovery source head must require its exact digest"
        );
        assert!(
            backup_continuity_expected_pins(
                root_pin.as_str(),
                0,
                Some(head_pin.as_str()),
                false,
                Some(1),
                Some(policy_pin.as_str()),
            )
            .is_err(),
            "a root recovery source head must forbid a transition digest"
        );

        for invalid_tail in [
            ["--next-provider", "openssh-file"],
            ["--next-signing-locator", "/private/successor"],
            ["--current-provider", "openssh-file"],
            ["--current-signing-locator", "/private/old-signer"],
            ["--old-provider", "openssh-file"],
            ["--old-signing-locator", "/private/old-signer"],
            ["--old-key", "/private/old-signer"],
            ["--previous-key", "/private/old-signer"],
            ["--expected-current-key-fingerprint", "SHA256:old-key"],
            ["--expected-successor-key-fingerprint", "SHA256:new-key"],
            ["--force", "true"],
            ["--latest", "true"],
        ] {
            assert!(
                Cli::try_parse_from(recovery_replay.into_iter().chain(invalid_tail)).is_err(),
                "recovery activation unexpectedly accepted incomplete or authority-confusing arguments: {invalid_tail:?}"
            );
        }
        assert!(
            Cli::try_parse_from(recovery_replay.into_iter().chain(["persona.archive.json"]))
                .is_err(),
            "recovery activation must not accept an ambiguous archive path"
        );

        let terminal = Cli::try_parse_from([
            "a-quo",
            "persona",
            "backup-hydrate-terminal",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--expected-archive-sha256",
            archive_pin.as_str(),
            "--expected-root-sha256",
            root_pin.as_str(),
            "--expected-head-sequence",
            "3",
            "--expected-head-sha256",
            head_pin.as_str(),
            "--expected-policy-version",
            "1",
            "--expected-policy-sha256",
            policy_pin.as_str(),
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            terminal.command,
            Commands::Persona {
                command: PersonaCommands::BackupHydrateTerminal {
                    expected_head_sequence: 3,
                    expected_policy_version: 1,
                    json: true,
                    ..
                }
            }
        ));

        let terminal_required = [
            "a-quo",
            "persona",
            "backup-hydrate-terminal",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--expected-archive-sha256",
            archive_pin.as_str(),
            "--expected-root-sha256",
            root_pin.as_str(),
            "--expected-head-sequence",
            "3",
            "--expected-head-sha256",
            head_pin.as_str(),
            "--expected-policy-version",
            "1",
            "--expected-policy-sha256",
            policy_pin.as_str(),
        ];
        for forbidden in [
            ["--current-provider", "openssh-file"],
            ["--current-signing-locator", "/private/signer"],
            ["--expected-current-key-fingerprint", "SHA256:current-key"],
            ["--recovery-proof", "recovery.json"],
            ["--force", "true"],
            ["--latest", "true"],
        ] {
            assert!(
                Cli::try_parse_from(terminal_required.into_iter().chain(forbidden)).is_err(),
                "terminal hydration unexpectedly accepted authority-bearing or ambiguous input: {forbidden:?}"
            );
        }
        for missing_flag in [
            "--expected-head-sha256",
            "--expected-policy-version",
            "--expected-policy-sha256",
        ] {
            let args = terminal_required
                .into_iter()
                .filter(|argument| *argument != missing_flag)
                .collect::<Vec<_>>();
            assert!(
                Cli::try_parse_from(args).is_err(),
                "terminal hydration unexpectedly accepted missing {missing_flag}"
            );
        }
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
    fn persona_root_request_requires_explicit_persona_and_new_output() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "continuity",
            "root-request",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--output",
            "publisher-root.json",
            "--socket",
            "/run/user/1000/a-quo/consent.sock",
        ])
        .unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::RootRequest {
                    persona_id,
                    output,
                    socket,
                },
        } = cli.command
        else {
            panic!("expected persona-root request command");
        };
        assert_eq!(persona_id, "02cc60fd-a039-4af7-bb51-e96f0591f910");
        assert_eq!(output, PathBuf::from("publisher-root.json"));
        assert_eq!(
            socket,
            Some(PathBuf::from("/run/user/1000/a-quo/consent.sock"))
        );
    }

    #[test]
    fn persona_transition_request_requires_root_pin_and_closed_key_inputs() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "continuity",
            "transition-request",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--expected-root-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--next-key",
            "/keys/publisher-next",
            "--next-public-key",
            "/keys/publisher-next.pub",
            "--next-provider",
            "openssh-file",
            "--output",
            "publisher-transition.json",
            "--socket",
            "/run/user/1000/a-quo/consent.sock",
        ])
        .unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::TransitionRequest {
                    persona_id,
                    expected_root_sha256,
                    next_key,
                    next_public_key,
                    next_provider,
                    output,
                    socket,
                },
        } = cli.command
        else {
            panic!("expected persona-transition request command");
        };
        assert_eq!(persona_id, "02cc60fd-a039-4af7-bb51-e96f0591f910");
        assert_eq!(expected_root_sha256, "a".repeat(64));
        assert_eq!(next_key, PathBuf::from("/keys/publisher-next"));
        assert_eq!(next_public_key, PathBuf::from("/keys/publisher-next.pub"));
        assert_eq!(next_provider, "openssh-file");
        assert_eq!(output, PathBuf::from("publisher-transition.json"));
        assert_eq!(
            socket,
            Some(PathBuf::from("/run/user/1000/a-quo/consent.sock"))
        );
    }

    #[test]
    fn recovery_policy_record_requires_persona_pins_and_exact_head() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "continuity",
            "recovery-policy-record",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--policy",
            "policy-v1.json",
            "--policy",
            "policy-v2.json",
            "--expected-root-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--expected-policy-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--expected-head-sequence",
            "3",
            "--expected-head-sha256",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ])
        .unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::RecoveryPolicyRecord {
                    persona_id,
                    policies,
                    expected_root_sha256,
                    expected_policy_sha256,
                    expected_head_sequence,
                    expected_head_sha256,
                },
        } = cli.command
        else {
            panic!("expected recovery-policy-record command");
        };
        assert_eq!(persona_id, "02cc60fd-a039-4af7-bb51-e96f0591f910");
        assert_eq!(
            policies,
            [
                PathBuf::from("policy-v1.json"),
                PathBuf::from("policy-v2.json")
            ]
        );
        assert_eq!(expected_root_sha256, "a".repeat(64));
        assert_eq!(expected_policy_sha256, "b".repeat(64));
        assert_eq!(expected_head_sequence, 3);
        assert_eq!(
            expected_head_sha256.as_deref(),
            Some("c".repeat(64).as_str())
        );
    }

    #[test]
    fn recovery_transition_commit_parses_prior_head_and_explicit_signer_binding() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "continuity",
            "recovery-transition-commit",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--proof",
            "recovery-transition.json",
            "--expected-root-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--expected-policy-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--expected-previous-head-sequence",
            "1",
            "--expected-previous-head-sha256",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "--next-provider",
            "openssh-file",
            "--next-signing-locator",
            "/keys/publisher-recovered",
        ])
        .unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::RecoveryTransitionCommit {
                    persona_id,
                    proof,
                    expected_root_sha256,
                    expected_policy_sha256,
                    expected_previous_head_sequence,
                    expected_previous_head_sha256,
                    next_provider,
                    next_signing_locator,
                },
        } = cli.command
        else {
            panic!("expected recovery-transition-commit command");
        };
        assert_eq!(persona_id, "02cc60fd-a039-4af7-bb51-e96f0591f910");
        assert_eq!(proof, PathBuf::from("recovery-transition.json"));
        assert_eq!(expected_root_sha256, "a".repeat(64));
        assert_eq!(expected_policy_sha256, "b".repeat(64));
        assert_eq!(expected_previous_head_sequence, 1);
        assert_eq!(
            expected_previous_head_sha256.as_deref(),
            Some("c".repeat(64).as_str())
        );
        assert_eq!(next_provider.as_deref(), Some("openssh-file"));
        assert_eq!(
            next_signing_locator,
            Some(PathBuf::from("/keys/publisher-recovered"))
        );
    }

    #[test]
    fn recovery_transition_commit_allows_only_a_complete_or_omitted_binding_pair() {
        let base = [
            "a-quo",
            "continuity",
            "recovery-transition-commit",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--proof",
            "recovery-transition.json",
            "--expected-root-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--expected-policy-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--expected-previous-head-sequence",
            "1",
            "--expected-previous-head-sha256",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ];

        let omitted = Cli::try_parse_from(base).unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::RecoveryTransitionCommit {
                    next_provider,
                    next_signing_locator,
                    ..
                },
        } = omitted.command
        else {
            panic!("expected recovery-transition-commit command");
        };
        assert!(next_provider.is_none());
        assert!(next_signing_locator.is_none());

        let mut provider_only = base.to_vec();
        provider_only.extend(["--next-provider", "openssh-file"]);
        assert!(Cli::try_parse_from(provider_only).is_err());

        let mut locator_only = base.to_vec();
        locator_only.extend(["--next-signing-locator", "/keys/publisher-recovered"]);
        assert!(Cli::try_parse_from(locator_only).is_err());
    }

    #[test]
    fn recovery_policy_terminal_revocation_capability_is_explicit() {
        let base = [
            "a-quo",
            "continuity",
            "recovery-policy-create",
            "--root",
            "root.json",
            "--threshold",
            "2",
            "--valid-days",
            "30",
            "--authority-key",
            "authority-one",
            "--authority-public-key",
            "authority-one.pub",
            "--authority-key",
            "authority-two",
            "--authority-public-key",
            "authority-two.pub",
            "--output",
            "policy.json",
        ];
        let default_policy = Cli::try_parse_from(base).unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::RecoveryPolicyCreate {
                    authorize_terminal_revocation,
                    ..
                },
        } = default_policy.command
        else {
            panic!("expected recovery-policy-create command");
        };
        assert!(!authorize_terminal_revocation);

        let mut opted_in = base.to_vec();
        opted_in.push("--authorize-terminal-revocation");
        let opted_in = Cli::try_parse_from(opted_in).unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::RecoveryPolicyCreate {
                    authorize_terminal_revocation,
                    ..
                },
        } = opted_in.command
        else {
            panic!("expected recovery-policy-create command");
        };
        assert!(authorize_terminal_revocation);
    }

    #[test]
    fn terminal_revocation_create_requires_pins_authorities_and_has_no_successor_input() {
        let base = [
            "a-quo",
            "continuity",
            "terminal-revocation-create",
            "--root",
            "root.json",
            "--policy",
            "policy.json",
            "--expected-root-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--expected-policy-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--prior-transition",
            "transition.json",
            "--expected-previous-head-sequence",
            "1",
            "--expected-previous-head-sha256",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "--reason",
            "compromise",
            "--authority-key",
            "authority-one",
            "--authority-public-key",
            "authority-one.pub",
            "--authority-key",
            "authority-two",
            "--authority-public-key",
            "authority-two.pub",
            "--output",
            "terminal-revocation.json",
            "--json",
        ];
        let cli = Cli::try_parse_from(base).unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::TerminalRevocationCreate {
                    expected_previous_head_sequence,
                    expected_previous_head_sha256,
                    authority_keys,
                    authority_public_keys,
                    output,
                    json,
                    ..
                },
        } = cli.command
        else {
            panic!("expected terminal-revocation-create command");
        };
        assert_eq!(expected_previous_head_sequence, 1);
        assert_eq!(
            expected_previous_head_sha256.as_deref(),
            Some("c".repeat(64).as_str())
        );
        assert_eq!(authority_keys.len(), 2);
        assert_eq!(authority_public_keys.len(), 2);
        assert_eq!(output, PathBuf::from("terminal-revocation.json"));
        assert!(json);

        for forbidden in ["--next-key", "--next-public-key", "--next-provider"] {
            let mut invalid = base.to_vec();
            invalid.extend([forbidden, "forbidden-successor"]);
            assert!(
                Cli::try_parse_from(invalid).is_err(),
                "{forbidden} must not be accepted by terminal revocation creation"
            );
        }
    }

    #[test]
    fn terminal_revocation_commit_has_no_signer_or_successor_arguments() {
        let base = [
            "a-quo",
            "continuity",
            "terminal-revocation-commit",
            "--persona-id",
            "02cc60fd-a039-4af7-bb51-e96f0591f910",
            "--proof",
            "terminal-revocation.json",
            "--expected-root-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--expected-policy-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--expected-previous-head-sequence",
            "0",
            "--json",
        ];
        let cli = Cli::try_parse_from(base).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Continuity {
                command: ContinuityCommands::TerminalRevocationCommit { json: true, .. }
            }
        ));
        for forbidden in ["--next-provider", "--next-signing-locator", "--next-key"] {
            let mut invalid = base.to_vec();
            invalid.extend([forbidden, "forbidden-successor"]);
            assert!(
                Cli::try_parse_from(invalid).is_err(),
                "{forbidden} must not be accepted by terminal revocation commit"
            );
        }
    }

    #[test]
    fn recovery_chain_uses_a_dedicated_final_terminal_revocation_flag() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "continuity",
            "recovery-chain-verify",
            "--root",
            "root.json",
            "--policy",
            "policy.json",
            "--transition",
            "transition.json",
            "--terminal-revocation",
            "terminal-revocation.json",
            "--expected-root-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--expected-policy-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .unwrap();
        let Commands::Continuity {
            command:
                ContinuityCommands::RecoveryChainVerify {
                    transitions,
                    terminal_revocation,
                    ..
                },
        } = cli.command
        else {
            panic!("expected recovery-chain-verify command");
        };
        assert_eq!(transitions, [PathBuf::from("transition.json")]);
        assert_eq!(
            terminal_revocation,
            Some(PathBuf::from("terminal-revocation.json"))
        );
    }

    #[test]
    fn recovery_transition_commit_rejects_one_sided_binding_before_io() {
        let missing = PathBuf::from("must-not-be-opened");
        let provider_only = commit_recovery_transition_command(
            Some(&missing),
            "persona-id",
            &missing,
            &"a".repeat(64),
            &"b".repeat(64),
            0,
            None,
            Some("openssh-file"),
            None,
        )
        .unwrap_err();
        assert!(
            provider_only
                .to_string()
                .contains("--next-provider and --next-signing-locator must be supplied together")
        );

        let locator_only = commit_recovery_transition_command(
            Some(&missing),
            "persona-id",
            &missing,
            &"a".repeat(64),
            &"b".repeat(64),
            0,
            None,
            None,
            Some(&missing),
        )
        .unwrap_err();
        assert!(
            locator_only
                .to_string()
                .contains("--next-provider and --next-signing-locator must be supplied together")
        );
        assert!(!missing.exists());
    }

    #[test]
    fn required_continuity_checkpoint_enforces_zero_and_nonzero_digest_rules() {
        assert_eq!(
            required_continuity_checkpoint(0, None, "--sequence", "--digest").unwrap(),
            PersonaContinuityCheckpoint {
                transition_sequence: 0,
                transition_sha256: None,
            }
        );
        assert!(
            required_continuity_checkpoint(0, Some(&"a".repeat(64)), "--sequence", "--digest")
                .unwrap_err()
                .to_string()
                .contains("--sequence 0 cannot have --digest")
        );
        assert!(
            required_continuity_checkpoint(1, None, "--sequence", "--digest")
                .unwrap_err()
                .to_string()
                .contains("a nonzero --sequence requires --digest")
        );
        assert_eq!(
            required_continuity_checkpoint(1, Some(&"a".repeat(64)), "--sequence", "--digest")
                .unwrap()
                .transition_sha256,
            Some("a".repeat(64))
        );
    }

    #[test]
    fn recovery_recording_pins_are_lowercase_sha256_values() {
        require_sha256_pin(&"0".repeat(64), "--pin").unwrap();
        assert!(require_sha256_pin(&"A".repeat(64), "--pin").is_err());
        assert!(require_sha256_pin(&"g".repeat(64), "--pin").is_err());
        assert!(require_sha256_pin(&"0".repeat(63), "--pin").is_err());
    }

    #[test]
    fn recovery_policy_record_count_preflight_happens_before_store_or_file_io() {
        let missing = PathBuf::from("must-not-be-opened");
        let policies = vec![missing.clone(); MAX_RECOVERY_POLICY_VERSIONS + 1];
        let error = record_recovery_policy_command(
            Some(&missing),
            "persona-id",
            &policies,
            &"a".repeat(64),
            &"b".repeat(64),
            0,
            None,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("recovery policy chain cannot contain more than 1024 proofs")
        );
        assert!(!missing.exists());
    }

    #[test]
    fn omarchy_install_parses_separate_operation_and_no_analysis_acknowledgements() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "omarchy",
            "install",
            "plugin.tar.zst",
            "--proof",
            "plugin.proof.json",
            "--yes",
            "--accept-behavioral-analysis-not-run",
        ])
        .unwrap();
        let Commands::Omarchy {
            command:
                OmarchyCommands::Install {
                    yes,
                    accept_behavioral_analysis_not_run,
                    ..
                },
        } = cli.command
        else {
            panic!("expected Omarchy install command");
        };
        assert!(yes);
        assert!(accept_behavioral_analysis_not_run);
    }

    #[test]
    fn omarchy_uninstall_parses_explicit_confirmation_without_an_analysis_waiver() {
        let cli = Cli::try_parse_from([
            "a-quo",
            "omarchy",
            "uninstall",
            "example.signed-plugin",
            "--yes",
        ])
        .unwrap();
        let Commands::Omarchy {
            command: OmarchyCommands::Uninstall { plugin_id, yes, .. },
        } = cli.command
        else {
            panic!("expected Omarchy uninstall command");
        };
        assert_eq!(plugin_id, "example.signed-plugin");
        assert!(yes);
    }

    #[test]
    fn omarchy_mutation_acknowledgements_fail_before_io() {
        let no_confirmation = require_omarchy_cli_acknowledgements("update", false, true)
            .expect_err("--yes must be independent");
        assert!(no_confirmation.to_string().contains("pass --yes"));

        let no_analysis_acknowledgement =
            require_omarchy_cli_acknowledgements("update", true, false)
                .expect_err("missing behavioural-analysis acknowledgement must fail");
        assert!(
            no_analysis_acknowledgement
                .to_string()
                .contains("--accept-behavioral-analysis-not-run")
        );

        require_omarchy_cli_acknowledgements("update", true, true)
            .expect("both explicit acknowledgements should pass the CLI preflight");

        let no_uninstall_confirmation = require_omarchy_uninstall_confirmation(false)
            .expect_err("uninstall must require --yes before path resolution");
        assert!(no_uninstall_confirmation.to_string().contains("pass --yes"));
        require_omarchy_uninstall_confirmation(true)
            .expect("explicit uninstall confirmation should pass the CLI preflight");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transition_public_key_comments_do_not_change_retry_identity() {
        let commented = format!("{BACKUP_KEY} workstation-comment");
        assert_eq!(normalized_public_key_text(&commented).unwrap(), BACKUP_KEY);
        assert_eq!(
            public_key_fingerprint(&commented).unwrap(),
            public_key_fingerprint(BACKUP_KEY).unwrap()
        );
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
