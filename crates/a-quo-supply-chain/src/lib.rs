//! Isolated, offline Sigstore bundle verification for A Quo.
//!
//! The untrusted bundle and trust-root parsers run only in a re-executed CLI
//! worker. On Linux the parent starts that worker inside a network-less
//! Bubblewrap namespace. The worker receives an artifact SHA-256 digest, not
//! the artifact bytes, plus bounded immutable snapshots of the bundle and the
//! explicitly selected trust root.

use std::io::{Read, Write};
use std::path::Path;

use a_quo_core::ArtifactDescriptor;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sigstore_verify::trust_root::TrustedRoot;
use sigstore_verify::types::{
    Bundle, HashAlgorithm, Sha256Hash, SignatureContent, Statement,
    bundle::VerificationMaterialContent,
};
use sigstore_verify::{VerificationPolicy, verify};
use thiserror::Error;

#[cfg(target_os = "linux")]
mod linux;

pub const SUPPLY_CHAIN_REPORT_SCHEMA: &str = "urn:a-quo:report:sigstore:v1";
pub const SIGSTORE_VERIFIER_VERSION: &str = "0.11.0";
pub const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
pub const SIGSTORE_TRUSTED_ROOT_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1";
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const SLSA_PROVENANCE_TYPE: &str = "https://slsa.dev/provenance/v1";

pub const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_TRUSTED_ROOT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_POLICY_BYTES: usize = 1024;
const MAX_DISPLAY_BYTES: usize = 2048;
const MAX_SUBJECTS: usize = 256;
const MAX_TLOG_ENTRIES: usize = 32;
const MAX_TIMESTAMPS: usize = 32;
const FRAME_MAGIC: &[u8; 8] = b"AQUOSIG1";
const FRAME_HEADER_BYTES: usize = 16;
const MAX_FRAME_BYTES: u64 = FRAME_HEADER_BYTES as u64 + MAX_BUNDLE_BYTES + MAX_TRUSTED_ROOT_BYTES;
const WORKER_REPORT_SCHEMA: &str = "urn:a-quo:internal:sigstore-worker:v1";

#[derive(Debug, Error)]
pub enum SupplyChainError {
    #[error("Sigstore verification is currently available only on Linux")]
    UnsupportedPlatform,

    #[error("invalid {field}: require non-empty, bounded text without controls or bidi overrides")]
    InvalidPolicy { field: &'static str },

    #[error("cannot safely open {kind} {path}: {source}")]
    OpenInput {
        kind: &'static str,
        path: std::path::PathBuf,
        #[source]
        source: rustix_or_io::PlatformIoError,
    },

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Snapshot(#[from] a_quo_ipc::LinuxIpcError),

    #[error("trusted Sigstore sandbox executable is unavailable or unsafe: {0}")]
    UnsafeSandboxExecutable(std::path::PathBuf),

    #[error("cannot inspect the running A Quo executable: {0}")]
    CurrentExecutable(#[source] std::io::Error),

    #[error("invalid internal Sigstore launcher argument")]
    InvalidLauncherArgument,

    #[error("Sigstore launcher received bytes that did not match the parent's sealed snapshot")]
    LauncherInputMismatch,

    #[error("invalid bounded Sigstore worker input frame")]
    InvalidInputFrame,

    #[error("cannot start the isolated Sigstore worker: {0}")]
    WorkerUnavailable(#[source] std::io::Error),

    #[error("isolated Sigstore launcher input could not be transferred")]
    WorkerInputIo,

    #[error("isolated Sigstore verification exceeded its 45-second deadline")]
    WorkerTimedOut,

    #[error("isolated Sigstore verification exceeded its bounded output limit")]
    WorkerOutputTooLarge,

    #[error("isolated Sigstore verification output could not be read")]
    WorkerOutputIo,

    #[error("isolated Sigstore worker failed ({0}); details were suppressed")]
    WorkerFailed(String),

    #[error("isolated Sigstore worker returned malformed or incompatible evidence")]
    InvalidWorkerReport,

    #[error("Sigstore worker could not read its bounded immutable input")]
    WorkerInput,

    #[error("Sigstore worker could not encode its bounded response")]
    WorkerEncoding,
}

pub type Result<T> = std::result::Result<T, SupplyChainError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyChainOutcome {
    Verified,
    Invalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Verified,
    NotVerified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    InvalidBundleJson,
    UnsupportedBundleFormat,
    InvalidTrustedRootJson,
    UnsupportedTrustedRootFormat,
    UnsupportedVerificationMaterial,
    UnsupportedArtifactDigest,
    InvalidDsseSignatureCount,
    InvalidInTotoStatement,
    InvalidSlsaProvenance,
    EvidenceTextUnsafe,
    SigstoreVerificationFailed,
    SignerIdentityMismatch,
    SignerIssuerMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    BlobSignature,
    InTotoStatement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaProvenanceSummary {
    pub predicate_type: String,
    pub structure: String,
    pub builder_id: String,
    pub build_type: String,
    pub expectations: String,
    pub build_level: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationSummary {
    pub kind: AttestationKind,
    pub statement_type: Option<String>,
    pub predicate_type: Option<String>,
    pub slsa_provenance: Option<SlsaProvenanceSummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPolicySummary {
    pub expected_identity: String,
    pub expected_issuer: String,
    pub actual_identity: Option<String>,
    pub actual_issuer: Option<String>,
    pub match_status: EvidenceStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainEvidence {
    pub bundle_format: EvidenceStatus,
    pub artifact_binding: EvidenceStatus,
    pub signature: EvidenceStatus,
    pub certificate_chain_and_sct: EvidenceStatus,
    pub transparency_log_inclusion: EvidenceStatus,
    pub signing_time: EvidenceStatus,
    pub integrated_time_unix: Option<i64>,
    pub verified_rfc3161_timestamps: usize,
    pub verified_transparency_entries: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainEnvironment {
    pub verifier: String,
    pub network: String,
    pub trust_root_source: String,
    pub trust_root_freshness: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainVerificationReport {
    pub schema: String,
    pub artifact: ArtifactDescriptor,
    pub bundle: ArtifactDescriptor,
    pub trusted_root: ArtifactDescriptor,
    pub outcome: SupplyChainOutcome,
    pub failure: Option<FailureCode>,
    pub evidence: SupplyChainEvidence,
    pub signer_policy: SignerPolicySummary,
    pub attestation: Option<AttestationSummary>,
    pub a_quo_persona_link: String,
    pub environment: SupplyChainEnvironment,
    pub not_established: Vec<String>,
}

impl SupplyChainVerificationReport {
    pub fn is_verified(&self) -> bool {
        self.outcome == SupplyChainOutcome::Verified
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerResponse {
    schema: String,
    verifier_version: String,
    result: WorkerResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "evidence", rename_all = "snake_case")]
enum WorkerResult {
    Verified(Box<WorkerEvidence>),
    Invalid(FailureCode),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerEvidence {
    identity: Option<String>,
    issuer: Option<String>,
    integrated_time_unix: Option<i64>,
    rfc3161_timestamp_count: usize,
    transparency_entry_count: usize,
    attestation: AttestationSummary,
}

/// Verify a standardized Sigstore v0.3 bundle against an explicit local trust
/// root and exact certificate identity policy.
#[cfg(target_os = "linux")]
pub fn verify_bundle(
    artifact: impl AsRef<Path>,
    bundle: impl AsRef<Path>,
    trusted_root: impl AsRef<Path>,
    expected_identity: &str,
    expected_issuer: &str,
) -> Result<SupplyChainVerificationReport> {
    validate_policy(expected_identity, "identity")?;
    validate_policy(expected_issuer, "issuer")?;
    linux::verify_bundle(
        artifact.as_ref(),
        bundle.as_ref(),
        trusted_root.as_ref(),
        expected_identity,
        expected_issuer,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn verify_bundle(
    _artifact: impl AsRef<Path>,
    _bundle: impl AsRef<Path>,
    _trusted_root: impl AsRef<Path>,
    expected_identity: &str,
    expected_issuer: &str,
) -> Result<SupplyChainVerificationReport> {
    validate_policy(expected_identity, "identity")?;
    validate_policy(expected_issuer, "issuer")?;
    Err(SupplyChainError::UnsupportedPlatform)
}

/// Run the hidden Linux sandbox launcher.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn run_launcher(
    artifact_sha256: &str,
    artifact_size: u64,
    expected_frame_sha256: &str,
    expected_frame_size: u64,
    expected_identity: &str,
    expected_issuer: &str,
) -> Result<()> {
    linux::run_launcher(
        artifact_sha256,
        artifact_size,
        expected_frame_sha256,
        expected_frame_size,
        expected_identity,
        expected_issuer,
    )
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn run_launcher(
    _artifact_sha256: &str,
    _artifact_size: u64,
    _expected_frame_sha256: &str,
    _expected_frame_size: u64,
    _expected_identity: &str,
    _expected_issuer: &str,
) -> Result<()> {
    Err(SupplyChainError::UnsupportedPlatform)
}

/// Run the hidden parser/crypto worker and write its closed response to stderr.
pub fn run_worker(
    input: impl AsRef<Path>,
    artifact_sha256: &str,
    artifact_size: u64,
    expected_identity: &str,
    expected_issuer: &str,
) -> Result<()> {
    validate_worker_arguments(
        artifact_sha256,
        artifact_size,
        expected_identity,
        expected_issuer,
    )?;
    let input = read_bounded_file(input.as_ref(), MAX_FRAME_BYTES)?;
    let response = inspect_in_worker(&input, artifact_sha256);
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    serde_json::to_writer(&mut lock, &response).map_err(|_| SupplyChainError::WorkerEncoding)?;
    lock.write_all(b"\n")
        .and_then(|()| lock.flush())
        .map_err(|_| SupplyChainError::WorkerOutputIo)
}

fn inspect_in_worker(frame: &[u8], artifact_sha256: &str) -> WorkerResponse {
    let result =
        inspect_in_worker_result(frame, artifact_sha256).unwrap_or_else(WorkerResult::Invalid);
    WorkerResponse {
        schema: WORKER_REPORT_SCHEMA.to_owned(),
        verifier_version: SIGSTORE_VERIFIER_VERSION.to_owned(),
        result,
    }
}

fn inspect_in_worker_result(
    frame: &[u8],
    artifact_sha256: &str,
) -> std::result::Result<WorkerResult, FailureCode> {
    let (bundle_bytes, root_bytes) = split_frame(frame)?;
    require_media_type(
        bundle_bytes,
        SIGSTORE_BUNDLE_MEDIA_TYPE,
        FailureCode::InvalidBundleJson,
        FailureCode::UnsupportedBundleFormat,
    )?;
    require_media_type(
        root_bytes,
        SIGSTORE_TRUSTED_ROOT_MEDIA_TYPE,
        FailureCode::InvalidTrustedRootJson,
        FailureCode::UnsupportedTrustedRootFormat,
    )?;

    let bundle_json =
        std::str::from_utf8(bundle_bytes).map_err(|_| FailureCode::InvalidBundleJson)?;
    let root_json =
        std::str::from_utf8(root_bytes).map_err(|_| FailureCode::InvalidTrustedRootJson)?;
    let bundle = Bundle::from_json(bundle_json).map_err(|_| FailureCode::InvalidBundleJson)?;
    let trusted_root =
        TrustedRoot::from_json(root_json).map_err(|_| FailureCode::InvalidTrustedRootJson)?;

    if bundle.media_type != SIGSTORE_BUNDLE_MEDIA_TYPE {
        return Err(FailureCode::UnsupportedBundleFormat);
    }
    if trusted_root.media_type != SIGSTORE_TRUSTED_ROOT_MEDIA_TYPE {
        return Err(FailureCode::UnsupportedTrustedRootFormat);
    }
    if !matches!(
        bundle.verification_material.content,
        VerificationMaterialContent::Certificate(_)
    ) {
        return Err(FailureCode::UnsupportedVerificationMaterial);
    }
    if bundle.verification_material.tlog_entries.len() > MAX_TLOG_ENTRIES
        || bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .len()
            > MAX_TIMESTAMPS
    {
        return Err(FailureCode::UnsupportedBundleFormat);
    }

    let attestation = inspect_attestation(&bundle)?;
    let artifact_digest = Sha256Hash::from_hex(artifact_sha256)
        .map_err(|_| FailureCode::UnsupportedArtifactDigest)?;
    let verification = verify(
        artifact_digest,
        &bundle,
        &VerificationPolicy::default(),
        &trusted_root,
    )
    .map_err(|_| FailureCode::SigstoreVerificationFailed)?;

    for value in [
        verification.identity.as_deref(),
        verification.issuer.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        require_safe_display(value)?;
    }

    Ok(WorkerResult::Verified(Box::new(WorkerEvidence {
        identity: verification.identity,
        issuer: verification.issuer,
        integrated_time_unix: verification.integrated_time,
        rfc3161_timestamp_count: bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .len(),
        transparency_entry_count: bundle.verification_material.tlog_entries.len(),
        attestation,
    })))
}

fn inspect_attestation(bundle: &Bundle) -> std::result::Result<AttestationSummary, FailureCode> {
    match &bundle.content {
        SignatureContent::MessageSignature(signature) => {
            let Some(digest) = &signature.message_digest else {
                return Err(FailureCode::UnsupportedArtifactDigest);
            };
            if digest.algorithm != HashAlgorithm::Sha2256 {
                return Err(FailureCode::UnsupportedArtifactDigest);
            }
            Ok(AttestationSummary {
                kind: AttestationKind::BlobSignature,
                statement_type: None,
                predicate_type: None,
                slsa_provenance: None,
            })
        }
        SignatureContent::DsseEnvelope(envelope) => {
            if envelope.signatures.len() != 1 {
                return Err(FailureCode::InvalidDsseSignatureCount);
            }
            if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
                return Err(FailureCode::InvalidInTotoStatement);
            }
            let payload = envelope.decode_payload();
            let statement: Statement = serde_json::from_slice(&payload)
                .map_err(|_| FailureCode::InvalidInTotoStatement)?;
            if statement.type_ != IN_TOTO_STATEMENT_TYPE
                || statement.subject.is_empty()
                || statement.subject.len() > MAX_SUBJECTS
            {
                return Err(FailureCode::InvalidInTotoStatement);
            }
            require_safe_display(&statement.predicate_type)?;
            let slsa_provenance = if statement.predicate_type == SLSA_PROVENANCE_TYPE {
                Some(inspect_slsa_provenance(&statement.predicate)?)
            } else {
                None
            };
            Ok(AttestationSummary {
                kind: AttestationKind::InTotoStatement,
                statement_type: Some(IN_TOTO_STATEMENT_TYPE.to_owned()),
                predicate_type: Some(statement.predicate_type),
                slsa_provenance,
            })
        }
    }
}

fn inspect_slsa_provenance(
    predicate: &Value,
) -> std::result::Result<SlsaProvenanceSummary, FailureCode> {
    let predicate = predicate
        .as_object()
        .ok_or(FailureCode::InvalidSlsaProvenance)?;
    let build_definition = required_object(predicate, "buildDefinition")?;
    let run_details = required_object(predicate, "runDetails")?;
    let builder = required_object(run_details, "builder")?;
    let build_type = required_safe_string(build_definition, "buildType")?;
    let builder_id = required_safe_string(builder, "id")?;

    require_object_or_empty(build_definition, "externalParameters")?;
    require_optional_object(build_definition, "internalParameters")?;
    require_optional_array(build_definition, "resolvedDependencies")?;
    require_optional_object(builder, "version")?;
    require_optional_array(builder, "builderDependencies")?;
    require_optional_object(run_details, "metadata")?;
    require_optional_array(run_details, "byproducts")?;

    Ok(SlsaProvenanceSummary {
        predicate_type: SLSA_PROVENANCE_TYPE.to_owned(),
        structure: "required_v1_fields_present".to_owned(),
        builder_id: builder_id.to_owned(),
        build_type: build_type.to_owned(),
        expectations: "not_evaluated".to_owned(),
        build_level: "not_established".to_owned(),
    })
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> std::result::Result<&'a Map<String, Value>, FailureCode> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or(FailureCode::InvalidSlsaProvenance)
}

fn required_safe_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> std::result::Result<&'a str, FailureCode> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(FailureCode::InvalidSlsaProvenance)?;
    require_safe_display(value)?;
    Ok(value)
}

fn require_object_or_empty(
    object: &Map<String, Value>,
    field: &str,
) -> std::result::Result<(), FailureCode> {
    match object.get(field) {
        None | Some(Value::Null) | Some(Value::Object(_)) => Ok(()),
        _ => Err(FailureCode::InvalidSlsaProvenance),
    }
}

fn require_optional_object(
    object: &Map<String, Value>,
    field: &str,
) -> std::result::Result<(), FailureCode> {
    require_object_or_empty(object, field)
}

fn require_optional_array(
    object: &Map<String, Value>,
    field: &str,
) -> std::result::Result<(), FailureCode> {
    match object.get(field) {
        None | Some(Value::Null) | Some(Value::Array(_)) => Ok(()),
        _ => Err(FailureCode::InvalidSlsaProvenance),
    }
}

fn require_media_type(
    json: &[u8],
    expected: &str,
    malformed: FailureCode,
    unsupported: FailureCode,
) -> std::result::Result<(), FailureCode> {
    let value: Value = serde_json::from_slice(json).map_err(|_| malformed)?;
    match value.get("mediaType").and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(unsupported),
    }
}

fn normalize_worker_response(
    artifact: ArtifactDescriptor,
    bundle: ArtifactDescriptor,
    trusted_root: ArtifactDescriptor,
    expected_identity: &str,
    expected_issuer: &str,
    response: WorkerResponse,
) -> Result<SupplyChainVerificationReport> {
    if response.schema != WORKER_REPORT_SCHEMA
        || response.verifier_version != SIGSTORE_VERIFIER_VERSION
    {
        return Err(SupplyChainError::InvalidWorkerReport);
    }

    let (outcome, failure, evidence, actual_identity, actual_issuer, attestation) =
        match response.result {
            WorkerResult::Invalid(failure) => (
                SupplyChainOutcome::Invalid,
                Some(failure),
                unverified_evidence(),
                None,
                None,
                None,
            ),
            WorkerResult::Verified(worker) => {
                validate_worker_evidence(&worker)?;
                let identity_matches = worker.identity.as_deref() == Some(expected_identity);
                let issuer_matches = worker.issuer.as_deref() == Some(expected_issuer);
                let (outcome, failure) = if !identity_matches {
                    (
                        SupplyChainOutcome::Invalid,
                        Some(FailureCode::SignerIdentityMismatch),
                    )
                } else if !issuer_matches {
                    (
                        SupplyChainOutcome::Invalid,
                        Some(FailureCode::SignerIssuerMismatch),
                    )
                } else {
                    (SupplyChainOutcome::Verified, None)
                };
                let evidence = SupplyChainEvidence {
                    bundle_format: EvidenceStatus::Verified,
                    artifact_binding: EvidenceStatus::Verified,
                    signature: EvidenceStatus::Verified,
                    certificate_chain_and_sct: EvidenceStatus::Verified,
                    transparency_log_inclusion: EvidenceStatus::Verified,
                    signing_time: EvidenceStatus::Verified,
                    integrated_time_unix: worker.integrated_time_unix,
                    verified_rfc3161_timestamps: worker.rfc3161_timestamp_count,
                    verified_transparency_entries: worker.transparency_entry_count,
                };
                (
                    outcome,
                    failure,
                    evidence,
                    worker.identity,
                    worker.issuer,
                    Some(worker.attestation),
                )
            }
        };

    let policy_matches = outcome == SupplyChainOutcome::Verified;
    Ok(SupplyChainVerificationReport {
        schema: SUPPLY_CHAIN_REPORT_SCHEMA.to_owned(),
        artifact,
        bundle,
        trusted_root,
        outcome,
        failure,
        evidence,
        signer_policy: SignerPolicySummary {
            expected_identity: expected_identity.to_owned(),
            expected_issuer: expected_issuer.to_owned(),
            actual_identity,
            actual_issuer,
            match_status: if policy_matches {
                EvidenceStatus::Verified
            } else {
                EvidenceStatus::NotVerified
            },
        },
        attestation,
        a_quo_persona_link: "not_established".to_owned(),
        environment: SupplyChainEnvironment {
            verifier: format!("sigstore-rust {SIGSTORE_VERIFIER_VERSION}"),
            network: "blocked_by_linux_namespace".to_owned(),
            trust_root_source: "explicit_local_snapshot".to_owned(),
            trust_root_freshness: "not_established".to_owned(),
        },
        not_established: vec![
            "the freshness or current revocation state of the supplied trust root".to_owned(),
            "a trusted SLSA builder or SLSA Build level".to_owned(),
            "expected source, build type, or external build parameters".to_owned(),
            "reproducibility, code review, or runtime behavior".to_owned(),
            "a link to an A Quo persona or a legal identity".to_owned(),
            "the safety or quality of the artifact".to_owned(),
        ],
    })
}

fn unverified_evidence() -> SupplyChainEvidence {
    SupplyChainEvidence {
        bundle_format: EvidenceStatus::NotVerified,
        artifact_binding: EvidenceStatus::NotVerified,
        signature: EvidenceStatus::NotVerified,
        certificate_chain_and_sct: EvidenceStatus::NotVerified,
        transparency_log_inclusion: EvidenceStatus::NotVerified,
        signing_time: EvidenceStatus::NotVerified,
        integrated_time_unix: None,
        verified_rfc3161_timestamps: 0,
        verified_transparency_entries: 0,
    }
}

fn validate_worker_evidence(evidence: &WorkerEvidence) -> Result<()> {
    if evidence.rfc3161_timestamp_count > MAX_TIMESTAMPS
        || evidence.transparency_entry_count == 0
        || evidence.transparency_entry_count > MAX_TLOG_ENTRIES
    {
        return Err(SupplyChainError::InvalidWorkerReport);
    }
    for value in [evidence.identity.as_deref(), evidence.issuer.as_deref()]
        .into_iter()
        .flatten()
    {
        if require_safe_display(value).is_err() {
            return Err(SupplyChainError::InvalidWorkerReport);
        }
    }
    validate_attestation_summary(&evidence.attestation)
}

fn validate_attestation_summary(attestation: &AttestationSummary) -> Result<()> {
    for value in [
        attestation.statement_type.as_deref(),
        attestation.predicate_type.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if require_safe_display(value).is_err() {
            return Err(SupplyChainError::InvalidWorkerReport);
        }
    }
    if let Some(slsa) = &attestation.slsa_provenance {
        for value in [
            slsa.predicate_type.as_str(),
            slsa.structure.as_str(),
            slsa.builder_id.as_str(),
            slsa.build_type.as_str(),
            slsa.expectations.as_str(),
            slsa.build_level.as_str(),
        ] {
            if require_safe_display(value).is_err() {
                return Err(SupplyChainError::InvalidWorkerReport);
            }
        }
        if attestation.predicate_type.as_deref() != Some(SLSA_PROVENANCE_TYPE)
            || slsa.predicate_type != SLSA_PROVENANCE_TYPE
            || slsa.structure != "required_v1_fields_present"
            || slsa.expectations != "not_evaluated"
            || slsa.build_level != "not_established"
        {
            return Err(SupplyChainError::InvalidWorkerReport);
        }
    }
    match attestation.kind {
        AttestationKind::BlobSignature
            if attestation.statement_type.is_none()
                && attestation.predicate_type.is_none()
                && attestation.slsa_provenance.is_none() =>
        {
            Ok(())
        }
        AttestationKind::InTotoStatement
            if attestation.statement_type.as_deref() == Some(IN_TOTO_STATEMENT_TYPE)
                && attestation.predicate_type.is_some() =>
        {
            Ok(())
        }
        _ => Err(SupplyChainError::InvalidWorkerReport),
    }
}

fn validate_policy(value: &str, field: &'static str) -> Result<()> {
    if value.len() > MAX_POLICY_BYTES || require_safe_display(value).is_err() {
        return Err(SupplyChainError::InvalidPolicy { field });
    }
    Ok(())
}

fn validate_worker_arguments(
    artifact_sha256: &str,
    artifact_size: u64,
    expected_identity: &str,
    expected_issuer: &str,
) -> Result<()> {
    if !valid_sha256(artifact_sha256)
        || artifact_size > a_quo_artifact_limit()
        || validate_policy(expected_identity, "identity").is_err()
        || validate_policy(expected_issuer, "issuer").is_err()
    {
        return Err(SupplyChainError::InvalidLauncherArgument);
    }
    Ok(())
}

fn require_safe_display(value: &str) -> std::result::Result<(), FailureCode> {
    if value.is_empty()
        || value.len() > MAX_DISPLAY_BYTES
        || value.chars().any(is_unsafe_display_character)
    {
        Err(FailureCode::EvidenceTextUnsafe)
    } else {
        Ok(())
    }
}

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn build_frame(bundle: &[u8], trusted_root: &[u8]) -> Result<Vec<u8>> {
    if bundle.is_empty()
        || trusted_root.is_empty()
        || bundle.len() as u64 > MAX_BUNDLE_BYTES
        || trusted_root.len() as u64 > MAX_TRUSTED_ROOT_BYTES
    {
        return Err(SupplyChainError::InvalidInputFrame);
    }
    let bundle_len =
        u32::try_from(bundle.len()).map_err(|_| SupplyChainError::InvalidInputFrame)?;
    let root_len =
        u32::try_from(trusted_root.len()).map_err(|_| SupplyChainError::InvalidInputFrame)?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + bundle.len() + trusted_root.len());
    frame.extend_from_slice(FRAME_MAGIC);
    frame.extend_from_slice(&bundle_len.to_be_bytes());
    frame.extend_from_slice(&root_len.to_be_bytes());
    frame.extend_from_slice(bundle);
    frame.extend_from_slice(trusted_root);
    Ok(frame)
}

fn split_frame(frame: &[u8]) -> std::result::Result<(&[u8], &[u8]), FailureCode> {
    if frame.len() < FRAME_HEADER_BYTES || &frame[..8] != FRAME_MAGIC {
        return Err(FailureCode::InvalidBundleJson);
    }
    let bundle_len = u32::from_be_bytes(
        frame[8..12]
            .try_into()
            .map_err(|_| FailureCode::InvalidBundleJson)?,
    ) as usize;
    let root_len = u32::from_be_bytes(
        frame[12..16]
            .try_into()
            .map_err(|_| FailureCode::InvalidTrustedRootJson)?,
    ) as usize;
    if bundle_len == 0
        || root_len == 0
        || bundle_len as u64 > MAX_BUNDLE_BYTES
        || root_len as u64 > MAX_TRUSTED_ROOT_BYTES
    {
        return Err(FailureCode::InvalidBundleJson);
    }
    let bundle_end = FRAME_HEADER_BYTES
        .checked_add(bundle_len)
        .ok_or(FailureCode::InvalidBundleJson)?;
    let root_end = bundle_end
        .checked_add(root_len)
        .ok_or(FailureCode::InvalidTrustedRootJson)?;
    if root_end != frame.len() {
        return Err(FailureCode::InvalidBundleJson);
    }
    Ok((
        &frame[FRAME_HEADER_BYTES..bundle_end],
        &frame[bundle_end..root_end],
    ))
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(|_| SupplyChainError::WorkerInput)?;
    let metadata = file.metadata().map_err(|_| SupplyChainError::WorkerInput)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(SupplyChainError::WorkerInput);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| SupplyChainError::WorkerInput)?,
    );
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SupplyChainError::WorkerInput)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(SupplyChainError::WorkerInput);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
const fn a_quo_artifact_limit() -> u64 {
    a_quo_ipc::MAX_ARTIFACT_BYTES
}

#[cfg(not(target_os = "linux"))]
const fn a_quo_artifact_limit() -> u64 {
    512 * 1024 * 1024
}

#[cfg(not(target_os = "linux"))]
mod rustix_or_io {
    pub type PlatformIoError = std::io::Error;
}

#[cfg(target_os = "linux")]
mod rustix_or_io {
    pub type PlatformIoError = rustix::io::Errno;
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn descriptor(byte: &str) -> ArtifactDescriptor {
        ArtifactDescriptor {
            digest: a_quo_core::Digest {
                algorithm: "sha256".to_owned(),
                value: byte.repeat(64),
            },
            size: 12,
        }
    }

    #[test]
    fn frame_is_closed_bounded_and_exact() {
        let frame = build_frame(b"bundle", b"root").unwrap();
        assert_eq!(split_frame(&frame).unwrap(), (&b"bundle"[..], &b"root"[..]));

        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(split_frame(&trailing).is_err());

        let mut wrong_magic = frame;
        wrong_magic[0] ^= 1;
        assert!(split_frame(&wrong_magic).is_err());
    }

    #[test]
    fn hostile_policy_and_signed_display_text_are_rejected() {
        assert!(validate_policy("https://issuer.example", "issuer").is_ok());
        assert!(validate_policy("issuer\nforged", "issuer").is_err());
        assert!(require_safe_display("builder\u{202e}fake").is_err());
    }

    #[test]
    fn slsa_summary_does_not_claim_a_level_or_expectations() {
        let predicate = serde_json::json!({
            "buildDefinition": {
                "buildType": "https://example.test/build/v1",
                "externalParameters": {"source": "example"}
            },
            "runDetails": {
                "builder": {"id": "https://builder.example.test/v1"}
            }
        });
        let summary = inspect_slsa_provenance(&predicate).unwrap();
        assert_eq!(summary.expectations, "not_evaluated");
        assert_eq!(summary.build_level, "not_established");

        let hostile = serde_json::json!({
            "buildDefinition": {
                "buildType": "https://example.test/build/v1",
                "externalParameters": []
            },
            "runDetails": {
                "builder": {"id": "https://builder.example.test/v1"}
            }
        });
        assert!(inspect_slsa_provenance(&hostile).is_err());
    }

    #[test]
    fn identity_mismatch_never_becomes_verified() {
        let report = normalize_worker_response(
            descriptor("a"),
            descriptor("b"),
            descriptor("c"),
            "expected@example.test",
            "https://issuer.example.test",
            WorkerResponse {
                schema: WORKER_REPORT_SCHEMA.to_owned(),
                verifier_version: SIGSTORE_VERIFIER_VERSION.to_owned(),
                result: WorkerResult::Verified(Box::new(WorkerEvidence {
                    identity: Some("other@example.test".to_owned()),
                    issuer: Some("https://issuer.example.test".to_owned()),
                    integrated_time_unix: Some(1_700_000_000),
                    rfc3161_timestamp_count: 0,
                    transparency_entry_count: 1,
                    attestation: AttestationSummary {
                        kind: AttestationKind::BlobSignature,
                        statement_type: None,
                        predicate_type: None,
                        slsa_provenance: None,
                    },
                })),
            },
        )
        .unwrap();
        assert_eq!(report.outcome, SupplyChainOutcome::Invalid);
        assert_eq!(report.failure, Some(FailureCode::SignerIdentityMismatch));
        assert_eq!(report.evidence.signature, EvidenceStatus::Verified);
        assert_eq!(
            report.signer_policy.match_status,
            EvidenceStatus::NotVerified
        );
    }

    #[test]
    fn hostile_verified_worker_evidence_is_not_rendered() {
        let response = WorkerResponse {
            schema: WORKER_REPORT_SCHEMA.to_owned(),
            verifier_version: SIGSTORE_VERIFIER_VERSION.to_owned(),
            result: WorkerResult::Verified(Box::new(WorkerEvidence {
                identity: Some("trusted@example.test\nFORGED".to_owned()),
                issuer: Some("https://issuer.example.test".to_owned()),
                integrated_time_unix: None,
                rfc3161_timestamp_count: 1,
                transparency_entry_count: 1,
                attestation: AttestationSummary {
                    kind: AttestationKind::BlobSignature,
                    statement_type: None,
                    predicate_type: None,
                    slsa_provenance: None,
                },
            })),
        };
        assert!(matches!(
            normalize_worker_response(
                descriptor("a"),
                descriptor("b"),
                descriptor("c"),
                "trusted@example.test",
                "https://issuer.example.test",
                response,
            ),
            Err(SupplyChainError::InvalidWorkerReport)
        ));
    }

    #[test]
    fn published_v03_slsa_fixture_verifies_without_network_or_artifact_bytes() {
        let Some(bundle_path) =
            published_crate_file("sigstore-bundle-0.11.0", "tests/fixtures/happy-path.json")
        else {
            return;
        };
        let Some(root_path) = published_crate_file(
            "sigstore-verify-0.11.0",
            "test_data/trusted_roots/public-good.json",
        ) else {
            return;
        };
        let bundle = fs::read(bundle_path).unwrap();
        let root = fs::read(root_path).unwrap();
        let frame = build_frame(&bundle, &root).unwrap();
        let response = inspect_in_worker(
            &frame,
            "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf",
        );

        let WorkerResult::Verified(evidence) = response.result else {
            panic!("published SLSA fixture did not verify: {response:?}");
        };
        assert_eq!(
            evidence.identity.as_deref(),
            Some(
                "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
            )
        );
        assert_eq!(
            evidence.issuer.as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
        let slsa = evidence.attestation.slsa_provenance.unwrap();
        assert_eq!(slsa.predicate_type, SLSA_PROVENANCE_TYPE);
        assert_eq!(slsa.expectations, "not_evaluated");
        assert_eq!(slsa.build_level, "not_established");
    }

    fn published_crate_file(crate_directory: &str, relative: &str) -> Option<PathBuf> {
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))?;
        for registry in fs::read_dir(cargo_home.join("registry/src"))
            .ok()?
            .flatten()
        {
            let candidate = registry.path().join(crate_directory).join(relative);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}
