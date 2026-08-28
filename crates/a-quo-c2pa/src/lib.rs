//! Isolated, offline-by-default C2PA media verification for A Quo.
//!
//! The C2PA parser runs only in a re-executed CLI worker. On Linux the parent
//! starts that worker inside a network-less Bubblewrap namespace with an
//! immutable media snapshot and fixed resource limits. This crate deliberately
//! does not provide C2PA signing or claim certificate trust without an explicit
//! trust policy.

use std::io::Write;
use std::path::Path;

use a_quo_core::ArtifactDescriptor;
use c2pa::{Context, Reader, Settings, ValidationState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(target_os = "linux")]
mod linux;

pub const MEDIA_REPORT_SCHEMA: &str = "urn:a-quo:report:c2pa:v1";
const WORKER_REPORT_SCHEMA: &str = "urn:a-quo:internal:c2pa-worker:v1";
pub const C2PA_SDK_VERSION: &str = "0.90.16";
pub const MAX_MEDIA_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DISPLAY_BYTES: usize = 256;
const MAX_FAILURE_CODE_BYTES: usize = 128;
const MAX_FAILURE_CODES: usize = 32;

#[derive(Debug, Error)]
pub enum MediaError {
    #[error("C2PA media verification is currently available only on Linux")]
    UnsupportedPlatform,

    #[error("cannot safely open media asset {path}: {source}")]
    OpenAsset {
        path: std::path::PathBuf,
        #[source]
        source: rustix_or_io::PlatformIoError,
    },

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Snapshot(#[from] a_quo_ipc::LinuxIpcError),

    #[error("trusted C2PA sandbox executable is unavailable or unsafe: {0}")]
    UnsafeSandboxExecutable(std::path::PathBuf),

    #[error("cannot inspect the running A Quo executable: {0}")]
    CurrentExecutable(#[source] std::io::Error),

    #[error("invalid internal C2PA launcher argument")]
    InvalidLauncherArgument,

    #[error("C2PA launcher received bytes that did not match the parent's sealed snapshot")]
    LauncherInputMismatch,

    #[error("cannot start the isolated C2PA worker: {0}")]
    WorkerUnavailable(#[source] std::io::Error),

    #[error("isolated C2PA launcher input could not be transferred")]
    WorkerInputIo,

    #[error("isolated C2PA verification exceeded its 45-second deadline")]
    WorkerTimedOut,

    #[error("isolated C2PA verification exceeded its bounded output limit")]
    WorkerOutputTooLarge,

    #[error("isolated C2PA verification output could not be read")]
    WorkerOutputIo,

    #[error("isolated C2PA worker failed ({0}); details were suppressed")]
    WorkerFailed(String),

    #[error("isolated C2PA worker returned malformed or incompatible evidence")]
    InvalidWorkerReport,

    #[error("C2PA worker could not initialize its fixed offline policy")]
    WorkerPolicy,

    #[error("C2PA worker could not encode its bounded response")]
    WorkerEncoding,
}

pub type Result<T> = std::result::Result<T, MediaError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaOutcome {
    Valid,
    Invalid,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSignatureStatus {
    ValidatedAsPartOfManifest,
    PresentButManifestInvalid,
    NotAvailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CawgIdentityStatus {
    Absent,
    PresentUnassessed,
    NotAvailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSignatureSummary {
    pub status: ClaimSignatureStatus,
    pub algorithm: Option<String>,
    pub certificate_issuer: Option<String>,
    pub certificate_common_name: Option<String>,
    pub signed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEnvironment {
    pub sdk: String,
    pub network: String,
    pub remote_manifests: String,
    pub sidecar_manifests: String,
    pub certificate_trust: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MediaVerificationReport {
    pub schema: String,
    pub artifact: ArtifactDescriptor,
    pub outcome: MediaOutcome,
    pub claim_signature: ClaimSignatureSummary,
    pub claim_generator: Option<String>,
    pub cawg_identity: CawgIdentityStatus,
    pub a_quo_persona_link: String,
    pub validation_failures: Vec<String>,
    pub environment: VerificationEnvironment,
    pub not_established: Vec<String>,
}

impl MediaVerificationReport {
    pub fn is_valid(&self) -> bool {
        self.outcome == MediaOutcome::Valid
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerResponse {
    schema: String,
    sdk_version: String,
    result: WorkerResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "evidence", rename_all = "snake_case")]
enum WorkerResult {
    Read(WorkerEvidence),
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerEvidence {
    validation_state: WorkerValidationState,
    claim_signature: Option<WorkerSignature>,
    claim_generator: Option<String>,
    cawg_identity_present: bool,
    validation_failures: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkerValidationState {
    Invalid,
    Valid,
    Trusted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerSignature {
    algorithm: Option<String>,
    certificate_issuer: Option<String>,
    certificate_common_name: Option<String>,
    signed_at: Option<String>,
}

/// Verify a media file through the platform's isolated C2PA worker.
///
/// Linux hashes and seals the input before launching the worker. No sidecar is
/// inferred from the original pathname and no remote manifest is fetched.
#[cfg(target_os = "linux")]
pub fn verify_media(path: impl AsRef<Path>) -> Result<MediaVerificationReport> {
    linux::verify_media(path.as_ref())
}

#[cfg(not(target_os = "linux"))]
pub fn verify_media(_path: impl AsRef<Path>) -> Result<MediaVerificationReport> {
    Err(MediaError::UnsupportedPlatform)
}

/// Run the internal Linux sandbox launcher.
///
/// This is public only so the A Quo CLI's hidden launcher command can call it.
/// Ordinary callers should use [`verify_media`].
#[cfg(target_os = "linux")]
pub fn run_launcher(expected_sha256: &str, expected_size: u64, extension: &str) -> Result<()> {
    linux::run_launcher(expected_sha256, expected_size, extension)
}

#[cfg(not(target_os = "linux"))]
pub fn run_launcher(_expected_sha256: &str, _expected_size: u64, _extension: &str) -> Result<()> {
    Err(MediaError::UnsupportedPlatform)
}

/// Run the internal parser worker and write its closed response to stderr.
///
/// This is public only so the A Quo CLI's hidden worker command can call it.
/// Ordinary callers should use [`verify_media`].
pub fn run_worker(asset: impl AsRef<Path>) -> Result<()> {
    let response = inspect_in_worker(asset.as_ref())?;
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    serde_json::to_writer(&mut lock, &response).map_err(|_| MediaError::WorkerEncoding)?;
    lock.write_all(b"\n")
        .and_then(|()| lock.flush())
        .map_err(|_| MediaError::WorkerOutputIo)
}

fn inspect_in_worker(asset: &Path) -> Result<WorkerResponse> {
    let settings = Settings::new()
        .with_json(
            r#"{
                "verify": {
                    "verify_after_reading": true,
                    "verify_trust": false,
                    "verify_timestamp_trust": false,
                    "ocsp_fetch": false,
                    "remote_manifest_fetch": false
                },
                "core": {
                    "decode_identity_assertions": false,
                    "allowed_network_hosts": [],
                    "backing_store_memory_threshold_in_mb": 64,
                    "max_decompressed_manifest_size_in_mb": 32
                },
                "cawg_trust": {
                    "verify_trust_list": false
                }
            }"#,
        )
        .map_err(|_| MediaError::WorkerPolicy)?;
    let context = Context::new()
        .with_settings(settings)
        .map_err(|_| MediaError::WorkerPolicy)?;
    let reader = match Reader::from_context(context).with_file(asset) {
        Ok(reader) => reader,
        Err(_) => return Ok(worker_response(WorkerResult::Unavailable)),
    };

    let active = reader.active_manifest();
    let claim_signature = active
        .and_then(|manifest| manifest.signature_info())
        .map(|signature| WorkerSignature {
            algorithm: signature
                .alg
                .as_ref()
                .and_then(|algorithm| bounded_display(&algorithm.to_string())),
            certificate_issuer: signature.issuer.as_deref().and_then(bounded_display),
            certificate_common_name: signature.common_name.as_deref().and_then(bounded_display),
            signed_at: signature.time.as_deref().and_then(bounded_display),
        });
    let claim_generator = active
        .and_then(|manifest| manifest.claim_generator())
        .and_then(bounded_display);
    let cawg_identity_present = active.is_some_and(|manifest| {
        manifest
            .assertions()
            .iter()
            .any(|assertion| assertion.label() == "cawg.identity")
    });
    let mut validation_failures = reader
        .validation_status()
        .unwrap_or_default()
        .iter()
        .filter_map(|status| bounded_failure_code(status.code()))
        .take(MAX_FAILURE_CODES)
        .collect::<Vec<_>>();
    validation_failures.sort();
    validation_failures.dedup();

    let validation_state = match reader.validation_state() {
        ValidationState::Invalid => WorkerValidationState::Invalid,
        ValidationState::Valid => WorkerValidationState::Valid,
        ValidationState::Trusted => WorkerValidationState::Trusted,
    };
    Ok(worker_response(WorkerResult::Read(WorkerEvidence {
        validation_state,
        claim_signature,
        claim_generator,
        cawg_identity_present,
        validation_failures,
    })))
}

fn worker_response(result: WorkerResult) -> WorkerResponse {
    WorkerResponse {
        schema: WORKER_REPORT_SCHEMA.to_owned(),
        sdk_version: C2PA_SDK_VERSION.to_owned(),
        result,
    }
}

fn normalize_worker_response(
    artifact: ArtifactDescriptor,
    response: WorkerResponse,
) -> Result<MediaVerificationReport> {
    if response.schema != WORKER_REPORT_SCHEMA || response.sdk_version != C2PA_SDK_VERSION {
        return Err(MediaError::InvalidWorkerReport);
    }

    let (outcome, signature, claim_generator, cawg_identity, validation_failures) =
        match response.result {
            WorkerResult::Unavailable => (
                MediaOutcome::Unavailable,
                ClaimSignatureSummary {
                    status: ClaimSignatureStatus::NotAvailable,
                    algorithm: None,
                    certificate_issuer: None,
                    certificate_common_name: None,
                    signed_at: None,
                },
                None,
                CawgIdentityStatus::NotAvailable,
                Vec::new(),
            ),
            WorkerResult::Read(evidence) => {
                validate_worker_evidence(&evidence)?;
                if evidence.validation_state == WorkerValidationState::Trusted {
                    return Err(MediaError::InvalidWorkerReport);
                }
                let outcome = match evidence.validation_state {
                    WorkerValidationState::Invalid => MediaOutcome::Invalid,
                    WorkerValidationState::Valid => MediaOutcome::Valid,
                    WorkerValidationState::Trusted => unreachable!("handled above"),
                };
                let signature = match evidence.claim_signature {
                    Some(signature) => ClaimSignatureSummary {
                        status: if outcome == MediaOutcome::Valid {
                            ClaimSignatureStatus::ValidatedAsPartOfManifest
                        } else {
                            ClaimSignatureStatus::PresentButManifestInvalid
                        },
                        algorithm: signature.algorithm,
                        certificate_issuer: signature.certificate_issuer,
                        certificate_common_name: signature.certificate_common_name,
                        signed_at: signature.signed_at,
                    },
                    None if outcome == MediaOutcome::Invalid => ClaimSignatureSummary {
                        status: ClaimSignatureStatus::NotAvailable,
                        algorithm: None,
                        certificate_issuer: None,
                        certificate_common_name: None,
                        signed_at: None,
                    },
                    None => return Err(MediaError::InvalidWorkerReport),
                };
                let cawg = if evidence.cawg_identity_present {
                    CawgIdentityStatus::PresentUnassessed
                } else {
                    CawgIdentityStatus::Absent
                };
                (
                    outcome,
                    signature,
                    evidence.claim_generator,
                    cawg,
                    evidence.validation_failures,
                )
            }
        };

    Ok(MediaVerificationReport {
        schema: MEDIA_REPORT_SCHEMA.to_owned(),
        artifact,
        outcome,
        claim_signature: signature,
        claim_generator,
        cawg_identity,
        a_quo_persona_link: "not_established".to_owned(),
        validation_failures,
        environment: VerificationEnvironment {
            sdk: format!("c2pa-rs {C2PA_SDK_VERSION}"),
            network: "blocked_by_linux_namespace".to_owned(),
            remote_manifests: "not_fetched".to_owned(),
            sidecar_manifests: "not_loaded".to_owned(),
            certificate_trust: "not_checked".to_owned(),
        },
        not_established: vec![
            "certificate trust or current revocation status".to_owned(),
            "the legal identity of a creator or publisher".to_owned(),
            "a link to an A Quo persona".to_owned(),
            "the truth, originality, safety, or quality of the media".to_owned(),
        ],
    })
}

fn validate_worker_evidence(evidence: &WorkerEvidence) -> Result<()> {
    if evidence.validation_failures.len() > MAX_FAILURE_CODES
        || evidence
            .validation_failures
            .iter()
            .any(|code| bounded_failure_code(code).as_deref() != Some(code.as_str()))
        || evidence
            .claim_generator
            .as_deref()
            .is_some_and(|value| bounded_display(value).as_deref() != Some(value))
    {
        return Err(MediaError::InvalidWorkerReport);
    }
    if let Some(signature) = &evidence.claim_signature {
        for value in [
            signature.algorithm.as_deref(),
            signature.certificate_issuer.as_deref(),
            signature.certificate_common_name.as_deref(),
            signature.signed_at.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if bounded_display(value).as_deref() != Some(value) {
                return Err(MediaError::InvalidWorkerReport);
            }
        }
    }
    Ok(())
}

fn bounded_display(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_DISPLAY_BYTES
        || value.chars().any(is_unsafe_display_character)
    {
        None
    } else {
        Some(value.to_owned())
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

fn bounded_failure_code(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_FAILURE_CODE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        None
    } else {
        Some(value.to_owned())
    }
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
    use super::*;

    fn artifact() -> ArtifactDescriptor {
        ArtifactDescriptor {
            digest: a_quo_core::Digest {
                algorithm: "sha256".to_owned(),
                value: "00".repeat(32),
            },
            size: 12,
        }
    }

    #[test]
    fn valid_integrity_never_becomes_identity_or_trust() {
        let report = normalize_worker_response(
            artifact(),
            worker_response(WorkerResult::Read(WorkerEvidence {
                validation_state: WorkerValidationState::Valid,
                claim_signature: Some(WorkerSignature {
                    algorithm: Some("es256".to_owned()),
                    certificate_issuer: Some("Example CA".to_owned()),
                    certificate_common_name: Some("Example Generator".to_owned()),
                    signed_at: None,
                }),
                claim_generator: Some("Example editor/1.0".to_owned()),
                cawg_identity_present: true,
                validation_failures: Vec::new(),
            })),
        )
        .unwrap();

        assert_eq!(report.outcome, MediaOutcome::Valid);
        assert_eq!(
            report.claim_signature.status,
            ClaimSignatureStatus::ValidatedAsPartOfManifest
        );
        assert_eq!(report.cawg_identity, CawgIdentityStatus::PresentUnassessed);
        assert_eq!(report.environment.certificate_trust, "not_checked");
        assert_eq!(report.a_quo_persona_link, "not_established");
    }

    #[test]
    fn trusted_worker_state_is_rejected_without_a_trust_policy() {
        let result = normalize_worker_response(
            artifact(),
            worker_response(WorkerResult::Read(WorkerEvidence {
                validation_state: WorkerValidationState::Trusted,
                claim_signature: None,
                claim_generator: None,
                cawg_identity_present: false,
                validation_failures: Vec::new(),
            })),
        );

        assert!(matches!(result, Err(MediaError::InvalidWorkerReport)));
    }

    #[test]
    fn hostile_worker_strings_are_rejected() {
        let result = normalize_worker_response(
            artifact(),
            worker_response(WorkerResult::Read(WorkerEvidence {
                validation_state: WorkerValidationState::Invalid,
                claim_signature: None,
                claim_generator: Some("bad\nterminal text".to_owned()),
                cawg_identity_present: false,
                validation_failures: vec!["claimSignature.mismatch".to_owned()],
            })),
        );

        assert!(matches!(result, Err(MediaError::InvalidWorkerReport)));

        assert!(bounded_display("Example\u{202e}CA").is_none());
    }

    #[test]
    fn unavailable_report_preserves_only_local_artifact_evidence() {
        let report =
            normalize_worker_response(artifact(), worker_response(WorkerResult::Unavailable))
                .unwrap();

        assert_eq!(report.outcome, MediaOutcome::Unavailable);
        assert_eq!(
            report.claim_signature.status,
            ClaimSignatureStatus::NotAvailable
        );
        assert_eq!(report.cawg_identity, CawgIdentityStatus::NotAvailable);
        assert_eq!(report.artifact.size, 12);
    }
}
