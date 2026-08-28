//! Portable artifact proofs for A Quo.
//!
//! A successful verification establishes integrity and control of a signing
//! key. It does not establish software safety or legal identity.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::tempdir;
use thiserror::Error;

pub const PROOF_SCHEMA: &str = "urn:a-quo:proof:sshsig:v1";
pub const STATEMENT_SCHEMA: &str = "urn:a-quo:statement:artifact:v1";
pub const SSHSIG_NAMESPACE: &str = "a-quo-artifact-v1";
pub const SIGNER_TIMEOUT_SECONDS: u64 = 120;

pub const MAX_PROOF_BYTES: u64 = 1_048_576;
const MAX_PUBLIC_KEY_BYTES: usize = 16_384;
const MAX_PERSONA_BYTES: usize = 256;
#[cfg(unix)]
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
#[cfg(not(unix))]
const SSH_KEYGEN: &str = "ssh-keygen";

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("cannot access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid proof JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported {field}: {value}")]
    Unsupported { field: &'static str, value: String },

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid persona: {0}")]
    InvalidPersona(String),

    #[error("invalid proof encoding: {0}")]
    InvalidEncoding(String),

    #[error("artifact digest or size does not match the signed statement")]
    ArtifactMismatch,

    #[error("public key fingerprint does not match the signed statement")]
    FingerprintMismatch,

    #[error("ssh-keygen could not be started: {0}")]
    SignerUnavailable(#[source] std::io::Error),

    #[error("trusted ssh-keygen executable is unavailable or unsafe: {0}")]
    UnsafeSigner(PathBuf),

    #[error("ssh-keygen {operation} failed with exit status {status}")]
    SignerFailed {
        operation: &'static str,
        status: String,
    },

    #[error("ssh-keygen {operation} exceeded the {SIGNER_TIMEOUT_SECONDS}-second deadline")]
    SignerTimedOut { operation: &'static str },

    #[error("ssh-keygen returned a non-UTF-8 signature")]
    NonUtf8Signature,

    #[error("proof is too large (maximum {MAX_PROOF_BYTES} bytes)")]
    ProofTooLarge,

    #[error("refusing to overwrite existing proof: {0}")]
    ProofAlreadyExists(PathBuf),
}

pub type Result<T> = std::result::Result<T, ProofError>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Digest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactDescriptor {
    pub digest: Digest,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerClaim {
    pub persona: String,
    pub key_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactStatement {
    pub schema: String,
    pub artifact: ArtifactDescriptor,
    pub signer: SignerClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureEnvelope {
    pub format: String,
    pub namespace: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationMaterial {
    pub format: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofBundle {
    pub schema: String,
    pub payload: String,
    pub signature: SignatureEnvelope,
    pub verification_material: VerificationMaterial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationReport {
    pub artifact_integrity: EvidenceStatus,
    pub signature: EvidenceStatus,
    pub signer: VerifiedSigner,
    pub not_established: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Verified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedSigner {
    pub persona: String,
    pub key_fingerprint: String,
    pub identity_binding: String,
}

/// Hash an artifact without loading it all into memory.
pub fn describe_artifact(path: impl AsRef<Path>) -> Result<ArtifactDescriptor> {
    let path = path.as_ref();
    let mut file = File::open(path).map_err(|source| ProofError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    describe_reader(&mut file, path)
}

fn describe_reader(reader: &mut impl Read, source_path: &Path) -> Result<ArtifactDescriptor> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let read = reader.read(&mut buffer).map_err(|source| ProofError::Io {
            path: source_path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(read as u64)
            .ok_or(ProofError::ArtifactMismatch)?;
    }

    Ok(ArtifactDescriptor {
        digest: Digest {
            algorithm: "sha256".to_owned(),
            value: format!("{:x}", hasher.finalize()),
        },
        size,
    })
}

/// Create an SSHSIG proof over an embedded artifact statement.
pub fn create_sshsig_proof(
    artifact_path: impl AsRef<Path>,
    private_key_path: impl AsRef<Path>,
    public_key_path: impl AsRef<Path>,
    persona: &str,
) -> Result<ProofBundle> {
    let artifact = describe_artifact(artifact_path)?;
    let public_key = read_public_key(public_key_path.as_ref())?;
    create_sshsig_proof_for_descriptor(artifact, private_key_path, &public_key, persona)
}

/// Create an SSHSIG proof for an already-computed immutable artifact descriptor.
///
/// The resulting signature is verified against `public_key` before it is
/// returned. This makes a stale or incorrect signing-key reference fail closed.
pub fn create_sshsig_proof_for_descriptor(
    artifact: ArtifactDescriptor,
    private_key_path: impl AsRef<Path>,
    public_key: &str,
    persona: &str,
) -> Result<ProofBundle> {
    let persona = validate_persona(persona)?;
    validate_artifact_descriptor(&artifact)?;
    let public_key = normalize_public_key(public_key)?;
    let key_fingerprint = public_key_fingerprint(&public_key)?;

    let statement = ArtifactStatement {
        schema: STATEMENT_SCHEMA.to_owned(),
        artifact,
        signer: SignerClaim {
            persona,
            key_fingerprint,
        },
    };
    let payload = serde_json::to_vec(&statement)?;
    let signature = sshsig_sign(&payload, private_key_path.as_ref())?;
    sshsig_verify(&payload, &signature, &public_key)?;

    Ok(ProofBundle {
        schema: PROOF_SCHEMA.to_owned(),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signature: SignatureEnvelope {
            format: "sshsig".to_owned(),
            namespace: SSHSIG_NAMESPACE.to_owned(),
            value: signature,
        },
        verification_material: VerificationMaterial {
            format: "openssh-public-key".to_owned(),
            public_key,
        },
    })
}

/// Verify an artifact against a portable proof bundle.
pub fn verify_sshsig_proof(
    artifact_path: impl AsRef<Path>,
    proof: &ProofBundle,
) -> Result<VerificationReport> {
    let descriptor = describe_artifact(artifact_path)?;
    verify_sshsig_proof_for_descriptor(&descriptor, proof)
}

/// Verify a portable proof against an already-computed artifact descriptor.
pub fn verify_sshsig_proof_for_descriptor(
    descriptor: &ArtifactDescriptor,
    proof: &ProofBundle,
) -> Result<VerificationReport> {
    validate_envelope(proof)?;
    let payload = decode_payload(&proof.payload)?;
    let statement: ArtifactStatement = serde_json::from_slice(&payload)?;
    validate_statement(&statement)?;

    validate_artifact_descriptor(descriptor)?;
    if descriptor != &statement.artifact {
        return Err(ProofError::ArtifactMismatch);
    }

    let public_key = normalize_public_key(&proof.verification_material.public_key)?;
    if public_key_fingerprint(&public_key)? != statement.signer.key_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }

    sshsig_verify(&payload, &proof.signature.value, &public_key)?;

    Ok(VerificationReport {
        artifact_integrity: EvidenceStatus::Verified,
        signature: EvidenceStatus::Verified,
        signer: VerifiedSigner {
            persona: statement.signer.persona,
            key_fingerprint: statement.signer.key_fingerprint,
            identity_binding: "self_asserted".to_owned(),
        },
        not_established: vec![
            "legal_identity".to_owned(),
            "current_authorization".to_owned(),
            "non_revocation".to_owned(),
            "trusted_timestamp".to_owned(),
            "build_provenance".to_owned(),
            "independent_review".to_owned(),
            "runtime_safety".to_owned(),
        ],
    })
}

/// Decode and validate the signed statement without asserting artifact integrity.
pub fn inspect_proof(proof: &ProofBundle) -> Result<ArtifactStatement> {
    validate_envelope(proof)?;
    let payload = decode_payload(&proof.payload)?;
    let statement = serde_json::from_slice(&payload)?;
    validate_statement(&statement)?;
    Ok(statement)
}

pub fn load_proof(path: impl AsRef<Path>) -> Result<ProofBundle> {
    let path = path.as_ref();
    let metadata = fs::metadata(path).map_err(|source| ProofError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > MAX_PROOF_BYTES {
        return Err(ProofError::ProofTooLarge);
    }
    let bytes = fs::read(path).map_err(|source| ProofError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_proof_new(path: impl AsRef<Path>, proof: &ProofBundle) -> Result<()> {
    let path = path.as_ref();
    let bytes = serde_json::to_vec_pretty(proof)?;
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ProofError::ProofAlreadyExists(path.to_path_buf()));
        }
        Err(source) => {
            return Err(ProofError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    file.write_all(&bytes).map_err(|source| ProofError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(b"\n").map_err(|source| ProofError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

pub fn default_proof_path(artifact_path: impl AsRef<Path>) -> PathBuf {
    let artifact_path = artifact_path.as_ref();
    let mut output = artifact_path.as_os_str().to_os_string();
    output.push(".a-quo-proof.json");
    PathBuf::from(output)
}

pub fn public_key_fingerprint(public_key: &str) -> Result<String> {
    let normalized = normalize_public_key(public_key)?;
    let mut fields = normalized.split_whitespace();
    let _algorithm = fields
        .next()
        .ok_or_else(|| ProofError::InvalidPublicKey("missing algorithm".to_owned()))?;
    let encoded = fields
        .next()
        .ok_or_else(|| ProofError::InvalidPublicKey("missing key data".to_owned()))?;
    let key_blob = STANDARD
        .decode(encoded)
        .map_err(|error| ProofError::InvalidPublicKey(error.to_string()))?;
    let digest = Sha256::digest(key_blob);
    Ok(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)))
}

fn validate_envelope(proof: &ProofBundle) -> Result<()> {
    require_value("proof schema", &proof.schema, PROOF_SCHEMA)?;
    require_value("signature format", &proof.signature.format, "sshsig")?;
    require_value(
        "signature namespace",
        &proof.signature.namespace,
        SSHSIG_NAMESPACE,
    )?;
    require_value(
        "verification material format",
        &proof.verification_material.format,
        "openssh-public-key",
    )?;
    Ok(())
}

fn decode_payload(payload: &str) -> Result<Vec<u8>> {
    if payload.len() as u64 > MAX_PROOF_BYTES {
        return Err(ProofError::ProofTooLarge);
    }
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| ProofError::InvalidEncoding(error.to_string()))
}

fn validate_statement(statement: &ArtifactStatement) -> Result<()> {
    require_value("statement schema", &statement.schema, STATEMENT_SCHEMA)?;
    validate_artifact_descriptor(&statement.artifact)?;
    validate_persona(&statement.signer.persona)?;
    Ok(())
}

fn validate_artifact_descriptor(descriptor: &ArtifactDescriptor) -> Result<()> {
    require_value("digest algorithm", &descriptor.digest.algorithm, "sha256")?;
    if descriptor.digest.value.len() != 64
        || !descriptor
            .digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProofError::InvalidEncoding(
            "SHA-256 digest must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }
    Ok(())
}

fn require_value(field: &'static str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProofError::Unsupported {
            field,
            value: actual.to_owned(),
        })
    }
}

fn validate_persona(persona: &str) -> Result<String> {
    let persona = persona.trim();
    if persona.is_empty() {
        return Err(ProofError::InvalidPersona("it cannot be empty".to_owned()));
    }
    if persona.len() > MAX_PERSONA_BYTES {
        return Err(ProofError::InvalidPersona(format!(
            "it cannot exceed {MAX_PERSONA_BYTES} UTF-8 bytes"
        )));
    }
    if persona.chars().any(is_unsafe_display_character) {
        return Err(ProofError::InvalidPersona(
            "control and bidirectional formatting characters are not allowed".to_owned(),
        ));
    }
    Ok(persona.to_owned())
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

fn read_public_key(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path).map_err(|source| ProofError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() as usize > MAX_PUBLIC_KEY_BYTES {
        return Err(ProofError::InvalidPublicKey(format!(
            "file exceeds {MAX_PUBLIC_KEY_BYTES} bytes"
        )));
    }
    let key = fs::read_to_string(path).map_err(|source| ProofError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    normalize_public_key(&key)
}

fn normalize_public_key(public_key: &str) -> Result<String> {
    if public_key.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(ProofError::InvalidPublicKey(format!(
            "key exceeds {MAX_PUBLIC_KEY_BYTES} bytes"
        )));
    }

    let mut fields = public_key.split_whitespace();
    let algorithm = fields
        .next()
        .ok_or_else(|| ProofError::InvalidPublicKey("missing algorithm".to_owned()))?;
    let encoded = fields
        .next()
        .ok_or_else(|| ProofError::InvalidPublicKey("missing key data".to_owned()))?;
    let blob = STANDARD
        .decode(encoded)
        .map_err(|error| ProofError::InvalidPublicKey(error.to_string()))?;

    if blob.len() < 4 {
        return Err(ProofError::InvalidPublicKey(
            "truncated OpenSSH key blob".to_owned(),
        ));
    }
    let algorithm_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let algorithm_end = 4_usize
        .checked_add(algorithm_len)
        .ok_or_else(|| ProofError::InvalidPublicKey("invalid algorithm length".to_owned()))?;
    let encoded_algorithm = blob
        .get(4..algorithm_end)
        .ok_or_else(|| ProofError::InvalidPublicKey("truncated algorithm name".to_owned()))?;
    if encoded_algorithm != algorithm.as_bytes() {
        return Err(ProofError::InvalidPublicKey(
            "algorithm label does not match the key blob".to_owned(),
        ));
    }

    Ok(format!("{algorithm} {encoded}"))
}

fn sshsig_sign(payload: &[u8], private_key_path: &Path) -> Result<String> {
    let mut command = ssh_keygen_command()?;
    let mut child = command
        .args(["-Y", "sign", "-f"])
        .arg(private_key_path)
        .args(["-n", SSHSIG_NAMESPACE, "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(ProofError::SignerUnavailable)?;

    let mut stdin = child.stdin.take().ok_or_else(|| {
        ProofError::SignerUnavailable(std::io::Error::other(
            "ssh-keygen signing stdin was unavailable",
        ))
    })?;
    stdin
        .write_all(payload)
        .map_err(ProofError::SignerUnavailable)?;
    drop(stdin);
    let output = wait_with_output_deadline(child, "signing")?;
    if !output.status.success() {
        return Err(ProofError::SignerFailed {
            operation: "signing",
            status: output.status.to_string(),
        });
    }
    String::from_utf8(output.stdout).map_err(|_| ProofError::NonUtf8Signature)
}

fn sshsig_verify(payload: &[u8], signature: &str, public_key: &str) -> Result<()> {
    let directory = tempdir().map_err(ProofError::SignerUnavailable)?;
    let allowed_signers = directory.path().join("allowed_signers");
    let signature_path = directory.path().join("signature");
    fs::write(&allowed_signers, format!("a-quo {public_key}\n"))
        .map_err(ProofError::SignerUnavailable)?;
    fs::write(&signature_path, signature).map_err(ProofError::SignerUnavailable)?;

    let mut command = ssh_keygen_command()?;
    let mut child = command
        .args(["-Y", "verify", "-f"])
        .arg(&allowed_signers)
        .args(["-I", "a-quo", "-n", SSHSIG_NAMESPACE, "-s"])
        .arg(&signature_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(ProofError::SignerUnavailable)?;

    let mut stdin = child.stdin.take().ok_or_else(|| {
        ProofError::SignerUnavailable(std::io::Error::other(
            "ssh-keygen verification stdin was unavailable",
        ))
    })?;
    stdin
        .write_all(payload)
        .map_err(ProofError::SignerUnavailable)?;
    drop(stdin);
    let output = wait_with_output_deadline(child, "verification")?;
    if !output.status.success() {
        return Err(ProofError::SignerFailed {
            operation: "verification",
            status: output.status.to_string(),
        });
    }
    Ok(())
}

fn wait_with_output_deadline(
    mut child: std::process::Child,
    operation: &'static str,
) -> Result<std::process::Output> {
    let deadline = Instant::now() + Duration::from_secs(SIGNER_TIMEOUT_SECONDS);
    loop {
        if child
            .try_wait()
            .map_err(ProofError::SignerUnavailable)?
            .is_some()
        {
            return child
                .wait_with_output()
                .map_err(ProofError::SignerUnavailable);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProofError::SignerTimedOut { operation });
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn ssh_keygen_command() -> Result<Command> {
    validate_ssh_keygen()?;
    let mut command = Command::new(SSH_KEYGEN);
    command.env_clear();
    #[cfg(unix)]
    command.env("PATH", "/usr/bin:/bin");
    #[cfg(not(unix))]
    copy_environment_if_present(&mut command, "PATH");
    copy_environment_if_present(&mut command, "SSH_AUTH_SOCK");
    for name in [
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "TERM",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        copy_environment_if_present(&mut command, name);
    }
    Ok(command)
}

fn copy_environment_if_present(command: &mut Command, name: &str) {
    if let Some(value) = std::env::var_os(name) {
        command.env(name, value);
    }
}

fn validate_ssh_keygen() -> Result<()> {
    let path = Path::new(SSH_KEYGEN);
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProofError::UnsafeSigner(path.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProofError::UnsafeSigner(path.to_path_buf()));
    }
    validate_ssh_keygen_permissions(path, &metadata)
}

#[cfg(unix)]
fn validate_ssh_keygen_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode();
    let owner = metadata.uid();
    if mode & 0o111 == 0 || mode & 0o022 != 0 || !matches!(owner, 0 | 65_534) {
        Err(ProofError::UnsafeSigner(path.to_path_buf()))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn validate_ssh_keygen_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_content() {
        let directory = tempdir().unwrap();
        let artifact = directory.path().join("artifact");
        fs::write(&artifact, b"A Quo\n").unwrap();

        let descriptor = describe_artifact(&artifact).unwrap();

        assert_eq!(descriptor.size, 6);
        assert_eq!(
            descriptor.digest.value,
            "6d5e60c4bae4bcb238ab8d4f79da8ad1f38e5cbdb654f5c38ca56ceda53086ee"
        );
    }

    #[test]
    fn rejects_control_characters_in_personas() {
        let error = validate_persona("trusted\npublisher").unwrap_err();
        assert!(matches!(error, ProofError::InvalidPersona(_)));
    }

    #[test]
    fn rejects_bidirectional_overrides_in_personas() {
        let error = validate_persona("trusted\u{202e}publisher").unwrap_err();
        assert!(matches!(error, ProofError::InvalidPersona(_)));
    }

    #[test]
    fn default_proof_path_does_not_replace_extension() {
        assert_eq!(
            default_proof_path("article.md"),
            PathBuf::from("article.md.a-quo-proof.json")
        );
    }
}
