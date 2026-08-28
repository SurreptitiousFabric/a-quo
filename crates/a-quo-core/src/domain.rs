use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    EvidenceStatus, ProofBundle, ProofError, Result, SignerClaim, VerifiedSigner,
    create_sshsig_payload_proof, decode_payload, decode_sshsig_payload,
    is_unsafe_display_character, normalize_public_key, public_key_fingerprint, read_public_key,
    sshsig_verify, validate_envelope, validate_key_fingerprint, validate_persona,
};

pub const DOMAIN_CONTROL_STATEMENT_SCHEMA: &str = "urn:a-quo:statement:domain-control:v1";
pub const DOMAIN_CONTROL_NAMESPACE: &str = "a-quo-domain-control-v1";
pub const DOMAIN_DEFAULT_VALIDITY_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const DOMAIN_MAX_VALIDITY_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const DOMAIN_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

const DOMAIN_NONCE_BYTES: usize = 32;
const DNS_COMMITMENT_CONTEXT: &[u8] = b"a-quo-domain-dns-txt-v1\0";
const DNS_TXT_PREFIX: &str = "a-quo-domain-v1=";
const MAX_DNS_NAME_BYTES: usize = 253;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainControlStatement {
    pub schema: String,
    pub domain: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signer: SignerClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DomainControlVerification {
    pub signature: EvidenceStatus,
    pub validity: EvidenceStatus,
    pub domain: String,
    pub dns_record_name: String,
    pub dns_txt_value: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signer: VerifiedSigner,
    pub not_established: Vec<String>,
}

/// Normalize a user-facing DNS name to its one signed ASCII representation.
pub fn canonicalize_domain(input: &str) -> Result<String> {
    if input.is_empty() || input.trim() != input {
        return Err(invalid_domain(
            "the name cannot be empty or contain surrounding whitespace",
        ));
    }
    if input.chars().any(is_unsafe_display_character) {
        return Err(invalid_domain(
            "control and bidirectional formatting characters are not allowed",
        ));
    }
    if input.contains("://")
        || input.contains('/')
        || input.contains('\\')
        || input.contains('@')
        || input.contains(':')
        || input.starts_with("*.")
    {
        return Err(invalid_domain(
            "expected one DNS name, not a URL, wildcard, address, or host with a port",
        ));
    }

    let without_root = input.strip_suffix('.').unwrap_or(input);
    if without_root.is_empty() || without_root.ends_with('.') {
        return Err(invalid_domain("the name contains an empty DNS label"));
    }
    let ascii = idna::domain_to_ascii_strict(without_root)
        .map_err(|_| invalid_domain("strict IDNA conversion failed"))?
        .to_ascii_lowercase();
    if ascii.len() > MAX_DNS_NAME_BYTES {
        return Err(invalid_domain("the DNS name exceeds 253 ASCII bytes"));
    }
    if IpAddr::from_str(&ascii).is_ok() {
        return Err(invalid_domain("IP address literals are not domain names"));
    }

    let labels = ascii.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return Err(invalid_domain(
            "a global DNS name requires at least two labels",
        ));
    }
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err(invalid_domain(
            "the name contains an invalid ASCII DNS label",
        ));
    }
    if is_special_use_domain(&ascii) {
        return Err(invalid_domain(
            "special-use and documentation domains cannot carry a global control proof",
        ));
    }
    Ok(ascii)
}

/// Construct a fresh unsigned statement whose exact bytes can be reviewed
/// before signing.
pub fn new_domain_control_statement(
    domain: &str,
    issued_at: i64,
    expires_at: i64,
    public_key: &str,
    persona: &str,
) -> Result<DomainControlStatement> {
    let domain = canonicalize_domain(domain)?;
    validate_validity(issued_at, expires_at)?;
    let persona = validate_persona(persona)?;
    let public_key = normalize_public_key(public_key)?;
    let mut nonce = [0_u8; DOMAIN_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| ProofError::EntropyUnavailable)?;

    Ok(DomainControlStatement {
        schema: DOMAIN_CONTROL_STATEMENT_SCHEMA.to_owned(),
        domain,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        issued_at,
        expires_at,
        signer: SignerClaim {
            persona,
            key_fingerprint: public_key_fingerprint(&public_key)?,
        },
    })
}

/// Create a domain proof with public verification material read from a file.
#[allow(clippy::too_many_arguments)]
pub fn create_domain_control_proof(
    domain: &str,
    issued_at: i64,
    expires_at: i64,
    private_key_path: impl AsRef<Path>,
    public_key_path: impl AsRef<Path>,
    persona: &str,
) -> Result<ProofBundle> {
    let public_key = read_public_key(public_key_path.as_ref())?;
    create_domain_control_proof_with_public_key(
        domain,
        issued_at,
        expires_at,
        private_key_path,
        &public_key,
        persona,
    )
}

/// Create a domain proof from already-loaded public verification material.
#[allow(clippy::too_many_arguments)]
pub fn create_domain_control_proof_with_public_key(
    domain: &str,
    issued_at: i64,
    expires_at: i64,
    private_key_path: impl AsRef<Path>,
    public_key: &str,
    persona: &str,
) -> Result<ProofBundle> {
    let statement =
        new_domain_control_statement(domain, issued_at, expires_at, public_key, persona)?;
    create_domain_control_proof_for_statement(statement, private_key_path, public_key)
}

/// Sign one previously constructed and reviewed domain statement.
pub fn create_domain_control_proof_for_statement(
    statement: DomainControlStatement,
    private_key_path: impl AsRef<Path>,
    public_key: &str,
) -> Result<ProofBundle> {
    validate_domain_statement(&statement)?;
    let public_key = normalize_public_key(public_key)?;
    if public_key_fingerprint(&public_key)? != statement.signer.key_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    let payload = serde_json::to_vec(&statement)?;
    create_sshsig_payload_proof(
        payload,
        private_key_path.as_ref(),
        &public_key,
        DOMAIN_CONTROL_NAMESPACE,
    )
}

/// Verify the domain-specific signature and current bounded validity, then
/// derive the exact TXT publication that a live resolver must observe.
pub fn verify_domain_control_proof(
    proof: &ProofBundle,
    now: i64,
) -> Result<DomainControlVerification> {
    if now < 0 {
        return Err(ProofError::InvalidDomainValidity(
            "verification time cannot be negative".to_owned(),
        ));
    }
    let (payload, public_key) = decode_sshsig_payload(proof, DOMAIN_CONTROL_NAMESPACE)?;
    let statement: DomainControlStatement = serde_json::from_slice(&payload)?;
    validate_domain_statement(&statement)?;
    if public_key_fingerprint(&public_key)? != statement.signer.key_fingerprint {
        return Err(ProofError::FingerprintMismatch);
    }
    sshsig_verify(
        &payload,
        &proof.signature.value,
        &public_key,
        DOMAIN_CONTROL_NAMESPACE,
    )?;
    validate_current_time(&statement, now)?;

    Ok(DomainControlVerification {
        signature: EvidenceStatus::Verified,
        validity: EvidenceStatus::Verified,
        domain: statement.domain.clone(),
        dns_record_name: format!("{}.", statement.domain),
        dns_txt_value: dns_txt_commitment(&payload),
        issued_at: statement.issued_at,
        expires_at: statement.expires_at,
        signer: VerifiedSigner {
            persona: statement.signer.persona,
            key_fingerprint: statement.signer.key_fingerprint,
            identity_binding: "self_asserted".to_owned(),
        },
        not_established: vec![
            "dns_publication".to_owned(),
            "legal_domain_ownership".to_owned(),
            "registrant_identity".to_owned(),
            "parent_or_subdomain_control".to_owned(),
            "website_content_control".to_owned(),
            "historical_dns_control".to_owned(),
            "trusted_timestamp".to_owned(),
        ],
    })
}

/// Decode a domain statement for inspection without claiming that its
/// signature, validity window, or DNS publication has been verified.
pub fn inspect_domain_control_proof(proof: &ProofBundle) -> Result<DomainControlStatement> {
    validate_envelope(proof, DOMAIN_CONTROL_NAMESPACE)?;
    let payload = decode_payload(&proof.payload)?;
    let statement = serde_json::from_slice(&payload)?;
    validate_domain_statement(&statement)?;
    Ok(statement)
}

fn validate_domain_statement(statement: &DomainControlStatement) -> Result<()> {
    if statement.schema != DOMAIN_CONTROL_STATEMENT_SCHEMA {
        return Err(ProofError::Unsupported {
            field: "statement schema",
            value: statement.schema.clone(),
        });
    }
    let canonical = canonicalize_domain(&statement.domain)?;
    if canonical != statement.domain {
        return Err(invalid_domain(
            "the signed name is not in canonical lowercase ASCII A-label form",
        ));
    }
    validate_nonce(&statement.nonce)?;
    validate_validity(statement.issued_at, statement.expires_at)?;
    validate_persona(&statement.signer.persona)?;
    validate_key_fingerprint(&statement.signer.key_fingerprint)?;
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<()> {
    let decoded = URL_SAFE_NO_PAD.decode(nonce).map_err(|_| {
        ProofError::InvalidDomainChallenge(
            "the nonce must be canonical unpadded Base64url".to_owned(),
        )
    })?;
    if decoded.len() != DOMAIN_NONCE_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != nonce {
        return Err(ProofError::InvalidDomainChallenge(
            "the nonce must encode exactly 32 random bytes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_validity(issued_at: i64, expires_at: i64) -> Result<()> {
    if issued_at < 0 || expires_at < 0 {
        return Err(ProofError::InvalidDomainValidity(
            "timestamps cannot be negative".to_owned(),
        ));
    }
    let duration = expires_at.checked_sub(issued_at).ok_or_else(|| {
        ProofError::InvalidDomainValidity("expiry must follow issuance".to_owned())
    })?;
    if duration <= 0 {
        return Err(ProofError::InvalidDomainValidity(
            "expiry must follow issuance".to_owned(),
        ));
    }
    if duration > DOMAIN_MAX_VALIDITY_SECONDS {
        return Err(ProofError::InvalidDomainValidity(format!(
            "the validity window cannot exceed {DOMAIN_MAX_VALIDITY_SECONDS} seconds"
        )));
    }
    Ok(())
}

fn validate_current_time(statement: &DomainControlStatement, now: i64) -> Result<()> {
    if now.saturating_add(DOMAIN_CLOCK_SKEW_SECONDS) < statement.issued_at {
        return Err(ProofError::DomainProofNotYetValid {
            now,
            issued_at: statement.issued_at,
        });
    }
    if now.saturating_sub(DOMAIN_CLOCK_SKEW_SECONDS) > statement.expires_at {
        return Err(ProofError::DomainProofExpired {
            now,
            expires_at: statement.expires_at,
        });
    }
    Ok(())
}

fn dns_txt_commitment(payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(DNS_COMMITMENT_CONTEXT);
    digest.update(payload);
    format!(
        "{DNS_TXT_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    )
}

fn is_special_use_domain(domain: &str) -> bool {
    const SPECIAL_SUFFIXES: &[&str] = &[
        "alt",
        "example",
        "example.com",
        "example.net",
        "example.org",
        "home.arpa",
        "invalid",
        "local",
        "localhost",
        "onion",
        "test",
    ];
    SPECIAL_SUFFIXES
        .iter()
        .any(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
}

fn invalid_domain(reason: &str) -> ProofError {
    ProofError::InvalidDomain(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> DomainControlStatement {
        DomainControlStatement {
            schema: DOMAIN_CONTROL_STATEMENT_SCHEMA.to_owned(),
            domain: "a-quo.ch".to_owned(),
            nonce: URL_SAFE_NO_PAD.encode([0x5a; DOMAIN_NONCE_BYTES]),
            issued_at: 1_787_875_200,
            expires_at: 1_788_480_000,
            signer: SignerClaim {
                persona: "A Quo publisher".to_owned(),
                key_fingerprint: format!(
                    "SHA256:{}",
                    base64::engine::general_purpose::STANDARD_NO_PAD
                        .encode([0x5a; DOMAIN_NONCE_BYTES])
                ),
            },
        }
    }

    #[test]
    fn canonicalizes_idna_and_an_optional_root_dot() {
        assert_eq!(
            canonicalize_domain("BÜCHER.ch").unwrap(),
            "xn--bcher-kva.ch"
        );
        assert_eq!(canonicalize_domain("A-QUO.CH.").unwrap(), "a-quo.ch");
    }

    #[test]
    fn rejects_urls_wildcards_addresses_local_names_and_noncanonical_statements() {
        for invalid in [
            "https://a-quo.ch",
            "*.a-quo.ch",
            "127.0.0.1",
            "localhost",
            "publisher.local",
            "example.com",
            "a-quo.ch:443",
            " a-quo.ch",
        ] {
            assert!(matches!(
                canonicalize_domain(invalid),
                Err(ProofError::InvalidDomain(_))
            ));
        }

        let mut invalid = statement();
        invalid.domain = "A-QUO.CH".to_owned();
        assert!(matches!(
            validate_domain_statement(&invalid),
            Err(ProofError::InvalidDomain(_))
        ));
    }

    #[test]
    fn nonce_and_validity_are_closed_and_bounded() {
        let valid = statement();
        validate_domain_statement(&valid).unwrap();

        let mut padded = valid.clone();
        padded.nonce.push('=');
        assert!(matches!(
            validate_domain_statement(&padded),
            Err(ProofError::InvalidDomainChallenge(_))
        ));

        let mut long_lived = valid;
        long_lived.expires_at = long_lived.issued_at + DOMAIN_MAX_VALIDITY_SECONDS + 1;
        assert!(matches!(
            validate_domain_statement(&long_lived),
            Err(ProofError::InvalidDomainValidity(_))
        ));
    }

    #[test]
    fn commitment_binds_the_exact_payload_and_fits_one_txt_string() {
        let first = dns_txt_commitment(b"first exact payload");
        let second = dns_txt_commitment(b"second exact payload");
        assert_ne!(first, second);
        assert!(first.starts_with(DNS_TXT_PREFIX));
        assert!(first.len() <= 255);
        assert!(!first.trim_start_matches(DNS_TXT_PREFIX).contains('='));
    }

    #[test]
    fn clock_skew_is_bounded_at_both_edges() {
        let value = statement();
        assert!(validate_current_time(&value, value.issued_at - DOMAIN_CLOCK_SKEW_SECONDS).is_ok());
        assert!(matches!(
            validate_current_time(&value, value.issued_at - DOMAIN_CLOCK_SKEW_SECONDS - 1),
            Err(ProofError::DomainProofNotYetValid { .. })
        ));
        assert!(
            validate_current_time(&value, value.expires_at + DOMAIN_CLOCK_SKEW_SECONDS).is_ok()
        );
        assert!(matches!(
            validate_current_time(&value, value.expires_at + DOMAIN_CLOCK_SKEW_SECONDS + 1),
            Err(ProofError::DomainProofExpired { .. })
        ));
    }
}
