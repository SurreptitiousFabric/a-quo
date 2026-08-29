use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::continuity::{
    CONTINUITY_CANONICALIZATION, PERSONA_ROOT_STATEMENT_SCHEMA, PersonaRootProof,
    PersonaRootStatement, VerifiedPersonaRoot, canonical_persona_root_statement_bytes,
    verify_persona_root_proof,
};
use crate::{ProofError, Result, parse_bounded_json, public_key_fingerprint};

pub const PERSONA_ROOT_CARD_SCHEMA: &str = "urn:a-quo:persona-root-card:v1";
pub const PERSONA_ROOT_PIN_SCHEMA: &str = "urn:a-quo:persona-root-pin:v1";
pub const PERSONA_ROOT_PIN_URI_PREFIX: &str = "aquo:persona-root-pin:v1:";
pub const MAX_PERSONA_ROOT_CARD_BYTES: usize = 4_096;
pub const MAX_PERSONA_ROOT_PIN_BYTES: usize = 4_096;
/// UX-only warning threshold between the root's self-signed `issued_at` and
/// the verifier's locally recorded first observation. It is not root expiry,
/// trusted time, or evidence that the root was safe before observation.
pub const PERSONA_ROOT_LATE_FIRST_CONTACT_WARNING_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Local UX reminder to review an old pin observation. Crossing this threshold
/// does not expire or invalidate the immutable persona root.
pub const PERSONA_ROOT_PIN_REVIEW_WARNING_SECONDS: u64 = 365 * 24 * 60 * 60;

const MAX_JCS_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const SHA256_HEX_BYTES: usize = 64;

/// Public, self-asserted contact material copied from one verified persona root.
///
/// A card contains no transport or trust claim. Its deterministic `pin_uri`
/// carries only the exact root-statement digest, making it suitable for a later
/// text or QR representation without putting a proof or verifier provenance in
/// that compact value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaRootCard {
    pub schema: String,
    pub canonicalization: String,
    pub persona: String,
    pub persona_anchor: String,
    pub root_version: u32,
    pub issued_at: i64,
    pub initial_key_fingerprint: String,
    pub root_statement_sha256: String,
    pub pin_uri: String,
}

/// Verifier-recorded basis for retaining one exact persona-root digest.
///
/// None of these variants cryptographically proves that two channels were
/// independent. `OutOfBandUserConfirmed` records only the verifier's statement
/// that a separate channel was used.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRootTrustBasis {
    TrustOnFirstUse,
    SameChannelCopy,
    OutOfBandUserConfirmed,
}

impl PersonaRootTrustBasis {
    pub fn source(self) -> PersonaRootTrustBasisSource {
        match self {
            Self::TrustOnFirstUse => PersonaRootTrustBasisSource::VerifierFirstObservation,
            Self::SameChannelCopy => PersonaRootTrustBasisSource::PublisherCandidateChannel,
            Self::OutOfBandUserConfirmed => PersonaRootTrustBasisSource::VerifierUserConfirmation,
        }
    }

    pub fn independence(self) -> PersonaRootChannelIndependence {
        match self {
            Self::TrustOnFirstUse | Self::SameChannelCopy => {
                PersonaRootChannelIndependence::NotEstablished
            }
            Self::OutOfBandUserConfirmed => PersonaRootChannelIndependence::UserReportedSeparate,
        }
    }
}

/// How verifier-owned trust-basis metadata entered a pin record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRootTrustBasisSource {
    VerifierFirstObservation,
    PublisherCandidateChannel,
    VerifierUserConfirmation,
}

/// User-facing channel label recorded by the verifier.
///
/// A channel label alone never elevates independence. For example, selecting
/// `InPerson` while using TOFU still yields `NotEstablished` independence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRootPinChannel {
    InPerson,
    Paper,
    Qr,
    Voice,
    File,
    Other,
}

/// What A Quo can say about channel independence from a verifier-owned pin.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRootChannelIndependence {
    NotEstablished,
    UserReportedSeparate,
}

/// Assurance available for verifier-recorded provenance metadata.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRootProvenanceAssurance {
    UserRecordedNotCryptographicallyVerified,
}

/// Portable verifier-owned provenance for one exact root digest.
///
/// The publisher card is deliberately not embedded. Optional
/// `source_artifact_sha256` is only an opaque verifier-recorded digest of source
/// material; it does not prove who supplied that material or how it travelled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaRootPin {
    pub schema: String,
    pub canonicalization: String,
    pub root_statement_sha256: String,
    pub recorded_at: i64,
    pub trust_basis: PersonaRootTrustBasis,
    pub channel: PersonaRootPinChannel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_artifact_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRootSignatureStatus {
    NotChecked,
    Verified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRootMatchStatus {
    NotChecked,
    Matched,
    Mismatched,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaRootClaimStatus {
    NotEstablished,
}

/// Internal-consistency result for a card alone.
///
/// This does not verify a root signature; signature verification requires the
/// corresponding persona-root proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaRootCardValidationReport {
    pub card_sha256: String,
    pub root_statement_sha256: String,
    pub pin_uri: String,
    pub root_signature: PersonaRootSignatureStatus,
}

/// Validation of verifier-owned pin metadata without elevating its provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaRootPinValidationReport {
    pub root_statement_sha256: String,
    pub recorded_at: i64,
    pub trust_basis: PersonaRootTrustBasis,
    pub trust_basis_source: PersonaRootTrustBasisSource,
    pub channel: PersonaRootPinChannel,
    pub channel_independence: PersonaRootChannelIndependence,
    pub provenance_assurance: PersonaRootProvenanceAssurance,
    pub source_artifact_sha256: Option<String>,
}

/// Comparison of a verified root, a publisher card, and verifier-owned pin.
///
/// Every evidence dimension remains separate. In particular, a matching pin or
/// user-reported separate channel never establishes current history, legal
/// identity, trusted time, current authority, or artifact truth and safety.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaRootDistributionComparisonReport {
    pub checked_at: i64,
    pub root_signature: PersonaRootSignatureStatus,
    pub card_match: PersonaRootMatchStatus,
    pub pin_match: PersonaRootMatchStatus,
    pub candidate_root_statement_sha256: String,
    pub pinned_root_statement_sha256: String,
    pub supplied_card_sha256: Option<String>,
    pub candidate_card_sha256: String,
    pub trust_basis: PersonaRootTrustBasis,
    pub trust_basis_source: PersonaRootTrustBasisSource,
    pub channel: PersonaRootPinChannel,
    pub channel_independence: PersonaRootChannelIndependence,
    pub provenance_assurance: PersonaRootProvenanceAssurance,
    pub source_artifact_sha256: Option<String>,
    /// The root's self-signed `issued_at` is later than the verifier's local
    /// `recorded_at`. This reports the ordering without treating either value
    /// as trusted time or rejecting the otherwise valid evidence.
    pub root_issued_after_local_observation: bool,
    /// UX warning over self-signed `issued_at` and local `recorded_at`, when
    /// those values have a non-negative ordering. This is not root expiry.
    pub late_first_contact: Option<bool>,
    pub first_contact_delay_seconds: Option<u64>,
    pub pin_observation_age_seconds: u64,
    /// Local reminder to review an old observation, not an expiry or mismatch
    /// of the immutable root or pin.
    pub pin_observation_review_due: bool,
    pub trusted_time: PersonaRootClaimStatus,
    pub current_history_freshness: PersonaRootClaimStatus,
    pub legal_identity: PersonaRootClaimStatus,
    pub current_signing_authority: PersonaRootClaimStatus,
    pub current_recovery_authority: PersonaRootClaimStatus,
    pub artifact_truth_or_safety: PersonaRootClaimStatus,
    pub root_card_possession_grants_authority: bool,
}

/// Verify a signed persona-root proof and derive its unsigned public card.
pub fn persona_root_card_from_proof(proof: &PersonaRootProof) -> Result<PersonaRootCard> {
    let verified = verify_persona_root_proof(proof)?;
    persona_root_card_from_verified_root(&verified)
}

fn persona_root_card_from_verified_root(verified: &VerifiedPersonaRoot) -> Result<PersonaRootCard> {
    let statement_bytes = canonical_persona_root_statement_bytes(&verified.statement)?;
    let statement_sha256 = sha256_hex(&statement_bytes);
    if verified.root_statement_sha256 != statement_sha256 {
        return Err(invalid_root_distribution(
            "verified root digest does not match its canonical statement",
        ));
    }
    if public_key_fingerprint(&verified.initial_public_key)?
        != verified.statement.initial_key_fingerprint
    {
        return Err(invalid_root_distribution(
            "verified root public key does not match its initial-key fingerprint",
        ));
    }

    let card = PersonaRootCard {
        schema: PERSONA_ROOT_CARD_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        persona: verified.statement.persona.clone(),
        persona_anchor: verified.statement.persona_anchor.clone(),
        root_version: verified.statement.root_version,
        issued_at: verified.statement.issued_at,
        initial_key_fingerprint: verified.statement.initial_key_fingerprint.clone(),
        pin_uri: persona_root_pin_uri(&statement_sha256)?,
        root_statement_sha256: statement_sha256,
    };
    validate_persona_root_card_fields(&card)?;
    Ok(card)
}

/// Create a verifier-owned pin. The basis and channel remain provenance
/// metadata, not cryptographic assertions.
pub fn new_persona_root_pin(
    root_statement_sha256: &str,
    recorded_at: i64,
    trust_basis: PersonaRootTrustBasis,
    channel: PersonaRootPinChannel,
    source_artifact_sha256: Option<&str>,
) -> Result<PersonaRootPin> {
    let pin = PersonaRootPin {
        schema: PERSONA_ROOT_PIN_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        root_statement_sha256: root_statement_sha256.to_owned(),
        recorded_at,
        trust_basis,
        channel,
        source_artifact_sha256: source_artifact_sha256.map(ToOwned::to_owned),
    };
    validate_persona_root_pin_fields(&pin)?;
    Ok(pin)
}

pub fn persona_root_pin_uri(root_statement_sha256: &str) -> Result<String> {
    validate_sha256("root statement SHA-256", root_statement_sha256)?;
    Ok(format!(
        "{PERSONA_ROOT_PIN_URI_PREFIX}{root_statement_sha256}"
    ))
}

/// Parse the closed digest-only URI carried by text and QR root cards.
pub fn parse_persona_root_pin_uri(uri: &str) -> Result<String> {
    let root_statement_sha256 = uri
        .strip_prefix(PERSONA_ROOT_PIN_URI_PREFIX)
        .ok_or_else(|| invalid_root_distribution("unsupported persona root pin URI"))?;
    validate_sha256("root statement SHA-256", root_statement_sha256)?;
    Ok(root_statement_sha256.to_owned())
}

pub fn canonical_persona_root_card_bytes(card: &PersonaRootCard) -> Result<Vec<u8>> {
    validate_persona_root_card_fields(card)?;
    let bytes = serde_json_canonicalizer::to_vec(card)?;
    require_bound(&bytes, MAX_PERSONA_ROOT_CARD_BYTES, "persona root card")?;
    Ok(bytes)
}

pub fn parse_persona_root_card_bytes(bytes: &[u8]) -> Result<PersonaRootCard> {
    let card: PersonaRootCard =
        parse_bounded_json(bytes, MAX_PERSONA_ROOT_CARD_BYTES, "persona root card")
            .map_err(invalid_root_distribution)?;
    let canonical = canonical_persona_root_card_bytes(&card)?;
    if canonical != bytes {
        return Err(invalid_root_distribution(
            "persona root card is not canonical RFC 8785 JSON",
        ));
    }
    Ok(card)
}

pub fn persona_root_card_sha256(card: &PersonaRootCard) -> Result<String> {
    Ok(sha256_hex(&canonical_persona_root_card_bytes(card)?))
}

pub fn validate_persona_root_card(
    card: &PersonaRootCard,
) -> Result<PersonaRootCardValidationReport> {
    let card_sha256 = persona_root_card_sha256(card)?;
    Ok(PersonaRootCardValidationReport {
        card_sha256,
        root_statement_sha256: card.root_statement_sha256.clone(),
        pin_uri: card.pin_uri.clone(),
        root_signature: PersonaRootSignatureStatus::NotChecked,
    })
}

pub fn canonical_persona_root_pin_bytes(pin: &PersonaRootPin) -> Result<Vec<u8>> {
    validate_persona_root_pin_fields(pin)?;
    let bytes = serde_json_canonicalizer::to_vec(pin)?;
    require_bound(&bytes, MAX_PERSONA_ROOT_PIN_BYTES, "persona root pin")?;
    Ok(bytes)
}

pub fn parse_persona_root_pin_bytes(bytes: &[u8]) -> Result<PersonaRootPin> {
    let pin: PersonaRootPin =
        parse_bounded_json(bytes, MAX_PERSONA_ROOT_PIN_BYTES, "persona root pin")
            .map_err(invalid_root_distribution)?;
    let canonical = canonical_persona_root_pin_bytes(&pin)?;
    if canonical != bytes {
        return Err(invalid_root_distribution(
            "persona root pin is not canonical RFC 8785 JSON",
        ));
    }
    Ok(pin)
}

pub fn persona_root_pin_sha256(pin: &PersonaRootPin) -> Result<String> {
    Ok(sha256_hex(&canonical_persona_root_pin_bytes(pin)?))
}

pub fn validate_persona_root_pin(pin: &PersonaRootPin) -> Result<PersonaRootPinValidationReport> {
    validate_persona_root_pin_fields(pin)?;
    Ok(PersonaRootPinValidationReport {
        root_statement_sha256: pin.root_statement_sha256.clone(),
        recorded_at: pin.recorded_at,
        trust_basis: pin.trust_basis,
        trust_basis_source: pin.trust_basis.source(),
        channel: pin.channel,
        channel_independence: pin.trust_basis.independence(),
        provenance_assurance:
            PersonaRootProvenanceAssurance::UserRecordedNotCryptographicallyVerified,
        source_artifact_sha256: pin.source_artifact_sha256.clone(),
    })
}

pub fn compare_persona_root_distribution(
    proof: &PersonaRootProof,
    supplied_card: Option<&PersonaRootCard>,
    pin: &PersonaRootPin,
    checked_at: i64,
) -> Result<PersonaRootDistributionComparisonReport> {
    let verified = verify_persona_root_proof(proof)?;
    compare_verified_persona_root_distribution(&verified, supplied_card, pin, checked_at)
}

fn compare_verified_persona_root_distribution(
    verified: &VerifiedPersonaRoot,
    supplied_card: Option<&PersonaRootCard>,
    pin: &PersonaRootPin,
    checked_at: i64,
) -> Result<PersonaRootDistributionComparisonReport> {
    validate_jcs_time("comparison checked_at", checked_at)?;
    let supplied_card_report = supplied_card.map(validate_persona_root_card).transpose()?;
    let pin_report = validate_persona_root_pin(pin)?;
    if checked_at < pin.recorded_at {
        return Err(invalid_root_distribution(
            "comparison checked_at cannot predate the verifier pin record",
        ));
    }

    let candidate_card = persona_root_card_from_verified_root(verified)?;
    let candidate_card_sha256 = persona_root_card_sha256(&candidate_card)?;
    let card_match = match supplied_card {
        Some(card) if card == &candidate_card => PersonaRootMatchStatus::Matched,
        Some(_) => PersonaRootMatchStatus::Mismatched,
        None => PersonaRootMatchStatus::NotChecked,
    };
    let pin_match = if pin.root_statement_sha256 == candidate_card.root_statement_sha256 {
        PersonaRootMatchStatus::Matched
    } else {
        PersonaRootMatchStatus::Mismatched
    };

    let root_issued_after_local_observation =
        pin_match == PersonaRootMatchStatus::Matched && candidate_card.issued_at > pin.recorded_at;
    let (late_first_contact, first_contact_delay_seconds) =
        if pin_match == PersonaRootMatchStatus::Matched && !root_issued_after_local_observation {
            let delay = u64::try_from(pin.recorded_at - candidate_card.issued_at)
                .expect("validated non-negative JCS time difference fits u64");
            (
                Some(delay > PERSONA_ROOT_LATE_FIRST_CONTACT_WARNING_SECONDS),
                Some(delay),
            )
        } else {
            (None, None)
        };

    let pin_observation_age_seconds = u64::try_from(checked_at - pin.recorded_at)
        .expect("validated non-negative JCS time difference fits u64");

    Ok(PersonaRootDistributionComparisonReport {
        checked_at,
        root_signature: PersonaRootSignatureStatus::Verified,
        card_match,
        pin_match,
        candidate_root_statement_sha256: candidate_card.root_statement_sha256.clone(),
        pinned_root_statement_sha256: pin.root_statement_sha256.clone(),
        supplied_card_sha256: supplied_card_report.map(|report| report.card_sha256),
        candidate_card_sha256,
        trust_basis: pin_report.trust_basis,
        trust_basis_source: pin_report.trust_basis_source,
        channel: pin_report.channel,
        channel_independence: pin_report.channel_independence,
        provenance_assurance: pin_report.provenance_assurance,
        source_artifact_sha256: pin_report.source_artifact_sha256,
        root_issued_after_local_observation,
        late_first_contact,
        first_contact_delay_seconds,
        pin_observation_age_seconds,
        pin_observation_review_due: pin_observation_age_seconds
            > PERSONA_ROOT_PIN_REVIEW_WARNING_SECONDS,
        trusted_time: PersonaRootClaimStatus::NotEstablished,
        current_history_freshness: PersonaRootClaimStatus::NotEstablished,
        legal_identity: PersonaRootClaimStatus::NotEstablished,
        current_signing_authority: PersonaRootClaimStatus::NotEstablished,
        current_recovery_authority: PersonaRootClaimStatus::NotEstablished,
        artifact_truth_or_safety: PersonaRootClaimStatus::NotEstablished,
        root_card_possession_grants_authority: false,
    })
}

fn validate_persona_root_card_fields(card: &PersonaRootCard) -> Result<()> {
    if card.schema != PERSONA_ROOT_CARD_SCHEMA {
        return Err(invalid_root_distribution(
            "unsupported persona root card schema",
        ));
    }
    if card.canonicalization != CONTINUITY_CANONICALIZATION {
        return Err(invalid_root_distribution(
            "unsupported persona root card canonicalization",
        ));
    }
    validate_sha256("root statement SHA-256", &card.root_statement_sha256)?;

    let statement = PersonaRootStatement {
        schema: PERSONA_ROOT_STATEMENT_SCHEMA.to_owned(),
        canonicalization: CONTINUITY_CANONICALIZATION.to_owned(),
        persona_anchor: card.persona_anchor.clone(),
        persona: card.persona.clone(),
        root_version: card.root_version,
        issued_at: card.issued_at,
        initial_key_fingerprint: card.initial_key_fingerprint.clone(),
    };
    let statement_bytes = canonical_persona_root_statement_bytes(&statement)?;
    if sha256_hex(&statement_bytes) != card.root_statement_sha256 {
        return Err(invalid_root_distribution(
            "persona root card digest does not match its copied root fields",
        ));
    }
    if card.pin_uri != persona_root_pin_uri(&card.root_statement_sha256)? {
        return Err(invalid_root_distribution(
            "persona root card pin URI does not match its root digest",
        ));
    }
    Ok(())
}

fn validate_persona_root_pin_fields(pin: &PersonaRootPin) -> Result<()> {
    if pin.schema != PERSONA_ROOT_PIN_SCHEMA {
        return Err(invalid_root_distribution(
            "unsupported persona root pin schema",
        ));
    }
    if pin.canonicalization != CONTINUITY_CANONICALIZATION {
        return Err(invalid_root_distribution(
            "unsupported persona root pin canonicalization",
        ));
    }
    validate_sha256("root statement SHA-256", &pin.root_statement_sha256)?;
    validate_jcs_time("pin recorded_at", pin.recorded_at)?;
    if let Some(source_artifact_sha256) = &pin.source_artifact_sha256 {
        validate_sha256("source artifact SHA-256", source_artifact_sha256)?;
    }
    Ok(())
}

fn validate_jcs_time(field: &str, value: i64) -> Result<()> {
    if (0..=MAX_JCS_SAFE_INTEGER).contains(&value) {
        Ok(())
    } else {
        Err(invalid_root_distribution(format!(
            "{field} must be an exact non-negative RFC 8785 integer"
        )))
    }
}

fn validate_sha256(field: &str, value: &str) -> Result<()> {
    if value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(invalid_root_distribution(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )))
    }
}

fn require_bound(bytes: &[u8], maximum: usize, description: &str) -> Result<()> {
    if bytes.len() <= maximum {
        Ok(())
    } else {
        Err(invalid_root_distribution(format!(
            "{description} exceeds {maximum} bytes"
        )))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid_root_distribution(reason: impl Into<String>) -> ProofError {
    ProofError::InvalidContinuityProof(format!(
        "invalid persona root distribution material: {}",
        reason.into()
    ))
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};

    use super::*;
    use crate::continuity::{
        new_persona_root_statement_with_anchor, persona_root_statement_sha256,
    };
    use crate::{
        ContinuitySignature, ContinuitySignatureRole, PERSONA_ROOT_NAMESPACE,
        PERSONA_ROOT_PROOF_SCHEMA,
    };

    const KEY_ONE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2wZ6f9bI6YlF1YyW5iU+a4jvfp9DCf3j6PYfnT1rYA";
    const KEY_TWO: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfX7hAdqGfF0mYz2oD88dL84M2yr2KoXqhh7sSRvqHQ";
    const ANCHOR_ONE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const ANCHOR_TWO: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";

    fn verified_root(
        anchor: &str,
        persona: &str,
        issued_at: i64,
        public_key: &str,
    ) -> VerifiedPersonaRoot {
        let statement =
            new_persona_root_statement_with_anchor(anchor, persona, issued_at, public_key).unwrap();
        let root_statement_sha256 = persona_root_statement_sha256(&statement).unwrap();
        VerifiedPersonaRoot {
            statement,
            root_statement_sha256,
            initial_public_key: public_key.to_owned(),
        }
    }

    fn card_fixture() -> (VerifiedPersonaRoot, PersonaRootCard) {
        let root = verified_root(ANCHOR_ONE, "JuniperQuill", 1_700_000_000, KEY_ONE);
        let card = persona_root_card_from_verified_root(&root).unwrap();
        (root, card)
    }

    fn assert_distribution_nonclaims(report: &PersonaRootDistributionComparisonReport) {
        assert_eq!(
            report.current_signing_authority,
            PersonaRootClaimStatus::NotEstablished
        );
        assert_eq!(
            report.current_recovery_authority,
            PersonaRootClaimStatus::NotEstablished
        );
        assert_eq!(
            report.artifact_truth_or_safety,
            PersonaRootClaimStatus::NotEstablished
        );
        assert!(!report.root_card_possession_grants_authority);
    }

    #[test]
    fn card_is_canonical_digest_bound_and_round_trips() {
        let (root, card) = card_fixture();
        let bytes = canonical_persona_root_card_bytes(&card).unwrap();
        assert_eq!(parse_persona_root_card_bytes(&bytes).unwrap(), card);
        assert_eq!(card.root_statement_sha256, root.root_statement_sha256);
        assert_eq!(
            card.pin_uri,
            format!(
                "{PERSONA_ROOT_PIN_URI_PREFIX}{}",
                root.root_statement_sha256
            )
        );
        assert_eq!(
            card.pin_uri.len(),
            PERSONA_ROOT_PIN_URI_PREFIX.len() + SHA256_HEX_BYTES
        );
        assert!(!card.pin_uri.contains("JuniperQuill"));
        assert!(!card.pin_uri.contains(ANCHOR_ONE));
        assert_eq!(
            parse_persona_root_pin_uri(&card.pin_uri).unwrap(),
            root.root_statement_sha256
        );

        let report = validate_persona_root_card(&card).unwrap();
        assert_eq!(
            report.root_signature,
            PersonaRootSignatureStatus::NotChecked
        );
        assert_eq!(report.card_sha256, sha256_hex(&bytes));
        assert_eq!(report.pin_uri, card.pin_uri);
    }

    #[test]
    fn verifier_pin_is_canonical_does_not_embed_card_and_round_trips() {
        let (_, card) = card_fixture();
        let card_sha256 = persona_root_card_sha256(&card).unwrap();
        let pin = new_persona_root_pin(
            &card.root_statement_sha256,
            card.issued_at + 5,
            PersonaRootTrustBasis::TrustOnFirstUse,
            PersonaRootPinChannel::File,
            Some(&card_sha256),
        )
        .unwrap();
        let bytes = canonical_persona_root_pin_bytes(&pin).unwrap();
        assert_eq!(parse_persona_root_pin_bytes(&bytes).unwrap(), pin);
        assert_eq!(persona_root_pin_sha256(&pin).unwrap(), sha256_hex(&bytes));

        let wire: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(wire.get("persona").is_none());
        assert!(wire.get("persona_anchor").is_none());
        assert!(wire.get("initial_key_fingerprint").is_none());
        assert!(wire.get("pin_uri").is_none());

        let report = validate_persona_root_pin(&pin).unwrap();
        assert_eq!(
            report.trust_basis_source,
            PersonaRootTrustBasisSource::VerifierFirstObservation
        );
        assert_eq!(
            report.channel_independence,
            PersonaRootChannelIndependence::NotEstablished
        );
        assert_eq!(
            report.provenance_assurance,
            PersonaRootProvenanceAssurance::UserRecordedNotCryptographicallyVerified
        );
    }

    #[test]
    fn comparison_keeps_every_evidence_dimension_separate() {
        let (root, card) = card_fixture();
        let pin = new_persona_root_pin(
            &card.root_statement_sha256,
            card.issued_at + 30,
            PersonaRootTrustBasis::OutOfBandUserConfirmed,
            PersonaRootPinChannel::Qr,
            None,
        )
        .unwrap();
        let report = compare_verified_persona_root_distribution(
            &root,
            Some(&card),
            &pin,
            card.issued_at + 90,
        )
        .unwrap();

        assert_eq!(report.root_signature, PersonaRootSignatureStatus::Verified);
        assert_eq!(report.card_match, PersonaRootMatchStatus::Matched);
        assert_eq!(report.pin_match, PersonaRootMatchStatus::Matched);
        assert_eq!(
            report.supplied_card_sha256.as_deref(),
            Some(report.candidate_card_sha256.as_str())
        );
        assert_eq!(
            report.trust_basis_source,
            PersonaRootTrustBasisSource::VerifierUserConfirmation
        );
        assert_eq!(
            report.channel_independence,
            PersonaRootChannelIndependence::UserReportedSeparate
        );
        assert_eq!(
            report.provenance_assurance,
            PersonaRootProvenanceAssurance::UserRecordedNotCryptographicallyVerified
        );
        assert_eq!(report.late_first_contact, Some(false));
        assert_eq!(report.first_contact_delay_seconds, Some(30));
        assert!(!report.root_issued_after_local_observation);
        assert_eq!(report.pin_observation_age_seconds, 60);
        assert!(!report.pin_observation_review_due);
        assert_eq!(report.trusted_time, PersonaRootClaimStatus::NotEstablished);
        assert_eq!(
            report.current_history_freshness,
            PersonaRootClaimStatus::NotEstablished
        );
        assert_eq!(
            report.legal_identity,
            PersonaRootClaimStatus::NotEstablished
        );
        assert_distribution_nonclaims(&report);
    }

    #[test]
    fn public_card_and_comparison_apis_reject_a_forged_root_proof() {
        let (root, card) = card_fixture();
        let payload = canonical_persona_root_statement_bytes(&root.statement).unwrap();
        let forged = PersonaRootProof {
            schema: PERSONA_ROOT_PROOF_SCHEMA.to_owned(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: ContinuitySignature {
                role: ContinuitySignatureRole::Root,
                format: "sshsig".to_owned(),
                namespace: PERSONA_ROOT_NAMESPACE.to_owned(),
                value: "not-an-armored-sshsig".to_owned(),
                public_key_format: "openssh-public-key".to_owned(),
                public_key: root.initial_public_key,
            },
        };
        let pin = new_persona_root_pin(
            &card.root_statement_sha256,
            card.issued_at,
            PersonaRootTrustBasis::TrustOnFirstUse,
            PersonaRootPinChannel::File,
            None,
        )
        .unwrap();

        assert!(persona_root_card_from_proof(&forged).is_err());
        assert!(
            compare_persona_root_distribution(&forged, Some(&card), &pin, card.issued_at).is_err()
        );
    }

    #[test]
    fn digest_only_pin_comparison_leaves_card_not_checked() {
        let (root, card) = card_fixture();
        let pin = new_persona_root_pin(
            &card.root_statement_sha256,
            card.issued_at,
            PersonaRootTrustBasis::OutOfBandUserConfirmed,
            PersonaRootPinChannel::Qr,
            None,
        )
        .unwrap();

        let report =
            compare_verified_persona_root_distribution(&root, None, &pin, card.issued_at + 5)
                .unwrap();
        assert_eq!(report.root_signature, PersonaRootSignatureStatus::Verified);
        assert_eq!(report.card_match, PersonaRootMatchStatus::NotChecked);
        assert_eq!(report.supplied_card_sha256, None);
        assert_eq!(report.pin_match, PersonaRootMatchStatus::Matched);
        assert_eq!(report.late_first_contact, Some(false));
        assert_eq!(report.first_contact_delay_seconds, Some(0));
        assert!(!report.root_issued_after_local_observation);
        assert_eq!(
            report.channel_independence,
            PersonaRootChannelIndependence::UserReportedSeparate
        );
        assert_eq!(
            report.current_history_freshness,
            PersonaRootClaimStatus::NotEstablished
        );
        assert_distribution_nonclaims(&report);
    }

    #[test]
    fn late_first_contact_warning_uses_strict_thirty_day_boundary() {
        let (root, card) = card_fixture();
        for (delay, expected_warning) in [
            (PERSONA_ROOT_LATE_FIRST_CONTACT_WARNING_SECONDS, false),
            (PERSONA_ROOT_LATE_FIRST_CONTACT_WARNING_SECONDS + 1, true),
        ] {
            let recorded_at = card.issued_at + i64::try_from(delay).unwrap();
            let pin = new_persona_root_pin(
                &card.root_statement_sha256,
                recorded_at,
                PersonaRootTrustBasis::TrustOnFirstUse,
                PersonaRootPinChannel::File,
                None,
            )
            .unwrap();
            let report =
                compare_verified_persona_root_distribution(&root, None, &pin, recorded_at).unwrap();
            assert_eq!(report.late_first_contact, Some(expected_warning));
            assert_eq!(report.first_contact_delay_seconds, Some(delay));
            assert_eq!(report.trusted_time, PersonaRootClaimStatus::NotEstablished);
            assert_eq!(
                report.current_history_freshness,
                PersonaRootClaimStatus::NotEstablished
            );
        }
    }

    #[test]
    fn root_issued_after_local_observation_is_reported_not_rejected() {
        let (root, card) = card_fixture();
        let pin = new_persona_root_pin(
            &card.root_statement_sha256,
            card.issued_at - 1,
            PersonaRootTrustBasis::TrustOnFirstUse,
            PersonaRootPinChannel::File,
            None,
        )
        .unwrap();

        let report = compare_verified_persona_root_distribution(
            &root,
            Some(&card),
            &pin,
            card.issued_at + 1,
        )
        .unwrap();
        assert!(report.root_issued_after_local_observation);
        assert_eq!(report.late_first_contact, None);
        assert_eq!(report.first_contact_delay_seconds, None);
        assert_eq!(report.pin_match, PersonaRootMatchStatus::Matched);
        assert_eq!(report.root_signature, PersonaRootSignatureStatus::Verified);
        assert_eq!(report.trusted_time, PersonaRootClaimStatus::NotEstablished);
        assert_eq!(
            report.current_history_freshness,
            PersonaRootClaimStatus::NotEstablished
        );
    }

    #[test]
    fn pin_review_reminder_does_not_expire_the_root() {
        let (root, card) = card_fixture();
        let pin = new_persona_root_pin(
            &card.root_statement_sha256,
            card.issued_at,
            PersonaRootTrustBasis::TrustOnFirstUse,
            PersonaRootPinChannel::File,
            None,
        )
        .unwrap();

        for (age, review_due) in [
            (PERSONA_ROOT_PIN_REVIEW_WARNING_SECONDS, false),
            (PERSONA_ROOT_PIN_REVIEW_WARNING_SECONDS + 1, true),
        ] {
            let checked_at = pin.recorded_at + i64::try_from(age).unwrap();
            let report =
                compare_verified_persona_root_distribution(&root, None, &pin, checked_at).unwrap();
            assert_eq!(report.pin_observation_age_seconds, age);
            assert_eq!(report.pin_observation_review_due, review_due);
            assert_eq!(report.pin_match, PersonaRootMatchStatus::Matched);
            assert_eq!(report.root_signature, PersonaRootSignatureStatus::Verified);
            assert_eq!(
                report.current_history_freshness,
                PersonaRootClaimStatus::NotEstablished
            );
            assert_distribution_nonclaims(&report);
        }
    }

    #[test]
    fn every_copied_card_field_is_bound_to_the_root_digest() {
        let (_, card) = card_fixture();

        let mut candidate = card.clone();
        candidate.schema = "urn:a-quo:persona-root-card:v2".to_owned();
        assert!(validate_persona_root_card(&candidate).is_err());

        let mut candidate = card.clone();
        candidate.canonicalization = "not-jcs".to_owned();
        assert!(validate_persona_root_card(&candidate).is_err());

        let mut candidate = card.clone();
        candidate.persona = "Substitute".to_owned();
        assert!(validate_persona_root_card(&candidate).is_err());

        let mut candidate = card.clone();
        candidate.persona_anchor = ANCHOR_TWO.to_owned();
        assert!(validate_persona_root_card(&candidate).is_err());

        let mut candidate = card.clone();
        candidate.root_version = 2;
        assert!(validate_persona_root_card(&candidate).is_err());

        let mut candidate = card.clone();
        candidate.issued_at += 1;
        assert!(validate_persona_root_card(&candidate).is_err());

        let mut candidate = card.clone();
        candidate.initial_key_fingerprint = "SHA256:not-the-key".to_owned();
        assert!(validate_persona_root_card(&candidate).is_err());

        let mut candidate = card.clone();
        candidate.root_statement_sha256 = "0".repeat(SHA256_HEX_BYTES);
        assert!(validate_persona_root_card(&candidate).is_err());

        let mut candidate = card;
        candidate.pin_uri.push('0');
        assert!(validate_persona_root_card(&candidate).is_err());
    }

    #[test]
    fn parsers_reject_unknown_malformed_noncanonical_and_oversized_input() {
        let (_, card) = card_fixture();
        let card_bytes = canonical_persona_root_card_bytes(&card).unwrap();
        let mut card_value: Value = serde_json::from_slice(&card_bytes).unwrap();
        card_value["unknown"] = json!(true);
        let unknown_card = serde_json_canonicalizer::to_vec(&card_value).unwrap();
        assert!(parse_persona_root_card_bytes(&unknown_card).is_err());
        let card_text = String::from_utf8(card_bytes.clone()).unwrap();
        let duplicate_card = format!(
            "{{\"schema\":\"{PERSONA_ROOT_CARD_SCHEMA}\",{}",
            &card_text[1..]
        );
        assert!(parse_persona_root_card_bytes(duplicate_card.as_bytes()).is_err());
        assert!(parse_persona_root_card_bytes(b"{").is_err());
        assert!(parse_persona_root_card_bytes(&serde_json::to_vec_pretty(&card).unwrap()).is_err());
        assert!(
            parse_persona_root_card_bytes(&vec![b' '; MAX_PERSONA_ROOT_CARD_BYTES + 1]).is_err()
        );

        let pin = new_persona_root_pin(
            &card.root_statement_sha256,
            card.issued_at,
            PersonaRootTrustBasis::SameChannelCopy,
            PersonaRootPinChannel::File,
            None,
        )
        .unwrap();
        let pin_bytes = canonical_persona_root_pin_bytes(&pin).unwrap();
        let mut pin_value: Value = serde_json::from_slice(&pin_bytes).unwrap();
        pin_value["unknown"] = json!(true);
        let unknown_pin = serde_json_canonicalizer::to_vec(&pin_value).unwrap();
        assert!(parse_persona_root_pin_bytes(&unknown_pin).is_err());
        let pin_text = String::from_utf8(pin_bytes.clone()).unwrap();
        let duplicate_pin = format!(
            "{{\"schema\":\"{PERSONA_ROOT_PIN_SCHEMA}\",{}",
            &pin_text[1..]
        );
        assert!(parse_persona_root_pin_bytes(duplicate_pin.as_bytes()).is_err());
        assert!(parse_persona_root_pin_bytes(b"[").is_err());
        assert!(parse_persona_root_pin_bytes(&serde_json::to_vec_pretty(&pin).unwrap()).is_err());
        assert!(parse_persona_root_pin_bytes(&vec![b' '; MAX_PERSONA_ROOT_PIN_BYTES + 1]).is_err());
    }

    #[test]
    fn digest_and_time_bounds_fail_closed() {
        let (root, card) = card_fixture();
        for malformed in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            assert!(persona_root_pin_uri(&malformed).is_err());
            assert!(
                new_persona_root_pin(
                    &malformed,
                    card.issued_at,
                    PersonaRootTrustBasis::TrustOnFirstUse,
                    PersonaRootPinChannel::File,
                    None,
                )
                .is_err()
            );
        }
        for malformed_uri in [
            card.root_statement_sha256.clone(),
            format!("aquo:persona-root-pin:v2:{}", card.root_statement_sha256),
            format!(" aquo:persona-root-pin:v1:{}", card.root_statement_sha256),
            format!("aquo:persona-root-pin:v1:{} ", card.root_statement_sha256),
            format!(
                "aquo:persona-root-pin:v1:{}?source=qr",
                card.root_statement_sha256
            ),
            format!(
                "aquo:persona-root-pin:v1:{}#fragment",
                card.root_statement_sha256
            ),
            format!(
                "aquo%3Apersona-root-pin%3Av1%3A{}",
                card.root_statement_sha256
            ),
            format!("aquo:root:v1:{}", card.root_statement_sha256),
            format!(
                "{}{}extra",
                PERSONA_ROOT_PIN_URI_PREFIX, card.root_statement_sha256
            ),
            format!(
                "{}{}0",
                PERSONA_ROOT_PIN_URI_PREFIX, card.root_statement_sha256
            ),
            format!(
                "{}{}",
                PERSONA_ROOT_PIN_URI_PREFIX,
                card.root_statement_sha256.to_uppercase()
            ),
        ] {
            assert!(parse_persona_root_pin_uri(&malformed_uri).is_err());
        }

        for invalid_time in [-1, MAX_JCS_SAFE_INTEGER + 1] {
            assert!(
                new_persona_root_pin(
                    &card.root_statement_sha256,
                    invalid_time,
                    PersonaRootTrustBasis::TrustOnFirstUse,
                    PersonaRootPinChannel::File,
                    None,
                )
                .is_err()
            );
        }
        assert!(
            new_persona_root_pin(
                &card.root_statement_sha256,
                card.issued_at,
                PersonaRootTrustBasis::TrustOnFirstUse,
                PersonaRootPinChannel::File,
                Some(&"A".repeat(64)),
            )
            .is_err()
        );

        let pin = new_persona_root_pin(
            &card.root_statement_sha256,
            card.issued_at + 10,
            PersonaRootTrustBasis::TrustOnFirstUse,
            PersonaRootPinChannel::File,
            None,
        )
        .unwrap();
        assert!(
            compare_verified_persona_root_distribution(
                &root,
                Some(&card),
                &pin,
                card.issued_at + 9,
            )
            .is_err()
        );

        let mut future_card = card;
        future_card.issued_at = MAX_JCS_SAFE_INTEGER + 1;
        assert!(validate_persona_root_card(&future_card).is_err());
    }

    #[test]
    fn valid_same_label_substitute_root_is_reported_not_promoted() {
        let (root_one, card_one) = card_fixture();
        let root_two = verified_root(
            ANCHOR_TWO,
            &root_one.statement.persona,
            root_one.statement.issued_at + 1,
            KEY_TWO,
        );
        let card_two = persona_root_card_from_verified_root(&root_two).unwrap();
        let pin_one = new_persona_root_pin(
            &card_one.root_statement_sha256,
            root_one.statement.issued_at + 10,
            PersonaRootTrustBasis::OutOfBandUserConfirmed,
            PersonaRootPinChannel::InPerson,
            None,
        )
        .unwrap();

        let candidate_report = compare_verified_persona_root_distribution(
            &root_two,
            Some(&card_two),
            &pin_one,
            root_one.statement.issued_at + 20,
        )
        .unwrap();
        assert_eq!(candidate_report.card_match, PersonaRootMatchStatus::Matched);
        assert_eq!(
            candidate_report.pin_match,
            PersonaRootMatchStatus::Mismatched
        );
        assert_eq!(candidate_report.late_first_contact, None);
        assert_eq!(candidate_report.first_contact_delay_seconds, None);
        assert_eq!(
            candidate_report.channel_independence,
            PersonaRootChannelIndependence::UserReportedSeparate
        );
        assert_eq!(
            candidate_report.current_history_freshness,
            PersonaRootClaimStatus::NotEstablished
        );
        assert_distribution_nonclaims(&candidate_report);

        let substituted_card_report = compare_verified_persona_root_distribution(
            &root_two,
            Some(&card_one),
            &pin_one,
            root_one.statement.issued_at + 20,
        )
        .unwrap();
        assert_eq!(
            substituted_card_report.card_match,
            PersonaRootMatchStatus::Mismatched
        );
        assert_eq!(
            substituted_card_report.pin_match,
            PersonaRootMatchStatus::Mismatched
        );
    }

    #[test]
    fn trust_basis_and_channel_cannot_claim_verified_independence() {
        let (_, card) = card_fixture();
        let cases = [
            (
                PersonaRootTrustBasis::TrustOnFirstUse,
                PersonaRootPinChannel::InPerson,
                PersonaRootTrustBasisSource::VerifierFirstObservation,
                PersonaRootChannelIndependence::NotEstablished,
            ),
            (
                PersonaRootTrustBasis::SameChannelCopy,
                PersonaRootPinChannel::Voice,
                PersonaRootTrustBasisSource::PublisherCandidateChannel,
                PersonaRootChannelIndependence::NotEstablished,
            ),
            (
                PersonaRootTrustBasis::OutOfBandUserConfirmed,
                PersonaRootPinChannel::File,
                PersonaRootTrustBasisSource::VerifierUserConfirmation,
                PersonaRootChannelIndependence::UserReportedSeparate,
            ),
        ];

        for (basis, channel, expected_source, expected_independence) in cases {
            let pin = new_persona_root_pin(
                &card.root_statement_sha256,
                card.issued_at,
                basis,
                channel,
                None,
            )
            .unwrap();
            let report = validate_persona_root_pin(&pin).unwrap();
            assert_eq!(report.trust_basis_source, expected_source);
            assert_eq!(report.channel_independence, expected_independence);
            assert_eq!(
                report.provenance_assurance,
                PersonaRootProvenanceAssurance::UserRecordedNotCryptographicallyVerified
            );
        }

        let mut card_value = serde_json::to_value(&card).unwrap();
        card_value["trust_basis"] = json!("out_of_band_user_confirmed");
        let injected = serde_json_canonicalizer::to_vec(&card_value).unwrap();
        assert!(parse_persona_root_card_bytes(&injected).is_err());
    }

    #[test]
    fn forged_verified_root_wrapper_is_rejected_before_card_creation() {
        let (root, _) = card_fixture();
        let mut wrong_digest = root.clone();
        wrong_digest.root_statement_sha256 = "0".repeat(64);
        assert!(persona_root_card_from_verified_root(&wrong_digest).is_err());

        let mut wrong_public_key = root;
        wrong_public_key.initial_public_key = KEY_TWO.to_owned();
        assert!(persona_root_card_from_verified_root(&wrong_public_key).is_err());
    }
}
