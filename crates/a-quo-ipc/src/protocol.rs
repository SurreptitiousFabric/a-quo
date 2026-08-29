use std::path::Path;

use a_quo_display::contains_unsafe_display_characters;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;
use uuid::Uuid;

const MAGIC: [u8; 8] = *b"AQUOIPC\0";
const HEADER_BYTES: usize = 20;
const ARTIFACT_REQUEST_PREFIX_BYTES: usize = 6;
const DOMAIN_REQUEST_PREFIX_BYTES: usize = 4;
const PERSONA_TRANSITION_REQUEST_PREFIX_BYTES: usize = 80;
const RECOVERY_PARTICIPATION_REQUEST_PREFIX_BYTES: usize = 120;
const RESPONSE_PREFIX_BYTES: usize = 4;
const MESSAGE_SIGN_REQUEST: u16 = 1;
const MESSAGE_SIGN_APPROVED: u16 = 2;
const MESSAGE_SIGN_REJECTED: u16 = 3;
const MESSAGE_DOMAIN_SIGN_REQUEST: u16 = 4;
const MESSAGE_PERSONA_ROOT_SIGN_REQUEST: u16 = 5;
const MESSAGE_PERSONA_TRANSITION_SIGN_REQUEST: u16 = 6;
const MESSAGE_RECOVERY_PARTICIPATION_REQUEST: u16 = 7;
const FLAGS_NONE: u16 = 0;
const MAX_ARTIFACT_REQUEST_PAYLOAD_BYTES: usize =
    ARTIFACT_REQUEST_PREFIX_BYTES + MAX_PERSONA_ID_BYTES + MAX_ARTIFACT_LABEL_BYTES;
const MAX_DOMAIN_REQUEST_PAYLOAD_BYTES: usize = DOMAIN_REQUEST_PREFIX_BYTES + MAX_PERSONA_ID_BYTES;
const MAX_PERSONA_TRANSITION_REQUEST_PAYLOAD_BYTES: usize = PERSONA_TRANSITION_REQUEST_PREFIX_BYTES
    + MAX_PERSONA_ID_BYTES
    + MAX_NEXT_SIGNING_REFERENCE_BYTES;
const MAX_RECOVERY_PARTICIPATION_REQUEST_PAYLOAD_BYTES: usize =
    RECOVERY_PARTICIPATION_REQUEST_PREFIX_BYTES
        + MAX_RECOVERY_PARTICIPANT_SIGNING_REFERENCE_BYTES
        + MAX_RECOVERY_PARTICIPANT_PUBLIC_KEY_BYTES;
const MAX_ARTIFACT_OR_DOMAIN_REQUEST_PAYLOAD_BYTES: usize =
    if MAX_ARTIFACT_REQUEST_PAYLOAD_BYTES > MAX_DOMAIN_REQUEST_PAYLOAD_BYTES {
        MAX_ARTIFACT_REQUEST_PAYLOAD_BYTES
    } else {
        MAX_DOMAIN_REQUEST_PAYLOAD_BYTES
    };
const MAX_EXISTING_REQUEST_PAYLOAD_BYTES: usize = if MAX_ARTIFACT_OR_DOMAIN_REQUEST_PAYLOAD_BYTES
    > MAX_PERSONA_TRANSITION_REQUEST_PAYLOAD_BYTES
{
    MAX_ARTIFACT_OR_DOMAIN_REQUEST_PAYLOAD_BYTES
} else {
    MAX_PERSONA_TRANSITION_REQUEST_PAYLOAD_BYTES
};
const MAX_REQUEST_PAYLOAD_BYTES: usize =
    if MAX_EXISTING_REQUEST_PAYLOAD_BYTES > MAX_RECOVERY_PARTICIPATION_REQUEST_PAYLOAD_BYTES {
        MAX_EXISTING_REQUEST_PAYLOAD_BYTES
    } else {
        MAX_RECOVERY_PARTICIPATION_REQUEST_PAYLOAD_BYTES
    };

pub(crate) const MAX_REQUEST_PACKET_BYTES: usize = HEADER_BYTES + MAX_REQUEST_PAYLOAD_BYTES;
pub(crate) const MAX_RESPONSE_PACKET_BYTES: usize = HEADER_BYTES + RESPONSE_PREFIX_BYTES;
pub const MAX_PERSONA_ID_BYTES: usize = 64;
pub const MAX_ARTIFACT_LABEL_BYTES: usize = 256;
pub const MAX_NEXT_SIGNING_REFERENCE_BYTES: usize = 4_096;
pub const MAX_RECOVERY_PARTICIPANT_SIGNING_REFERENCE_BYTES: usize = 4_096;
pub const MAX_RECOVERY_PARTICIPANT_PUBLIC_KEY_BYTES: usize = 16_384;
pub const MAX_RECOVERY_POLICY_VERSION: u32 = 1_024;
pub const MIN_RECOVERY_THRESHOLD: u32 = 2;
pub const MAX_RECOVERY_THRESHOLD: u32 = 32;
pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("consent message is shorter than the fixed header")]
    TruncatedHeader,

    #[error("invalid consent protocol magic")]
    InvalidMagic,

    #[error("unsupported consent protocol version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },

    #[error("unsupported consent message type {0}")]
    UnsupportedMessageType(u16),

    #[error("unsupported consent message flags 0x{0:04x}")]
    UnsupportedFlags(u16),

    #[error("consent payload exceeds its fixed limit")]
    PayloadTooLarge,

    #[error("consent message payload is truncated")]
    TruncatedPayload,

    #[error("consent message contains trailing bytes")]
    TrailingBytes,

    #[error("consent payload has an invalid fixed layout")]
    InvalidLayout,

    #[error("unsupported artifact kind {0}")]
    UnsupportedArtifactKind(u8),

    #[error("unsupported transition key provider {0}")]
    UnsupportedTransitionKeyProvider(u8),

    #[error("unsupported recovery participant key provider {0}")]
    UnsupportedRecoveryParticipantKeyProvider(u8),

    #[error("invalid persona ID: {0}")]
    InvalidPersonaId(String),

    #[error("invalid artifact label: {0}")]
    InvalidArtifactLabel(String),

    #[error("invalid transition sequence: {0}")]
    InvalidTransitionSequence(String),

    #[error("invalid next signing reference: {0}")]
    InvalidNextSigningReference(String),

    #[error("invalid recovery participant signing reference: {0}")]
    InvalidRecoveryParticipantSigningReference(String),

    #[error("invalid recovery participant public key: {0}")]
    InvalidRecoveryParticipantPublicKey(String),

    #[error("invalid recovery policy pin: {0}")]
    InvalidRecoveryPolicyPin(String),

    #[error("invalid recovery head pin: {0}")]
    InvalidRecoveryHeadPin(String),

    #[error("unsupported rejection code {0}")]
    UnsupportedRejectionCode(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArtifactKind {
    Generic = 1,
    SoftwareRelease = 2,
    Article = 3,
    Image = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransitionKeyProvider {
    OpensshFile = 1,
    SshAgent = 2,
    Fido2 = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecoveryParticipantKeyProvider {
    OpensshFile = 1,
    SshAgent = 2,
    Fido2 = 3,
}

impl RecoveryParticipantKeyProvider {
    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::OpensshFile),
            2 => Ok(Self::SshAgent),
            3 => Ok(Self::Fido2),
            _ => Err(ProtocolError::UnsupportedRecoveryParticipantKeyProvider(
                value,
            )),
        }
    }
}

impl TransitionKeyProvider {
    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::OpensshFile),
            2 => Ok(Self::SshAgent),
            3 => Ok(Self::Fido2),
            _ => Err(ProtocolError::UnsupportedTransitionKeyProvider(value)),
        }
    }
}

impl ArtifactKind {
    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Generic),
            2 => Ok(Self::SoftwareRelease),
            3 => Ok(Self::Article),
            4 => Ok(Self::Image),
            _ => Err(ProtocolError::UnsupportedArtifactKind(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignRequest {
    pub persona_id: Option<String>,
    pub subject: SignSubject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignSubject {
    Artifact {
        artifact_kind: ArtifactKind,
        artifact_label: String,
    },
    DomainControl,
    PersonaRoot,
    PersonaTransition {
        expected_sequence: u32,
        expected_root_sha256: [u8; 32],
        expected_previous_transition_sha256: Option<[u8; 32]>,
        next_key_provider: TransitionKeyProvider,
        next_signing_reference: String,
    },
    RecoveryParticipation {
        participant_key_provider: RecoveryParticipantKeyProvider,
        participant_signing_reference: String,
        participant_public_key: String,
        expected_root_sha256: [u8; 32],
        expected_policy_version: u32,
        expected_policy_sha256: [u8; 32],
        expected_policy_threshold: u32,
        expected_previous_head_sequence: u32,
        expected_previous_head_sha256: Option<[u8; 32]>,
    },
}

impl SignRequest {
    pub fn new(
        persona_id: impl Into<String>,
        artifact_kind: ArtifactKind,
        artifact_label: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            persona_id: Some(persona_id.into()),
            subject: SignSubject::Artifact {
                artifact_kind,
                artifact_label: artifact_label.into(),
            },
        };
        validate_request(&request)?;
        Ok(request)
    }

    pub fn new_domain(persona_id: impl Into<String>) -> Result<Self, ProtocolError> {
        let request = Self {
            persona_id: Some(persona_id.into()),
            subject: SignSubject::DomainControl,
        };
        validate_request(&request)?;
        Ok(request)
    }

    pub fn new_persona_root(persona_id: impl Into<String>) -> Result<Self, ProtocolError> {
        let request = Self {
            persona_id: Some(persona_id.into()),
            subject: SignSubject::PersonaRoot,
        };
        validate_request(&request)?;
        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_persona_transition(
        persona_id: impl Into<String>,
        expected_sequence: u32,
        expected_root_sha256: [u8; 32],
        expected_previous_transition_sha256: Option<[u8; 32]>,
        next_key_provider: TransitionKeyProvider,
        next_signing_reference: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            persona_id: Some(persona_id.into()),
            subject: SignSubject::PersonaTransition {
                expected_sequence,
                expected_root_sha256,
                expected_previous_transition_sha256,
                next_key_provider,
                next_signing_reference: next_signing_reference.into(),
            },
        };
        validate_request(&request)?;
        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_recovery_participation(
        participant_key_provider: RecoveryParticipantKeyProvider,
        participant_signing_reference: impl Into<String>,
        participant_public_key: impl Into<String>,
        expected_root_sha256: [u8; 32],
        expected_policy_version: u32,
        expected_policy_sha256: [u8; 32],
        expected_policy_threshold: u32,
        expected_previous_head_sequence: u32,
        expected_previous_head_sha256: Option<[u8; 32]>,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            persona_id: None,
            subject: SignSubject::RecoveryParticipation {
                participant_key_provider,
                participant_signing_reference: participant_signing_reference.into(),
                participant_public_key: participant_public_key.into(),
                expected_root_sha256,
                expected_policy_version,
                expected_policy_sha256,
                expected_policy_threshold,
                expected_previous_head_sequence,
                expected_previous_head_sha256,
            },
        };
        validate_request(&request)?;
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RejectionCode {
    UserDeclined = 1,
    Cancelled = 2,
    InvalidRequest = 3,
    PersonaUnavailable = 4,
    SignerUnavailable = 5,
    InternalError = 6,
    ConsentUnavailable = 7,
}

impl RejectionCode {
    fn decode(value: u16) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::UserDeclined),
            2 => Ok(Self::Cancelled),
            3 => Ok(Self::InvalidRequest),
            4 => Ok(Self::PersonaUnavailable),
            5 => Ok(Self::SignerUnavailable),
            6 => Ok(Self::InternalError),
            7 => Ok(Self::ConsentUnavailable),
            _ => Err(ProtocolError::UnsupportedRejectionCode(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignResponse {
    /// The transport must attach exactly one sealed proof descriptor.
    Approved,
    /// Rejections never carry a descriptor or attacker-controlled text.
    Rejected(RejectionCode),
}

pub fn encode_sign_request(request: &SignRequest) -> Result<Vec<u8>, ProtocolError> {
    validate_request(request)?;
    match &request.subject {
        SignSubject::Artifact {
            artifact_kind,
            artifact_label,
        } => encode_artifact_sign_request(request, *artifact_kind, artifact_label),
        SignSubject::DomainControl => encode_domain_sign_request(request),
        SignSubject::PersonaRoot => encode_persona_root_sign_request(request),
        SignSubject::PersonaTransition { .. } => encode_persona_transition_sign_request(request),
        SignSubject::RecoveryParticipation { .. } => encode_recovery_participation_request(request),
    }
}

fn encode_artifact_sign_request(
    request: &SignRequest,
    artifact_kind: ArtifactKind,
    artifact_label: &str,
) -> Result<Vec<u8>, ProtocolError> {
    let persona = required_persona_id(request)?.as_bytes();
    let label = artifact_label.as_bytes();
    let payload_len = ARTIFACT_REQUEST_PREFIX_BYTES + persona.len() + label.len();
    let mut message = encode_header(MESSAGE_SIGN_REQUEST, payload_len);
    message.push(artifact_kind as u8);
    message.push(0);
    message.extend_from_slice(&(persona.len() as u16).to_be_bytes());
    message.extend_from_slice(&(label.len() as u16).to_be_bytes());
    message.extend_from_slice(persona);
    message.extend_from_slice(label);
    Ok(message)
}

fn encode_domain_sign_request(request: &SignRequest) -> Result<Vec<u8>, ProtocolError> {
    encode_single_persona_request(request, MESSAGE_DOMAIN_SIGN_REQUEST)
}

fn encode_persona_root_sign_request(request: &SignRequest) -> Result<Vec<u8>, ProtocolError> {
    encode_single_persona_request(request, MESSAGE_PERSONA_ROOT_SIGN_REQUEST)
}

fn encode_persona_transition_sign_request(request: &SignRequest) -> Result<Vec<u8>, ProtocolError> {
    let SignSubject::PersonaTransition {
        expected_sequence,
        expected_root_sha256,
        expected_previous_transition_sha256,
        next_key_provider,
        next_signing_reference,
    } = &request.subject
    else {
        return Err(ProtocolError::InvalidLayout);
    };
    let persona = required_persona_id(request)?.as_bytes();
    let locator = next_signing_reference.as_bytes();
    let payload_len = PERSONA_TRANSITION_REQUEST_PREFIX_BYTES
        .checked_add(persona.len())
        .and_then(|length| length.checked_add(locator.len()))
        .ok_or(ProtocolError::PayloadTooLarge)?;
    let mut message = encode_header(MESSAGE_PERSONA_TRANSITION_SIGN_REQUEST, payload_len);
    message.push(*next_key_provider as u8);
    message.push(u8::from(expected_previous_transition_sha256.is_some()));
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&expected_sequence.to_be_bytes());
    message.extend_from_slice(&(persona.len() as u16).to_be_bytes());
    message.extend_from_slice(&(locator.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u32.to_be_bytes());
    message.extend_from_slice(expected_root_sha256);
    message.extend_from_slice(&expected_previous_transition_sha256.unwrap_or([0_u8; 32]));
    debug_assert_eq!(
        message.len(),
        HEADER_BYTES + PERSONA_TRANSITION_REQUEST_PREFIX_BYTES
    );
    message.extend_from_slice(persona);
    message.extend_from_slice(locator);
    Ok(message)
}

fn encode_recovery_participation_request(request: &SignRequest) -> Result<Vec<u8>, ProtocolError> {
    let SignSubject::RecoveryParticipation {
        participant_key_provider,
        participant_signing_reference,
        participant_public_key,
        expected_root_sha256,
        expected_policy_version,
        expected_policy_sha256,
        expected_policy_threshold,
        expected_previous_head_sequence,
        expected_previous_head_sha256,
    } = &request.subject
    else {
        return Err(ProtocolError::InvalidLayout);
    };
    let locator = participant_signing_reference.as_bytes();
    let public_key = participant_public_key.as_bytes();
    let payload_len = RECOVERY_PARTICIPATION_REQUEST_PREFIX_BYTES
        .checked_add(locator.len())
        .and_then(|length| length.checked_add(public_key.len()))
        .ok_or(ProtocolError::PayloadTooLarge)?;
    let mut message = encode_header(MESSAGE_RECOVERY_PARTICIPATION_REQUEST, payload_len);
    message.push(*participant_key_provider as u8);
    message.push(u8::from(expected_previous_head_sha256.is_some()));
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&expected_policy_version.to_be_bytes());
    message.extend_from_slice(&expected_policy_threshold.to_be_bytes());
    message.extend_from_slice(&expected_previous_head_sequence.to_be_bytes());
    message.extend_from_slice(&(locator.len() as u16).to_be_bytes());
    message.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u32.to_be_bytes());
    message.extend_from_slice(expected_root_sha256);
    message.extend_from_slice(expected_policy_sha256);
    message.extend_from_slice(&expected_previous_head_sha256.unwrap_or([0_u8; 32]));
    debug_assert_eq!(
        message.len(),
        HEADER_BYTES + RECOVERY_PARTICIPATION_REQUEST_PREFIX_BYTES
    );
    message.extend_from_slice(locator);
    message.extend_from_slice(public_key);
    Ok(message)
}

fn encode_single_persona_request(
    request: &SignRequest,
    message_type: u16,
) -> Result<Vec<u8>, ProtocolError> {
    let persona = required_persona_id(request)?.as_bytes();
    let payload_len = DOMAIN_REQUEST_PREFIX_BYTES + persona.len();
    let mut message = encode_header(message_type, payload_len);
    message.extend_from_slice(&(persona.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(persona);
    Ok(message)
}

pub fn decode_sign_request(message: &[u8]) -> Result<SignRequest, ProtocolError> {
    match decode_common_header(message)? {
        MESSAGE_SIGN_REQUEST => decode_artifact_sign_request(message),
        MESSAGE_DOMAIN_SIGN_REQUEST => decode_domain_sign_request(message),
        MESSAGE_PERSONA_ROOT_SIGN_REQUEST => decode_persona_root_sign_request(message),
        MESSAGE_PERSONA_TRANSITION_SIGN_REQUEST => decode_persona_transition_sign_request(message),
        MESSAGE_RECOVERY_PARTICIPATION_REQUEST => decode_recovery_participation_request(message),
        other => Err(ProtocolError::UnsupportedMessageType(other)),
    }
}

fn decode_artifact_sign_request(message: &[u8]) -> Result<SignRequest, ProtocolError> {
    let payload = decode_header(
        message,
        MESSAGE_SIGN_REQUEST,
        MAX_ARTIFACT_REQUEST_PAYLOAD_BYTES,
    )?;
    if payload.len() < ARTIFACT_REQUEST_PREFIX_BYTES || payload[1] != 0 {
        return Err(ProtocolError::InvalidLayout);
    }

    let artifact_kind = ArtifactKind::decode(payload[0])?;
    let persona_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    let label_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    let expected = ARTIFACT_REQUEST_PREFIX_BYTES
        .checked_add(persona_len)
        .and_then(|length| length.checked_add(label_len))
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }

    let persona_end = ARTIFACT_REQUEST_PREFIX_BYTES + persona_len;
    let persona_id = std::str::from_utf8(&payload[ARTIFACT_REQUEST_PREFIX_BYTES..persona_end])
        .map_err(|_| ProtocolError::InvalidPersonaId("it must be UTF-8".to_owned()))?
        .to_owned();
    let artifact_label = std::str::from_utf8(&payload[persona_end..])
        .map_err(|_| ProtocolError::InvalidArtifactLabel("it must be UTF-8".to_owned()))?
        .to_owned();
    SignRequest::new(persona_id, artifact_kind, artifact_label)
}

fn decode_domain_sign_request(message: &[u8]) -> Result<SignRequest, ProtocolError> {
    let persona_id = decode_single_persona_request(message, MESSAGE_DOMAIN_SIGN_REQUEST)?;
    SignRequest::new_domain(persona_id)
}

fn decode_persona_root_sign_request(message: &[u8]) -> Result<SignRequest, ProtocolError> {
    let persona_id = decode_single_persona_request(message, MESSAGE_PERSONA_ROOT_SIGN_REQUEST)?;
    SignRequest::new_persona_root(persona_id)
}

fn decode_persona_transition_sign_request(message: &[u8]) -> Result<SignRequest, ProtocolError> {
    let payload = decode_header(
        message,
        MESSAGE_PERSONA_TRANSITION_SIGN_REQUEST,
        MAX_PERSONA_TRANSITION_REQUEST_PAYLOAD_BYTES,
    )?;
    if payload.len() < PERSONA_TRANSITION_REQUEST_PREFIX_BYTES
        || payload[2..4] != [0, 0]
        || payload[12..16] != [0, 0, 0, 0]
        || payload[1] > 1
    {
        return Err(ProtocolError::InvalidLayout);
    }
    let next_key_provider = TransitionKeyProvider::decode(payload[0])?;
    let expected_sequence = read_u32(payload, 4);
    let persona_len = usize::from(read_u16(payload, 8));
    let locator_len = usize::from(read_u16(payload, 10));
    let expected = PERSONA_TRANSITION_REQUEST_PREFIX_BYTES
        .checked_add(persona_len)
        .and_then(|length| length.checked_add(locator_len))
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }

    let mut expected_root_sha256 = [0_u8; 32];
    expected_root_sha256.copy_from_slice(&payload[16..48]);
    let mut previous = [0_u8; 32];
    previous.copy_from_slice(&payload[48..80]);
    let expected_previous_transition_sha256 = match payload[1] {
        0 if previous == [0_u8; 32] => None,
        0 => return Err(ProtocolError::InvalidLayout),
        1 => Some(previous),
        _ => unreachable!("presence byte was checked"),
    };

    let persona_end = PERSONA_TRANSITION_REQUEST_PREFIX_BYTES + persona_len;
    let persona_id =
        std::str::from_utf8(&payload[PERSONA_TRANSITION_REQUEST_PREFIX_BYTES..persona_end])
            .map_err(|_| ProtocolError::InvalidPersonaId("it must be UTF-8".to_owned()))?
            .to_owned();
    let next_signing_reference = std::str::from_utf8(&payload[persona_end..])
        .map_err(|_| ProtocolError::InvalidNextSigningReference("it must be UTF-8".to_owned()))?
        .to_owned();
    SignRequest::new_persona_transition(
        persona_id,
        expected_sequence,
        expected_root_sha256,
        expected_previous_transition_sha256,
        next_key_provider,
        next_signing_reference,
    )
}

fn decode_recovery_participation_request(message: &[u8]) -> Result<SignRequest, ProtocolError> {
    let payload = decode_header(
        message,
        MESSAGE_RECOVERY_PARTICIPATION_REQUEST,
        MAX_RECOVERY_PARTICIPATION_REQUEST_PAYLOAD_BYTES,
    )?;
    if payload.len() < RECOVERY_PARTICIPATION_REQUEST_PREFIX_BYTES
        || payload[2..4] != [0, 0]
        || payload[20..24] != [0, 0, 0, 0]
        || payload[1] > 1
    {
        return Err(ProtocolError::InvalidLayout);
    }
    let participant_key_provider = RecoveryParticipantKeyProvider::decode(payload[0])?;
    let expected_policy_version = read_u32(payload, 4);
    let expected_policy_threshold = read_u32(payload, 8);
    let expected_previous_head_sequence = read_u32(payload, 12);
    let locator_len = usize::from(read_u16(payload, 16));
    let public_key_len = usize::from(read_u16(payload, 18));
    let expected = RECOVERY_PARTICIPATION_REQUEST_PREFIX_BYTES
        .checked_add(locator_len)
        .and_then(|length| length.checked_add(public_key_len))
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }

    let mut expected_root_sha256 = [0_u8; 32];
    expected_root_sha256.copy_from_slice(&payload[24..56]);
    let mut expected_policy_sha256 = [0_u8; 32];
    expected_policy_sha256.copy_from_slice(&payload[56..88]);
    let mut previous = [0_u8; 32];
    previous.copy_from_slice(&payload[88..120]);
    let expected_previous_head_sha256 = match payload[1] {
        0 if previous == [0_u8; 32] => None,
        0 => return Err(ProtocolError::InvalidLayout),
        1 => Some(previous),
        _ => unreachable!("presence byte was checked"),
    };

    let locator_end = RECOVERY_PARTICIPATION_REQUEST_PREFIX_BYTES + locator_len;
    let participant_signing_reference =
        std::str::from_utf8(&payload[RECOVERY_PARTICIPATION_REQUEST_PREFIX_BYTES..locator_end])
            .map_err(|_| {
                ProtocolError::InvalidRecoveryParticipantSigningReference(
                    "it must be UTF-8".to_owned(),
                )
            })?
            .to_owned();
    let participant_public_key = std::str::from_utf8(&payload[locator_end..])
        .map_err(|_| {
            ProtocolError::InvalidRecoveryParticipantPublicKey("it must be UTF-8".to_owned())
        })?
        .to_owned();
    SignRequest::new_recovery_participation(
        participant_key_provider,
        participant_signing_reference,
        participant_public_key,
        expected_root_sha256,
        expected_policy_version,
        expected_policy_sha256,
        expected_policy_threshold,
        expected_previous_head_sequence,
        expected_previous_head_sha256,
    )
}

fn decode_single_persona_request(
    message: &[u8],
    message_type: u16,
) -> Result<String, ProtocolError> {
    let payload = decode_header(message, message_type, MAX_DOMAIN_REQUEST_PAYLOAD_BYTES)?;
    if payload.len() < DOMAIN_REQUEST_PREFIX_BYTES || payload[2..4] != [0, 0] {
        return Err(ProtocolError::InvalidLayout);
    }
    let persona_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
    let expected = DOMAIN_REQUEST_PREFIX_BYTES
        .checked_add(persona_len)
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }
    std::str::from_utf8(&payload[DOMAIN_REQUEST_PREFIX_BYTES..])
        .map_err(|_| ProtocolError::InvalidPersonaId("it must be UTF-8".to_owned()))
        .map(ToOwned::to_owned)
}

pub fn encode_sign_response(response: SignResponse) -> Vec<u8> {
    match response {
        SignResponse::Approved => encode_header(MESSAGE_SIGN_APPROVED, 0),
        SignResponse::Rejected(code) => {
            let mut message = encode_header(MESSAGE_SIGN_REJECTED, RESPONSE_PREFIX_BYTES);
            message.extend_from_slice(&(code as u16).to_be_bytes());
            message.extend_from_slice(&0_u16.to_be_bytes());
            message
        }
    }
}

pub fn decode_sign_response(message: &[u8]) -> Result<SignResponse, ProtocolError> {
    let message_type = decode_common_header(message)?;
    match message_type {
        MESSAGE_SIGN_APPROVED => {
            let payload = decode_header(message, MESSAGE_SIGN_APPROVED, 0)?;
            debug_assert!(payload.is_empty());
            Ok(SignResponse::Approved)
        }
        MESSAGE_SIGN_REJECTED => {
            let payload = decode_header(message, MESSAGE_SIGN_REJECTED, RESPONSE_PREFIX_BYTES)?;
            if payload.len() != RESPONSE_PREFIX_BYTES || payload[2..] != [0, 0] {
                return Err(ProtocolError::InvalidLayout);
            }
            Ok(SignResponse::Rejected(RejectionCode::decode(
                u16::from_be_bytes([payload[0], payload[1]]),
            )?))
        }
        other => Err(ProtocolError::UnsupportedMessageType(other)),
    }
}

fn encode_header(message_type: u16, payload_len: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(HEADER_BYTES + payload_len);
    message.extend_from_slice(&MAGIC);
    message.extend_from_slice(&PROTOCOL_MAJOR.to_be_bytes());
    message.extend_from_slice(&PROTOCOL_MINOR.to_be_bytes());
    message.extend_from_slice(&message_type.to_be_bytes());
    message.extend_from_slice(&FLAGS_NONE.to_be_bytes());
    message.extend_from_slice(&(payload_len as u32).to_be_bytes());
    message
}

fn decode_common_header(message: &[u8]) -> Result<u16, ProtocolError> {
    if message.len() < HEADER_BYTES {
        return Err(ProtocolError::TruncatedHeader);
    }
    if message[..MAGIC.len()] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let major = u16::from_be_bytes([message[8], message[9]]);
    let minor = u16::from_be_bytes([message[10], message[11]]);
    if major != PROTOCOL_MAJOR || minor != PROTOCOL_MINOR {
        return Err(ProtocolError::UnsupportedVersion { major, minor });
    }
    let flags = u16::from_be_bytes([message[14], message[15]]);
    if flags != FLAGS_NONE {
        return Err(ProtocolError::UnsupportedFlags(flags));
    }
    Ok(u16::from_be_bytes([message[12], message[13]]))
}

fn decode_header(
    message: &[u8],
    expected_type: u16,
    maximum_payload: usize,
) -> Result<&[u8], ProtocolError> {
    let message_type = decode_common_header(message)?;
    if message_type != expected_type {
        return Err(ProtocolError::UnsupportedMessageType(message_type));
    }
    let payload_len =
        u32::from_be_bytes([message[16], message[17], message[18], message[19]]) as usize;
    if payload_len > maximum_payload {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let expected_len = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(ProtocolError::PayloadTooLarge)?;
    match message.len().cmp(&expected_len) {
        std::cmp::Ordering::Less => Err(ProtocolError::TruncatedPayload),
        std::cmp::Ordering::Greater => Err(ProtocolError::TrailingBytes),
        std::cmp::Ordering::Equal => Ok(&message[HEADER_BYTES..]),
    }
}

fn validate_request(request: &SignRequest) -> Result<(), ProtocolError> {
    let is_recovery_participation =
        matches!(request.subject, SignSubject::RecoveryParticipation { .. });
    match (&request.persona_id, is_recovery_participation) {
        (None, true) => {}
        (Some(_), true) => {
            return Err(ProtocolError::InvalidPersonaId(
                "recovery participation must not expose a coordinator-local persona UUID"
                    .to_owned(),
            ));
        }
        (None, false) => {
            return Err(ProtocolError::InvalidPersonaId(
                "this request purpose requires a local persona UUID".to_owned(),
            ));
        }
        (Some(persona_id), false) => {
            if persona_id.len() > MAX_PERSONA_ID_BYTES {
                return Err(ProtocolError::InvalidPersonaId(format!(
                    "it cannot exceed {MAX_PERSONA_ID_BYTES} bytes"
                )));
            }
            let parsed = Uuid::parse_str(persona_id)
                .map_err(|_| ProtocolError::InvalidPersonaId("expected a UUID".to_owned()))?;
            if parsed.to_string() != *persona_id {
                return Err(ProtocolError::InvalidPersonaId(
                    "expected the canonical lowercase UUID form".to_owned(),
                ));
            }
        }
    }

    if let SignSubject::Artifact { artifact_label, .. } = &request.subject {
        if artifact_label.is_empty() {
            return Err(ProtocolError::InvalidArtifactLabel(
                "it cannot be empty".to_owned(),
            ));
        }
        if artifact_label.len() > MAX_ARTIFACT_LABEL_BYTES {
            return Err(ProtocolError::InvalidArtifactLabel(format!(
                "it cannot exceed {MAX_ARTIFACT_LABEL_BYTES} UTF-8 bytes"
            )));
        }
        if artifact_label.trim() != artifact_label {
            return Err(ProtocolError::InvalidArtifactLabel(
                "leading and trailing whitespace are not allowed".to_owned(),
            ));
        }
        if contains_unsafe_display_characters(artifact_label) {
            return Err(ProtocolError::InvalidArtifactLabel(
                "control, line/paragraph separator, or default-ignorable Unicode characters are not allowed".to_owned(),
            ));
        }
    }
    if let SignSubject::PersonaTransition {
        expected_sequence,
        expected_previous_transition_sha256,
        next_signing_reference,
        ..
    } = &request.subject
    {
        if *expected_sequence == 0 {
            return Err(ProtocolError::InvalidTransitionSequence(
                "it must start at 1".to_owned(),
            ));
        }
        match (*expected_sequence, expected_previous_transition_sha256) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(ProtocolError::InvalidTransitionSequence(
                    "sequence 1 cannot name a previous transition digest".to_owned(),
                ));
            }
            (_, Some(_)) => {}
            (_, None) => {
                return Err(ProtocolError::InvalidTransitionSequence(
                    "sequences after 1 require a previous transition digest".to_owned(),
                ));
            }
        }
        validate_next_signing_reference(next_signing_reference)?;
    }
    if let SignSubject::RecoveryParticipation {
        participant_signing_reference,
        participant_public_key,
        expected_policy_version,
        expected_policy_threshold,
        expected_previous_head_sequence,
        expected_previous_head_sha256,
        ..
    } = &request.subject
    {
        validate_recovery_participant_signing_reference(participant_signing_reference)?;
        validate_recovery_participant_public_key(participant_public_key)?;
        if !(1..=MAX_RECOVERY_POLICY_VERSION).contains(expected_policy_version) {
            return Err(ProtocolError::InvalidRecoveryPolicyPin(format!(
                "version must be 1 through {MAX_RECOVERY_POLICY_VERSION}"
            )));
        }
        if !(MIN_RECOVERY_THRESHOLD..=MAX_RECOVERY_THRESHOLD).contains(expected_policy_threshold) {
            return Err(ProtocolError::InvalidRecoveryPolicyPin(format!(
                "threshold must be {MIN_RECOVERY_THRESHOLD} through {MAX_RECOVERY_THRESHOLD}"
            )));
        }
        match (
            *expected_previous_head_sequence,
            expected_previous_head_sha256,
        ) {
            (0, None) => {}
            (0, Some(_)) => {
                return Err(ProtocolError::InvalidRecoveryHeadPin(
                    "the root head cannot name a transition digest".to_owned(),
                ));
            }
            (_, Some(_)) => {}
            (_, None) => {
                return Err(ProtocolError::InvalidRecoveryHeadPin(
                    "a transition head requires its exact digest".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn required_persona_id(request: &SignRequest) -> Result<&str, ProtocolError> {
    request
        .persona_id
        .as_deref()
        .ok_or_else(|| ProtocolError::InvalidPersonaId("missing local persona UUID".to_owned()))
}

fn validate_next_signing_reference(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidNextSigningReference(
            "it cannot be empty".to_owned(),
        ));
    }
    if value.len() > MAX_NEXT_SIGNING_REFERENCE_BYTES {
        return Err(ProtocolError::InvalidNextSigningReference(format!(
            "it cannot exceed {MAX_NEXT_SIGNING_REFERENCE_BYTES} UTF-8 bytes"
        )));
    }
    if value.trim() != value {
        return Err(ProtocolError::InvalidNextSigningReference(
            "leading and trailing whitespace are not allowed".to_owned(),
        ));
    }
    if !Path::new(value).is_absolute() {
        return Err(ProtocolError::InvalidNextSigningReference(
            "it must be an absolute path".to_owned(),
        ));
    }
    if contains_unsafe_display_characters(value) {
        return Err(ProtocolError::InvalidNextSigningReference(
            "control, line/paragraph separator, or default-ignorable Unicode characters are not allowed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_recovery_participant_signing_reference(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidRecoveryParticipantSigningReference(
            "it cannot be empty".to_owned(),
        ));
    }
    if value.len() > MAX_RECOVERY_PARTICIPANT_SIGNING_REFERENCE_BYTES {
        return Err(ProtocolError::InvalidRecoveryParticipantSigningReference(
            format!(
                "it cannot exceed {MAX_RECOVERY_PARTICIPANT_SIGNING_REFERENCE_BYTES} UTF-8 bytes"
            ),
        ));
    }
    if value.trim() != value {
        return Err(ProtocolError::InvalidRecoveryParticipantSigningReference(
            "leading and trailing whitespace are not allowed".to_owned(),
        ));
    }
    if !Path::new(value).is_absolute() {
        return Err(ProtocolError::InvalidRecoveryParticipantSigningReference(
            "it must be an absolute path".to_owned(),
        ));
    }
    if contains_unsafe_display_characters(value) {
        return Err(ProtocolError::InvalidRecoveryParticipantSigningReference(
            "control, line/paragraph separator, or default-ignorable Unicode characters are not allowed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_recovery_participant_public_key(value: &str) -> Result<(), ProtocolError> {
    let invalid =
        |reason: &str| ProtocolError::InvalidRecoveryParticipantPublicKey(reason.to_owned());
    if value.is_empty() {
        return Err(invalid("it cannot be empty"));
    }
    if value.len() > MAX_RECOVERY_PARTICIPANT_PUBLIC_KEY_BYTES {
        return Err(invalid(&format!(
            "it cannot exceed {MAX_RECOVERY_PARTICIPANT_PUBLIC_KEY_BYTES} UTF-8 bytes"
        )));
    }
    if contains_unsafe_display_characters(value) {
        return Err(invalid(
            "control, line/paragraph separator, or default-ignorable Unicode characters are not allowed",
        ));
    }
    let Some((algorithm, encoded)) = value.split_once(' ') else {
        return Err(invalid("expected normalized OpenSSH public-key text"));
    };
    if algorithm.is_empty()
        || encoded.is_empty()
        || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
        || value != format!("{algorithm} {encoded}")
    {
        return Err(invalid(
            "expected exactly an algorithm and key blob separated by one ASCII space",
        ));
    }
    let blob = STANDARD
        .decode(encoded)
        .map_err(|_| invalid("key data must use canonical Base64"))?;
    if STANDARD.encode(&blob) != encoded {
        return Err(invalid("key data must use canonical Base64"));
    }
    let length_bytes = blob
        .get(..4)
        .ok_or_else(|| invalid("truncated OpenSSH key blob"))?;
    let algorithm_len = u32::from_be_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]) as usize;
    let algorithm_end = 4_usize
        .checked_add(algorithm_len)
        .ok_or_else(|| invalid("invalid OpenSSH algorithm length"))?;
    if blob.get(4..algorithm_end) != Some(algorithm.as_bytes()) {
        return Err(invalid(
            "algorithm label does not match the OpenSSH key blob",
        ));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SignRequest {
        SignRequest::new(
            "8b2fc4ef-ef26-48df-b849-8bc4e595e96c",
            ArtifactKind::SoftwareRelease,
            "a-quo-0.1.0.tar.zst",
        )
        .unwrap()
    }

    fn transition_request(sequence: u32, previous: Option<[u8; 32]>) -> SignRequest {
        SignRequest::new_persona_transition(
            "8b2fc4ef-ef26-48df-b849-8bc4e595e96c",
            sequence,
            [0x11; 32],
            previous,
            TransitionKeyProvider::Fido2,
            "/run/user/1000/a-quo/next-key",
        )
        .unwrap()
    }

    fn participant_public_key(byte: u8) -> String {
        let algorithm = b"ssh-ed25519";
        let mut blob = Vec::new();
        blob.extend_from_slice(&(algorithm.len() as u32).to_be_bytes());
        blob.extend_from_slice(algorithm);
        blob.extend_from_slice(&32_u32.to_be_bytes());
        blob.extend_from_slice(&[byte; 32]);
        format!("ssh-ed25519 {}", STANDARD.encode(blob))
    }

    fn recovery_participation_request(
        previous_head_sequence: u32,
        previous_head_sha256: Option<[u8; 32]>,
    ) -> SignRequest {
        SignRequest::new_recovery_participation(
            RecoveryParticipantKeyProvider::Fido2,
            "/run/user/1000/a-quo/recovery-authority",
            participant_public_key(0x55),
            [0x11; 32],
            7,
            [0x22; 32],
            2,
            previous_head_sequence,
            previous_head_sha256,
        )
        .unwrap()
    }

    #[test]
    fn request_round_trip_is_exact() {
        let request = request();
        let encoded = encode_sign_request(&request).unwrap();
        assert_eq!(decode_sign_request(&encoded).unwrap(), request);
    }

    #[test]
    fn domain_request_round_trip_is_exact_and_separate() {
        let request = SignRequest::new_domain("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap();
        let encoded = encode_sign_request(&request).unwrap();
        assert_eq!(
            u16::from_be_bytes([encoded[12], encoded[13]]),
            MESSAGE_DOMAIN_SIGN_REQUEST
        );
        assert_eq!(decode_sign_request(&encoded).unwrap(), request);

        let mut reserved = encoded;
        reserved[HEADER_BYTES + 3] = 1;
        assert!(matches!(
            decode_sign_request(&reserved),
            Err(ProtocolError::InvalidLayout)
        ));
    }

    #[test]
    fn persona_root_request_round_trip_is_exact_and_separate() {
        let request =
            SignRequest::new_persona_root("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap();
        let encoded = encode_sign_request(&request).unwrap();
        assert_eq!(
            u16::from_be_bytes([encoded[12], encoded[13]]),
            MESSAGE_PERSONA_ROOT_SIGN_REQUEST
        );
        assert_eq!(decode_sign_request(&encoded).unwrap(), request);

        let mut reserved = encoded;
        reserved[HEADER_BYTES + 2] = 1;
        assert!(matches!(
            decode_sign_request(&reserved),
            Err(ProtocolError::InvalidLayout)
        ));
    }

    #[test]
    fn persona_transition_request_round_trip_is_exact_and_separate() {
        let request = transition_request(2, Some([0x22; 32]));
        let encoded = encode_sign_request(&request).unwrap();
        assert_eq!(
            u16::from_be_bytes([encoded[12], encoded[13]]),
            MESSAGE_PERSONA_TRANSITION_SIGN_REQUEST
        );
        assert_eq!(encoded[HEADER_BYTES], TransitionKeyProvider::Fido2 as u8);
        assert_eq!(encoded[HEADER_BYTES + 1], 1);
        assert_eq!(&encoded[HEADER_BYTES + 16..HEADER_BYTES + 48], &[0x11; 32]);
        assert_eq!(&encoded[HEADER_BYTES + 48..HEADER_BYTES + 80], &[0x22; 32]);
        assert_eq!(decode_sign_request(&encoded).unwrap(), request);

        let first = transition_request(1, None);
        let first_encoded = encode_sign_request(&first).unwrap();
        assert_eq!(first_encoded[HEADER_BYTES + 1], 0);
        assert_eq!(
            &first_encoded[HEADER_BYTES + 48..HEADER_BYTES + 80],
            &[0_u8; 32]
        );
        assert_eq!(decode_sign_request(&first_encoded).unwrap(), first);
    }

    #[test]
    fn recovery_participation_request_round_trip_is_exact_and_separate() {
        let request = recovery_participation_request(4, Some([0x33; 32]));
        let encoded = encode_sign_request(&request).unwrap();
        assert_eq!(
            u16::from_be_bytes([encoded[12], encoded[13]]),
            MESSAGE_RECOVERY_PARTICIPATION_REQUEST
        );
        assert_eq!(
            encoded[HEADER_BYTES],
            RecoveryParticipantKeyProvider::Fido2 as u8
        );
        assert_eq!(encoded[HEADER_BYTES + 1], 1);
        assert_eq!(read_u32(&encoded, HEADER_BYTES + 4), 7);
        assert_eq!(read_u32(&encoded, HEADER_BYTES + 8), 2);
        assert_eq!(read_u32(&encoded, HEADER_BYTES + 12), 4);
        assert_eq!(&encoded[HEADER_BYTES + 24..HEADER_BYTES + 56], &[0x11; 32]);
        assert_eq!(&encoded[HEADER_BYTES + 56..HEADER_BYTES + 88], &[0x22; 32]);
        assert_eq!(&encoded[HEADER_BYTES + 88..HEADER_BYTES + 120], &[0x33; 32]);
        assert_eq!(decode_sign_request(&encoded).unwrap(), request);

        let root_head = recovery_participation_request(0, None);
        let root_head_encoded = encode_sign_request(&root_head).unwrap();
        assert_eq!(root_head_encoded[HEADER_BYTES + 1], 0);
        assert_eq!(
            &root_head_encoded[HEADER_BYTES + 88..HEADER_BYTES + 120],
            &[0_u8; 32]
        );
        assert_eq!(decode_sign_request(&root_head_encoded).unwrap(), root_head);
    }

    #[test]
    fn recovery_participation_request_rejects_unpinned_or_impossible_state() {
        for (version, threshold) in [
            (0, 2),
            (MAX_RECOVERY_POLICY_VERSION + 1, 2),
            (1, 1),
            (1, 33),
        ] {
            let result = SignRequest::new_recovery_participation(
                RecoveryParticipantKeyProvider::OpensshFile,
                "/safe/recovery-key",
                participant_public_key(0x55),
                [0x11; 32],
                version,
                [0x22; 32],
                threshold,
                0,
                None,
            );
            assert!(matches!(
                result,
                Err(ProtocolError::InvalidRecoveryPolicyPin(_))
            ));
        }

        for (sequence, digest) in [(0, Some([0x33; 32])), (1, None)] {
            let result = SignRequest::new_recovery_participation(
                RecoveryParticipantKeyProvider::SshAgent,
                "/safe/recovery-key",
                participant_public_key(0x55),
                [0x11; 32],
                1,
                [0x22; 32],
                2,
                sequence,
                digest,
            );
            assert!(matches!(
                result,
                Err(ProtocolError::InvalidRecoveryHeadPin(_))
            ));
        }
    }

    #[test]
    fn recovery_participation_request_rejects_hostile_layout_and_text() {
        let encoded =
            encode_sign_request(&recovery_participation_request(4, Some([0x33; 32]))).unwrap();

        let mut unknown_provider = encoded.clone();
        unknown_provider[HEADER_BYTES] = 99;
        assert!(matches!(
            decode_sign_request(&unknown_provider),
            Err(ProtocolError::UnsupportedRecoveryParticipantKeyProvider(99))
        ));

        for offset in [HEADER_BYTES + 2, HEADER_BYTES + 20] {
            let mut reserved = encoded.clone();
            reserved[offset] = 1;
            assert!(matches!(
                decode_sign_request(&reserved),
                Err(ProtocolError::InvalidLayout)
            ));
        }

        let mut invalid_presence = encoded.clone();
        invalid_presence[HEADER_BYTES + 1] = 2;
        assert!(matches!(
            decode_sign_request(&invalid_presence),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut absent_nonzero = encoded.clone();
        absent_nonzero[HEADER_BYTES + 1] = 0;
        assert!(matches!(
            decode_sign_request(&absent_nonzero),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut bad_public_key_length = encoded.clone();
        bad_public_key_length[HEADER_BYTES + 18..HEADER_BYTES + 20]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            decode_sign_request(&bad_public_key_length),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut unknown_flags = encoded.clone();
        unknown_flags[15] = 1;
        assert!(matches!(
            decode_sign_request(&unknown_flags),
            Err(ProtocolError::UnsupportedFlags(1))
        ));

        let mut bad_public_key_utf8 = encoded;
        *bad_public_key_utf8.last_mut().unwrap() = 0xff;
        assert!(matches!(
            decode_sign_request(&bad_public_key_utf8),
            Err(ProtocolError::InvalidRecoveryParticipantPublicKey(_))
        ));

        for locator in ["relative/key", "/safe\u{202e}key"] {
            assert!(matches!(
                SignRequest::new_recovery_participation(
                    RecoveryParticipantKeyProvider::Fido2,
                    locator,
                    participant_public_key(0x55),
                    [0x11; 32],
                    1,
                    [0x22; 32],
                    2,
                    0,
                    None,
                ),
                Err(ProtocolError::InvalidRecoveryParticipantSigningReference(_))
            ));
        }

        for public_key in [
            format!("{} comment", participant_public_key(0x55)),
            format!("{}\u{202e}", participant_public_key(0x55)),
        ] {
            assert!(matches!(
                SignRequest::new_recovery_participation(
                    RecoveryParticipantKeyProvider::Fido2,
                    "/safe/key",
                    public_key,
                    [0x11; 32],
                    1,
                    [0x22; 32],
                    2,
                    0,
                    None,
                ),
                Err(ProtocolError::InvalidRecoveryParticipantPublicKey(_))
            ));
        }
    }

    #[test]
    fn recovery_participation_cannot_be_reinterpreted_as_artifact_signing() {
        let recovery_request = recovery_participation_request(0, None);
        assert_eq!(recovery_request.persona_id, None);
        let recovery = encode_sign_request(&recovery_request).unwrap();
        let local_persona = Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap();
        assert!(
            !recovery
                .windows(local_persona.as_bytes().len())
                .any(|window| window == local_persona.as_bytes())
        );
        let artifact = encode_sign_request(&request()).unwrap();

        let mut recovery_as_artifact = recovery;
        recovery_as_artifact[12..14].copy_from_slice(&MESSAGE_SIGN_REQUEST.to_be_bytes());
        assert!(decode_sign_request(&recovery_as_artifact).is_err());

        let mut artifact_as_recovery = artifact;
        artifact_as_recovery[12..14]
            .copy_from_slice(&MESSAGE_RECOVERY_PARTICIPATION_REQUEST.to_be_bytes());
        assert!(decode_sign_request(&artifact_as_recovery).is_err());

        let mut leaked_local_id = recovery_request;
        leaked_local_id.persona_id = Some("8b2fc4ef-ef26-48df-b849-8bc4e595e96c".to_owned());
        assert!(matches!(
            encode_sign_request(&leaked_local_id),
            Err(ProtocolError::InvalidPersonaId(_))
        ));

        let mut missing_local_id = request();
        missing_local_id.persona_id = None;
        assert!(matches!(
            encode_sign_request(&missing_local_id),
            Err(ProtocolError::InvalidPersonaId(_))
        ));
    }

    #[test]
    fn transition_request_rejects_unsafe_sequence_and_locator_values() {
        for (sequence, previous) in [(0, None), (1, Some([0x22; 32])), (2, None)] {
            assert!(matches!(
                SignRequest::new_persona_transition(
                    "8b2fc4ef-ef26-48df-b849-8bc4e595e96c",
                    sequence,
                    [0x11; 32],
                    previous,
                    TransitionKeyProvider::OpensshFile,
                    "/safe/key",
                ),
                Err(ProtocolError::InvalidTransitionSequence(_))
            ));
        }

        for locator in [
            "relative/key".to_owned(),
            " /safe/key".to_owned(),
            "/safe\u{202e}key".to_owned(),
            format!("/{}", "a".repeat(MAX_NEXT_SIGNING_REFERENCE_BYTES)),
        ] {
            assert!(matches!(
                SignRequest::new_persona_transition(
                    "8b2fc4ef-ef26-48df-b849-8bc4e595e96c",
                    1,
                    [0x11; 32],
                    None,
                    TransitionKeyProvider::SshAgent,
                    locator,
                ),
                Err(ProtocolError::InvalidNextSigningReference(_))
            ));
        }
    }

    #[test]
    fn transition_request_rejects_hostile_fixed_layout_and_text() {
        let encoded = encode_sign_request(&transition_request(2, Some([0x22; 32]))).unwrap();

        let mut unknown_provider = encoded.clone();
        unknown_provider[HEADER_BYTES] = 99;
        assert!(matches!(
            decode_sign_request(&unknown_provider),
            Err(ProtocolError::UnsupportedTransitionKeyProvider(99))
        ));

        for offset in [HEADER_BYTES + 2, HEADER_BYTES + 12] {
            let mut reserved = encoded.clone();
            reserved[offset] = 1;
            assert!(matches!(
                decode_sign_request(&reserved),
                Err(ProtocolError::InvalidLayout)
            ));
        }

        let mut invalid_presence = encoded.clone();
        invalid_presence[HEADER_BYTES + 1] = 2;
        assert!(matches!(
            decode_sign_request(&invalid_presence),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut absent_nonzero = encoded.clone();
        absent_nonzero[HEADER_BYTES + 1] = 0;
        assert!(matches!(
            decode_sign_request(&absent_nonzero),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut bad_locator_length = encoded.clone();
        bad_locator_length[HEADER_BYTES + 10..HEADER_BYTES + 12]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            decode_sign_request(&bad_locator_length),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut bad_locator_utf8 = encoded;
        *bad_locator_utf8.last_mut().unwrap() = 0xff;
        assert!(matches!(
            decode_sign_request(&bad_locator_utf8),
            Err(ProtocolError::InvalidNextSigningReference(_))
        ));
    }

    #[test]
    fn response_round_trips_are_exact() {
        for response in [
            SignResponse::Approved,
            SignResponse::Rejected(RejectionCode::UserDeclined),
            SignResponse::Rejected(RejectionCode::SignerUnavailable),
            SignResponse::Rejected(RejectionCode::ConsentUnavailable),
        ] {
            assert_eq!(
                decode_sign_response(&encode_sign_response(response)).unwrap(),
                response
            );
        }
    }

    #[test]
    fn rejects_unknown_version_type_flags_and_trailing_bytes() {
        let encoded = encode_sign_request(&request()).unwrap();

        let mut unknown_version = encoded.clone();
        unknown_version[11] = 1;
        assert!(matches!(
            decode_sign_request(&unknown_version),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        let mut unknown_type = encoded.clone();
        unknown_type[13] = 99;
        assert!(matches!(
            decode_sign_request(&unknown_type),
            Err(ProtocolError::UnsupportedMessageType(99))
        ));

        let mut unknown_flags = encoded.clone();
        unknown_flags[15] = 1;
        assert!(matches!(
            decode_sign_request(&unknown_flags),
            Err(ProtocolError::UnsupportedFlags(1))
        ));

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            decode_sign_request(&trailing),
            Err(ProtocolError::TrailingBytes)
        ));
    }

    #[test]
    fn rejects_length_smuggling_invalid_utf8_and_reserved_bytes() {
        let encoded = encode_sign_request(&request()).unwrap();

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(matches!(
            decode_sign_request(&truncated),
            Err(ProtocolError::TruncatedPayload)
        ));

        let mut bad_inner_length = encoded.clone();
        bad_inner_length[23] = 1;
        assert!(matches!(
            decode_sign_request(&bad_inner_length),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut bad_utf8 = encoded.clone();
        bad_utf8[26] = 0xff;
        assert!(matches!(
            decode_sign_request(&bad_utf8),
            Err(ProtocolError::InvalidPersonaId(_))
        ));

        let mut reserved = encoded;
        reserved[21] = 1;
        assert!(matches!(
            decode_sign_request(&reserved),
            Err(ProtocolError::InvalidLayout)
        ));
    }

    #[test]
    fn rejects_noncanonical_personas_and_dangerous_labels() {
        assert!(matches!(
            SignRequest::new(
                "8B2FC4EF-EF26-48DF-B849-8BC4E595E96C",
                ArtifactKind::Article,
                "article.md"
            ),
            Err(ProtocolError::InvalidPersonaId(_))
        ));
        assert!(matches!(
            SignRequest::new(
                "8b2fc4ef-ef26-48df-b849-8bc4e595e96c",
                ArtifactKind::Article,
                "safe\u{202e}fdp.exe"
            ),
            Err(ProtocolError::InvalidArtifactLabel(_))
        ));
    }
}
