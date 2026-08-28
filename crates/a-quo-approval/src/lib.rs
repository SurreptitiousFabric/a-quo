//! Closed, bounded protocol between the signing daemon and its one-shot
//! consent process.
//!
//! This is deliberately a pipe protocol, not a discoverable service. The
//! consent process receives display-only evidence and returns one decision
//! bound to the request UUID. It never receives artifact bytes or a signer.

use std::io::{Read, Write};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use thiserror::Error;
use uuid::Uuid;

const MAGIC: [u8; 8] = *b"AQUOAPR\0";
const HEADER_BYTES: usize = 20;
const ARTIFACT_PROMPT_PREFIX_BYTES: usize = 96;
const DOMAIN_PROMPT_PREFIX_BYTES: usize = 76;
const PERSONA_ROOT_PROMPT_PREFIX_BYTES: usize = 96;
const DECISION_PAYLOAD_BYTES: usize = 16;
const MESSAGE_ARTIFACT_PROMPT: u16 = 1;
const MESSAGE_APPROVE: u16 = 2;
const MESSAGE_DECLINE: u16 = 3;
const MESSAGE_CANCEL: u16 = 4;
const MESSAGE_DOMAIN_PROMPT: u16 = 5;
const MESSAGE_PERSONA_ROOT_PROMPT: u16 = 6;
const FLAGS_NONE: u16 = 0;
const DOMAIN_MAX_VALIDITY_SECONDS: i64 = 30 * 24 * 60 * 60;
const DNS_TXT_PREFIX: &str = "a-quo-domain-v1=";

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
pub const MAX_PERSONA_LABEL_BYTES: usize = 256;
pub const MAX_KEY_FINGERPRINT_BYTES: usize = 128;
pub const MAX_ARTIFACT_LABEL_BYTES: usize = 256;
pub const MAX_DOMAIN_BYTES: usize = 253;
pub const MAX_DNS_TXT_VALUE_BYTES: usize = 128;
pub const MAX_PERSONA_ANCHOR_BYTES: usize = 43;
const MAX_ARTIFACT_PROMPT_PAYLOAD_BYTES: usize = ARTIFACT_PROMPT_PREFIX_BYTES
    + MAX_PERSONA_LABEL_BYTES
    + MAX_KEY_FINGERPRINT_BYTES
    + MAX_ARTIFACT_LABEL_BYTES;
const MAX_DOMAIN_PROMPT_PAYLOAD_BYTES: usize = DOMAIN_PROMPT_PREFIX_BYTES
    + MAX_PERSONA_LABEL_BYTES
    + MAX_KEY_FINGERPRINT_BYTES
    + MAX_DOMAIN_BYTES
    + MAX_DNS_TXT_VALUE_BYTES;
const MAX_PERSONA_ROOT_PROMPT_PAYLOAD_BYTES: usize = PERSONA_ROOT_PROMPT_PREFIX_BYTES
    + MAX_PERSONA_LABEL_BYTES
    + MAX_KEY_FINGERPRINT_BYTES
    + MAX_PERSONA_ANCHOR_BYTES;
const MAX_ARTIFACT_OR_DOMAIN_PROMPT_PAYLOAD_BYTES: usize =
    if MAX_ARTIFACT_PROMPT_PAYLOAD_BYTES > MAX_DOMAIN_PROMPT_PAYLOAD_BYTES {
        MAX_ARTIFACT_PROMPT_PAYLOAD_BYTES
    } else {
        MAX_DOMAIN_PROMPT_PAYLOAD_BYTES
    };
pub const MAX_PROMPT_PAYLOAD_BYTES: usize =
    if MAX_ARTIFACT_OR_DOMAIN_PROMPT_PAYLOAD_BYTES > MAX_PERSONA_ROOT_PROMPT_PAYLOAD_BYTES {
        MAX_ARTIFACT_OR_DOMAIN_PROMPT_PAYLOAD_BYTES
    } else {
        MAX_PERSONA_ROOT_PROMPT_PAYLOAD_BYTES
    };
pub const MAX_MESSAGE_BYTES: usize = HEADER_BYTES + MAX_PROMPT_PAYLOAD_BYTES;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("approval message is shorter than the fixed header")]
    TruncatedHeader,

    #[error("invalid approval protocol magic")]
    InvalidMagic,

    #[error("unsupported approval protocol version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },

    #[error("unsupported approval message type {0}")]
    UnsupportedMessageType(u16),

    #[error("unsupported approval message flags 0x{0:04x}")]
    UnsupportedFlags(u16),

    #[error("approval payload exceeds its fixed limit")]
    PayloadTooLarge,

    #[error("approval message payload is truncated")]
    TruncatedPayload,

    #[error("approval message contains trailing bytes")]
    TrailingBytes,

    #[error("approval payload has an invalid fixed layout")]
    InvalidLayout,

    #[error("unsupported artifact kind {0}")]
    UnsupportedArtifactKind(u8),

    #[error("unsupported persona purpose {0}")]
    UnsupportedPersonaPurpose(u8),

    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },

    #[error("cannot read approval message: {0}")]
    Read(#[source] std::io::Error),

    #[error("cannot write approval message: {0}")]
    Write(#[source] std::io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArtifactKind {
    Generic = 1,
    SoftwareRelease = 2,
    Article = 3,
    Image = 4,
}

impl ArtifactKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Generic => "generic artifact",
            Self::SoftwareRelease => "software release",
            Self::Article => "article",
            Self::Image => "image",
        }
    }

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PersonaPurpose {
    Personal = 1,
    Pseudonymous = 2,
    Project = 3,
    Organization = 4,
    LegalBridge = 5,
}

impl PersonaPurpose {
    pub fn label(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Pseudonymous => "pseudonymous",
            Self::Project => "project",
            Self::Organization => "organization",
            Self::LegalBridge => "legal bridge",
        }
    }

    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Personal),
            2 => Ok(Self::Pseudonymous),
            3 => Ok(Self::Project),
            4 => Ok(Self::Organization),
            5 => Ok(Self::LegalBridge),
            _ => Err(ProtocolError::UnsupportedPersonaPurpose(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPrompt {
    pub request_id: Uuid,
    pub persona_id: Uuid,
    pub persona_label: String,
    pub persona_purpose: PersonaPurpose,
    pub key_fingerprint: String,
    pub subject: ApprovalSubject,
    pub peer: PeerIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalSubject {
    Artifact(ArtifactApproval),
    Domain(DomainApproval),
    PersonaRoot(PersonaRootApproval),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactApproval {
    pub artifact_kind: ArtifactKind,
    pub artifact_label: String,
    pub artifact_sha256: [u8; 32],
    pub artifact_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainApproval {
    pub domain: String,
    pub dns_txt_value: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonaRootApproval {
    pub persona_anchor: String,
    pub root_statement_sha256: [u8; 32],
    pub issued_at: i64,
}

impl ApprovalPrompt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: Uuid,
        persona_id: Uuid,
        persona_label: impl Into<String>,
        persona_purpose: PersonaPurpose,
        key_fingerprint: impl Into<String>,
        artifact_kind: ArtifactKind,
        artifact_label: impl Into<String>,
        artifact_sha256: [u8; 32],
        artifact_size: u64,
        peer: PeerIdentity,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_subject(
            request_id,
            persona_id,
            persona_label,
            persona_purpose,
            key_fingerprint,
            ApprovalSubject::Artifact(ArtifactApproval {
                artifact_kind,
                artifact_label: artifact_label.into(),
                artifact_sha256,
                artifact_size,
            }),
            peer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_domain(
        request_id: Uuid,
        persona_id: Uuid,
        persona_label: impl Into<String>,
        persona_purpose: PersonaPurpose,
        key_fingerprint: impl Into<String>,
        domain: impl Into<String>,
        dns_txt_value: impl Into<String>,
        issued_at: i64,
        expires_at: i64,
        peer: PeerIdentity,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_subject(
            request_id,
            persona_id,
            persona_label,
            persona_purpose,
            key_fingerprint,
            ApprovalSubject::Domain(DomainApproval {
                domain: domain.into(),
                dns_txt_value: dns_txt_value.into(),
                issued_at,
                expires_at,
            }),
            peer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_persona_root(
        request_id: Uuid,
        persona_id: Uuid,
        persona_label: impl Into<String>,
        persona_purpose: PersonaPurpose,
        key_fingerprint: impl Into<String>,
        persona_anchor: impl Into<String>,
        root_statement_sha256: [u8; 32],
        issued_at: i64,
        peer: PeerIdentity,
    ) -> Result<Self, ProtocolError> {
        Self::new_with_subject(
            request_id,
            persona_id,
            persona_label,
            persona_purpose,
            key_fingerprint,
            ApprovalSubject::PersonaRoot(PersonaRootApproval {
                persona_anchor: persona_anchor.into(),
                root_statement_sha256,
                issued_at,
            }),
            peer,
        )
    }

    fn new_with_subject(
        request_id: Uuid,
        persona_id: Uuid,
        persona_label: impl Into<String>,
        persona_purpose: PersonaPurpose,
        key_fingerprint: impl Into<String>,
        subject: ApprovalSubject,
        peer: PeerIdentity,
    ) -> Result<Self, ProtocolError> {
        let prompt = Self {
            request_id,
            persona_id,
            persona_label: persona_label.into(),
            persona_purpose,
            key_fingerprint: key_fingerprint.into(),
            subject,
            peer,
        };
        validate_prompt(&prompt)?;
        Ok(prompt)
    }
}

impl ArtifactApproval {
    pub fn sha256_hex(&self) -> String {
        encode_hex(&self.artifact_sha256)
    }
}

impl PersonaRootApproval {
    pub fn root_sha256_hex(&self) -> String {
        encode_hex(&self.root_statement_sha256)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approve,
    Decline,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionResponse {
    pub request_id: Uuid,
    pub decision: ApprovalDecision,
}

pub fn encode_prompt(prompt: &ApprovalPrompt) -> Result<Vec<u8>, ProtocolError> {
    validate_prompt(prompt)?;
    match &prompt.subject {
        ApprovalSubject::Artifact(artifact) => encode_artifact_prompt(prompt, artifact),
        ApprovalSubject::Domain(domain) => encode_domain_prompt(prompt, domain),
        ApprovalSubject::PersonaRoot(root) => encode_persona_root_prompt(prompt, root),
    }
}

fn encode_artifact_prompt(
    prompt: &ApprovalPrompt,
    artifact: &ArtifactApproval,
) -> Result<Vec<u8>, ProtocolError> {
    let persona_label = prompt.persona_label.as_bytes();
    let fingerprint = prompt.key_fingerprint.as_bytes();
    let artifact_label = artifact.artifact_label.as_bytes();
    let payload_len = ARTIFACT_PROMPT_PREFIX_BYTES
        .checked_add(persona_label.len())
        .and_then(|length| length.checked_add(fingerprint.len()))
        .and_then(|length| length.checked_add(artifact_label.len()))
        .ok_or(ProtocolError::PayloadTooLarge)?;
    let mut message = encode_header(MESSAGE_ARTIFACT_PROMPT, payload_len);
    message.push(artifact.artifact_kind as u8);
    message.push(prompt.persona_purpose as u8);
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&prompt.peer.pid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.uid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.gid.to_be_bytes());
    message.extend_from_slice(&artifact.artifact_size.to_be_bytes());
    message.extend_from_slice(prompt.request_id.as_bytes());
    message.extend_from_slice(prompt.persona_id.as_bytes());
    message.extend_from_slice(&artifact.artifact_sha256);
    message.extend_from_slice(&(persona_label.len() as u16).to_be_bytes());
    message.extend_from_slice(&(fingerprint.len() as u16).to_be_bytes());
    message.extend_from_slice(&(artifact_label.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    debug_assert_eq!(message.len(), HEADER_BYTES + ARTIFACT_PROMPT_PREFIX_BYTES);
    message.extend_from_slice(persona_label);
    message.extend_from_slice(fingerprint);
    message.extend_from_slice(artifact_label);
    Ok(message)
}

fn encode_domain_prompt(
    prompt: &ApprovalPrompt,
    domain: &DomainApproval,
) -> Result<Vec<u8>, ProtocolError> {
    let persona_label = prompt.persona_label.as_bytes();
    let fingerprint = prompt.key_fingerprint.as_bytes();
    let domain_name = domain.domain.as_bytes();
    let dns_txt_value = domain.dns_txt_value.as_bytes();
    let payload_len = DOMAIN_PROMPT_PREFIX_BYTES
        .checked_add(persona_label.len())
        .and_then(|length| length.checked_add(fingerprint.len()))
        .and_then(|length| length.checked_add(domain_name.len()))
        .and_then(|length| length.checked_add(dns_txt_value.len()))
        .ok_or(ProtocolError::PayloadTooLarge)?;
    let mut message = encode_header(MESSAGE_DOMAIN_PROMPT, payload_len);
    message.push(prompt.persona_purpose as u8);
    message.extend_from_slice(&[0_u8; 3]);
    message.extend_from_slice(&prompt.peer.pid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.uid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.gid.to_be_bytes());
    message.extend_from_slice(&domain.issued_at.to_be_bytes());
    message.extend_from_slice(&domain.expires_at.to_be_bytes());
    message.extend_from_slice(prompt.request_id.as_bytes());
    message.extend_from_slice(prompt.persona_id.as_bytes());
    message.extend_from_slice(&(persona_label.len() as u16).to_be_bytes());
    message.extend_from_slice(&(fingerprint.len() as u16).to_be_bytes());
    message.extend_from_slice(&(domain_name.len() as u16).to_be_bytes());
    message.extend_from_slice(&(dns_txt_value.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u32.to_be_bytes());
    debug_assert_eq!(message.len(), HEADER_BYTES + DOMAIN_PROMPT_PREFIX_BYTES);
    message.extend_from_slice(persona_label);
    message.extend_from_slice(fingerprint);
    message.extend_from_slice(domain_name);
    message.extend_from_slice(dns_txt_value);
    Ok(message)
}

fn encode_persona_root_prompt(
    prompt: &ApprovalPrompt,
    root: &PersonaRootApproval,
) -> Result<Vec<u8>, ProtocolError> {
    let persona_label = prompt.persona_label.as_bytes();
    let fingerprint = prompt.key_fingerprint.as_bytes();
    let persona_anchor = root.persona_anchor.as_bytes();
    let payload_len = PERSONA_ROOT_PROMPT_PREFIX_BYTES
        .checked_add(persona_label.len())
        .and_then(|length| length.checked_add(fingerprint.len()))
        .and_then(|length| length.checked_add(persona_anchor.len()))
        .ok_or(ProtocolError::PayloadTooLarge)?;
    let mut message = encode_header(MESSAGE_PERSONA_ROOT_PROMPT, payload_len);
    message.push(prompt.persona_purpose as u8);
    message.extend_from_slice(&[0_u8; 3]);
    message.extend_from_slice(&prompt.peer.pid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.uid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.gid.to_be_bytes());
    message.extend_from_slice(&root.issued_at.to_be_bytes());
    message.extend_from_slice(prompt.request_id.as_bytes());
    message.extend_from_slice(prompt.persona_id.as_bytes());
    message.extend_from_slice(&root.root_statement_sha256);
    message.extend_from_slice(&(persona_label.len() as u16).to_be_bytes());
    message.extend_from_slice(&(fingerprint.len() as u16).to_be_bytes());
    message.extend_from_slice(&(persona_anchor.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    debug_assert_eq!(
        message.len(),
        HEADER_BYTES + PERSONA_ROOT_PROMPT_PREFIX_BYTES
    );
    message.extend_from_slice(persona_label);
    message.extend_from_slice(fingerprint);
    message.extend_from_slice(persona_anchor);
    Ok(message)
}

pub fn decode_prompt(message: &[u8]) -> Result<ApprovalPrompt, ProtocolError> {
    match decode_common_header(message)? {
        MESSAGE_ARTIFACT_PROMPT => decode_artifact_prompt(message),
        MESSAGE_DOMAIN_PROMPT => decode_domain_prompt(message),
        MESSAGE_PERSONA_ROOT_PROMPT => decode_persona_root_prompt(message),
        other => Err(ProtocolError::UnsupportedMessageType(other)),
    }
}

fn decode_artifact_prompt(message: &[u8]) -> Result<ApprovalPrompt, ProtocolError> {
    let payload = decode_header(
        message,
        MESSAGE_ARTIFACT_PROMPT,
        MAX_ARTIFACT_PROMPT_PAYLOAD_BYTES,
    )?;
    if payload.len() < ARTIFACT_PROMPT_PREFIX_BYTES
        || payload[2..4] != [0, 0]
        || payload[94..96] != [0, 0]
    {
        return Err(ProtocolError::InvalidLayout);
    }
    let artifact_kind = ArtifactKind::decode(payload[0])?;
    let persona_purpose = PersonaPurpose::decode(payload[1])?;
    let peer = PeerIdentity {
        pid: read_u32(payload, 4),
        uid: read_u32(payload, 8),
        gid: read_u32(payload, 12),
    };
    let artifact_size = read_u64(payload, 16);
    let request_id =
        Uuid::from_slice(&payload[24..40]).map_err(|_| ProtocolError::InvalidLayout)?;
    let persona_id =
        Uuid::from_slice(&payload[40..56]).map_err(|_| ProtocolError::InvalidLayout)?;
    let mut artifact_sha256 = [0_u8; 32];
    artifact_sha256.copy_from_slice(&payload[56..88]);
    let persona_label_len = usize::from(read_u16(payload, 88));
    let fingerprint_len = usize::from(read_u16(payload, 90));
    let artifact_label_len = usize::from(read_u16(payload, 92));
    let expected = ARTIFACT_PROMPT_PREFIX_BYTES
        .checked_add(persona_label_len)
        .and_then(|length| length.checked_add(fingerprint_len))
        .and_then(|length| length.checked_add(artifact_label_len))
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }

    let persona_end = ARTIFACT_PROMPT_PREFIX_BYTES + persona_label_len;
    let fingerprint_end = persona_end + fingerprint_len;
    let persona_label = decode_text(
        "persona label",
        &payload[ARTIFACT_PROMPT_PREFIX_BYTES..persona_end],
    )?;
    let key_fingerprint = decode_text("key fingerprint", &payload[persona_end..fingerprint_end])?;
    let artifact_label = decode_text("artifact label", &payload[fingerprint_end..])?;
    ApprovalPrompt::new(
        request_id,
        persona_id,
        persona_label,
        persona_purpose,
        key_fingerprint,
        artifact_kind,
        artifact_label,
        artifact_sha256,
        artifact_size,
        peer,
    )
}

fn decode_domain_prompt(message: &[u8]) -> Result<ApprovalPrompt, ProtocolError> {
    let payload = decode_header(
        message,
        MESSAGE_DOMAIN_PROMPT,
        MAX_DOMAIN_PROMPT_PAYLOAD_BYTES,
    )?;
    if payload.len() < DOMAIN_PROMPT_PREFIX_BYTES
        || payload[1..4] != [0, 0, 0]
        || payload[72..76] != [0, 0, 0, 0]
    {
        return Err(ProtocolError::InvalidLayout);
    }
    let persona_purpose = PersonaPurpose::decode(payload[0])?;
    let peer = PeerIdentity {
        pid: read_u32(payload, 4),
        uid: read_u32(payload, 8),
        gid: read_u32(payload, 12),
    };
    let issued_at = read_i64(payload, 16);
    let expires_at = read_i64(payload, 24);
    let request_id =
        Uuid::from_slice(&payload[32..48]).map_err(|_| ProtocolError::InvalidLayout)?;
    let persona_id =
        Uuid::from_slice(&payload[48..64]).map_err(|_| ProtocolError::InvalidLayout)?;
    let persona_label_len = usize::from(read_u16(payload, 64));
    let fingerprint_len = usize::from(read_u16(payload, 66));
    let domain_len = usize::from(read_u16(payload, 68));
    let dns_txt_len = usize::from(read_u16(payload, 70));
    let expected = DOMAIN_PROMPT_PREFIX_BYTES
        .checked_add(persona_label_len)
        .and_then(|length| length.checked_add(fingerprint_len))
        .and_then(|length| length.checked_add(domain_len))
        .and_then(|length| length.checked_add(dns_txt_len))
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }

    let persona_end = DOMAIN_PROMPT_PREFIX_BYTES + persona_label_len;
    let fingerprint_end = persona_end + fingerprint_len;
    let domain_end = fingerprint_end + domain_len;
    let persona_label = decode_text(
        "persona label",
        &payload[DOMAIN_PROMPT_PREFIX_BYTES..persona_end],
    )?;
    let key_fingerprint = decode_text("key fingerprint", &payload[persona_end..fingerprint_end])?;
    let domain = decode_text("domain", &payload[fingerprint_end..domain_end])?;
    let dns_txt_value = decode_text("DNS TXT value", &payload[domain_end..])?;
    ApprovalPrompt::new_domain(
        request_id,
        persona_id,
        persona_label,
        persona_purpose,
        key_fingerprint,
        domain,
        dns_txt_value,
        issued_at,
        expires_at,
        peer,
    )
}

fn decode_persona_root_prompt(message: &[u8]) -> Result<ApprovalPrompt, ProtocolError> {
    let payload = decode_header(
        message,
        MESSAGE_PERSONA_ROOT_PROMPT,
        MAX_PERSONA_ROOT_PROMPT_PAYLOAD_BYTES,
    )?;
    if payload.len() < PERSONA_ROOT_PROMPT_PREFIX_BYTES
        || payload[1..4] != [0, 0, 0]
        || payload[94..96] != [0, 0]
    {
        return Err(ProtocolError::InvalidLayout);
    }
    let persona_purpose = PersonaPurpose::decode(payload[0])?;
    let peer = PeerIdentity {
        pid: read_u32(payload, 4),
        uid: read_u32(payload, 8),
        gid: read_u32(payload, 12),
    };
    let issued_at = read_i64(payload, 16);
    let request_id =
        Uuid::from_slice(&payload[24..40]).map_err(|_| ProtocolError::InvalidLayout)?;
    let persona_id =
        Uuid::from_slice(&payload[40..56]).map_err(|_| ProtocolError::InvalidLayout)?;
    let mut root_statement_sha256 = [0_u8; 32];
    root_statement_sha256.copy_from_slice(&payload[56..88]);
    let persona_label_len = usize::from(read_u16(payload, 88));
    let fingerprint_len = usize::from(read_u16(payload, 90));
    let persona_anchor_len = usize::from(read_u16(payload, 92));
    let expected = PERSONA_ROOT_PROMPT_PREFIX_BYTES
        .checked_add(persona_label_len)
        .and_then(|length| length.checked_add(fingerprint_len))
        .and_then(|length| length.checked_add(persona_anchor_len))
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }

    let persona_end = PERSONA_ROOT_PROMPT_PREFIX_BYTES + persona_label_len;
    let fingerprint_end = persona_end + fingerprint_len;
    let persona_label = decode_text(
        "persona label",
        &payload[PERSONA_ROOT_PROMPT_PREFIX_BYTES..persona_end],
    )?;
    let key_fingerprint = decode_text("key fingerprint", &payload[persona_end..fingerprint_end])?;
    let persona_anchor = decode_text("persona anchor", &payload[fingerprint_end..])?;
    ApprovalPrompt::new_persona_root(
        request_id,
        persona_id,
        persona_label,
        persona_purpose,
        key_fingerprint,
        persona_anchor,
        root_statement_sha256,
        issued_at,
        peer,
    )
}

pub fn encode_decision(response: DecisionResponse) -> Vec<u8> {
    let message_type = match response.decision {
        ApprovalDecision::Approve => MESSAGE_APPROVE,
        ApprovalDecision::Decline => MESSAGE_DECLINE,
        ApprovalDecision::Cancel => MESSAGE_CANCEL,
    };
    let mut message = encode_header(message_type, DECISION_PAYLOAD_BYTES);
    message.extend_from_slice(response.request_id.as_bytes());
    message
}

pub fn decode_decision(message: &[u8]) -> Result<DecisionResponse, ProtocolError> {
    let message_type = decode_common_header(message)?;
    let decision = match message_type {
        MESSAGE_APPROVE => ApprovalDecision::Approve,
        MESSAGE_DECLINE => ApprovalDecision::Decline,
        MESSAGE_CANCEL => ApprovalDecision::Cancel,
        other => return Err(ProtocolError::UnsupportedMessageType(other)),
    };
    let payload = decode_header(message, message_type, DECISION_PAYLOAD_BYTES)?;
    if payload.len() != DECISION_PAYLOAD_BYTES {
        return Err(ProtocolError::InvalidLayout);
    }
    let request_id = Uuid::from_slice(payload).map_err(|_| ProtocolError::InvalidLayout)?;
    Ok(DecisionResponse {
        request_id,
        decision,
    })
}

pub fn read_prompt(mut input: impl Read) -> Result<ApprovalPrompt, ProtocolError> {
    decode_prompt(&read_one_message(&mut input, MAX_PROMPT_PAYLOAD_BYTES)?)
}

pub fn write_prompt(mut output: impl Write, prompt: &ApprovalPrompt) -> Result<(), ProtocolError> {
    output
        .write_all(&encode_prompt(prompt)?)
        .map_err(ProtocolError::Write)?;
    output.flush().map_err(ProtocolError::Write)
}

pub fn read_decision(mut input: impl Read) -> Result<DecisionResponse, ProtocolError> {
    decode_decision(&read_one_message(&mut input, DECISION_PAYLOAD_BYTES)?)
}

pub fn write_decision(
    mut output: impl Write,
    response: DecisionResponse,
) -> Result<(), ProtocolError> {
    output
        .write_all(&encode_decision(response))
        .map_err(ProtocolError::Write)?;
    output.flush().map_err(ProtocolError::Write)
}

fn read_one_message(
    input: &mut impl Read,
    maximum_payload: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    input
        .read_exact(&mut header)
        .map_err(map_read_header_error)?;
    decode_common_header(&header)?;
    let payload_len = read_u32(&header, 16) as usize;
    if payload_len > maximum_payload {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let mut message = Vec::with_capacity(HEADER_BYTES + payload_len);
    message.extend_from_slice(&header);
    message.resize(HEADER_BYTES + payload_len, 0);
    input
        .read_exact(&mut message[HEADER_BYTES..])
        .map_err(map_read_payload_error)?;
    let mut extra = [0_u8; 1];
    match input.read(&mut extra) {
        Ok(0) => Ok(message),
        Ok(_) => Err(ProtocolError::TrailingBytes),
        Err(error) => Err(ProtocolError::Read(error)),
    }
}

fn map_read_header_error(error: std::io::Error) -> ProtocolError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        ProtocolError::TruncatedHeader
    } else {
        ProtocolError::Read(error)
    }
}

fn map_read_payload_error(error: std::io::Error) -> ProtocolError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        ProtocolError::TruncatedPayload
    } else {
        ProtocolError::Read(error)
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
    let major = read_u16(message, 8);
    let minor = read_u16(message, 10);
    if major != PROTOCOL_MAJOR || minor != PROTOCOL_MINOR {
        return Err(ProtocolError::UnsupportedVersion { major, minor });
    }
    let flags = read_u16(message, 14);
    if flags != FLAGS_NONE {
        return Err(ProtocolError::UnsupportedFlags(flags));
    }
    Ok(read_u16(message, 12))
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
    let payload_len = read_u32(message, 16) as usize;
    if payload_len > maximum_payload {
        return Err(ProtocolError::PayloadTooLarge);
    }
    let expected = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(ProtocolError::PayloadTooLarge)?;
    match message.len().cmp(&expected) {
        std::cmp::Ordering::Less => Err(ProtocolError::TruncatedPayload),
        std::cmp::Ordering::Greater => Err(ProtocolError::TrailingBytes),
        std::cmp::Ordering::Equal => Ok(&message[HEADER_BYTES..]),
    }
}

fn validate_prompt(prompt: &ApprovalPrompt) -> Result<(), ProtocolError> {
    if prompt.request_id.is_nil() {
        return Err(ProtocolError::InvalidField {
            field: "request ID",
            reason: "it cannot be the nil UUID".to_owned(),
        });
    }
    if prompt.persona_id.is_nil() {
        return Err(ProtocolError::InvalidField {
            field: "persona ID",
            reason: "it cannot be the nil UUID".to_owned(),
        });
    }
    validate_text(
        "persona label",
        &prompt.persona_label,
        MAX_PERSONA_LABEL_BYTES,
    )?;
    validate_text(
        "key fingerprint",
        &prompt.key_fingerprint,
        MAX_KEY_FINGERPRINT_BYTES,
    )?;
    let fingerprint = prompt
        .key_fingerprint
        .strip_prefix("SHA256:")
        .ok_or_else(|| ProtocolError::InvalidField {
            field: "key fingerprint",
            reason: "expected the canonical OpenSSH SHA256 form".to_owned(),
        })?;
    let decoded = STANDARD_NO_PAD
        .decode(fingerprint)
        .map_err(|_| ProtocolError::InvalidField {
            field: "key fingerprint",
            reason: "expected canonical unpadded Base64 after SHA256:".to_owned(),
        })?;
    if decoded.len() != 32 || STANDARD_NO_PAD.encode(&decoded) != fingerprint {
        return Err(ProtocolError::InvalidField {
            field: "key fingerprint",
            reason: "expected the canonical 32-byte OpenSSH SHA256 digest".to_owned(),
        });
    }
    match &prompt.subject {
        ApprovalSubject::Artifact(artifact) => validate_text(
            "artifact label",
            &artifact.artifact_label,
            MAX_ARTIFACT_LABEL_BYTES,
        )?,
        ApprovalSubject::Domain(domain) => validate_domain_approval(domain)?,
        ApprovalSubject::PersonaRoot(root) => validate_persona_root_approval(root)?,
    }
    if prompt.peer.pid == 0 {
        return Err(ProtocolError::InvalidField {
            field: "peer PID",
            reason: "it must be nonzero".to_owned(),
        });
    }
    Ok(())
}

fn validate_persona_root_approval(root: &PersonaRootApproval) -> Result<(), ProtocolError> {
    validate_text(
        "persona anchor",
        &root.persona_anchor,
        MAX_PERSONA_ANCHOR_BYTES,
    )?;
    let decoded =
        URL_SAFE_NO_PAD
            .decode(&root.persona_anchor)
            .map_err(|_| ProtocolError::InvalidField {
                field: "persona anchor",
                reason: "expected canonical unpadded Base64url".to_owned(),
            })?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != root.persona_anchor {
        return Err(ProtocolError::InvalidField {
            field: "persona anchor",
            reason: "expected one canonical 32-byte persona anchor".to_owned(),
        });
    }
    if root.issued_at < 0 {
        return Err(ProtocolError::InvalidField {
            field: "root issuance time",
            reason: "it must be nonnegative".to_owned(),
        });
    }
    Ok(())
}

fn validate_domain_approval(domain: &DomainApproval) -> Result<(), ProtocolError> {
    validate_text("domain", &domain.domain, MAX_DOMAIN_BYTES)?;
    let labels = domain.domain.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || is_special_use_domain(&domain.domain)
    {
        return Err(ProtocolError::InvalidField {
            field: "domain",
            reason: "expected a canonical global lowercase ASCII DNS name".to_owned(),
        });
    }

    validate_text(
        "DNS TXT value",
        &domain.dns_txt_value,
        MAX_DNS_TXT_VALUE_BYTES,
    )?;
    let encoded = domain
        .dns_txt_value
        .strip_prefix(DNS_TXT_PREFIX)
        .ok_or_else(|| ProtocolError::InvalidField {
            field: "DNS TXT value",
            reason: "expected the A Quo domain commitment prefix".to_owned(),
        })?;
    let digest = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidField {
            field: "DNS TXT value",
            reason: "expected canonical unpadded Base64url".to_owned(),
        })?;
    if digest.len() != 32 || URL_SAFE_NO_PAD.encode(&digest) != encoded {
        return Err(ProtocolError::InvalidField {
            field: "DNS TXT value",
            reason: "expected one canonical 32-byte SHA-256 commitment".to_owned(),
        });
    }

    let validity = domain
        .expires_at
        .checked_sub(domain.issued_at)
        .ok_or_else(|| ProtocolError::InvalidField {
            field: "domain validity",
            reason: "expiry must follow issuance".to_owned(),
        })?;
    if domain.issued_at < 0 || validity <= 0 || validity > DOMAIN_MAX_VALIDITY_SECONDS {
        return Err(ProtocolError::InvalidField {
            field: "domain validity",
            reason: format!(
                "timestamps must be nonnegative and span at most {DOMAIN_MAX_VALIDITY_SECONDS} seconds"
            ),
        });
    }
    Ok(())
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

fn validate_text(field: &'static str, value: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "it cannot be empty".to_owned(),
        });
    }
    if value.len() > maximum {
        return Err(ProtocolError::InvalidField {
            field,
            reason: format!("it cannot exceed {maximum} UTF-8 bytes"),
        });
    }
    if value.trim() != value {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "leading and trailing whitespace are not allowed".to_owned(),
        });
    }
    if value.chars().any(is_unsafe_display_character) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "control and bidirectional formatting characters are not allowed".to_owned(),
        });
    }
    Ok(())
}

fn decode_text(field: &'static str, bytes: &[u8]) -> Result<String, ProtocolError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ProtocolError::InvalidField {
            field,
            reason: "it must be UTF-8".to_owned(),
        })
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

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn prompt() -> ApprovalPrompt {
        ApprovalPrompt::new(
            Uuid::parse_str("f62e45ae-2a08-411e-b5fb-e3a6c92dd4cf").unwrap(),
            Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap(),
            "A Quo publisher",
            PersonaPurpose::Project,
            "SHA256:9XgBXfKpFQkNWfOqvPq6NKBFe0MPNF34Z2Qv7xw8mXY",
            ArtifactKind::SoftwareRelease,
            "a-quo-0.1.0.tar.zst",
            [0xab; 32],
            1_234_567,
            PeerIdentity {
                pid: 4242,
                uid: 1000,
                gid: 1000,
            },
        )
        .unwrap()
    }

    fn domain_prompt() -> ApprovalPrompt {
        ApprovalPrompt::new_domain(
            Uuid::parse_str("f62e45ae-2a08-411e-b5fb-e3a6c92dd4cf").unwrap(),
            Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap(),
            "A Quo publisher",
            PersonaPurpose::Project,
            "SHA256:9XgBXfKpFQkNWfOqvPq6NKBFe0MPNF34Z2Qv7xw8mXY",
            "a-quo.ch",
            format!("{DNS_TXT_PREFIX}{}", URL_SAFE_NO_PAD.encode([0x42; 32])),
            1_787_875_200,
            1_788_480_000,
            PeerIdentity {
                pid: 4242,
                uid: 1000,
                gid: 1000,
            },
        )
        .unwrap()
    }

    fn persona_root_prompt() -> ApprovalPrompt {
        ApprovalPrompt::new_persona_root(
            Uuid::parse_str("f62e45ae-2a08-411e-b5fb-e3a6c92dd4cf").unwrap(),
            Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap(),
            "A Quo publisher",
            PersonaPurpose::Project,
            "SHA256:9XgBXfKpFQkNWfOqvPq6NKBFe0MPNF34Z2Qv7xw8mXY",
            URL_SAFE_NO_PAD.encode([0x24; 32]),
            [0x42; 32],
            1_787_875_200,
            PeerIdentity {
                pid: 4242,
                uid: 1000,
                gid: 1000,
            },
        )
        .unwrap()
    }

    #[test]
    fn prompt_round_trip_is_exact() {
        let prompt = prompt();
        let encoded = encode_prompt(&prompt).unwrap();
        assert_eq!(decode_prompt(&encoded).unwrap(), prompt);
        let ApprovalSubject::Artifact(artifact) = &prompt.subject else {
            panic!("expected artifact prompt");
        };
        assert_eq!(artifact.sha256_hex(), "ab".repeat(32));
    }

    #[test]
    fn domain_prompt_round_trip_is_exact_and_separate() {
        let prompt = domain_prompt();
        let encoded = encode_prompt(&prompt).unwrap();
        assert_eq!(read_u16(&encoded, 12), MESSAGE_DOMAIN_PROMPT);
        assert_eq!(decode_prompt(&encoded).unwrap(), prompt);

        let mut reserved = encoded;
        reserved[HEADER_BYTES + 1] = 1;
        assert!(matches!(
            decode_prompt(&reserved),
            Err(ProtocolError::InvalidLayout)
        ));
    }

    #[test]
    fn persona_root_prompt_round_trip_is_exact_and_separate() {
        let prompt = persona_root_prompt();
        let encoded = encode_prompt(&prompt).unwrap();
        assert_eq!(read_u16(&encoded, 12), MESSAGE_PERSONA_ROOT_PROMPT);
        assert_eq!(decode_prompt(&encoded).unwrap(), prompt);
        let ApprovalSubject::PersonaRoot(root) = &prompt.subject else {
            panic!("expected persona-root prompt");
        };
        assert_eq!(root.root_sha256_hex(), "42".repeat(32));

        let mut reserved = encoded;
        reserved[HEADER_BYTES + 94] = 1;
        assert!(matches!(
            decode_prompt(&reserved),
            Err(ProtocolError::InvalidLayout)
        ));
    }

    #[test]
    fn persona_root_prompt_rejects_noncanonical_anchor_and_negative_time() {
        let mut padded = persona_root_prompt();
        let ApprovalSubject::PersonaRoot(root) = &mut padded.subject else {
            panic!("expected persona-root prompt");
        };
        root.persona_anchor.push('=');
        assert!(matches!(
            encode_prompt(&padded),
            Err(ProtocolError::InvalidField {
                field: "persona anchor",
                ..
            })
        ));

        let mut negative = persona_root_prompt();
        let ApprovalSubject::PersonaRoot(root) = &mut negative.subject else {
            panic!("expected persona-root prompt");
        };
        root.issued_at = -1;
        assert!(matches!(
            encode_prompt(&negative),
            Err(ProtocolError::InvalidField {
                field: "root issuance time",
                ..
            })
        ));
    }

    #[test]
    fn decisions_are_bound_to_request_id() {
        for decision in [
            ApprovalDecision::Approve,
            ApprovalDecision::Decline,
            ApprovalDecision::Cancel,
        ] {
            let response = DecisionResponse {
                request_id: prompt().request_id,
                decision,
            };
            assert_eq!(
                decode_decision(&encode_decision(response)).unwrap(),
                response
            );
        }
    }

    #[test]
    fn stream_helpers_require_exact_eof() {
        let prompt = prompt();
        let mut encoded = encode_prompt(&prompt).unwrap();
        assert_eq!(read_prompt(Cursor::new(&encoded)).unwrap(), prompt);
        encoded.push(0);
        assert!(matches!(
            read_prompt(Cursor::new(encoded)),
            Err(ProtocolError::TrailingBytes)
        ));
    }

    #[test]
    fn rejects_unknown_version_type_flags_and_lengths() {
        let encoded = encode_prompt(&prompt()).unwrap();

        let mut unknown_version = encoded.clone();
        unknown_version[11] = 1;
        assert!(matches!(
            decode_prompt(&unknown_version),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        let mut unknown_type = encoded.clone();
        unknown_type[13] = 99;
        assert!(matches!(
            decode_prompt(&unknown_type),
            Err(ProtocolError::UnsupportedMessageType(99))
        ));

        let mut unknown_flags = encoded.clone();
        unknown_flags[15] = 1;
        assert!(matches!(
            decode_prompt(&unknown_flags),
            Err(ProtocolError::UnsupportedFlags(1))
        ));

        let mut bad_inner_length = encoded;
        bad_inner_length[109] = 0xff;
        assert!(matches!(
            decode_prompt(&bad_inner_length),
            Err(ProtocolError::InvalidLayout)
        ));
    }

    #[test]
    fn rejects_reserved_bytes_invalid_utf8_and_dangerous_text() {
        let mut reserved = encode_prompt(&prompt()).unwrap();
        reserved[22] = 1;
        assert!(matches!(
            decode_prompt(&reserved),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut bad_utf8 = encode_prompt(&prompt()).unwrap();
        bad_utf8[HEADER_BYTES + ARTIFACT_PROMPT_PREFIX_BYTES] = 0xff;
        assert!(matches!(
            decode_prompt(&bad_utf8),
            Err(ProtocolError::InvalidField { .. })
        ));

        let mut dangerous = prompt();
        let ApprovalSubject::Artifact(artifact) = &mut dangerous.subject else {
            panic!("expected artifact prompt");
        };
        artifact.artifact_label = "safe\u{202e}fdp.exe".to_owned();
        assert!(matches!(
            encode_prompt(&dangerous),
            Err(ProtocolError::InvalidField { .. })
        ));
    }

    #[test]
    fn rejects_nil_ids_and_noncanonical_fingerprints() {
        let mut nil_id = prompt();
        nil_id.request_id = Uuid::nil();
        assert!(matches!(
            encode_prompt(&nil_id),
            Err(ProtocolError::InvalidField {
                field: "request ID",
                ..
            })
        ));

        let mut fingerprint = prompt();
        fingerprint.key_fingerprint = "MD5:aa:bb".to_owned();
        assert!(matches!(
            encode_prompt(&fingerprint),
            Err(ProtocolError::InvalidField {
                field: "key fingerprint",
                ..
            })
        ));

        let mut url_safe = prompt();
        url_safe.key_fingerprint = "SHA256:9XgBXfKpFQkNWfOqvPq6NKBFe0MPNF34Z2Qv7xw8m_Y".to_owned();
        assert!(matches!(
            encode_prompt(&url_safe),
            Err(ProtocolError::InvalidField {
                field: "key fingerprint",
                ..
            })
        ));

        let mut noncanonical_tail = prompt();
        noncanonical_tail.key_fingerprint =
            "SHA256:9XgBXfKpFQkNWfOqvPq6NKBFe0MPNF34Z2Qv7xw8mXZ".to_owned();
        assert!(matches!(
            encode_prompt(&noncanonical_tail),
            Err(ProtocolError::InvalidField {
                field: "key fingerprint",
                ..
            })
        ));
    }

    #[test]
    fn oversized_declared_payload_is_rejected_before_allocation() {
        let mut header = encode_header(MESSAGE_ARTIFACT_PROMPT, 0);
        header[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            read_prompt(Cursor::new(header)),
            Err(ProtocolError::PayloadTooLarge)
        ));
    }

    #[test]
    fn domain_prompts_reject_noncanonical_claims_and_commitments() {
        let mut uppercase = domain_prompt();
        let ApprovalSubject::Domain(domain) = &mut uppercase.subject else {
            panic!("expected domain prompt");
        };
        domain.domain = "A-QUO.CH".to_owned();
        assert!(matches!(
            encode_prompt(&uppercase),
            Err(ProtocolError::InvalidField {
                field: "domain",
                ..
            })
        ));

        let mut padded = domain_prompt();
        let ApprovalSubject::Domain(domain) = &mut padded.subject else {
            panic!("expected domain prompt");
        };
        domain.dns_txt_value.push('=');
        assert!(matches!(
            encode_prompt(&padded),
            Err(ProtocolError::InvalidField {
                field: "DNS TXT value",
                ..
            })
        ));

        let mut too_long = domain_prompt();
        let ApprovalSubject::Domain(domain) = &mut too_long.subject else {
            panic!("expected domain prompt");
        };
        domain.expires_at = domain.issued_at + DOMAIN_MAX_VALIDITY_SECONDS + 1;
        assert!(matches!(
            encode_prompt(&too_long),
            Err(ProtocolError::InvalidField {
                field: "domain validity",
                ..
            })
        ));
    }
}
