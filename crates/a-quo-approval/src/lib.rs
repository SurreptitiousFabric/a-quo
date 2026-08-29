//! Closed, bounded protocol between the signing daemon and its one-shot
//! consent process.
//!
//! This is deliberately a pipe protocol, not a discoverable service. The
//! consent process receives display-only evidence and returns one decision
//! bound to the request UUID. It never receives artifact bytes or a signer.

use std::io::{Read, Write};

use a_quo_display::contains_unsafe_display_characters;
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
const PERSONA_TRANSITION_PROMPT_PREFIX_BYTES: usize = 168;
const RECOVERY_PARTICIPATION_PROMPT_PREFIX_BYTES: usize = 200;
const DECISION_PAYLOAD_BYTES: usize = 16;
const MESSAGE_ARTIFACT_PROMPT: u16 = 1;
const MESSAGE_APPROVE: u16 = 2;
const MESSAGE_DECLINE: u16 = 3;
const MESSAGE_CANCEL: u16 = 4;
const MESSAGE_DOMAIN_PROMPT: u16 = 5;
const MESSAGE_PERSONA_ROOT_PROMPT: u16 = 6;
const MESSAGE_PERSONA_TRANSITION_PROMPT: u16 = 7;
const MESSAGE_RECOVERY_PARTICIPATION_PROMPT: u16 = 8;
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
pub const MAX_RECOVERY_CEREMONY_ID_BYTES: usize = 43;
pub const MAX_RECOVERY_POLICY_VERSION: u32 = 1_024;
pub const MIN_RECOVERY_THRESHOLD: u32 = 2;
pub const MAX_RECOVERY_THRESHOLD: u32 = 32;
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
const MAX_PERSONA_TRANSITION_PROMPT_PAYLOAD_BYTES: usize = PERSONA_TRANSITION_PROMPT_PREFIX_BYTES
    + MAX_PERSONA_LABEL_BYTES
    + MAX_KEY_FINGERPRINT_BYTES
    + MAX_KEY_FINGERPRINT_BYTES
    + MAX_PERSONA_ANCHOR_BYTES;
const MAX_RECOVERY_PARTICIPATION_PROMPT_PAYLOAD_BYTES: usize =
    RECOVERY_PARTICIPATION_PROMPT_PREFIX_BYTES
        + MAX_PERSONA_LABEL_BYTES
        + MAX_KEY_FINGERPRINT_BYTES
        + MAX_KEY_FINGERPRINT_BYTES
        + MAX_KEY_FINGERPRINT_BYTES
        + MAX_PERSONA_ANCHOR_BYTES
        + MAX_RECOVERY_CEREMONY_ID_BYTES;
const MAX_ARTIFACT_OR_DOMAIN_PROMPT_PAYLOAD_BYTES: usize =
    if MAX_ARTIFACT_PROMPT_PAYLOAD_BYTES > MAX_DOMAIN_PROMPT_PAYLOAD_BYTES {
        MAX_ARTIFACT_PROMPT_PAYLOAD_BYTES
    } else {
        MAX_DOMAIN_PROMPT_PAYLOAD_BYTES
    };
const MAX_ROOT_OR_TRANSITION_PROMPT_PAYLOAD_BYTES: usize =
    if MAX_PERSONA_ROOT_PROMPT_PAYLOAD_BYTES > MAX_PERSONA_TRANSITION_PROMPT_PAYLOAD_BYTES {
        MAX_PERSONA_ROOT_PROMPT_PAYLOAD_BYTES
    } else {
        MAX_PERSONA_TRANSITION_PROMPT_PAYLOAD_BYTES
    };
const MAX_EXISTING_PROMPT_PAYLOAD_BYTES: usize =
    if MAX_ARTIFACT_OR_DOMAIN_PROMPT_PAYLOAD_BYTES > MAX_ROOT_OR_TRANSITION_PROMPT_PAYLOAD_BYTES {
        MAX_ARTIFACT_OR_DOMAIN_PROMPT_PAYLOAD_BYTES
    } else {
        MAX_ROOT_OR_TRANSITION_PROMPT_PAYLOAD_BYTES
    };
pub const MAX_PROMPT_PAYLOAD_BYTES: usize =
    if MAX_EXISTING_PROMPT_PAYLOAD_BYTES > MAX_RECOVERY_PARTICIPATION_PROMPT_PAYLOAD_BYTES {
        MAX_EXISTING_PROMPT_PAYLOAD_BYTES
    } else {
        MAX_RECOVERY_PARTICIPATION_PROMPT_PAYLOAD_BYTES
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

    #[error("unsupported recovery participation role {0}")]
    UnsupportedRecoveryParticipantRole(u8),

    #[error("unsupported recovery transition reason {0}")]
    UnsupportedRecoveryReason(u8),

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecoveryParticipantRole {
    RecoveryAuthority = 1,
    NextSigningKey = 2,
}

impl RecoveryParticipantRole {
    pub fn label(self) -> &'static str {
        match self {
            Self::RecoveryAuthority => "recovery authority",
            Self::NextSigningKey => "next signing key",
        }
    }

    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::RecoveryAuthority),
            2 => Ok(Self::NextSigningKey),
            _ => Err(ProtocolError::UnsupportedRecoveryParticipantRole(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecoveryReason {
    Recovery = 1,
    Compromise = 2,
}

impl RecoveryReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::Compromise => "compromise",
        }
    }

    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Recovery),
            2 => Ok(Self::Compromise),
            _ => Err(ProtocolError::UnsupportedRecoveryReason(value)),
        }
    }
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
    pub persona_id: Option<Uuid>,
    pub persona_label: String,
    pub persona_purpose: Option<PersonaPurpose>,
    pub key_fingerprint: String,
    pub subject: ApprovalSubject,
    pub peer: PeerIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalSubject {
    Artifact(ArtifactApproval),
    Domain(DomainApproval),
    PersonaRoot(PersonaRootApproval),
    PersonaTransition(PersonaTransitionApproval),
    RecoveryParticipation(RecoveryParticipationApproval),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonaTransitionApproval {
    pub persona_anchor: String,
    pub root_statement_sha256: [u8; 32],
    pub sequence: u32,
    pub previous_transition_sha256: Option<[u8; 32]>,
    pub issued_at: i64,
    pub previous_key_fingerprint: String,
    pub next_key_fingerprint: String,
    pub transition_statement_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryParticipationApproval {
    pub request_sha256: [u8; 32],
    pub ceremony_id: String,
    pub ceremony_expires_at: i64,
    pub persona_anchor: String,
    pub root_statement_sha256: [u8; 32],
    pub recovery_policy_version: u32,
    pub recovery_policy_sha256: [u8; 32],
    pub recovery_policy_threshold: u32,
    pub previous_head_sequence: u32,
    pub previous_head_sha256: Option<[u8; 32]>,
    pub reason: RecoveryReason,
    pub previous_key_fingerprint: String,
    pub next_key_fingerprint: String,
    pub participant_role: RecoveryParticipantRole,
    pub participant_key_fingerprint: String,
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
            Some(persona_id),
            persona_label,
            Some(persona_purpose),
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
            Some(persona_id),
            persona_label,
            Some(persona_purpose),
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
            Some(persona_id),
            persona_label,
            Some(persona_purpose),
            key_fingerprint,
            ApprovalSubject::PersonaRoot(PersonaRootApproval {
                persona_anchor: persona_anchor.into(),
                root_statement_sha256,
                issued_at,
            }),
            peer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_persona_transition(
        request_id: Uuid,
        persona_id: Uuid,
        persona_label: impl Into<String>,
        persona_purpose: PersonaPurpose,
        previous_key_fingerprint: impl Into<String>,
        persona_anchor: impl Into<String>,
        root_statement_sha256: [u8; 32],
        sequence: u32,
        previous_transition_sha256: Option<[u8; 32]>,
        issued_at: i64,
        next_key_fingerprint: impl Into<String>,
        transition_statement_sha256: [u8; 32],
        peer: PeerIdentity,
    ) -> Result<Self, ProtocolError> {
        let previous_key_fingerprint = previous_key_fingerprint.into();
        Self::new_with_subject(
            request_id,
            Some(persona_id),
            persona_label,
            Some(persona_purpose),
            previous_key_fingerprint.clone(),
            ApprovalSubject::PersonaTransition(PersonaTransitionApproval {
                persona_anchor: persona_anchor.into(),
                root_statement_sha256,
                sequence,
                previous_transition_sha256,
                issued_at,
                previous_key_fingerprint,
                next_key_fingerprint: next_key_fingerprint.into(),
                transition_statement_sha256,
            }),
            peer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_recovery_participation(
        request_id: Uuid,
        persona_label: impl Into<String>,
        participant_key_fingerprint: impl Into<String>,
        request_sha256: [u8; 32],
        ceremony_id: impl Into<String>,
        ceremony_expires_at: i64,
        persona_anchor: impl Into<String>,
        root_statement_sha256: [u8; 32],
        recovery_policy_version: u32,
        recovery_policy_sha256: [u8; 32],
        recovery_policy_threshold: u32,
        previous_head_sequence: u32,
        previous_head_sha256: Option<[u8; 32]>,
        reason: RecoveryReason,
        previous_key_fingerprint: impl Into<String>,
        next_key_fingerprint: impl Into<String>,
        participant_role: RecoveryParticipantRole,
        peer: PeerIdentity,
    ) -> Result<Self, ProtocolError> {
        let participant_key_fingerprint = participant_key_fingerprint.into();
        Self::new_with_subject(
            request_id,
            None,
            persona_label,
            None,
            participant_key_fingerprint.clone(),
            ApprovalSubject::RecoveryParticipation(RecoveryParticipationApproval {
                request_sha256,
                ceremony_id: ceremony_id.into(),
                ceremony_expires_at,
                persona_anchor: persona_anchor.into(),
                root_statement_sha256,
                recovery_policy_version,
                recovery_policy_sha256,
                recovery_policy_threshold,
                previous_head_sequence,
                previous_head_sha256,
                reason,
                previous_key_fingerprint: previous_key_fingerprint.into(),
                next_key_fingerprint: next_key_fingerprint.into(),
                participant_role,
                participant_key_fingerprint,
            }),
            peer,
        )
    }

    fn new_with_subject(
        request_id: Uuid,
        persona_id: Option<Uuid>,
        persona_label: impl Into<String>,
        persona_purpose: Option<PersonaPurpose>,
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

impl PersonaTransitionApproval {
    pub fn root_sha256_hex(&self) -> String {
        encode_hex(&self.root_statement_sha256)
    }

    pub fn previous_sha256_hex(&self) -> Option<String> {
        self.previous_transition_sha256
            .as_ref()
            .map(|digest| encode_hex(digest))
    }

    pub fn transition_sha256_hex(&self) -> String {
        encode_hex(&self.transition_statement_sha256)
    }
}

impl RecoveryParticipationApproval {
    pub fn request_sha256_hex(&self) -> String {
        encode_hex(&self.request_sha256)
    }

    pub fn root_sha256_hex(&self) -> String {
        encode_hex(&self.root_statement_sha256)
    }

    pub fn policy_sha256_hex(&self) -> String {
        encode_hex(&self.recovery_policy_sha256)
    }

    pub fn previous_head_sha256_hex(&self) -> Option<String> {
        self.previous_head_sha256
            .as_ref()
            .map(|digest| encode_hex(digest))
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
        ApprovalSubject::PersonaTransition(transition) => {
            encode_persona_transition_prompt(prompt, transition)
        }
        ApprovalSubject::RecoveryParticipation(recovery) => {
            encode_recovery_participation_prompt(prompt, recovery)
        }
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
    message.push(required_persona_purpose(prompt)? as u8);
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&prompt.peer.pid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.uid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.gid.to_be_bytes());
    message.extend_from_slice(&artifact.artifact_size.to_be_bytes());
    message.extend_from_slice(prompt.request_id.as_bytes());
    message.extend_from_slice(required_persona_id(prompt)?.as_bytes());
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
    message.push(required_persona_purpose(prompt)? as u8);
    message.extend_from_slice(&[0_u8; 3]);
    message.extend_from_slice(&prompt.peer.pid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.uid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.gid.to_be_bytes());
    message.extend_from_slice(&domain.issued_at.to_be_bytes());
    message.extend_from_slice(&domain.expires_at.to_be_bytes());
    message.extend_from_slice(prompt.request_id.as_bytes());
    message.extend_from_slice(required_persona_id(prompt)?.as_bytes());
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
    message.push(required_persona_purpose(prompt)? as u8);
    message.extend_from_slice(&[0_u8; 3]);
    message.extend_from_slice(&prompt.peer.pid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.uid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.gid.to_be_bytes());
    message.extend_from_slice(&root.issued_at.to_be_bytes());
    message.extend_from_slice(prompt.request_id.as_bytes());
    message.extend_from_slice(required_persona_id(prompt)?.as_bytes());
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

fn encode_persona_transition_prompt(
    prompt: &ApprovalPrompt,
    transition: &PersonaTransitionApproval,
) -> Result<Vec<u8>, ProtocolError> {
    let persona_label = prompt.persona_label.as_bytes();
    let previous_fingerprint = transition.previous_key_fingerprint.as_bytes();
    let next_fingerprint = transition.next_key_fingerprint.as_bytes();
    let persona_anchor = transition.persona_anchor.as_bytes();
    let payload_len = PERSONA_TRANSITION_PROMPT_PREFIX_BYTES
        .checked_add(persona_label.len())
        .and_then(|length| length.checked_add(previous_fingerprint.len()))
        .and_then(|length| length.checked_add(next_fingerprint.len()))
        .and_then(|length| length.checked_add(persona_anchor.len()))
        .ok_or(ProtocolError::PayloadTooLarge)?;
    let mut message = encode_header(MESSAGE_PERSONA_TRANSITION_PROMPT, payload_len);
    message.push(required_persona_purpose(prompt)? as u8);
    message.push(u8::from(transition.previous_transition_sha256.is_some()));
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(&prompt.peer.pid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.uid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.gid.to_be_bytes());
    message.extend_from_slice(&transition.sequence.to_be_bytes());
    message.extend_from_slice(&transition.issued_at.to_be_bytes());
    message.extend_from_slice(prompt.request_id.as_bytes());
    message.extend_from_slice(required_persona_id(prompt)?.as_bytes());
    message.extend_from_slice(&transition.root_statement_sha256);
    message.extend_from_slice(&transition.previous_transition_sha256.unwrap_or([0_u8; 32]));
    message.extend_from_slice(&transition.transition_statement_sha256);
    message.extend_from_slice(&(persona_label.len() as u16).to_be_bytes());
    message.extend_from_slice(&(previous_fingerprint.len() as u16).to_be_bytes());
    message.extend_from_slice(&(next_fingerprint.len() as u16).to_be_bytes());
    message.extend_from_slice(&(persona_anchor.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u32.to_be_bytes());
    debug_assert_eq!(
        message.len(),
        HEADER_BYTES + PERSONA_TRANSITION_PROMPT_PREFIX_BYTES
    );
    message.extend_from_slice(persona_label);
    message.extend_from_slice(previous_fingerprint);
    message.extend_from_slice(next_fingerprint);
    message.extend_from_slice(persona_anchor);
    Ok(message)
}

fn encode_recovery_participation_prompt(
    prompt: &ApprovalPrompt,
    recovery: &RecoveryParticipationApproval,
) -> Result<Vec<u8>, ProtocolError> {
    let persona_label = prompt.persona_label.as_bytes();
    let participant_fingerprint = recovery.participant_key_fingerprint.as_bytes();
    let previous_fingerprint = recovery.previous_key_fingerprint.as_bytes();
    let next_fingerprint = recovery.next_key_fingerprint.as_bytes();
    let persona_anchor = recovery.persona_anchor.as_bytes();
    let ceremony_id = recovery.ceremony_id.as_bytes();
    let payload_len = RECOVERY_PARTICIPATION_PROMPT_PREFIX_BYTES
        .checked_add(persona_label.len())
        .and_then(|length| length.checked_add(participant_fingerprint.len()))
        .and_then(|length| length.checked_add(previous_fingerprint.len()))
        .and_then(|length| length.checked_add(next_fingerprint.len()))
        .and_then(|length| length.checked_add(persona_anchor.len()))
        .and_then(|length| length.checked_add(ceremony_id.len()))
        .ok_or(ProtocolError::PayloadTooLarge)?;
    let mut message = encode_header(MESSAGE_RECOVERY_PARTICIPATION_PROMPT, payload_len);
    message.push(recovery.participant_role as u8);
    message.push(recovery.reason as u8);
    message.push(u8::from(recovery.previous_head_sha256.is_some()));
    message.push(0);
    message.extend_from_slice(&prompt.peer.pid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.uid.to_be_bytes());
    message.extend_from_slice(&prompt.peer.gid.to_be_bytes());
    message.extend_from_slice(&recovery.recovery_policy_version.to_be_bytes());
    message.extend_from_slice(&recovery.recovery_policy_threshold.to_be_bytes());
    message.extend_from_slice(&recovery.previous_head_sequence.to_be_bytes());
    message.extend_from_slice(&0_u32.to_be_bytes());
    message.extend_from_slice(&recovery.ceremony_expires_at.to_be_bytes());
    message.extend_from_slice(prompt.request_id.as_bytes());
    message.extend_from_slice(&recovery.request_sha256);
    message.extend_from_slice(&recovery.root_statement_sha256);
    message.extend_from_slice(&recovery.recovery_policy_sha256);
    message.extend_from_slice(&recovery.previous_head_sha256.unwrap_or([0_u8; 32]));
    message.extend_from_slice(&(persona_label.len() as u16).to_be_bytes());
    message.extend_from_slice(&(participant_fingerprint.len() as u16).to_be_bytes());
    message.extend_from_slice(&(previous_fingerprint.len() as u16).to_be_bytes());
    message.extend_from_slice(&(next_fingerprint.len() as u16).to_be_bytes());
    message.extend_from_slice(&(persona_anchor.len() as u16).to_be_bytes());
    message.extend_from_slice(&(ceremony_id.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u32.to_be_bytes());
    debug_assert_eq!(
        message.len(),
        HEADER_BYTES + RECOVERY_PARTICIPATION_PROMPT_PREFIX_BYTES
    );
    message.extend_from_slice(persona_label);
    message.extend_from_slice(participant_fingerprint);
    message.extend_from_slice(previous_fingerprint);
    message.extend_from_slice(next_fingerprint);
    message.extend_from_slice(persona_anchor);
    message.extend_from_slice(ceremony_id);
    Ok(message)
}

pub fn decode_prompt(message: &[u8]) -> Result<ApprovalPrompt, ProtocolError> {
    match decode_common_header(message)? {
        MESSAGE_ARTIFACT_PROMPT => decode_artifact_prompt(message),
        MESSAGE_DOMAIN_PROMPT => decode_domain_prompt(message),
        MESSAGE_PERSONA_ROOT_PROMPT => decode_persona_root_prompt(message),
        MESSAGE_PERSONA_TRANSITION_PROMPT => decode_persona_transition_prompt(message),
        MESSAGE_RECOVERY_PARTICIPATION_PROMPT => decode_recovery_participation_prompt(message),
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

fn decode_persona_transition_prompt(message: &[u8]) -> Result<ApprovalPrompt, ProtocolError> {
    let payload = decode_header(
        message,
        MESSAGE_PERSONA_TRANSITION_PROMPT,
        MAX_PERSONA_TRANSITION_PROMPT_PAYLOAD_BYTES,
    )?;
    if payload.len() < PERSONA_TRANSITION_PROMPT_PREFIX_BYTES
        || payload[2..4] != [0, 0]
        || payload[164..168] != [0, 0, 0, 0]
        || payload[1] > 1
    {
        return Err(ProtocolError::InvalidLayout);
    }
    let persona_purpose = PersonaPurpose::decode(payload[0])?;
    let peer = PeerIdentity {
        pid: read_u32(payload, 4),
        uid: read_u32(payload, 8),
        gid: read_u32(payload, 12),
    };
    let sequence = read_u32(payload, 16);
    let issued_at = read_i64(payload, 20);
    let request_id =
        Uuid::from_slice(&payload[28..44]).map_err(|_| ProtocolError::InvalidLayout)?;
    let persona_id =
        Uuid::from_slice(&payload[44..60]).map_err(|_| ProtocolError::InvalidLayout)?;
    let mut root_statement_sha256 = [0_u8; 32];
    root_statement_sha256.copy_from_slice(&payload[60..92]);
    let mut previous = [0_u8; 32];
    previous.copy_from_slice(&payload[92..124]);
    let previous_transition_sha256 = match payload[1] {
        0 if previous == [0_u8; 32] => None,
        0 => return Err(ProtocolError::InvalidLayout),
        1 => Some(previous),
        _ => unreachable!("presence byte was checked"),
    };
    let mut transition_statement_sha256 = [0_u8; 32];
    transition_statement_sha256.copy_from_slice(&payload[124..156]);
    let persona_label_len = usize::from(read_u16(payload, 156));
    let previous_fingerprint_len = usize::from(read_u16(payload, 158));
    let next_fingerprint_len = usize::from(read_u16(payload, 160));
    let persona_anchor_len = usize::from(read_u16(payload, 162));
    let expected = PERSONA_TRANSITION_PROMPT_PREFIX_BYTES
        .checked_add(persona_label_len)
        .and_then(|length| length.checked_add(previous_fingerprint_len))
        .and_then(|length| length.checked_add(next_fingerprint_len))
        .and_then(|length| length.checked_add(persona_anchor_len))
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }

    let persona_end = PERSONA_TRANSITION_PROMPT_PREFIX_BYTES + persona_label_len;
    let previous_end = persona_end + previous_fingerprint_len;
    let next_end = previous_end + next_fingerprint_len;
    let persona_label = decode_text(
        "persona label",
        &payload[PERSONA_TRANSITION_PROMPT_PREFIX_BYTES..persona_end],
    )?;
    let previous_key_fingerprint = decode_text(
        "previous key fingerprint",
        &payload[persona_end..previous_end],
    )?;
    let next_key_fingerprint =
        decode_text("next key fingerprint", &payload[previous_end..next_end])?;
    let persona_anchor = decode_text("persona anchor", &payload[next_end..])?;
    ApprovalPrompt::new_persona_transition(
        request_id,
        persona_id,
        persona_label,
        persona_purpose,
        previous_key_fingerprint,
        persona_anchor,
        root_statement_sha256,
        sequence,
        previous_transition_sha256,
        issued_at,
        next_key_fingerprint,
        transition_statement_sha256,
        peer,
    )
}

fn decode_recovery_participation_prompt(message: &[u8]) -> Result<ApprovalPrompt, ProtocolError> {
    let payload = decode_header(
        message,
        MESSAGE_RECOVERY_PARTICIPATION_PROMPT,
        MAX_RECOVERY_PARTICIPATION_PROMPT_PAYLOAD_BYTES,
    )?;
    if payload.len() < RECOVERY_PARTICIPATION_PROMPT_PREFIX_BYTES
        || payload[3] != 0
        || payload[28..32] != [0, 0, 0, 0]
        || payload[196..200] != [0, 0, 0, 0]
        || payload[2] > 1
    {
        return Err(ProtocolError::InvalidLayout);
    }
    let participant_role = RecoveryParticipantRole::decode(payload[0])?;
    let reason = RecoveryReason::decode(payload[1])?;
    let peer = PeerIdentity {
        pid: read_u32(payload, 4),
        uid: read_u32(payload, 8),
        gid: read_u32(payload, 12),
    };
    let recovery_policy_version = read_u32(payload, 16);
    let recovery_policy_threshold = read_u32(payload, 20);
    let previous_head_sequence = read_u32(payload, 24);
    let ceremony_expires_at = read_i64(payload, 32);
    let request_id =
        Uuid::from_slice(&payload[40..56]).map_err(|_| ProtocolError::InvalidLayout)?;
    let mut request_sha256 = [0_u8; 32];
    request_sha256.copy_from_slice(&payload[56..88]);
    let mut root_statement_sha256 = [0_u8; 32];
    root_statement_sha256.copy_from_slice(&payload[88..120]);
    let mut recovery_policy_sha256 = [0_u8; 32];
    recovery_policy_sha256.copy_from_slice(&payload[120..152]);
    let mut previous_head = [0_u8; 32];
    previous_head.copy_from_slice(&payload[152..184]);
    let previous_head_sha256 = match payload[2] {
        0 if previous_head == [0_u8; 32] => None,
        0 => return Err(ProtocolError::InvalidLayout),
        1 => Some(previous_head),
        _ => unreachable!("presence byte was checked"),
    };
    let persona_label_len = usize::from(read_u16(payload, 184));
    let participant_fingerprint_len = usize::from(read_u16(payload, 186));
    let previous_fingerprint_len = usize::from(read_u16(payload, 188));
    let next_fingerprint_len = usize::from(read_u16(payload, 190));
    let persona_anchor_len = usize::from(read_u16(payload, 192));
    let ceremony_id_len = usize::from(read_u16(payload, 194));
    let expected = RECOVERY_PARTICIPATION_PROMPT_PREFIX_BYTES
        .checked_add(persona_label_len)
        .and_then(|length| length.checked_add(participant_fingerprint_len))
        .and_then(|length| length.checked_add(previous_fingerprint_len))
        .and_then(|length| length.checked_add(next_fingerprint_len))
        .and_then(|length| length.checked_add(persona_anchor_len))
        .and_then(|length| length.checked_add(ceremony_id_len))
        .ok_or(ProtocolError::InvalidLayout)?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLayout);
    }

    let persona_end = RECOVERY_PARTICIPATION_PROMPT_PREFIX_BYTES + persona_label_len;
    let participant_end = persona_end + participant_fingerprint_len;
    let previous_end = participant_end + previous_fingerprint_len;
    let next_end = previous_end + next_fingerprint_len;
    let anchor_end = next_end + persona_anchor_len;
    let persona_label = decode_text(
        "persona label",
        &payload[RECOVERY_PARTICIPATION_PROMPT_PREFIX_BYTES..persona_end],
    )?;
    let participant_key_fingerprint = decode_text(
        "participant key fingerprint",
        &payload[persona_end..participant_end],
    )?;
    let previous_key_fingerprint = decode_text(
        "previous key fingerprint",
        &payload[participant_end..previous_end],
    )?;
    let next_key_fingerprint =
        decode_text("next key fingerprint", &payload[previous_end..next_end])?;
    let persona_anchor = decode_text("persona anchor", &payload[next_end..anchor_end])?;
    let ceremony_id = decode_text("ceremony ID", &payload[anchor_end..])?;
    ApprovalPrompt::new_recovery_participation(
        request_id,
        persona_label,
        participant_key_fingerprint,
        request_sha256,
        ceremony_id,
        ceremony_expires_at,
        persona_anchor,
        root_statement_sha256,
        recovery_policy_version,
        recovery_policy_sha256,
        recovery_policy_threshold,
        previous_head_sequence,
        previous_head_sha256,
        reason,
        previous_key_fingerprint,
        next_key_fingerprint,
        participant_role,
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
    let is_recovery_participation =
        matches!(&prompt.subject, ApprovalSubject::RecoveryParticipation(_));
    match (
        prompt.persona_id,
        prompt.persona_purpose,
        is_recovery_participation,
    ) {
        (None, None, true) => {}
        (Some(_), _, true) | (_, Some(_), true) => {
            return Err(ProtocolError::InvalidField {
                field: "local persona metadata",
                reason: "recovery participation must not expose a coordinator-local persona UUID or purpose".to_owned(),
            });
        }
        (Some(persona_id), Some(_), false) if !persona_id.is_nil() => {}
        (Some(persona_id), Some(_), false) if persona_id.is_nil() => {
            return Err(ProtocolError::InvalidField {
                field: "persona ID",
                reason: "it cannot be the nil UUID".to_owned(),
            });
        }
        _ => {
            return Err(ProtocolError::InvalidField {
                field: "local persona metadata",
                reason: "this prompt purpose requires both a persona UUID and purpose".to_owned(),
            });
        }
    }
    validate_text(
        "persona label",
        &prompt.persona_label,
        MAX_PERSONA_LABEL_BYTES,
    )?;
    validate_key_fingerprint("key fingerprint", &prompt.key_fingerprint)?;
    match &prompt.subject {
        ApprovalSubject::Artifact(artifact) => validate_text(
            "artifact label",
            &artifact.artifact_label,
            MAX_ARTIFACT_LABEL_BYTES,
        )?,
        ApprovalSubject::Domain(domain) => validate_domain_approval(domain)?,
        ApprovalSubject::PersonaRoot(root) => validate_persona_root_approval(root)?,
        ApprovalSubject::PersonaTransition(transition) => {
            validate_persona_transition_approval(prompt, transition)?
        }
        ApprovalSubject::RecoveryParticipation(recovery) => {
            validate_recovery_participation_approval(prompt, recovery)?
        }
    }
    if prompt.peer.pid == 0 {
        return Err(ProtocolError::InvalidField {
            field: "peer PID",
            reason: "it must be nonzero".to_owned(),
        });
    }
    Ok(())
}

fn required_persona_id(prompt: &ApprovalPrompt) -> Result<Uuid, ProtocolError> {
    prompt
        .persona_id
        .ok_or_else(|| ProtocolError::InvalidField {
            field: "persona ID",
            reason: "it is required for this prompt purpose".to_owned(),
        })
}

fn required_persona_purpose(prompt: &ApprovalPrompt) -> Result<PersonaPurpose, ProtocolError> {
    prompt
        .persona_purpose
        .ok_or_else(|| ProtocolError::InvalidField {
            field: "persona purpose",
            reason: "it is required for this prompt purpose".to_owned(),
        })
}

fn validate_key_fingerprint(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    validate_text(field, value, MAX_KEY_FINGERPRINT_BYTES)?;
    let fingerprint = value
        .strip_prefix("SHA256:")
        .ok_or_else(|| ProtocolError::InvalidField {
            field,
            reason: "expected the canonical OpenSSH SHA256 form".to_owned(),
        })?;
    let decoded = STANDARD_NO_PAD
        .decode(fingerprint)
        .map_err(|_| ProtocolError::InvalidField {
            field,
            reason: "expected canonical unpadded Base64 after SHA256:".to_owned(),
        })?;
    if decoded.len() != 32 || STANDARD_NO_PAD.encode(&decoded) != fingerprint {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "expected the canonical 32-byte OpenSSH SHA256 digest".to_owned(),
        });
    }
    Ok(())
}

fn validate_persona_root_approval(root: &PersonaRootApproval) -> Result<(), ProtocolError> {
    validate_persona_anchor(&root.persona_anchor)?;
    if root.issued_at < 0 {
        return Err(ProtocolError::InvalidField {
            field: "root issuance time",
            reason: "it must be nonnegative".to_owned(),
        });
    }
    Ok(())
}

fn validate_persona_anchor(anchor: &str) -> Result<(), ProtocolError> {
    validate_text("persona anchor", anchor, MAX_PERSONA_ANCHOR_BYTES)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(anchor)
        .map_err(|_| ProtocolError::InvalidField {
            field: "persona anchor",
            reason: "expected canonical unpadded Base64url".to_owned(),
        })?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != anchor {
        return Err(ProtocolError::InvalidField {
            field: "persona anchor",
            reason: "expected one canonical 32-byte persona anchor".to_owned(),
        });
    }
    Ok(())
}

fn validate_persona_transition_approval(
    prompt: &ApprovalPrompt,
    transition: &PersonaTransitionApproval,
) -> Result<(), ProtocolError> {
    validate_persona_anchor(&transition.persona_anchor)?;
    if transition.issued_at < 0 {
        return Err(ProtocolError::InvalidField {
            field: "transition issuance time",
            reason: "it must be nonnegative".to_owned(),
        });
    }
    if transition.sequence == 0 {
        return Err(ProtocolError::InvalidField {
            field: "transition sequence",
            reason: "it must start at 1".to_owned(),
        });
    }
    match (transition.sequence, transition.previous_transition_sha256) {
        (1, None) => {}
        (1, Some(_)) => {
            return Err(ProtocolError::InvalidField {
                field: "previous transition digest",
                reason: "sequence 1 cannot name a previous transition".to_owned(),
            });
        }
        (_, Some(_)) => {}
        (_, None) => {
            return Err(ProtocolError::InvalidField {
                field: "previous transition digest",
                reason: "sequences after 1 require a previous transition".to_owned(),
            });
        }
    }
    if prompt.key_fingerprint != transition.previous_key_fingerprint {
        return Err(ProtocolError::InvalidField {
            field: "previous key fingerprint",
            reason: "it must equal the prompt's selected signing key".to_owned(),
        });
    }
    validate_key_fingerprint(
        "previous key fingerprint",
        &transition.previous_key_fingerprint,
    )?;
    validate_key_fingerprint("next key fingerprint", &transition.next_key_fingerprint)?;
    if transition.previous_key_fingerprint == transition.next_key_fingerprint {
        return Err(ProtocolError::InvalidField {
            field: "next key fingerprint",
            reason: "it must differ from the previous key".to_owned(),
        });
    }
    Ok(())
}

fn validate_recovery_participation_approval(
    prompt: &ApprovalPrompt,
    recovery: &RecoveryParticipationApproval,
) -> Result<(), ProtocolError> {
    validate_persona_anchor(&recovery.persona_anchor)?;
    validate_recovery_ceremony_id(&recovery.ceremony_id)?;
    if recovery.ceremony_expires_at <= 0 {
        return Err(ProtocolError::InvalidField {
            field: "ceremony expiry",
            reason: "it must be positive".to_owned(),
        });
    }
    if !(1..=MAX_RECOVERY_POLICY_VERSION).contains(&recovery.recovery_policy_version) {
        return Err(ProtocolError::InvalidField {
            field: "recovery policy version",
            reason: format!("it must be 1 through {MAX_RECOVERY_POLICY_VERSION}"),
        });
    }
    if !(MIN_RECOVERY_THRESHOLD..=MAX_RECOVERY_THRESHOLD)
        .contains(&recovery.recovery_policy_threshold)
    {
        return Err(ProtocolError::InvalidField {
            field: "recovery policy threshold",
            reason: format!("it must be {MIN_RECOVERY_THRESHOLD} through {MAX_RECOVERY_THRESHOLD}"),
        });
    }
    match (
        recovery.previous_head_sequence,
        recovery.previous_head_sha256,
    ) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err(ProtocolError::InvalidField {
                field: "previous head digest",
                reason: "the root head cannot name a transition digest".to_owned(),
            });
        }
        (_, Some(_)) => {}
        (_, None) => {
            return Err(ProtocolError::InvalidField {
                field: "previous head digest",
                reason: "a transition head requires its exact digest".to_owned(),
            });
        }
    }
    validate_key_fingerprint(
        "participant key fingerprint",
        &recovery.participant_key_fingerprint,
    )?;
    if prompt.key_fingerprint != recovery.participant_key_fingerprint {
        return Err(ProtocolError::InvalidField {
            field: "participant key fingerprint",
            reason: "it must equal the prompt's selected participant key".to_owned(),
        });
    }
    validate_key_fingerprint(
        "previous key fingerprint",
        &recovery.previous_key_fingerprint,
    )?;
    validate_key_fingerprint("next key fingerprint", &recovery.next_key_fingerprint)?;
    if recovery.previous_key_fingerprint == recovery.next_key_fingerprint {
        return Err(ProtocolError::InvalidField {
            field: "next key fingerprint",
            reason: "recovery must replace the previous key with a distinct key".to_owned(),
        });
    }
    match recovery.participant_role {
        RecoveryParticipantRole::RecoveryAuthority
            if recovery.participant_key_fingerprint == recovery.previous_key_fingerprint
                || recovery.participant_key_fingerprint == recovery.next_key_fingerprint =>
        {
            return Err(ProtocolError::InvalidField {
                field: "participant key fingerprint",
                reason: "a recovery authority must be distinct from both online signing keys"
                    .to_owned(),
            });
        }
        RecoveryParticipantRole::NextSigningKey
            if recovery.participant_key_fingerprint != recovery.next_key_fingerprint =>
        {
            return Err(ProtocolError::InvalidField {
                field: "participant key fingerprint",
                reason: "the next-key participant must match the proposed next signing key"
                    .to_owned(),
            });
        }
        RecoveryParticipantRole::RecoveryAuthority | RecoveryParticipantRole::NextSigningKey => {}
    }
    Ok(())
}

fn validate_recovery_ceremony_id(value: &str) -> Result<(), ProtocolError> {
    validate_text("ceremony ID", value, MAX_RECOVERY_CEREMONY_ID_BYTES)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProtocolError::InvalidField {
            field: "ceremony ID",
            reason: "expected canonical unpadded Base64url".to_owned(),
        })?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ProtocolError::InvalidField {
            field: "ceremony ID",
            reason: "expected one canonical 32-byte ceremony identifier".to_owned(),
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
    if contains_unsafe_display_characters(value) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "control, line/paragraph separator, or default-ignorable Unicode characters are not allowed".to_owned(),
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

    fn fingerprint(byte: u8) -> String {
        format!("SHA256:{}", STANDARD_NO_PAD.encode([byte; 32]))
    }

    fn persona_transition_prompt(
        sequence: u32,
        previous_transition_sha256: Option<[u8; 32]>,
    ) -> ApprovalPrompt {
        ApprovalPrompt::new_persona_transition(
            Uuid::parse_str("f62e45ae-2a08-411e-b5fb-e3a6c92dd4cf").unwrap(),
            Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap(),
            "A Quo publisher",
            PersonaPurpose::Project,
            fingerprint(0x11),
            URL_SAFE_NO_PAD.encode([0x24; 32]),
            [0x42; 32],
            sequence,
            previous_transition_sha256,
            1_787_875_200,
            fingerprint(0x22),
            [0x44; 32],
            PeerIdentity {
                pid: 4242,
                uid: 1000,
                gid: 1000,
            },
        )
        .unwrap()
    }

    fn recovery_participation_prompt(
        role: RecoveryParticipantRole,
        participant_key_fingerprint: String,
        previous_head_sequence: u32,
        previous_head_sha256: Option<[u8; 32]>,
    ) -> ApprovalPrompt {
        ApprovalPrompt::new_recovery_participation(
            Uuid::parse_str("f62e45ae-2a08-411e-b5fb-e3a6c92dd4cf").unwrap(),
            "A Quo publisher",
            participant_key_fingerprint,
            [0x31; 32],
            URL_SAFE_NO_PAD.encode([0x32; 32]),
            1_787_878_800,
            URL_SAFE_NO_PAD.encode([0x24; 32]),
            [0x42; 32],
            7,
            [0x52; 32],
            2,
            previous_head_sequence,
            previous_head_sha256,
            RecoveryReason::Compromise,
            fingerprint(0x11),
            fingerprint(0x22),
            role,
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
    fn persona_transition_prompt_round_trip_is_exact_and_separate() {
        let prompt = persona_transition_prompt(2, Some([0x43; 32]));
        let encoded = encode_prompt(&prompt).unwrap();
        assert_eq!(read_u16(&encoded, 12), MESSAGE_PERSONA_TRANSITION_PROMPT);
        assert_eq!(encoded[HEADER_BYTES + 1], 1);
        assert_eq!(&encoded[HEADER_BYTES + 60..HEADER_BYTES + 92], &[0x42; 32]);
        assert_eq!(&encoded[HEADER_BYTES + 92..HEADER_BYTES + 124], &[0x43; 32]);
        assert_eq!(
            &encoded[HEADER_BYTES + 124..HEADER_BYTES + 156],
            &[0x44; 32]
        );
        assert_eq!(decode_prompt(&encoded).unwrap(), prompt);

        let ApprovalSubject::PersonaTransition(transition) = &prompt.subject else {
            panic!("expected persona-transition prompt");
        };
        assert_eq!(prompt.key_fingerprint, transition.previous_key_fingerprint);
        assert_eq!(transition.root_sha256_hex(), "42".repeat(32));
        assert_eq!(transition.previous_sha256_hex(), Some("43".repeat(32)));
        assert_eq!(transition.transition_sha256_hex(), "44".repeat(32));

        let first = persona_transition_prompt(1, None);
        let first_encoded = encode_prompt(&first).unwrap();
        assert_eq!(first_encoded[HEADER_BYTES + 1], 0);
        assert_eq!(
            &first_encoded[HEADER_BYTES + 92..HEADER_BYTES + 124],
            &[0_u8; 32]
        );
        assert_eq!(decode_prompt(&first_encoded).unwrap(), first);
    }

    #[test]
    fn persona_transition_prompt_rejects_unsafe_semantics() {
        let mut zero = persona_transition_prompt(1, None);
        let ApprovalSubject::PersonaTransition(transition) = &mut zero.subject else {
            panic!("expected persona-transition prompt");
        };
        transition.sequence = 0;
        assert!(matches!(
            encode_prompt(&zero),
            Err(ProtocolError::InvalidField {
                field: "transition sequence",
                ..
            })
        ));

        let mut first_with_prior = persona_transition_prompt(1, None);
        let ApprovalSubject::PersonaTransition(transition) = &mut first_with_prior.subject else {
            panic!("expected persona-transition prompt");
        };
        transition.previous_transition_sha256 = Some([0x33; 32]);
        assert!(matches!(
            encode_prompt(&first_with_prior),
            Err(ProtocolError::InvalidField {
                field: "previous transition digest",
                ..
            })
        ));

        let mut later_without_prior = persona_transition_prompt(2, Some([0x43; 32]));
        let ApprovalSubject::PersonaTransition(transition) = &mut later_without_prior.subject
        else {
            panic!("expected persona-transition prompt");
        };
        transition.previous_transition_sha256 = None;
        assert!(matches!(
            encode_prompt(&later_without_prior),
            Err(ProtocolError::InvalidField {
                field: "previous transition digest",
                ..
            })
        ));

        let mut negative = persona_transition_prompt(1, None);
        let ApprovalSubject::PersonaTransition(transition) = &mut negative.subject else {
            panic!("expected persona-transition prompt");
        };
        transition.issued_at = -1;
        assert!(matches!(
            encode_prompt(&negative),
            Err(ProtocolError::InvalidField {
                field: "transition issuance time",
                ..
            })
        ));
    }

    #[test]
    fn persona_transition_prompt_rejects_key_and_anchor_substitution() {
        let mut unbound_previous = persona_transition_prompt(1, None);
        let ApprovalSubject::PersonaTransition(transition) = &mut unbound_previous.subject else {
            panic!("expected persona-transition prompt");
        };
        transition.previous_key_fingerprint = fingerprint(0x33);
        assert!(matches!(
            encode_prompt(&unbound_previous),
            Err(ProtocolError::InvalidField {
                field: "previous key fingerprint",
                ..
            })
        ));

        let mut same_key = persona_transition_prompt(1, None);
        let ApprovalSubject::PersonaTransition(transition) = &mut same_key.subject else {
            panic!("expected persona-transition prompt");
        };
        transition.next_key_fingerprint = transition.previous_key_fingerprint.clone();
        assert!(matches!(
            encode_prompt(&same_key),
            Err(ProtocolError::InvalidField {
                field: "next key fingerprint",
                ..
            })
        ));

        let mut dangerous_key = persona_transition_prompt(1, None);
        let ApprovalSubject::PersonaTransition(transition) = &mut dangerous_key.subject else {
            panic!("expected persona-transition prompt");
        };
        transition.next_key_fingerprint.push('\u{202e}');
        assert!(matches!(
            encode_prompt(&dangerous_key),
            Err(ProtocolError::InvalidField {
                field: "next key fingerprint",
                ..
            })
        ));

        let mut padded_anchor = persona_transition_prompt(1, None);
        let ApprovalSubject::PersonaTransition(transition) = &mut padded_anchor.subject else {
            panic!("expected persona-transition prompt");
        };
        transition.persona_anchor.push('=');
        assert!(matches!(
            encode_prompt(&padded_anchor),
            Err(ProtocolError::InvalidField {
                field: "persona anchor",
                ..
            })
        ));
    }

    #[test]
    fn persona_transition_prompt_rejects_hostile_fixed_layout_and_text() {
        let encoded = encode_prompt(&persona_transition_prompt(2, Some([0x43; 32]))).unwrap();
        for offset in [HEADER_BYTES + 2, HEADER_BYTES + 164] {
            let mut reserved = encoded.clone();
            reserved[offset] = 1;
            assert!(matches!(
                decode_prompt(&reserved),
                Err(ProtocolError::InvalidLayout)
            ));
        }

        let mut invalid_presence = encoded.clone();
        invalid_presence[HEADER_BYTES + 1] = 2;
        assert!(matches!(
            decode_prompt(&invalid_presence),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut absent_nonzero = encoded.clone();
        absent_nonzero[HEADER_BYTES + 1] = 0;
        assert!(matches!(
            decode_prompt(&absent_nonzero),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut bad_anchor_length = encoded.clone();
        bad_anchor_length[HEADER_BYTES + 162..HEADER_BYTES + 164]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            decode_prompt(&bad_anchor_length),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut bad_utf8 = encoded;
        *bad_utf8.last_mut().unwrap() = 0xff;
        assert!(matches!(
            decode_prompt(&bad_utf8),
            Err(ProtocolError::InvalidField { .. })
        ));
    }

    #[test]
    fn recovery_participation_prompt_round_trip_is_exact_and_separate() {
        let prompt = recovery_participation_prompt(
            RecoveryParticipantRole::RecoveryAuthority,
            fingerprint(0x33),
            3,
            Some([0x62; 32]),
        );
        let encoded = encode_prompt(&prompt).unwrap();
        assert_eq!(
            read_u16(&encoded, 12),
            MESSAGE_RECOVERY_PARTICIPATION_PROMPT
        );
        assert_eq!(
            encoded[HEADER_BYTES],
            RecoveryParticipantRole::RecoveryAuthority as u8
        );
        assert_eq!(encoded[HEADER_BYTES + 1], RecoveryReason::Compromise as u8);
        assert_eq!(encoded[HEADER_BYTES + 2], 1);
        assert_eq!(encoded[HEADER_BYTES + 3], 0);
        assert_eq!(read_u32(&encoded, HEADER_BYTES + 16), 7);
        assert_eq!(read_u32(&encoded, HEADER_BYTES + 20), 2);
        assert_eq!(read_u32(&encoded, HEADER_BYTES + 24), 3);
        assert_eq!(&encoded[HEADER_BYTES + 56..HEADER_BYTES + 88], &[0x31; 32]);
        assert_eq!(&encoded[HEADER_BYTES + 88..HEADER_BYTES + 120], &[0x42; 32]);
        assert_eq!(
            &encoded[HEADER_BYTES + 120..HEADER_BYTES + 152],
            &[0x52; 32]
        );
        assert_eq!(
            &encoded[HEADER_BYTES + 152..HEADER_BYTES + 184],
            &[0x62; 32]
        );
        assert_eq!(decode_prompt(&encoded).unwrap(), prompt);
        assert_eq!(prompt.persona_id, None);
        assert_eq!(prompt.persona_purpose, None);

        let ApprovalSubject::RecoveryParticipation(recovery) = &prompt.subject else {
            panic!("expected recovery-participation prompt");
        };
        assert_eq!(recovery.request_sha256_hex(), "31".repeat(32));
        assert_eq!(recovery.root_sha256_hex(), "42".repeat(32));
        assert_eq!(recovery.policy_sha256_hex(), "52".repeat(32));
        assert_eq!(recovery.previous_head_sha256_hex(), Some("62".repeat(32)));
        assert_eq!(recovery.participant_role.label(), "recovery authority");
        assert_eq!(recovery.reason.label(), "compromise");

        let root_head = recovery_participation_prompt(
            RecoveryParticipantRole::NextSigningKey,
            fingerprint(0x22),
            0,
            None,
        );
        let root_head_encoded = encode_prompt(&root_head).unwrap();
        assert_eq!(root_head_encoded[HEADER_BYTES + 2], 0);
        assert_eq!(
            &root_head_encoded[HEADER_BYTES + 152..HEADER_BYTES + 184],
            &[0_u8; 32]
        );
        assert_eq!(decode_prompt(&root_head_encoded).unwrap(), root_head);
    }

    #[test]
    fn recovery_participation_prompt_rejects_hostile_layout_flags_and_lengths() {
        let encoded = encode_prompt(&recovery_participation_prompt(
            RecoveryParticipantRole::RecoveryAuthority,
            fingerprint(0x33),
            3,
            Some([0x62; 32]),
        ))
        .unwrap();

        for offset in [HEADER_BYTES + 3, HEADER_BYTES + 28, HEADER_BYTES + 196] {
            let mut reserved = encoded.clone();
            reserved[offset] = 1;
            assert!(matches!(
                decode_prompt(&reserved),
                Err(ProtocolError::InvalidLayout)
            ));
        }

        let mut unknown_role = encoded.clone();
        unknown_role[HEADER_BYTES] = 99;
        assert!(matches!(
            decode_prompt(&unknown_role),
            Err(ProtocolError::UnsupportedRecoveryParticipantRole(99))
        ));

        let mut unknown_reason = encoded.clone();
        unknown_reason[HEADER_BYTES + 1] = 99;
        assert!(matches!(
            decode_prompt(&unknown_reason),
            Err(ProtocolError::UnsupportedRecoveryReason(99))
        ));

        let mut invalid_presence = encoded.clone();
        invalid_presence[HEADER_BYTES + 2] = 2;
        assert!(matches!(
            decode_prompt(&invalid_presence),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut absent_nonzero = encoded.clone();
        absent_nonzero[HEADER_BYTES + 2] = 0;
        assert!(matches!(
            decode_prompt(&absent_nonzero),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut bad_ceremony_length = encoded.clone();
        bad_ceremony_length[HEADER_BYTES + 194..HEADER_BYTES + 196]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            decode_prompt(&bad_ceremony_length),
            Err(ProtocolError::InvalidLayout)
        ));

        let mut unknown_flags = encoded.clone();
        unknown_flags[15] = 1;
        assert!(matches!(
            decode_prompt(&unknown_flags),
            Err(ProtocolError::UnsupportedFlags(1))
        ));

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(matches!(
            decode_prompt(&truncated),
            Err(ProtocolError::TruncatedPayload)
        ));

        let mut bad_utf8 = encoded;
        *bad_utf8.last_mut().unwrap() = 0xff;
        assert!(matches!(
            decode_prompt(&bad_utf8),
            Err(ProtocolError::InvalidField {
                field: "ceremony ID",
                ..
            })
        ));
    }

    #[test]
    fn recovery_participation_prompt_rejects_dangerous_or_inconsistent_display_facts() {
        let authority = || {
            recovery_participation_prompt(
                RecoveryParticipantRole::RecoveryAuthority,
                fingerprint(0x33),
                3,
                Some([0x62; 32]),
            )
        };

        let mut dangerous_label = authority();
        dangerous_label.persona_label.push('\u{202e}');
        assert!(matches!(
            encode_prompt(&dangerous_label),
            Err(ProtocolError::InvalidField {
                field: "persona label",
                ..
            })
        ));

        let mut dangerous_participant = authority();
        let ApprovalSubject::RecoveryParticipation(recovery) = &mut dangerous_participant.subject
        else {
            panic!("expected recovery-participation prompt");
        };
        recovery.participant_key_fingerprint.push('\u{202e}');
        assert!(matches!(
            encode_prompt(&dangerous_participant),
            Err(ProtocolError::InvalidField {
                field: "participant key fingerprint",
                ..
            })
        ));

        let mut padded_ceremony = authority();
        let ApprovalSubject::RecoveryParticipation(recovery) = &mut padded_ceremony.subject else {
            panic!("expected recovery-participation prompt");
        };
        recovery.ceremony_id.push('=');
        assert!(matches!(
            encode_prompt(&padded_ceremony),
            Err(ProtocolError::InvalidField {
                field: "ceremony ID",
                ..
            })
        ));

        let mut expired = authority();
        let ApprovalSubject::RecoveryParticipation(recovery) = &mut expired.subject else {
            panic!("expected recovery-participation prompt");
        };
        recovery.ceremony_expires_at = 0;
        assert!(matches!(
            encode_prompt(&expired),
            Err(ProtocolError::InvalidField {
                field: "ceremony expiry",
                ..
            })
        ));

        let mut self_reported_authority = authority();
        let ApprovalSubject::RecoveryParticipation(recovery) = &mut self_reported_authority.subject
        else {
            panic!("expected recovery-participation prompt");
        };
        recovery.participant_key_fingerprint = recovery.next_key_fingerprint.clone();
        self_reported_authority.key_fingerprint = recovery.next_key_fingerprint.clone();
        assert!(matches!(
            encode_prompt(&self_reported_authority),
            Err(ProtocolError::InvalidField {
                field: "participant key fingerprint",
                ..
            })
        ));

        let mut wrong_next_participant = recovery_participation_prompt(
            RecoveryParticipantRole::NextSigningKey,
            fingerprint(0x22),
            0,
            None,
        );
        let ApprovalSubject::RecoveryParticipation(recovery) = &mut wrong_next_participant.subject
        else {
            panic!("expected recovery-participation prompt");
        };
        recovery.next_key_fingerprint = fingerprint(0x44);
        assert!(matches!(
            encode_prompt(&wrong_next_participant),
            Err(ProtocolError::InvalidField {
                field: "participant key fingerprint",
                ..
            })
        ));
    }

    #[test]
    fn recovery_participation_prompt_rejects_invalid_policy_head_and_key_facts() {
        let authority = || {
            recovery_participation_prompt(
                RecoveryParticipantRole::RecoveryAuthority,
                fingerprint(0x33),
                3,
                Some([0x62; 32]),
            )
        };

        for version in [0, MAX_RECOVERY_POLICY_VERSION + 1] {
            let mut prompt = authority();
            let ApprovalSubject::RecoveryParticipation(recovery) = &mut prompt.subject else {
                panic!("expected recovery-participation prompt");
            };
            recovery.recovery_policy_version = version;
            assert!(matches!(
                encode_prompt(&prompt),
                Err(ProtocolError::InvalidField {
                    field: "recovery policy version",
                    ..
                })
            ));
        }

        for threshold in [MIN_RECOVERY_THRESHOLD - 1, MAX_RECOVERY_THRESHOLD + 1] {
            let mut prompt = authority();
            let ApprovalSubject::RecoveryParticipation(recovery) = &mut prompt.subject else {
                panic!("expected recovery-participation prompt");
            };
            recovery.recovery_policy_threshold = threshold;
            assert!(matches!(
                encode_prompt(&prompt),
                Err(ProtocolError::InvalidField {
                    field: "recovery policy threshold",
                    ..
                })
            ));
        }

        for (sequence, digest) in [(0, Some([0x62; 32])), (1, None)] {
            let mut prompt = authority();
            let ApprovalSubject::RecoveryParticipation(recovery) = &mut prompt.subject else {
                panic!("expected recovery-participation prompt");
            };
            recovery.previous_head_sequence = sequence;
            recovery.previous_head_sha256 = digest;
            assert!(matches!(
                encode_prompt(&prompt),
                Err(ProtocolError::InvalidField {
                    field: "previous head digest",
                    ..
                })
            ));
        }

        let mut unchanged_key = authority();
        let ApprovalSubject::RecoveryParticipation(recovery) = &mut unchanged_key.subject else {
            panic!("expected recovery-participation prompt");
        };
        recovery.next_key_fingerprint = recovery.previous_key_fingerprint.clone();
        assert!(matches!(
            encode_prompt(&unchanged_key),
            Err(ProtocolError::InvalidField {
                field: "next key fingerprint",
                ..
            })
        ));
    }

    #[test]
    fn recovery_participation_prompt_cannot_be_reinterpreted_as_artifact_consent() {
        let recovery_prompt = recovery_participation_prompt(
            RecoveryParticipantRole::RecoveryAuthority,
            fingerprint(0x33),
            0,
            None,
        );
        assert_eq!(recovery_prompt.persona_id, None);
        assert_eq!(recovery_prompt.persona_purpose, None);
        let recovery = encode_prompt(&recovery_prompt).unwrap();
        let local_persona = Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap();
        assert!(
            !recovery
                .windows(local_persona.as_bytes().len())
                .any(|window| window == local_persona.as_bytes())
        );
        let artifact = encode_prompt(&prompt()).unwrap();

        let mut recovery_as_artifact = recovery;
        recovery_as_artifact[12..14].copy_from_slice(&MESSAGE_ARTIFACT_PROMPT.to_be_bytes());
        assert!(decode_prompt(&recovery_as_artifact).is_err());

        let mut artifact_as_recovery = artifact;
        artifact_as_recovery[12..14]
            .copy_from_slice(&MESSAGE_RECOVERY_PARTICIPATION_PROMPT.to_be_bytes());
        assert!(decode_prompt(&artifact_as_recovery).is_err());

        let mut leaked_local_metadata = recovery_prompt;
        leaked_local_metadata.persona_id =
            Some(Uuid::parse_str("8b2fc4ef-ef26-48df-b849-8bc4e595e96c").unwrap());
        leaked_local_metadata.persona_purpose = Some(PersonaPurpose::Project);
        assert!(matches!(
            encode_prompt(&leaked_local_metadata),
            Err(ProtocolError::InvalidField {
                field: "local persona metadata",
                ..
            })
        ));

        let mut missing_local_metadata = prompt();
        missing_local_metadata.persona_id = None;
        missing_local_metadata.persona_purpose = None;
        assert!(matches!(
            encode_prompt(&missing_local_metadata),
            Err(ProtocolError::InvalidField {
                field: "local persona metadata",
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

        for label in [
            "safe\u{202e}fdp.exe",
            "safe\u{2028}line",
            "safe\u{2029}paragraph",
            "safe\u{200b}file",
            "safe\u{2060}file",
            "emoji\u{fe0f}selector",
        ] {
            let mut dangerous = prompt();
            let ApprovalSubject::Artifact(artifact) = &mut dangerous.subject else {
                panic!("expected artifact prompt");
            };
            artifact.artifact_label = label.to_owned();
            assert!(matches!(
                encode_prompt(&dangerous),
                Err(ProtocolError::InvalidField { .. })
            ));
        }

        let mut visible = prompt();
        let ApprovalSubject::Artifact(artifact) = &mut visible.subject else {
            panic!("expected artifact prompt");
        };
        artifact.artifact_label = "Cafe\u{0301} 😀".to_owned();
        assert!(encode_prompt(&visible).is_ok());
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
