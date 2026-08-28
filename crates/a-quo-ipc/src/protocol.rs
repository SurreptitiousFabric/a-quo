use thiserror::Error;
use uuid::Uuid;

const MAGIC: [u8; 8] = *b"AQUOIPC\0";
const HEADER_BYTES: usize = 20;
const ARTIFACT_REQUEST_PREFIX_BYTES: usize = 6;
const DOMAIN_REQUEST_PREFIX_BYTES: usize = 4;
const RESPONSE_PREFIX_BYTES: usize = 4;
const MESSAGE_SIGN_REQUEST: u16 = 1;
const MESSAGE_SIGN_APPROVED: u16 = 2;
const MESSAGE_SIGN_REJECTED: u16 = 3;
const MESSAGE_DOMAIN_SIGN_REQUEST: u16 = 4;
const FLAGS_NONE: u16 = 0;
const MAX_ARTIFACT_REQUEST_PAYLOAD_BYTES: usize =
    ARTIFACT_REQUEST_PREFIX_BYTES + MAX_PERSONA_ID_BYTES + MAX_ARTIFACT_LABEL_BYTES;
const MAX_DOMAIN_REQUEST_PAYLOAD_BYTES: usize = DOMAIN_REQUEST_PREFIX_BYTES + MAX_PERSONA_ID_BYTES;
const MAX_REQUEST_PAYLOAD_BYTES: usize =
    if MAX_ARTIFACT_REQUEST_PAYLOAD_BYTES > MAX_DOMAIN_REQUEST_PAYLOAD_BYTES {
        MAX_ARTIFACT_REQUEST_PAYLOAD_BYTES
    } else {
        MAX_DOMAIN_REQUEST_PAYLOAD_BYTES
    };

pub(crate) const MAX_REQUEST_PACKET_BYTES: usize = HEADER_BYTES + MAX_REQUEST_PAYLOAD_BYTES;
pub(crate) const MAX_RESPONSE_PACKET_BYTES: usize = HEADER_BYTES + RESPONSE_PREFIX_BYTES;
pub const MAX_PERSONA_ID_BYTES: usize = 64;
pub const MAX_ARTIFACT_LABEL_BYTES: usize = 256;
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

    #[error("invalid persona ID: {0}")]
    InvalidPersonaId(String),

    #[error("invalid artifact label: {0}")]
    InvalidArtifactLabel(String),

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
    pub persona_id: String,
    pub subject: SignSubject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignSubject {
    Artifact {
        artifact_kind: ArtifactKind,
        artifact_label: String,
    },
    DomainControl,
}

impl SignRequest {
    pub fn new(
        persona_id: impl Into<String>,
        artifact_kind: ArtifactKind,
        artifact_label: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            persona_id: persona_id.into(),
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
            persona_id: persona_id.into(),
            subject: SignSubject::DomainControl,
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
    }
}

fn encode_artifact_sign_request(
    request: &SignRequest,
    artifact_kind: ArtifactKind,
    artifact_label: &str,
) -> Result<Vec<u8>, ProtocolError> {
    let persona = request.persona_id.as_bytes();
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
    let persona = request.persona_id.as_bytes();
    let payload_len = DOMAIN_REQUEST_PREFIX_BYTES + persona.len();
    let mut message = encode_header(MESSAGE_DOMAIN_SIGN_REQUEST, payload_len);
    message.extend_from_slice(&(persona.len() as u16).to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    message.extend_from_slice(persona);
    Ok(message)
}

pub fn decode_sign_request(message: &[u8]) -> Result<SignRequest, ProtocolError> {
    match decode_common_header(message)? {
        MESSAGE_SIGN_REQUEST => decode_artifact_sign_request(message),
        MESSAGE_DOMAIN_SIGN_REQUEST => decode_domain_sign_request(message),
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
    let payload = decode_header(
        message,
        MESSAGE_DOMAIN_SIGN_REQUEST,
        MAX_DOMAIN_REQUEST_PAYLOAD_BYTES,
    )?;
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
    let persona_id = std::str::from_utf8(&payload[DOMAIN_REQUEST_PREFIX_BYTES..])
        .map_err(|_| ProtocolError::InvalidPersonaId("it must be UTF-8".to_owned()))?
        .to_owned();
    SignRequest::new_domain(persona_id)
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
    if request.persona_id.len() > MAX_PERSONA_ID_BYTES {
        return Err(ProtocolError::InvalidPersonaId(format!(
            "it cannot exceed {MAX_PERSONA_ID_BYTES} bytes"
        )));
    }
    let parsed = Uuid::parse_str(&request.persona_id)
        .map_err(|_| ProtocolError::InvalidPersonaId("expected a UUID".to_owned()))?;
    if parsed.to_string() != request.persona_id {
        return Err(ProtocolError::InvalidPersonaId(
            "expected the canonical lowercase UUID form".to_owned(),
        ));
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
        if artifact_label.chars().any(is_unsafe_display_character) {
            return Err(ProtocolError::InvalidArtifactLabel(
                "control and bidirectional formatting characters are not allowed".to_owned(),
            ));
        }
    }
    Ok(())
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
