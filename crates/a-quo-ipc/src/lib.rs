//! Strict, bounded consent IPC for A Quo.
//!
//! The codec is deliberately closed and non-extensible. Linux transport uses
//! one `SOCK_SEQPACKET` message and exactly one capability-bearing file
//! descriptor for signing requests. No signing authority is exposed over
//! D-Bus.

mod protocol;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{
    ConnectionState, LinuxIpcError, MAX_ARTIFACT_BYTES, MAX_DOMAIN_STATEMENT_BYTES,
    MAX_PERSONA_ROOT_STATEMENT_BYTES, MAX_PERSONA_TRANSITION_PUBLIC_KEY_BYTES,
    MAX_RECOVERY_PARTICIPATION_REQUEST_BYTES, PeerCredentials, ReceivedSignRequest,
    ReceivedSignResponse, SealedArtifact, SealedProof, connect_consent_socket, connection_state,
    peer_credentials, receive_sign_request, receive_sign_response, seal_proof_bytes,
    send_sign_approved, send_sign_rejected, send_sign_request, snapshot_artifact, snapshot_stream,
};
pub use protocol::{
    ArtifactKind, MAX_ARTIFACT_LABEL_BYTES, MAX_NEXT_SIGNING_REFERENCE_BYTES, MAX_PERSONA_ID_BYTES,
    MAX_RECOVERY_PARTICIPANT_PUBLIC_KEY_BYTES, MAX_RECOVERY_PARTICIPANT_SIGNING_REFERENCE_BYTES,
    MAX_RECOVERY_POLICY_VERSION, MAX_RECOVERY_THRESHOLD, MIN_RECOVERY_THRESHOLD, PROTOCOL_MAJOR,
    PROTOCOL_MINOR, ProtocolError, RecoveryParticipantKeyProvider, RejectionCode, SignRequest,
    SignResponse, SignSubject, TransitionKeyProvider, decode_sign_request, decode_sign_response,
    encode_sign_request, encode_sign_response,
};
