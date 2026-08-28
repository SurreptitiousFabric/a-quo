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
    MAX_PERSONA_ROOT_STATEMENT_BYTES, PeerCredentials, ReceivedSignRequest, ReceivedSignResponse,
    SealedArtifact, SealedProof, connect_consent_socket, connection_state, peer_credentials,
    receive_sign_request, receive_sign_response, seal_proof_bytes, send_sign_approved,
    send_sign_rejected, send_sign_request, snapshot_artifact,
};
pub use protocol::{
    ArtifactKind, MAX_ARTIFACT_LABEL_BYTES, MAX_PERSONA_ID_BYTES, PROTOCOL_MAJOR, PROTOCOL_MINOR,
    ProtocolError, RejectionCode, SignRequest, SignResponse, SignSubject, decode_sign_request,
    decode_sign_response, encode_sign_request, encode_sign_response,
};
