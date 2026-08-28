use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use a_quo_core::{ArtifactDescriptor, Digest, MAX_PROOF_BYTES};
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, memfd_create};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::protocol::{MAX_REQUEST_PACKET_BYTES, MAX_RESPONSE_PACKET_BYTES};
use crate::{
    ProtocolError, RejectionCode, SignRequest, SignResponse, decode_sign_request,
    decode_sign_response, encode_sign_request, encode_sign_response,
};

pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const SNAPSHOT_SEALS: SealFlags = SealFlags::SEAL
    .union(SealFlags::SHRINK)
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE);

#[derive(Debug, Error)]
pub enum LinuxIpcError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("Unix socket operation failed: {0}")]
    Socket(#[source] rustix::io::Errno),

    #[error("consent packet was truncated")]
    TruncatedPacket,

    #[error("consent descriptor data was truncated")]
    TruncatedDescriptors,

    #[error("descriptor count does not match the consent message type; received {0}")]
    WrongDescriptorCount(usize),

    #[error("consent packet contained unsupported ancillary data")]
    UnsupportedAncillaryData,

    #[error("consent packet was not sent atomically")]
    PartialPacket,

    #[error("refusing consent peer UID {actual}; expected UID {expected}")]
    ForeignPeer { actual: u32, expected: u32 },

    #[error("artifact descriptor is not a regular file")]
    ArtifactNotRegular,

    #[error("artifact exceeds the {maximum}-byte snapshot limit")]
    ArtifactTooLarge { maximum: u64 },

    #[error("invalid artifact snapshot limit {0}")]
    InvalidSnapshotLimit(u64),

    #[error("descriptor I/O failed: {0}")]
    FileIo(#[source] std::io::Error),

    #[error("descriptor sealing failed: {0}")]
    Sealing(#[source] rustix::io::Errno),

    #[error("kernel did not apply every required immutability seal")]
    IncompleteSeals,

    #[error("proof exceeds the {MAX_PROOF_BYTES}-byte transport limit")]
    ProofTooLarge,

    #[error("proof descriptor is empty or not a regular file")]
    InvalidProofDescriptor,

    #[error("proof descriptor does not have every required immutability seal")]
    UnsealedProof,
}

pub type Result<T> = std::result::Result<T, LinuxIpcError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug)]
pub struct ReceivedSignRequest {
    pub request: SignRequest,
    pub artifact: OwnedFd,
    pub peer: PeerCredentials,
}

#[derive(Debug)]
pub struct ReceivedSignResponse {
    pub response: SignResponse,
    pub proof: Option<SealedProof>,
    pub peer: PeerCredentials,
}

#[derive(Debug)]
pub struct SealedArtifact {
    file: File,
    descriptor: ArtifactDescriptor,
}

#[derive(Debug)]
pub struct SealedProof {
    file: File,
    size: u64,
}

impl SealedArtifact {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn descriptor(&self) -> &ArtifactDescriptor {
        &self.descriptor
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

impl SealedProof {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

pub fn peer_credentials(socket: impl AsFd) -> Result<PeerCredentials> {
    let credentials =
        rustix::net::sockopt::socket_peercred(socket).map_err(LinuxIpcError::Socket)?;
    Ok(PeerCredentials {
        pid: credentials.pid.as_raw_pid(),
        uid: credentials.uid.as_raw(),
        gid: credentials.gid.as_raw(),
    })
}

pub fn send_sign_request(
    socket: impl AsFd,
    request: &SignRequest,
    artifact: impl AsFd,
) -> Result<()> {
    let packet = encode_sign_request(request)?;
    send_packet_with_descriptor(socket, &packet, artifact.as_fd())
}

pub fn send_sign_approved(socket: impl AsFd, proof: &SealedProof) -> Result<()> {
    validate_proof_file(&proof.file)?;
    send_packet_with_descriptor(
        socket,
        &encode_sign_response(SignResponse::Approved),
        proof.file.as_fd(),
    )
}

pub fn send_sign_rejected(socket: impl AsFd, code: RejectionCode) -> Result<()> {
    send_packet(socket, &encode_sign_response(SignResponse::Rejected(code)))
}

pub fn receive_sign_request(socket: impl AsFd) -> Result<ReceivedSignRequest> {
    let peer = peer_credentials(socket.as_fd())?;
    let expected_uid = rustix::process::getuid().as_raw();
    if peer.uid != expected_uid {
        return Err(LinuxIpcError::ForeignPeer {
            actual: peer.uid,
            expected: expected_uid,
        });
    }
    receive_sign_request_from_peer(socket, peer)
}

fn receive_sign_request_from_peer(
    socket: impl AsFd,
    peer: PeerCredentials,
) -> Result<ReceivedSignRequest> {
    let mut packet = [0_u8; MAX_REQUEST_PACKET_BYTES];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary_space);
    let received = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut packet)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC,
    )
    .map_err(LinuxIpcError::Socket)?;

    validate_received_packet(&received, packet.len())?;
    let mut descriptors = collect_descriptors(&mut ancillary)?;
    if descriptors.len() != 1 {
        return Err(LinuxIpcError::WrongDescriptorCount(descriptors.len()));
    }

    let request = decode_sign_request(&packet[..received.bytes])?;
    Ok(ReceivedSignRequest {
        request,
        artifact: descriptors.pop().expect("descriptor count was checked"),
        peer,
    })
}

pub fn receive_sign_response(socket: impl AsFd) -> Result<ReceivedSignResponse> {
    let peer = peer_credentials(socket.as_fd())?;
    let expected_uid = rustix::process::getuid().as_raw();
    if peer.uid != expected_uid {
        return Err(LinuxIpcError::ForeignPeer {
            actual: peer.uid,
            expected: expected_uid,
        });
    }
    receive_sign_response_from_peer(socket, peer)
}

fn receive_sign_response_from_peer(
    socket: impl AsFd,
    peer: PeerCredentials,
) -> Result<ReceivedSignResponse> {
    let mut packet = [0_u8; MAX_RESPONSE_PACKET_BYTES];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary_space);
    let received = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut packet)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC | RecvFlags::TRUNC,
    )
    .map_err(LinuxIpcError::Socket)?;

    validate_received_packet(&received, packet.len())?;
    let mut descriptors = collect_descriptors(&mut ancillary)?;
    let response = decode_sign_response(&packet[..received.bytes])?;
    let proof = match response {
        SignResponse::Approved if descriptors.len() == 1 => Some(proof_from_descriptor(
            descriptors.pop().expect("descriptor count was checked"),
        )?),
        SignResponse::Rejected(_) if descriptors.is_empty() => None,
        _ => return Err(LinuxIpcError::WrongDescriptorCount(descriptors.len())),
    };

    Ok(ReceivedSignResponse {
        response,
        proof,
        peer,
    })
}

pub fn seal_proof_bytes(bytes: &[u8]) -> Result<SealedProof> {
    if bytes.is_empty() {
        return Err(LinuxIpcError::InvalidProofDescriptor);
    }
    if bytes.len() as u64 > MAX_PROOF_BYTES {
        return Err(LinuxIpcError::ProofTooLarge);
    }
    let proof_fd = memfd_create(
        "a-quo-proof",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(LinuxIpcError::Sealing)?;
    let mut file = File::from(proof_fd);
    file.write_all(bytes).map_err(LinuxIpcError::FileIo)?;
    file.flush().map_err(LinuxIpcError::FileIo)?;
    apply_and_verify_seals(&file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(LinuxIpcError::FileIo)?;
    Ok(SealedProof {
        file,
        size: bytes.len() as u64,
    })
}

pub fn snapshot_artifact(source: OwnedFd, maximum: u64) -> Result<SealedArtifact> {
    if maximum == 0 || maximum > MAX_ARTIFACT_BYTES {
        return Err(LinuxIpcError::InvalidSnapshotLimit(maximum));
    }

    let mut source = File::from(source);
    let metadata = source.metadata().map_err(LinuxIpcError::FileIo)?;
    if !metadata.is_file() {
        return Err(LinuxIpcError::ArtifactNotRegular);
    }
    if metadata.len() > maximum {
        return Err(LinuxIpcError::ArtifactTooLarge { maximum });
    }
    source
        .seek(SeekFrom::Start(0))
        .map_err(LinuxIpcError::FileIo)?;

    let snapshot_fd = memfd_create(
        "a-quo-artifact",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(LinuxIpcError::Sealing)?;
    let mut snapshot = File::from(snapshot_fd);
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let remaining = maximum - size;
        let read_limit = if remaining < buffer.len() as u64 {
            usize::try_from(remaining).expect("remaining fits the buffer") + 1
        } else {
            buffer.len()
        };
        let read = source
            .read(&mut buffer[..read_limit])
            .map_err(LinuxIpcError::FileIo)?;
        if read == 0 {
            break;
        }
        if read as u64 > remaining {
            return Err(LinuxIpcError::ArtifactTooLarge { maximum });
        }
        snapshot
            .write_all(&buffer[..read])
            .map_err(LinuxIpcError::FileIo)?;
        hasher.update(&buffer[..read]);
        size += read as u64;
    }

    snapshot.flush().map_err(LinuxIpcError::FileIo)?;
    apply_and_verify_seals(&snapshot)?;
    snapshot
        .seek(SeekFrom::Start(0))
        .map_err(LinuxIpcError::FileIo)?;

    Ok(SealedArtifact {
        file: snapshot,
        descriptor: ArtifactDescriptor {
            digest: Digest {
                algorithm: "sha256".to_owned(),
                value: format!("{:x}", hasher.finalize()),
            },
            size,
        },
    })
}

fn send_packet(socket: impl AsFd, packet: &[u8]) -> Result<()> {
    let mut ancillary = SendAncillaryBuffer::default();
    let sent = sendmsg(
        socket,
        &[IoSlice::new(packet)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(LinuxIpcError::Socket)?;
    if sent != packet.len() {
        return Err(LinuxIpcError::PartialPacket);
    }
    Ok(())
}

fn send_packet_with_descriptor(
    socket: impl AsFd,
    packet: &[u8],
    descriptor: BorrowedFd<'_>,
) -> Result<()> {
    let descriptors = [descriptor];
    let mut ancillary_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut ancillary_space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(LinuxIpcError::PartialPacket);
    }
    let sent = sendmsg(
        socket,
        &[IoSlice::new(packet)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(LinuxIpcError::Socket)?;
    if sent != packet.len() {
        return Err(LinuxIpcError::PartialPacket);
    }
    Ok(())
}

fn validate_received_packet(received: &rustix::net::RecvMsg, buffer_len: usize) -> Result<()> {
    if received.flags.contains(ReturnFlags::TRUNC) || received.bytes > buffer_len {
        return Err(LinuxIpcError::TruncatedPacket);
    }
    if received.flags.contains(ReturnFlags::CTRUNC) {
        return Err(LinuxIpcError::TruncatedDescriptors);
    }
    Ok(())
}

fn collect_descriptors(ancillary: &mut RecvAncillaryBuffer<'_>) -> Result<Vec<OwnedFd>> {
    let mut descriptors = Vec::with_capacity(2);
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
            _ => return Err(LinuxIpcError::UnsupportedAncillaryData),
        }
    }
    Ok(descriptors)
}

fn apply_and_verify_seals(file: &File) -> Result<()> {
    fcntl_add_seals(file, SNAPSHOT_SEALS).map_err(LinuxIpcError::Sealing)?;
    let applied = fcntl_get_seals(file).map_err(LinuxIpcError::Sealing)?;
    if !applied.contains(SNAPSHOT_SEALS) {
        return Err(LinuxIpcError::IncompleteSeals);
    }
    Ok(())
}

fn validate_proof_file(file: &File) -> Result<u64> {
    let metadata = file.metadata().map_err(LinuxIpcError::FileIo)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(LinuxIpcError::InvalidProofDescriptor);
    }
    if metadata.len() > MAX_PROOF_BYTES {
        return Err(LinuxIpcError::ProofTooLarge);
    }
    let seals = fcntl_get_seals(file).map_err(|_| LinuxIpcError::UnsealedProof)?;
    if !seals.contains(SNAPSHOT_SEALS) {
        return Err(LinuxIpcError::UnsealedProof);
    }
    Ok(metadata.len())
}

fn proof_from_descriptor(descriptor: OwnedFd) -> Result<SealedProof> {
    let mut file = File::from(descriptor);
    let size = validate_proof_file(&file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(LinuxIpcError::FileIo)?;
    Ok(SealedProof { file, size })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::fd::{BorrowedFd, OwnedFd};

    use rustix::net::{AddressFamily, Protocol, SocketFlags, SocketType, socketpair};
    use tempfile::tempdir;

    use super::*;
    use crate::ArtifactKind;

    fn sockets() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None::<Protocol>,
        )
        .unwrap()
    }

    fn request() -> SignRequest {
        SignRequest::new(
            "8b2fc4ef-ef26-48df-b849-8bc4e595e96c",
            ArtifactKind::Image,
            "portrait.png",
        )
        .unwrap()
    }

    fn test_peer() -> PeerCredentials {
        PeerCredentials {
            pid: rustix::process::getpid().as_raw_pid(),
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
        }
    }

    #[test]
    fn transfers_exactly_one_descriptor_with_peer_evidence() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("portrait.png");
        fs::write(&path, b"not really a PNG").unwrap();
        let artifact = File::open(path).unwrap();
        let (client, server) = sockets();

        send_sign_request(&client, &request(), &artifact).unwrap();
        let received = receive_sign_request_from_peer(&server, test_peer()).unwrap();

        assert_eq!(received.request, request());
        assert_eq!(received.peer.uid, rustix::process::getuid().as_raw());
        assert!(File::from(received.artifact).metadata().unwrap().is_file());
    }

    #[test]
    fn rejects_missing_and_multiple_descriptors() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("artifact");
        fs::write(&path, b"bytes").unwrap();
        let artifact = File::open(path).unwrap();
        let packet = encode_sign_request(&request()).unwrap();

        let (client, server) = sockets();
        let mut ancillary = SendAncillaryBuffer::default();
        let sent = sendmsg(
            &client,
            &[IoSlice::new(&packet)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert_eq!(sent, packet.len());
        assert!(matches!(
            receive_sign_request_from_peer(&server, test_peer()),
            Err(LinuxIpcError::WrongDescriptorCount(0))
        ));

        let (client, server) = sockets();
        let descriptors: [BorrowedFd<'_>; 2] = [artifact.as_fd(), artifact.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            &client,
            &[IoSlice::new(&packet)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(matches!(
            receive_sign_request_from_peer(&server, test_peer()),
            Err(LinuxIpcError::WrongDescriptorCount(2))
        ));
    }

    #[test]
    fn rejects_truncated_packets_and_excessive_descriptor_data() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("artifact");
        fs::write(&path, b"bytes").unwrap();
        let artifact = File::open(path).unwrap();

        let (client, server) = sockets();
        let oversized = vec![0_u8; MAX_REQUEST_PACKET_BYTES + 1];
        let descriptors = [artifact.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            &client,
            &[IoSlice::new(&oversized)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(matches!(
            receive_sign_request_from_peer(&server, test_peer()),
            Err(LinuxIpcError::TruncatedPacket)
        ));

        let (client, server) = sockets();
        let packet = encode_sign_request(&request()).unwrap();
        let descriptors: [BorrowedFd<'_>; 16] = [artifact.as_fd(); 16];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(16))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            &client,
            &[IoSlice::new(&packet)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        match receive_sign_request_from_peer(&server, test_peer()) {
            Err(LinuxIpcError::TruncatedDescriptors) => {}
            Err(LinuxIpcError::WrongDescriptorCount(count)) if count > 1 => {}
            other => panic!("expected excess-descriptor rejection, received {other:?}"),
        }
    }

    #[test]
    fn snapshot_is_bounded_sealed_and_independent_of_source() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("article.md");
        fs::write(&path, b"signed version").unwrap();
        let mut source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        source.seek(SeekFrom::End(0)).unwrap();
        let sealed = snapshot_artifact(source.into(), 1024).unwrap();

        fs::write(&path, b"changed after consent").unwrap();
        let mut contents = String::new();
        sealed
            .file()
            .try_clone()
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "signed version");
        assert_eq!(sealed.descriptor().size, 14);
        assert_eq!(
            sealed.descriptor().digest.value,
            "a0b31da6b70875edfa8670a62b8e0d20cac790eafa63192e162605bdfa5ae1e2"
        );

        let mut attempted_write = sealed.file().try_clone().unwrap();
        assert!(attempted_write.write_all(b"tamper").is_err());
    }

    #[test]
    fn approved_and_rejected_responses_preserve_descriptor_rules() {
        let proof_bytes = br#"{"schema":"urn:a-quo:proof:sshsig:v1"}"#;
        let proof = seal_proof_bytes(proof_bytes).unwrap();
        let (server, client) = sockets();

        send_sign_approved(&server, &proof).unwrap();
        let received = receive_sign_response_from_peer(&client, test_peer()).unwrap();
        assert_eq!(received.response, SignResponse::Approved);
        assert_eq!(received.peer.uid, rustix::process::getuid().as_raw());
        let received_proof = received.proof.unwrap();
        assert_eq!(received_proof.size(), proof_bytes.len() as u64);
        let mut received_bytes = Vec::new();
        received_proof
            .file()
            .try_clone()
            .unwrap()
            .read_to_end(&mut received_bytes)
            .unwrap();
        assert_eq!(received_bytes, proof_bytes);

        let (server, client) = sockets();
        send_sign_rejected(&server, RejectionCode::UserDeclined).unwrap();
        let received = receive_sign_response_from_peer(&client, test_peer()).unwrap();
        assert_eq!(
            received.response,
            SignResponse::Rejected(RejectionCode::UserDeclined)
        );
        assert!(received.proof.is_none());
    }

    #[test]
    fn rejects_mutable_proof_descriptors() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("mutable-proof.json");
        fs::write(&path, b"{}").unwrap();
        let proof = File::open(path).unwrap();
        let packet = encode_sign_response(SignResponse::Approved);
        let (server, client) = sockets();

        send_packet_with_descriptor(&server, &packet, proof.as_fd()).unwrap();
        assert!(matches!(
            receive_sign_response_from_peer(&client, test_peer()),
            Err(LinuxIpcError::UnsealedProof)
        ));
    }

    #[test]
    fn rejects_non_regular_and_oversized_artifacts() {
        let directory = tempdir().unwrap();
        let directory_fd = File::open(directory.path()).unwrap();
        assert!(matches!(
            snapshot_artifact(directory_fd.into(), 1024),
            Err(LinuxIpcError::ArtifactNotRegular)
        ));

        let path = directory.path().join("large");
        fs::write(&path, b"12345").unwrap();
        assert!(matches!(
            snapshot_artifact(File::open(path).unwrap().into(), 4),
            Err(LinuxIpcError::ArtifactTooLarge { maximum: 4 })
        ));
    }
}
