use std::fs;
use std::process::Command;

use a_quo_core::{EvidenceStatus, ProofError, create_sshsig_proof, verify_sshsig_proof};
use tempfile::tempdir;

#[test]
fn signs_verifies_and_rejects_tampered_artifact() {
    let directory = tempdir().unwrap();
    let private_key = directory.path().join("persona_key");
    let public_key = directory.path().join("persona_key.pub");
    let artifact = directory.path().join("plugin.tar.zst");

    let keygen = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&private_key)
        .status()
        .expect("OpenSSH ssh-keygen must be installed for the integration test");
    assert!(keygen.success());

    fs::write(&artifact, b"immutable plugin release").unwrap();
    let proof =
        create_sshsig_proof(&artifact, &private_key, &public_key, "A Quo test publisher").unwrap();

    let report = verify_sshsig_proof(&artifact, &proof).unwrap();
    assert_eq!(report.artifact_integrity, EvidenceStatus::Verified);
    assert_eq!(report.signature, EvidenceStatus::Verified);
    assert_eq!(report.signer.identity_binding, "self_asserted");
    assert!(
        report
            .not_established
            .contains(&"runtime_safety".to_owned())
    );

    fs::write(&artifact, b"modified plugin release").unwrap();
    let error = verify_sshsig_proof(&artifact, &proof).unwrap_err();
    assert!(matches!(error, ProofError::ArtifactMismatch));
}
