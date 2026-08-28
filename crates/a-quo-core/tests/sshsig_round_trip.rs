use std::fs;
use std::process::Command;

use a_quo_core::{
    EvidenceStatus, ProofError, create_sshsig_proof, create_sshsig_proof_for_descriptor,
    describe_artifact, verify_sshsig_proof, verify_sshsig_proof_for_descriptor,
};
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

#[test]
fn descriptor_signing_rejects_a_mismatched_private_key() {
    let directory = tempdir().unwrap();
    let first_key = directory.path().join("first_key");
    let second_key = directory.path().join("second_key");
    let artifact = directory.path().join("article.md");

    for key in [&first_key, &second_key] {
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(key)
            .status()
            .expect("OpenSSH ssh-keygen must be installed for the integration test");
        assert!(status.success());
    }

    fs::write(&artifact, b"the reviewed article bytes").unwrap();
    let descriptor = describe_artifact(&artifact).unwrap();
    let second_public_key = fs::read_to_string(second_key.with_extension("pub")).unwrap();
    let error = create_sshsig_proof_for_descriptor(
        descriptor.clone(),
        &first_key,
        &second_public_key,
        "Article publisher",
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ProofError::SignerFailed {
            operation: "verification",
            ..
        }
    ));

    let first_public_key = fs::read_to_string(first_key.with_extension("pub")).unwrap();
    let proof = create_sshsig_proof_for_descriptor(
        descriptor.clone(),
        &first_key,
        &first_public_key,
        "Article publisher",
    )
    .unwrap();
    let report = verify_sshsig_proof_for_descriptor(&descriptor, &proof).unwrap();
    assert_eq!(report.signature, EvidenceStatus::Verified);
}
