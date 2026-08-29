use std::fs;
use std::process::Command;

use a_quo_core::{
    EvidenceStatus, LiveSignerBindingProvider, ProofError, create_sshsig_proof,
    create_sshsig_proof_for_descriptor, describe_artifact, prove_live_signer_binding,
    public_key_fingerprint, validate_verified_live_signer_binding, verify_sshsig_proof,
    verify_sshsig_proof_for_descriptor,
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
    assert!(matches!(error, ProofError::SignatureVerificationFailed));

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

#[test]
fn live_signer_receipt_binds_provider_key_locator_and_unchanged_target() {
    let directory = tempdir().unwrap();
    let signer = directory.path().join("live_signer");
    let replacement = directory.path().join("replacement_signer");
    for key in [&signer, &replacement] {
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(key)
            .status()
            .expect("OpenSSH ssh-keygen must be installed for the integration test");
        assert!(status.success());
    }

    let canonical_signer = fs::canonicalize(&signer).unwrap();
    let public_key = fs::read_to_string(signer.with_extension("pub")).unwrap();
    let fingerprint = public_key_fingerprint(&public_key).unwrap();
    let receipt = prove_live_signer_binding(
        &canonical_signer,
        &public_key,
        LiveSignerBindingProvider::OpensshFile,
    )
    .unwrap();
    validate_verified_live_signer_binding(
        &receipt,
        LiveSignerBindingProvider::OpensshFile,
        &canonical_signer,
        &public_key,
        &fingerprint,
    )
    .unwrap();

    assert!(matches!(
        validate_verified_live_signer_binding(
            &receipt,
            LiveSignerBindingProvider::SshAgent,
            &canonical_signer,
            &public_key,
            &fingerprint,
        ),
        Err(ProofError::LiveSignerBindingMismatch)
    ));

    let replacement_public_key = fs::read_to_string(replacement.with_extension("pub")).unwrap();
    let replacement_fingerprint = public_key_fingerprint(&replacement_public_key).unwrap();
    assert!(matches!(
        validate_verified_live_signer_binding(
            &receipt,
            LiveSignerBindingProvider::OpensshFile,
            &canonical_signer,
            &replacement_public_key,
            &replacement_fingerprint,
        ),
        Err(ProofError::LiveSignerBindingMismatch)
    ));

    fs::write(&canonical_signer, fs::read(&replacement).unwrap()).unwrap();
    assert!(matches!(
        validate_verified_live_signer_binding(
            &receipt,
            LiveSignerBindingProvider::OpensshFile,
            &canonical_signer,
            &public_key,
            &fingerprint,
        ),
        Err(ProofError::LiveSignerLocatorChanged)
    ));
}

#[test]
fn native_verifier_accepts_openssh_modern_algorithm_matrix() {
    let directory = tempdir().unwrap();
    let artifact = directory.path().join("release.tar.zst");
    fs::write(&artifact, b"algorithm interoperability fixture").unwrap();

    for (label, key_type, bits) in [
        ("ed25519", "ed25519", None),
        ("ecdsa-p256", "ecdsa", Some("256")),
        ("ecdsa-p384", "ecdsa", Some("384")),
        ("ecdsa-p521", "ecdsa", Some("521")),
        ("rsa-2048", "rsa", Some("2048")),
        ("rsa-4096", "rsa", Some("4096")),
    ] {
        let private_key = directory.path().join(label);
        let mut keygen = Command::new("ssh-keygen");
        keygen
            .args(["-q", "-t", key_type, "-N", "", "-f"])
            .arg(&private_key);
        if let Some(bits) = bits {
            keygen.args(["-b", bits]);
        }
        assert!(
            keygen.status().unwrap().success(),
            "failed to generate {label} interoperability key"
        );

        let proof = create_sshsig_proof(
            &artifact,
            &private_key,
            private_key.with_extension("pub"),
            "Algorithm matrix",
        )
        .unwrap();
        let report = verify_sshsig_proof(&artifact, &proof).unwrap();
        assert_eq!(report.signature, EvidenceStatus::Verified, "{label}");
    }
}
