use std::fs;
use std::process::Command;

use a_quo_core::{
    DOMAIN_CONTROL_NAMESPACE, EvidenceStatus, ProofError, create_domain_control_proof,
    create_sshsig_proof, verify_domain_control_proof, verify_sshsig_proof,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tempfile::tempdir;

const ISSUED_AT: i64 = 1_787_875_200;
const EXPIRES_AT: i64 = 1_788_480_000;

#[test]
fn domain_proof_is_namespaced_bounded_and_bound_to_its_dns_commitment() {
    let directory = tempdir().unwrap();
    let private_key = directory.path().join("domain_key");
    let public_key = private_key.with_extension("pub");
    let artifact = directory.path().join("article.md");
    generate_key(&private_key);
    fs::write(&artifact, b"article bytes").unwrap();

    let proof = create_domain_control_proof(
        "BÜCHER.ch",
        ISSUED_AT,
        EXPIRES_AT,
        &private_key,
        &public_key,
        "Domain publisher",
    )
    .unwrap();
    assert_eq!(proof.signature.namespace, DOMAIN_CONTROL_NAMESPACE);

    let report = verify_domain_control_proof(&proof, ISSUED_AT).unwrap();
    assert_eq!(report.signature, EvidenceStatus::Verified);
    assert_eq!(report.validity, EvidenceStatus::Verified);
    assert_eq!(report.domain, "xn--bcher-kva.ch");
    assert_eq!(report.dns_record_name, "xn--bcher-kva.ch.");
    assert!(report.dns_txt_value.starts_with("a-quo-domain-v1="));
    assert!(
        report
            .not_established
            .contains(&"legal_domain_ownership".to_owned())
    );

    assert!(matches!(
        verify_domain_control_proof(&proof, EXPIRES_AT + 301),
        Err(ProofError::DomainProofExpired { .. })
    ));
    assert!(matches!(
        verify_sshsig_proof(&artifact, &proof),
        Err(ProofError::Unsupported {
            field: "signature namespace",
            ..
        })
    ));

    let artifact_proof =
        create_sshsig_proof(&artifact, &private_key, &public_key, "Domain publisher").unwrap();
    assert!(matches!(
        verify_domain_control_proof(&artifact_proof, ISSUED_AT),
        Err(ProofError::Unsupported {
            field: "signature namespace",
            ..
        })
    ));

    let mut tampered = proof;
    let payload = URL_SAFE_NO_PAD.decode(&tampered.payload).unwrap();
    let mut statement: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    statement["domain"] = serde_json::Value::String("attacker.ch".to_owned());
    tampered.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&statement).unwrap());
    assert!(matches!(
        verify_domain_control_proof(&tampered, ISSUED_AT),
        Err(ProofError::SignatureVerificationFailed)
    ));
}

fn generate_key(path: &std::path::Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("OpenSSH ssh-keygen must be installed for the integration test");
    assert!(status.success());
}
