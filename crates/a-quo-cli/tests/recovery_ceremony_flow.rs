use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use a_quo_core::{
    RecoveryCeremonyRequest, RecoveryPolicyProof, RecoverySigner, RecoveryTransitionProof,
    canonical_recovery_ceremony_response_bytes, parse_recovery_ceremony_request_bytes,
    sign_recovery_ceremony_request, verify_initial_recovery_policy_proof,
    verify_persona_root_proof, verify_recovery_ceremony_request, verify_recovery_transition_proof,
};
use a_quo_store::{KeyProvider, PersonaPurpose, PersonaStore};
use tempfile::tempdir;

#[test]
fn portable_recovery_ceremony_assembles_deterministically_and_commits() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let coordinator = private_directory(directory.path(), "coordinator");
    let authority_one_home = private_directory(directory.path(), "authority-one-device");
    let authority_two_home = private_directory(directory.path(), "authority-two-device");
    let successor_home = private_directory(directory.path(), "successor-device");
    let current = key(&coordinator, "current");
    let authority_one = key(&authority_one_home, "recovery-authority");
    let authority_two = key(&authority_two_home, "recovery-authority");
    let successor = key(&successor_home, "successor");

    let store_path = coordinator.join("personas.sqlite3");
    let root_path = coordinator.join("persona-root.json");
    let policy_path = coordinator.join("recovery-policy.json");
    let request_path = coordinator.join("recovery-request.json");
    let wrong_pin_response_path = coordinator.join("wrong-pin-response.json");
    let authority_one_response = authority_one_home.join("response.json");
    let authority_two_response = authority_two_home.join("response.json");
    let successor_response = successor_home.join("response.json");
    let proof_one_path = coordinator.join("recovery-transition-one.json");
    let proof_two_path = coordinator.join("recovery-transition-two.json");

    let mut store = PersonaStore::open(&store_path).unwrap();
    let persona = store
        .create_persona("Juniper Ledger", PersonaPurpose::Project)
        .unwrap();
    let current_public = fs::read_to_string(&current.public).unwrap();
    let current_record = store
        .enroll_key(&persona.id, &current_public, KeyProvider::OpensshFile)
        .unwrap();
    store
        .bind_signing_reference(&current_record.fingerprint, &current.private)
        .unwrap();

    let root_created = run(aquo()
        .args(["continuity", "root-create", "--persona", "Juniper Ledger"])
        .arg("--key")
        .arg(&current.private)
        .arg("--public-key")
        .arg(&current.public)
        .arg("--output")
        .arg(&root_path));
    assert_success(&root_created, "root creation");
    let root_proof = serde_json::from_slice(&fs::read(&root_path).unwrap()).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();
    store
        .record_continuity_root(&persona.id, &root_proof, &root.root_statement_sha256)
        .unwrap();
    drop(store);

    let policy_created = run(aquo()
        .args(["continuity", "recovery-policy-create"])
        .arg("--root")
        .arg(&root_path)
        .args(["--threshold", "2", "--valid-days", "30"])
        .arg("--authority-key")
        .arg(&authority_one.private)
        .arg("--authority-public-key")
        .arg(&authority_one.public)
        .arg("--authority-key")
        .arg(&authority_two.private)
        .arg("--authority-public-key")
        .arg(&authority_two.public)
        .arg("--output")
        .arg(&policy_path));
    assert_success(&policy_created, "recovery policy creation");
    let policy_proof: RecoveryPolicyProof =
        serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    let policy = verify_initial_recovery_policy_proof(&root, &policy_proof).unwrap();

    let policy_recorded = run(aquo()
        .arg("--store")
        .arg(&store_path)
        .args([
            "continuity",
            "recovery-policy-record",
            "--persona-id",
            &persona.id,
        ])
        .arg("--policy")
        .arg(&policy_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .args(["--expected-head-sequence", "0"]));
    assert_success(&policy_recorded, "recovery policy recording");

    let started = run(aquo()
        .arg("--store")
        .arg(&store_path)
        .args([
            "continuity",
            "recovery-transition-ceremony-start",
            "--persona-id",
            &persona.id,
        ])
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .args([
            "--expected-previous-head-sequence",
            "0",
            "--reason",
            "recovery",
            "--valid-minutes",
            "30",
        ])
        .arg("--next-public-key")
        .arg(&successor.public)
        .arg("--output")
        .arg(&request_path));
    assert_success(&started, "ceremony start");
    let started_text = String::from_utf8(started.stdout).unwrap();
    assert!(started_text.contains("Live persona state: not changed"));
    assert!(started_text.contains("Each participant must independently verify"));

    let request_bytes = fs::read(&request_path).unwrap();
    let request: RecoveryCeremonyRequest =
        parse_recovery_ceremony_request_bytes(&request_bytes).unwrap();
    assert_eq!(request.expected_head.transition_sequence, 0);
    assert_eq!(request.expected_head.transition_sha256, None);
    let checked_at = now_unix();
    let verified = verify_recovery_ceremony_request(&request, checked_at).unwrap();

    // Participant-side pin rejection happens before connecting to the daemon.
    let wrong_pin = run(aquo()
        .args(["continuity", "recovery-transition-ceremony-respond"])
        .arg("--request")
        .arg(&request_path)
        .arg("--expected-root-sha256")
        .arg("0".repeat(64))
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .args([
            "--expected-previous-head-sequence",
            "0",
            "--participant-provider",
            "openssh-file",
        ])
        .arg("--participant-signing-locator")
        .arg(&authority_one.private)
        .arg("--participant-public-key")
        .arg(&authority_one.public)
        .arg("--output")
        .arg(&wrong_pin_response_path)
        .arg("--socket")
        .arg(directory.path().join("does-not-exist.sock")));
    assert!(!wrong_pin.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_pin.stderr)
            .contains("does not match the independently supplied root digest")
    );
    assert!(!wrong_pin_response_path.exists());

    write_response(&verified, &authority_one, &authority_one_response);
    write_response(&verified, &authority_two, &authority_two_response);
    write_response(&verified, &successor, &successor_response);

    let assembled_one = run(&mut assemble_command(
        &request_path,
        &[
            &authority_two_response,
            &successor_response,
            &authority_one_response,
            &authority_one_response,
        ],
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        &proof_one_path,
    ));
    assert_success(&assembled_one, "unordered ceremony assembly with duplicate");
    let assembled_text = String::from_utf8(assembled_one.stdout).unwrap();
    assert!(assembled_text.contains("Distinct authority responses: 2"));
    assert!(assembled_text.contains("commit remains a separate atomic operation"));

    let assembled_two = run(&mut assemble_command(
        &request_path,
        &[
            &authority_one_response,
            &authority_two_response,
            &successor_response,
        ],
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        &proof_two_path,
    ));
    assert_success(
        &assembled_two,
        "deterministically reordered ceremony assembly",
    );
    assert_eq!(
        fs::read(&proof_one_path).unwrap(),
        fs::read(&proof_two_path).unwrap()
    );

    let proof: RecoveryTransitionProof =
        serde_json::from_slice(&fs::read(&proof_one_path).unwrap()).unwrap();
    let recovered = verify_recovery_transition_proof(&root, &policy, &proof).unwrap();
    assert_eq!(recovered.recovery_signer_fingerprints.len(), 2);
    assert_eq!(
        recovered.statement.ceremony_id,
        verified.statement().ceremony_id
    );
    assert_eq!(
        recovered.statement.expires_at,
        verified.statement().expires_at
    );

    let committed = run(aquo()
        .arg("--store")
        .arg(&store_path)
        .args([
            "continuity",
            "recovery-transition-commit",
            "--persona-id",
            &persona.id,
        ])
        .arg("--proof")
        .arg(&proof_one_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .args([
            "--expected-previous-head-sequence",
            "0",
            "--next-provider",
            "openssh-file",
        ])
        .arg("--next-signing-locator")
        .arg(&successor.private));
    assert_success(&committed, "assembled recovery commit");

    let snapshot = PersonaStore::open(&store_path)
        .unwrap()
        .continuity_snapshot(&persona.id)
        .unwrap();
    assert_eq!(snapshot.head.transition_sequence, 1);
    assert_eq!(
        snapshot.head.current_key_fingerprint,
        recovered.statement.next_key_fingerprint
    );

    let artifact = coordinator.join("after-recovery.txt");
    let artifact_proof = coordinator.join("after-recovery.proof.json");
    fs::write(
        &artifact,
        b"signed after the multi-party recovery ceremony\n",
    )
    .unwrap();
    let signed = run(aquo()
        .arg("--store")
        .arg(&store_path)
        .arg("sign")
        .arg(&artifact)
        .arg("--key")
        .arg(&successor.private)
        .arg("--public-key")
        .arg(&successor.public)
        .arg("--persona-id")
        .arg(&persona.id)
        .arg("--output")
        .arg(&artifact_proof));
    assert_success(&signed, "post-recovery artifact signing");
}

fn private_directory(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

struct TestKey {
    private: PathBuf,
    public: PathBuf,
}

fn key(directory: &Path, name: &str) -> TestKey {
    let private = directory.join(name);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&private)
        .status()
        .expect("OpenSSH ssh-keygen must be installed for the integration test");
    assert!(status.success());
    let public = private.with_extension("pub");
    TestKey { private, public }
}

fn write_response(
    verified: &a_quo_core::VerifiedRecoveryCeremonyRequest,
    key: &TestKey,
    output: &Path,
) {
    let response = sign_recovery_ceremony_request(
        verified,
        &RecoverySigner {
            private_key_path: key.private.clone(),
            public_key: fs::read_to_string(&key.public).unwrap(),
        },
        now_unix(),
    )
    .unwrap();
    fs::write(
        output,
        canonical_recovery_ceremony_response_bytes(&response).unwrap(),
    )
    .unwrap();
}

fn assemble_command(
    request: &Path,
    responses: &[&PathBuf],
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    output: &Path,
) -> Command {
    let mut command = aquo();
    command
        .args(["continuity", "recovery-transition-ceremony-assemble"])
        .arg("--request")
        .arg(request);
    for response in responses {
        command.arg("--response").arg(response);
    }
    command
        .arg("--expected-root-sha256")
        .arg(expected_root_sha256)
        .arg("--expected-policy-sha256")
        .arg(expected_policy_sha256)
        .args(["--expected-previous-head-sequence", "0"])
        .arg("--output")
        .arg(output);
    command
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn aquo() -> Command {
    Command::new(env!("CARGO_BIN_EXE_a-quo"))
}

fn run(command: &mut Command) -> Output {
    command.output().expect("run A Quo CLI")
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
