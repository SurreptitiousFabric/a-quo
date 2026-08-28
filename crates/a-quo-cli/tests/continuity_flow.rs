#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use a_quo_daemon::{
    ApprovalBackend, ApprovalDecision, ApprovalError, ApprovalPrompt, ConsentListener,
    DaemonOutcome, ListenerError, handle_connection,
};
#[cfg(target_os = "linux")]
use a_quo_store::{KeyProvider, PersonaPurpose, PersonaStore};
use serde_json::Value;
use tempfile::tempdir;

#[cfg(target_os = "linux")]
struct ApproveExactPrompt;

#[cfg(target_os = "linux")]
const REQUIRE_CONSENT_SOCKET_TESTS_ENV: &str = "A_QUO_REQUIRE_CONSENT_SOCKET_TESTS";

#[cfg(target_os = "linux")]
impl ApprovalBackend for ApproveExactPrompt {
    fn decide(&mut self, _prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
        Ok(ApprovalDecision::Approve)
    }
}

#[cfg(target_os = "linux")]
fn consent_socket_tests_are_required(value: Option<&OsStr>) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(false);
    };
    match value.to_str() {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(value) => Err(format!(
            "{REQUIRE_CONSENT_SOCKET_TESTS_ENV} must be `0`, `1`, or unset, not {value:?}"
        )),
        None => Err(format!(
            "{REQUIRE_CONSENT_SOCKET_TESTS_ENV} must be valid UTF-8 containing `0` or `1`"
        )),
    }
}

#[cfg(target_os = "linux")]
fn bind_consent_listener(directory: &Path, test_name: &str) -> Option<ConsentListener> {
    let required = consent_socket_tests_are_required(
        std::env::var_os(REQUIRE_CONSENT_SOCKET_TESTS_ENV).as_deref(),
    )
    .unwrap_or_else(|error| panic!("{error}"));

    match ConsentListener::bind(directory) {
        Ok(listener) => Some(listener),
        Err(ListenerError::Socket(rustix::io::Errno::PERM)) if required => panic!(
            "{test_name}: consent socket bind returned EPERM while \
             {REQUIRE_CONSENT_SOCKET_TESTS_ENV}=1; the required Linux socket integration did not run"
        ),
        Err(ListenerError::Socket(rustix::io::Errno::PERM)) => {
            eprintln!(
                "SKIPPED {test_name}: this constrained environment returned EPERM while binding \
                 the private consent socket (set {REQUIRE_CONSENT_SOCKET_TESTS_ENV}=1 to require it)"
            );
            None
        }
        Err(error) => panic!("{test_name}: listener bind failed unexpectedly: {error}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn consent_socket_requirement_flag_is_closed_and_explicit() {
    assert!(!consent_socket_tests_are_required(None).unwrap());
    assert!(!consent_socket_tests_are_required(Some(OsStr::new("0"))).unwrap());
    assert!(consent_socket_tests_are_required(Some(OsStr::new("1"))).unwrap());
    assert!(consent_socket_tests_are_required(Some(OsStr::new("true"))).is_err());
    assert!(consent_socket_tests_are_required(Some(OsStr::from_bytes(&[0xff]))).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn cli_requests_and_reverifies_a_daemon_signed_root() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let key_path = directory.path().join("registered-key");
    let store_path = directory.path().join("personas.db");
    let output_path = directory.path().join("trusted-root.json");
    generate_key(&key_path);

    let mut store = PersonaStore::open(&store_path).unwrap();
    let persona = store
        .create_persona("Trusted CLI publisher", PersonaPurpose::Project)
        .unwrap();
    let public_key = fs::read_to_string(key_path.with_extension("pub")).unwrap();
    let key = store
        .enroll_key(&persona.id, &public_key, KeyProvider::OpensshFile)
        .unwrap();
    store
        .bind_signing_reference(&key.fingerprint, &key_path)
        .unwrap();
    drop(store);

    let Some(listener) = bind_consent_listener(
        directory.path(),
        "cli_requests_and_reverifies_a_daemon_signed_root",
    ) else {
        return;
    };
    let socket_path = listener.path().to_path_buf();
    let server_store_path = store_path.clone();
    let server = thread::spawn(move || {
        let mut store = PersonaStore::open(server_store_path).unwrap();
        let connection = listener.accept().unwrap();
        let outcome = handle_connection(&connection, &mut store, &mut ApproveExactPrompt);
        assert!(matches!(
            outcome,
            DaemonOutcome::Approved {
                subject: a_quo_daemon::ApprovedSubject::PersonaRoot(_),
                ..
            }
        ));
    });

    let created = run_success(
        aquo()
            .arg("--store")
            .arg(&store_path)
            .args(["continuity", "root-request", "--persona-id", &persona.id])
            .arg("--output")
            .arg(&output_path)
            .arg("--socket")
            .arg(&socket_path),
    );
    server.join().unwrap();
    let created_text = String::from_utf8(created.stdout).unwrap();
    assert!(created_text.contains("Trusted local consent: approved exact root statement"));
    assert!(created_text.contains("Trust step still required"));

    let verified = run_success(
        aquo()
            .args(["continuity", "root-verify"])
            .arg(&output_path)
            .arg("--json"),
    );
    let verified: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified["signature"], "verified");
    assert_eq!(verified["statement"]["persona"], "Trusted CLI publisher");
    assert_eq!(
        fs::metadata(&output_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let before = fs::read(&output_path).unwrap();
    let recovered = run_success(
        aquo()
            .arg("--store")
            .arg(&store_path)
            .args(["continuity", "root-request", "--persona-id", &persona.id])
            .arg("--output")
            .arg(&output_path)
            .arg("--socket")
            .arg(&socket_path),
    );
    assert!(
        String::from_utf8_lossy(&recovered.stdout)
            .contains("exported the exact previously approved root proof")
    );
    assert_eq!(fs::read(&output_path).unwrap(), before);
}

#[cfg(target_os = "linux")]
#[test]
fn trusted_rotation_commits_once_and_recovers_without_a_daemon() {
    let directory = tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let first_key = directory.path().join("first-key");
    let next_key = directory.path().join("next-key");
    let store_path = directory.path().join("personas.db");
    let root_output = directory.path().join("root.json");
    let transition_output = directory.path().join("transition.json");
    let recovered_output = directory.path().join("transition-recovered.json");
    let conflicting_output = directory.path().join("do-not-overwrite.json");
    generate_key(&first_key);
    generate_key(&next_key);
    let next_public_path = next_key.with_extension("pub");
    let next_public = fs::read_to_string(&next_public_path).unwrap();
    let mut next_public_fields = next_public.split_whitespace();
    let next_algorithm = next_public_fields.next().unwrap();
    let next_encoded = next_public_fields.next().unwrap();
    fs::write(
        &next_public_path,
        format!("{next_algorithm} {next_encoded} explicit-retry-comment\n"),
    )
    .unwrap();

    let mut store = PersonaStore::open(&store_path).unwrap();
    let persona = store
        .create_persona("Journaled CLI publisher", PersonaPurpose::Project)
        .unwrap();
    let first_public = fs::read_to_string(first_key.with_extension("pub")).unwrap();
    let first = store
        .enroll_key(&persona.id, &first_public, KeyProvider::OpensshFile)
        .unwrap();
    store
        .bind_signing_reference(&first.fingerprint, &first_key)
        .unwrap();
    drop(store);

    let Some(listener) = bind_consent_listener(
        directory.path(),
        "trusted_rotation_commits_once_and_recovers_without_a_daemon",
    ) else {
        return;
    };
    let socket_path = listener.path().to_path_buf();
    let server_store_path = store_path.clone();
    let server = thread::spawn(move || {
        let mut store = PersonaStore::open(server_store_path).unwrap();
        let mut approval = ApproveExactPrompt;

        let root_connection = listener.accept().unwrap();
        assert!(matches!(
            handle_connection(&root_connection, &mut store, &mut approval),
            DaemonOutcome::Approved {
                subject: a_quo_daemon::ApprovedSubject::PersonaRoot(_),
                ..
            }
        ));

        let transition_connection = listener.accept().unwrap();
        assert!(matches!(
            handle_connection(&transition_connection, &mut store, &mut approval),
            DaemonOutcome::Approved {
                subject: a_quo_daemon::ApprovedSubject::PersonaTransition(_),
                ..
            }
        ));
    });

    run_success(
        aquo()
            .arg("--store")
            .arg(&store_path)
            .args(["continuity", "root-request", "--persona-id", &persona.id])
            .arg("--output")
            .arg(&root_output)
            .arg("--socket")
            .arg(&socket_path),
    );
    let root_verified = run_success(
        aquo()
            .args(["continuity", "root-verify"])
            .arg(&root_output)
            .arg("--json"),
    );
    let root_verified: Value = serde_json::from_slice(&root_verified.stdout).unwrap();
    let root_digest = root_verified["root_statement_sha256"]
        .as_str()
        .unwrap()
        .to_owned();

    let rotated = run_success(
        aquo()
            .arg("--store")
            .arg(&store_path)
            .args([
                "continuity",
                "transition-request",
                "--persona-id",
                &persona.id,
                "--expected-root-sha256",
                &root_digest,
                "--next-provider",
                "openssh-file",
            ])
            .arg("--next-key")
            .arg(&next_key)
            .arg("--next-public-key")
            .arg(&next_public_path)
            .arg("--output")
            .arg(&transition_output)
            .arg("--socket")
            .arg(&socket_path),
    );
    server.join().unwrap();
    assert!(
        String::from_utf8_lossy(&rotated.stdout)
            .contains("Trusted local consent: approved the exact two-key transition")
    );

    let verified = run_success(
        aquo()
            .args(["continuity", "transition-verify"])
            .arg(&transition_output)
            .arg("--json"),
    );
    let verified: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified["previous_key_signature"], "verified");
    assert_eq!(verified["next_key_signature"], "verified");
    assert_eq!(verified["statement"]["sequence"], 1);

    let store = PersonaStore::open(&store_path).unwrap();
    let snapshot = store.routine_continuity_snapshot(&persona.id).unwrap();
    assert_eq!(snapshot.head.transition_sequence, 1);
    assert_eq!(snapshot.transitions.len(), 1);
    assert_eq!(
        store
            .active_signer_for_persona(&persona.id)
            .unwrap()
            .signing_reference
            .locator,
        next_key
    );
    drop(store);
    fs::remove_file(&next_key).unwrap();

    let recovered = run_success(
        aquo()
            .arg("--store")
            .arg(&store_path)
            .args([
                "continuity",
                "transition-request",
                "--persona-id",
                &persona.id,
                "--expected-root-sha256",
                &root_digest,
                "--next-provider",
                "openssh-file",
            ])
            .arg("--next-key")
            .arg(&next_key)
            .arg("--next-public-key")
            .arg(&next_public_path)
            .arg("--output")
            .arg(&recovered_output)
            .arg("--socket")
            .arg(&socket_path),
    );
    assert!(
        String::from_utf8_lossy(&recovered.stdout)
            .contains("exported the exact previously committed transition proof")
    );
    assert_eq!(
        fs::read(&recovered_output).unwrap(),
        fs::read(&transition_output).unwrap()
    );

    fs::write(&conflicting_output, b"do not overwrite\n").unwrap();
    let before = fs::read(&conflicting_output).unwrap();
    let refused = run(aquo()
        .arg("--store")
        .arg(&store_path)
        .args([
            "continuity",
            "transition-request",
            "--persona-id",
            &persona.id,
            "--expected-root-sha256",
            &root_digest,
            "--next-provider",
            "openssh-file",
        ])
        .arg("--next-key")
        .arg(&next_key)
        .arg("--next-public-key")
        .arg(&next_public_path)
        .arg("--output")
        .arg(&conflicting_output)
        .arg("--socket")
        .arg(&socket_path));
    assert!(!refused.status.success());
    assert!(!String::from_utf8_lossy(&refused.stderr).contains("cannot connect"));
    assert_eq!(fs::read(&conflicting_output).unwrap(), before);
}

#[test]
fn cli_creates_and_verifies_a_two_transition_chain() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let first_key = directory.path().join("first_key");
    let second_key = directory.path().join("second_key");
    let third_key = directory.path().join("third_key");
    let root_proof = directory.path().join("root.json");
    let first_transition = directory.path().join("transition-1.json");
    let second_transition = directory.path().join("transition-2.json");
    generate_key(&first_key);
    generate_key(&second_key);
    generate_key(&third_key);

    let created_root = run_success(
        aquo()
            .args([
                "continuity",
                "root-create",
                "--persona",
                "CLI release publisher",
                "--key",
            ])
            .arg(&first_key)
            .arg("--public-key")
            .arg(first_key.with_extension("pub"))
            .arg("--output")
            .arg(&root_proof),
    );
    let created_root_text = String::from_utf8(created_root.stdout).unwrap();
    assert!(created_root_text.contains("VERIFIED SELF-ASSERTED PERSONA ROOT"));
    assert!(created_root_text.contains("no trusted A Quo consent ceremony was used"));

    let verified_root = run_success(
        aquo()
            .args(["continuity", "root-verify"])
            .arg(&root_proof)
            .arg("--json"),
    );
    let verified_root: Value = serde_json::from_slice(&verified_root.stdout).unwrap();
    let expected_root_sha256 = verified_root["root_statement_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(verified_root["signature"], "verified");
    assert_eq!(verified_root["external_root_pin"], "not_checked");

    let mut first_transition_command =
        transition_command(&root_proof, &[], &first_key, &second_key, &first_transition);
    run_success(&mut first_transition_command);
    let verified_transition = run_success(
        aquo()
            .args(["continuity", "transition-verify"])
            .arg(&first_transition)
            .arg("--json"),
    );
    let verified_transition: Value = serde_json::from_slice(&verified_transition.stdout).unwrap();
    assert_eq!(verified_transition["previous_key_signature"], "verified");
    assert_eq!(verified_transition["next_key_signature"], "verified");
    assert_eq!(verified_transition["ordered_chain"], "not_checked");

    let mut second_transition_command = transition_command(
        &root_proof,
        std::slice::from_ref(&first_transition),
        &second_key,
        &third_key,
        &second_transition,
    );
    run_success(&mut second_transition_command);
    let chain = run_success(
        chain_command(
            &root_proof,
            &[first_transition.clone(), second_transition.clone()],
            &expected_root_sha256,
        )
        .arg("--json"),
    );
    let chain: Value = serde_json::from_slice(&chain.stdout).unwrap();
    assert_eq!(chain["root_signature"], "verified");
    assert_eq!(chain["expected_root_digest"], "verified");
    assert_eq!(chain["chain"], "verified");
    assert_eq!(chain["transition_count"], 2);

    let mut wrong_pin_command = chain_command(
        &root_proof,
        &[first_transition, second_transition],
        &"0".repeat(64),
    );
    let wrong_pin = run(&mut wrong_pin_command);
    assert!(!wrong_pin.status.success());
    assert!(String::from_utf8_lossy(&wrong_pin.stderr).contains("root statement digest"));

    let before_refused_overwrite = fs::read(&root_proof).unwrap();
    let refused_overwrite = run(aquo()
        .args([
            "continuity",
            "root-create",
            "--persona",
            "CLI release publisher",
            "--key",
        ])
        .arg(&first_key)
        .arg("--public-key")
        .arg(first_key.with_extension("pub"))
        .arg("--output")
        .arg(&root_proof));
    assert!(!refused_overwrite.status.success());
    assert!(!String::from_utf8_lossy(&refused_overwrite.stderr).contains("Signing data"));
    assert_eq!(fs::read(&root_proof).unwrap(), before_refused_overwrite);

    #[cfg(unix)]
    for proof in [
        &root_proof,
        &directory.path().join("transition-1.json"),
        &directory.path().join("transition-2.json"),
    ] {
        assert_eq!(
            fs::metadata(proof).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

fn transition_command(
    root: &Path,
    prior_transitions: &[std::path::PathBuf],
    previous_key: &Path,
    next_key: &Path,
    output: &Path,
) -> Command {
    let mut command = aquo();
    command
        .args(["continuity", "transition-create", "--root"])
        .arg(root);
    for transition in prior_transitions {
        command.arg("--prior-transition").arg(transition);
    }
    command
        .arg("--previous-key")
        .arg(previous_key)
        .arg("--previous-public-key")
        .arg(previous_key.with_extension("pub"))
        .arg("--next-key")
        .arg(next_key)
        .arg("--next-public-key")
        .arg(next_key.with_extension("pub"))
        .arg("--output")
        .arg(output);
    command
}

fn chain_command(root: &Path, transitions: &[std::path::PathBuf], digest: &str) -> Command {
    let mut command = aquo();
    command
        .args(["continuity", "chain-verify", "--root"])
        .arg(root);
    for transition in transitions {
        command.arg("--transition").arg(transition);
    }
    command.arg("--expected-root-sha256").arg(digest);
    command
}

fn aquo() -> Command {
    Command::new(env!("CARGO_BIN_EXE_a-quo"))
}

fn generate_key(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("OpenSSH ssh-keygen must be installed for the integration test");
    assert!(status.success());
}

fn run(command: &mut Command) -> Output {
    command.output().unwrap()
}

fn run_success(command: &mut Command) -> Output {
    let output = run(command);
    assert!(
        output.status.success(),
        "command failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
