use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

#[test]
fn registered_persona_lifecycle_fails_closed() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = directory.path().join("personas.sqlite3");
    let artifact = directory.path().join("plugin-release.tar.zst");
    let first_key = directory.path().join("first_key");
    let second_key = directory.path().join("second_key");
    let first_proof = directory.path().join("first.proof.json");
    let second_proof = directory.path().join("second.proof.json");

    generate_key(&first_key);
    generate_key(&second_key);
    fs::write(&artifact, b"immutable plugin release").unwrap();

    let created = run_success(aquo(&store).args([
        "persona",
        "create",
        "--label",
        "Test project publisher",
        "--purpose",
        "project",
        "--json",
    ]));
    let created: Value = serde_json::from_slice(&created.stdout).unwrap();
    let persona_id = created["id"].as_str().unwrap();

    run_success(
        aquo(&store)
            .args(["persona", "key-add", "--persona-id", persona_id])
            .arg("--public-key")
            .arg(first_key.with_extension("pub"))
            .args(["--provider", "openssh-file"]),
    );

    run_success(&mut sign_command(
        &store,
        &artifact,
        &first_key,
        persona_id,
        &first_proof,
    ));
    let active = verify_json(&store, &artifact, &first_proof);
    assert_eq!(active["signature"], "verified");
    assert_eq!(active["local_registry"]["key_status"], "active");
    assert!(active["local_registry"]["persona"].get("id").is_none());
    assert!(active["local_registry"].get("public_key").is_none());
    assert!(active["local_registry"].get("events").is_none());

    let rotated = run_success(
        aquo(&store)
            .args(["persona", "key-rotate", "--persona-id", persona_id])
            .arg("--public-key")
            .arg(second_key.with_extension("pub"))
            .args([
                "--provider",
                "openssh-file",
                "--reason",
                "recovery",
                "--note",
                "test replacement key",
                "--json",
            ]),
    );
    let rotated: Value = serde_json::from_slice(&rotated.stdout).unwrap();
    let second_fingerprint = rotated["fingerprint"].as_str().unwrap();

    let retired = verify_json(&store, &artifact, &first_proof);
    assert_eq!(retired["signature"], "verified");
    assert_eq!(retired["local_registry"]["key_status"], "retired");

    let refused_retired = run(&mut sign_command(
        &store,
        &artifact,
        &first_key,
        persona_id,
        &directory.path().join("retired.proof.json"),
    ));
    assert!(!refused_retired.status.success());
    assert!(
        String::from_utf8_lossy(&refused_retired.stderr)
            .contains("refusing to sign with retired key")
    );
    assert!(!directory.path().join("retired.proof.json").exists());

    run_success(&mut sign_command(
        &store,
        &artifact,
        &second_key,
        persona_id,
        &second_proof,
    ));
    run_success(aquo(&store).args([
        "persona",
        "key-compromise",
        "--fingerprint",
        second_fingerprint,
        "--actor",
        "Test project owner",
        "--policy",
        "example.invalid/security/key-compromise-v1",
    ]));

    let compromised = verify_json(&store, &artifact, &second_proof);
    assert_eq!(compromised["signature"], "verified");
    assert_eq!(compromised["local_registry"]["key_status"], "compromised");
    let compromise_event = &compromised["local_registry"]["status_event"];
    assert_eq!(compromise_event["event_type"], "compromised");
    assert!(compromise_event.get("persona_id").is_none());
    assert!(compromise_event.get("key_fingerprint").is_none());
    assert_eq!(compromise_event["actor"], "Test project owner");
    assert_eq!(
        compromise_event["policy"],
        "example.invalid/security/key-compromise-v1"
    );

    let refused_compromised = run(&mut sign_command(
        &store,
        &artifact,
        &second_key,
        persona_id,
        &directory.path().join("compromised.proof.json"),
    ));
    assert!(!refused_compromised.status.success());
    assert!(
        String::from_utf8_lossy(&refused_compromised.stderr)
            .contains("refusing to sign with compromised key")
    );
    assert!(!directory.path().join("compromised.proof.json").exists());

    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&store).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

fn aquo(store: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_a-quo"));
    command.arg("--store").arg(store);
    command
}

fn sign_command(
    store: &Path,
    artifact: &Path,
    key: &Path,
    persona_id: &str,
    output: &Path,
) -> Command {
    let mut command = aquo(store);
    command
        .arg("sign")
        .arg(artifact)
        .arg("--key")
        .arg(key)
        .arg("--public-key")
        .arg(key.with_extension("pub"))
        .arg("--persona-id")
        .arg(persona_id)
        .arg("--output")
        .arg(output);
    command
}

fn verify_json(store: &Path, artifact: &Path, proof: &Path) -> Value {
    let mut command = aquo(store);
    command
        .arg("verify")
        .arg(artifact)
        .arg("--proof")
        .arg(proof)
        .arg("--json");
    let output = run_success(&mut command);
    serde_json::from_slice(&output.stdout).unwrap()
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
