use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

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
