use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use a_quo_core::{
    PersonaRootProof, RecoveryPolicyProof, verify_initial_recovery_policy_proof,
    verify_persona_root_proof, verify_recovery_policy_update_proof,
};
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn cli_creates_and_verifies_a_pinned_threshold_recovery() {
    let directory = tempdir().unwrap();
    let online_one = key(directory.path(), "online_one");
    let online_two = key(directory.path(), "online_two");
    let online_three = key(directory.path(), "online_three");
    let online_four = key(directory.path(), "online_four");
    let authority_one = key(directory.path(), "authority_one");
    let authority_two = key(directory.path(), "authority_two");
    let authority_three = key(directory.path(), "authority_three");
    let authority_four = key(directory.path(), "authority_four");
    let root_path = directory.path().join("persona-root.json");
    let policy_path = directory.path().join("recovery-policy.json");
    let pre_policy_routine_path = directory.path().join("pre-policy-routine-transition.json");
    let transition_path = directory.path().join("recovery-transition.json");
    let policy_update_path = directory.path().join("recovery-policy-v2.json");
    let routine_path = directory
        .path()
        .join("post-recovery-routine-transition.json");

    let root_created = run(aquo()
        .args(["continuity", "root-create", "--persona", "CLI Publisher"])
        .arg("--key")
        .arg(&online_one.private)
        .arg("--public-key")
        .arg(&online_one.public)
        .arg("--output")
        .arg(&root_path));
    assert_success(&root_created, "root creation");
    let root_proof: PersonaRootProof =
        serde_json::from_slice(&fs::read(&root_path).unwrap()).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();

    let pre_policy_routine = run(aquo()
        .args(["continuity", "transition-create"])
        .arg("--root")
        .arg(&root_path)
        .arg("--previous-key")
        .arg(&online_one.private)
        .arg("--previous-public-key")
        .arg(&online_one.public)
        .arg("--next-key")
        .arg(&online_two.private)
        .arg("--next-public-key")
        .arg(&online_two.public)
        .arg("--output")
        .arg(&pre_policy_routine_path));
    assert_success(&pre_policy_routine, "pre-policy routine transition");

    let mut policy_command = aquo();
    policy_command
        .args(["continuity", "recovery-policy-create"])
        .arg("--root")
        .arg(&root_path)
        .arg("--prior-transition")
        .arg(&pre_policy_routine_path)
        .args(["--threshold", "2", "--valid-days", "30"]);
    for authority in [&authority_one, &authority_two, &authority_three] {
        policy_command
            .arg("--authority-key")
            .arg(&authority.private)
            .arg("--authority-public-key")
            .arg(&authority.public);
    }
    policy_command.arg("--output").arg(&policy_path);
    let policy_created = run(&mut policy_command);
    assert_success(&policy_created, "policy creation");
    let policy_proof: RecoveryPolicyProof =
        serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    let policy = verify_initial_recovery_policy_proof(&root, &policy_proof).unwrap();

    let policy_verified = run(aquo()
        .args(["continuity", "recovery-policy-verify"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .arg("--json"));
    assert_success(&policy_verified, "policy verification");
    let policy_report: Value = serde_json::from_slice(&policy_verified.stdout).unwrap();
    assert_eq!(policy_report["time_status"], "active");
    assert_eq!(policy_report["threshold"], 2);
    assert_eq!(policy_report["authority_count"], 3);
    assert_eq!(policy_report["latest_checkpoint_sequence"], 1);
    assert_eq!(
        policy_report["checkpoint_against_transition_chain"],
        "not_checked_without_transition_chain"
    );

    let mut transition_command = aquo();
    transition_command
        .args(["continuity", "recovery-transition-create"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .arg("--prior-transition")
        .arg(&pre_policy_routine_path)
        .args(["--reason", "recovery"]);
    for authority in [&authority_one, &authority_two] {
        transition_command
            .arg("--authority-key")
            .arg(&authority.private)
            .arg("--authority-public-key")
            .arg(&authority.public);
    }
    transition_command
        .arg("--next-key")
        .arg(&online_three.private)
        .arg("--next-public-key")
        .arg(&online_three.public)
        .arg("--output")
        .arg(&transition_path);
    let transition_created = run(&mut transition_command);
    assert_success(&transition_created, "recovery transition creation");

    let routine_created = run(aquo()
        .args(["continuity", "transition-create"])
        .arg("--root")
        .arg(&root_path)
        .arg("--prior-transition")
        .arg(&pre_policy_routine_path)
        .arg("--prior-transition")
        .arg(&transition_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .arg("--previous-key")
        .arg(&online_three.private)
        .arg("--previous-public-key")
        .arg(&online_three.public)
        .arg("--next-key")
        .arg(&online_four.private)
        .arg("--next-public-key")
        .arg(&online_four.public)
        .arg("--output")
        .arg(&routine_path));
    assert_success(&routine_created, "post-recovery routine transition");

    let chain_verified = run(aquo()
        .args(["continuity", "recovery-chain-verify"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--transition")
        .arg(&pre_policy_routine_path)
        .arg("--transition")
        .arg(&transition_path)
        .arg("--transition")
        .arg(&routine_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .arg("--json"));
    assert_success(&chain_verified, "recovery-aware chain verification");
    let chain_report: Value = serde_json::from_slice(&chain_verified.stdout).unwrap();
    assert_eq!(chain_report["transition_chain"], "verified");
    assert_eq!(chain_report["policy_transition_checkpoints"], "verified");
    assert_eq!(chain_report["recovery_transition_count"], 1);
    assert_eq!(chain_report["routine_transition_count"], 2);
    assert_eq!(
        chain_report["current_key_fingerprint"],
        a_quo_core::public_key_fingerprint(&fs::read_to_string(&online_four.public).unwrap())
            .unwrap()
    );

    let mut update_command = aquo();
    update_command
        .args(["continuity", "recovery-policy-update"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--transition")
        .arg(&pre_policy_routine_path)
        .arg("--transition")
        .arg(&transition_path)
        .arg("--transition")
        .arg(&routine_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .args(["--threshold", "2", "--valid-days", "30"]);
    for authority in [&authority_one, &authority_two] {
        update_command
            .arg("--previous-authority-key")
            .arg(&authority.private)
            .arg("--previous-authority-public-key")
            .arg(&authority.public);
    }
    for authority in [&authority_two, &authority_three, &authority_four] {
        update_command
            .arg("--current-authority-key")
            .arg(&authority.private)
            .arg("--current-authority-public-key")
            .arg(&authority.public);
    }
    update_command.arg("--output").arg(&policy_update_path);
    let policy_updated = run(&mut update_command);
    assert_success(&policy_updated, "policy update");
    let policy_update_proof: RecoveryPolicyProof =
        serde_json::from_slice(&fs::read(&policy_update_path).unwrap()).unwrap();
    let updated =
        verify_recovery_policy_update_proof(&root, &policy, &policy_update_proof).unwrap();
    assert_eq!(
        updated.statement.continuity_checkpoint.transition_sequence,
        3
    );

    let updated_chain = run(aquo()
        .args(["continuity", "recovery-chain-verify"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--policy")
        .arg(&policy_update_path)
        .arg("--transition")
        .arg(&pre_policy_routine_path)
        .arg("--transition")
        .arg(&transition_path)
        .arg("--transition")
        .arg(&routine_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&updated.policy_statement_sha256)
        .arg("--json"));
    assert_success(&updated_chain, "updated recovery-aware chain verification");
    let updated_report: Value = serde_json::from_slice(&updated_chain.stdout).unwrap();
    assert_eq!(updated_report["latest_policy_version"], 2);
    assert_eq!(updated_report["latest_policy_checkpoint_sequence"], 3);
    assert_eq!(
        updated_report["latest_policy_checkpoint_sha256"],
        chain_report["last_transition_sha256"]
    );
    assert_eq!(updated_report["policy_transition_checkpoints"], "verified");

    let historical_transition = run(aquo()
        .args(["continuity", "recovery-transition-verify"])
        .arg(&transition_path)
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--policy")
        .arg(&policy_update_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&updated.policy_statement_sha256)
        .arg("--json"));
    assert_success(
        &historical_transition,
        "historical recovery-transition verification",
    );

    let wrong_pin = run(aquo()
        .args(["continuity", "recovery-chain-verify"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--transition")
        .arg(&pre_policy_routine_path)
        .arg("--transition")
        .arg(&transition_path)
        .arg("--transition")
        .arg(&routine_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg("0".repeat(64)));
    assert!(!wrong_pin.status.success());
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
