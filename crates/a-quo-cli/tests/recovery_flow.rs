use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
#[cfg(target_os = "linux")]
use std::thread;

use a_quo_core::{
    PersonaContinuityTransitionProof, PersonaRootProof, PersonaTransitionProof,
    RecoveryPolicyCapability, RecoveryPolicyProof, RecoverySigner, RecoveryTransitionProof,
    create_recovery_transition_proof, inspect_recovery_transition_proof,
    verify_initial_recovery_policy_proof, verify_persona_root_proof,
    verify_recovery_policy_update_proof,
};
#[cfg(target_os = "linux")]
use a_quo_daemon::{
    ApprovalBackend, ApprovalDecision, ApprovalError, ApprovalPrompt, ConsentListener,
    DaemonOutcome, handle_connection,
};
use a_quo_store::{KeyProvider, PersonaPurpose, PersonaStore};
use serde_json::Value;
use tempfile::tempdir;

#[cfg(target_os = "linux")]
struct ApproveExactPrompt;

#[cfg(target_os = "linux")]
impl ApprovalBackend for ApproveExactPrompt {
    fn decide(&mut self, _prompt: &ApprovalPrompt) -> Result<ApprovalDecision, ApprovalError> {
        Ok(ApprovalDecision::Approve)
    }
}

#[test]
fn cli_creates_and_verifies_a_pinned_threshold_recovery() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let online_one = key(directory.path(), "online_one");
    let online_two = key(directory.path(), "online_two");
    let online_three = key(directory.path(), "online_three");
    let online_four = key(directory.path(), "online_four");
    let authority_one = key(directory.path(), "authority_one");
    let authority_two = key(directory.path(), "authority_two");
    let authority_three = key(directory.path(), "authority_three");
    let authority_four = key(directory.path(), "authority_four");
    let store_path = directory.path().join("personas.sqlite3");
    let root_path = directory.path().join("persona-root.json");
    let policy_path = directory.path().join("recovery-policy.json");
    let pre_policy_routine_path = directory.path().join("pre-policy-routine-transition.json");
    let transition_path = directory.path().join("recovery-transition.json");
    let policy_update_path = directory.path().join("recovery-policy-v2.json");
    let routine_path = directory
        .path()
        .join("post-recovery-routine-transition.json");

    let mut store = PersonaStore::open(&store_path).unwrap();
    let persona = store
        .create_persona("CLI Publisher", PersonaPurpose::Project)
        .unwrap();
    let online_one_public = fs::read_to_string(&online_one.public).unwrap();
    let online_one_record = store
        .enroll_key(&persona.id, &online_one_public, KeyProvider::OpensshFile)
        .unwrap();
    store
        .bind_signing_reference(&online_one_record.fingerprint, &online_one.private)
        .unwrap();

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
    store
        .record_continuity_root(&persona.id, &root_proof, &root.root_statement_sha256)
        .unwrap();

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
    let pre_policy_routine_proof: PersonaTransitionProof =
        serde_json::from_slice(&fs::read(&pre_policy_routine_path).unwrap()).unwrap();
    let committed_routine = store
        .commit_routine_transition(
            &persona.id,
            &pre_policy_routine_proof,
            KeyProvider::OpensshFile,
            &online_two.private,
        )
        .unwrap();
    drop(store);

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
    assert_eq!(
        policy.statement.schema,
        a_quo_core::RECOVERY_POLICY_STATEMENT_SCHEMA
    );

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
        .args(["--expected-head-sequence", "1"])
        .arg("--expected-head-sha256")
        .arg(&committed_routine.transition_statement_sha256));
    assert_success(&policy_recorded, "policy journal recording");
    let policy_recorded_text = String::from_utf8(policy_recorded.stdout).unwrap();
    assert!(policy_recorded_text.contains("new policy evidence recorded"));
    assert!(policy_recorded_text.contains(&policy.policy_statement_sha256));
    assert!(policy_recorded_text.contains("This records already-signed threshold evidence."));
    assert!(
        policy_recorded_text
            .contains("does not claim independent people/devices or trusted multi-party consent")
    );
    assert!(
        policy_recorded_text
            .contains("Signed does not mean safe and does not establish legal identity.")
    );

    let policy_replayed = run(aquo()
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
        .args(["--expected-head-sequence", "1"])
        .arg("--expected-head-sha256")
        .arg(&committed_routine.transition_statement_sha256));
    assert_success(&policy_replayed, "policy journal replay");
    assert!(
        String::from_utf8(policy_replayed.stdout)
            .unwrap()
            .contains("already recorded; exact chain replay")
    );

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

    let before_recovery = PersonaStore::open(&store_path)
        .unwrap()
        .continuity_snapshot(&persona.id)
        .unwrap();
    let missing_first_binding = run(&mut recovery_commit_command(
        &store_path,
        &persona.id,
        &transition_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    ));
    assert!(!missing_first_binding.status.success());
    assert!(
        String::from_utf8_lossy(&missing_first_binding.stderr)
            .contains("required for a first recovery transition commit")
    );

    let mut provider_only = recovery_commit_command(
        &store_path,
        &persona.id,
        &transition_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    );
    provider_only.args(["--next-provider", "openssh-file"]);
    assert!(!run(&mut provider_only).status.success());

    let mut locator_only = recovery_commit_command(
        &store_path,
        &persona.id,
        &transition_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    );
    locator_only
        .arg("--next-signing-locator")
        .arg(&online_three.private);
    assert!(!run(&mut locator_only).status.success());
    assert_eq!(
        PersonaStore::open(&store_path)
            .unwrap()
            .continuity_snapshot(&persona.id)
            .unwrap(),
        before_recovery
    );

    let original_transition_proof: RecoveryTransitionProof =
        serde_json::from_slice(&fs::read(&transition_path).unwrap()).unwrap();
    let alternate_statement =
        inspect_recovery_transition_proof(&original_transition_proof).unwrap();
    let alternate_signers = [&authority_two, &authority_three]
        .into_iter()
        .map(|authority| RecoverySigner {
            private_key_path: authority.private.clone(),
            public_key: fs::read_to_string(&authority.public).unwrap(),
        })
        .collect::<Vec<_>>();
    let online_three_public = fs::read_to_string(&online_three.public).unwrap();
    let alternate_transition_proof = create_recovery_transition_proof(
        alternate_statement,
        &policy,
        &alternate_signers,
        &online_three.private,
        &online_three_public,
    )
    .unwrap();
    assert_ne!(alternate_transition_proof, original_transition_proof);
    let alternate_transition_path = directory.path().join("recovery-transition-alternate.json");
    fs::write(
        &alternate_transition_path,
        serde_json::to_vec_pretty(&alternate_transition_proof).unwrap(),
    )
    .unwrap();

    let mut first_commit = recovery_commit_command(
        &store_path,
        &persona.id,
        &transition_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    );
    first_commit
        .args(["--next-provider", "openssh-file"])
        .arg("--next-signing-locator")
        .arg(&online_three.private);
    let transition_committed = run(&mut first_commit);
    assert_success(&transition_committed, "recovery transition commit");
    let transition_committed_text = String::from_utf8(transition_committed.stdout).unwrap();
    assert!(transition_committed_text.contains("new transition committed"));
    assert!(transition_committed_text.contains("This records already-signed threshold evidence."));

    let first_committed = PersonaStore::open(&store_path)
        .unwrap()
        .continuity_snapshot(&persona.id)
        .unwrap();
    let alternate_replayed = run(&mut recovery_commit_command(
        &store_path,
        &persona.id,
        &alternate_transition_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    ));
    assert_success(&alternate_replayed, "alternate recovery transition replay");
    let alternate_replayed_text = String::from_utf8(alternate_replayed.stdout).unwrap();
    assert!(alternate_replayed_text.contains("already committed; statement replay"));
    assert!(
        alternate_replayed_text.contains("reused from verified current-head metadata for replay")
    );
    assert_eq!(
        PersonaStore::open(&store_path)
            .unwrap()
            .continuity_snapshot(&persona.id)
            .unwrap(),
        first_committed
    );

    let mut invalid_alternate_proof = alternate_transition_proof.clone();
    invalid_alternate_proof.recovery_signatures[0]
        .value
        .push('A');
    let invalid_alternate_path = directory.path().join("recovery-transition-invalid.json");
    fs::write(
        &invalid_alternate_path,
        serde_json::to_vec_pretty(&invalid_alternate_proof).unwrap(),
    )
    .unwrap();
    let invalid_alternate_replay = run(&mut recovery_commit_command(
        &store_path,
        &persona.id,
        &invalid_alternate_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    ));
    assert!(!invalid_alternate_replay.status.success());
    assert_eq!(
        PersonaStore::open(&store_path)
            .unwrap()
            .continuity_snapshot(&persona.id)
            .unwrap(),
        first_committed
    );

    let mut mismatched_binding = recovery_commit_command(
        &store_path,
        &persona.id,
        &alternate_transition_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    );
    mismatched_binding
        .args(["--next-provider", "openssh-file"])
        .arg("--next-signing-locator")
        .arg(&online_four.private);
    let mismatched_binding = run(&mut mismatched_binding);
    assert!(!mismatched_binding.status.success());
    assert!(
        String::from_utf8_lossy(&mismatched_binding.stderr)
            .contains("does not match the committed recovery head")
    );
    assert_eq!(
        PersonaStore::open(&store_path)
            .unwrap()
            .continuity_snapshot(&persona.id)
            .unwrap(),
        first_committed
    );

    let stored_signer_bytes = fs::read(&online_three.private).unwrap();
    let stored_signer_permissions = fs::metadata(&online_three.private).unwrap().permissions();
    fs::remove_file(&online_three.private).unwrap();
    let missing_target_omitted_replay = run(&mut recovery_commit_command(
        &store_path,
        &persona.id,
        &alternate_transition_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    ));
    assert_success(
        &missing_target_omitted_replay,
        "missing-target replay with stored binding",
    );
    let mut missing_target_explicit_replay = recovery_commit_command(
        &store_path,
        &persona.id,
        &transition_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
        1,
        Some(&committed_routine.transition_statement_sha256),
    );
    missing_target_explicit_replay
        .args(["--next-provider", "openssh-file"])
        .arg("--next-signing-locator")
        .arg(&online_three.private);
    assert_success(
        &run(&mut missing_target_explicit_replay),
        "missing-target replay with exact supplied binding",
    );
    assert_eq!(
        PersonaStore::open(&store_path)
            .unwrap()
            .continuity_snapshot(&persona.id)
            .unwrap(),
        first_committed
    );
    fs::write(&online_three.private, stored_signer_bytes).unwrap();
    fs::set_permissions(&online_three.private, stored_signer_permissions).unwrap();

    let live = PersonaStore::open(&store_path)
        .unwrap()
        .continuity_snapshot(&persona.id)
        .unwrap();
    let Some(PersonaContinuityTransitionProof::Recovery(authoritative_proof)) =
        live.transitions.last()
    else {
        panic!("expected a recovery transition at the live head");
    };
    assert_eq!(authoritative_proof, &original_transition_proof);

    #[cfg(target_os = "linux")]
    {
        let forbidden_recovery_retry_path = directory.path().join("not-a-routine-retry.json");
        let forbidden_recovery_retry = run(aquo()
            .arg("--store")
            .arg(&store_path)
            .args([
                "continuity",
                "transition-request",
                "--persona-id",
                &persona.id,
            ])
            .arg("--expected-root-sha256")
            .arg(&root.root_statement_sha256)
            .arg("--next-key")
            .arg(&online_three.private)
            .arg("--next-public-key")
            .arg(&online_three.public)
            .args(["--next-provider", "openssh-file"])
            .arg("--output")
            .arg(&forbidden_recovery_retry_path));
        assert!(!forbidden_recovery_retry.status.success());
        assert!(
            String::from_utf8_lossy(&forbidden_recovery_retry.stderr)
                .contains("current continuity head is a recovery transition")
        );
        assert!(!forbidden_recovery_retry_path.exists());

        if let Ok(listener) = ConsentListener::bind(directory.path()) {
            let socket_path = listener.path().to_path_buf();
            let server_store_path = store_path.clone();
            let server = thread::spawn(move || {
                let mut store = PersonaStore::open(server_store_path).unwrap();
                let connection = listener.accept().unwrap();
                assert!(matches!(
                    handle_connection(&connection, &mut store, &mut ApproveExactPrompt),
                    DaemonOutcome::Approved {
                        subject: a_quo_daemon::ApprovedSubject::PersonaTransition(_),
                        ..
                    }
                ));
            });
            let routine_requested = run(aquo()
                .arg("--store")
                .arg(&store_path)
                .args([
                    "continuity",
                    "transition-request",
                    "--persona-id",
                    &persona.id,
                ])
                .arg("--expected-root-sha256")
                .arg(&root.root_statement_sha256)
                .arg("--next-key")
                .arg(&online_four.private)
                .arg("--next-public-key")
                .arg(&online_four.public)
                .args(["--next-provider", "openssh-file"])
                .arg("--output")
                .arg(&routine_path)
                .arg("--socket")
                .arg(&socket_path));
            server.join().unwrap();
            assert_success(
                &routine_requested,
                "post-recovery daemon routine transition",
            );

            let routine_retry_path = directory.path().join("post-recovery-routine-retry.json");
            let routine_retried = run(aquo()
                .arg("--store")
                .arg(&store_path)
                .args([
                    "continuity",
                    "transition-request",
                    "--persona-id",
                    &persona.id,
                ])
                .arg("--expected-root-sha256")
                .arg(&root.root_statement_sha256)
                .arg("--next-key")
                .arg(&online_four.private)
                .arg("--next-public-key")
                .arg(&online_four.public)
                .args(["--next-provider", "openssh-file"])
                .arg("--output")
                .arg(&routine_retry_path));
            assert_success(&routine_retried, "post-recovery routine transition replay");
            assert!(
                String::from_utf8_lossy(&routine_retried.stdout)
                    .contains("exact previously committed transition proof")
            );
            assert_eq!(
                fs::read(&routine_retry_path).unwrap(),
                fs::read(&routine_path).unwrap()
            );
        }
    }

    if !routine_path.exists() {
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
    }

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
        chain_report["chain_tip_key_fingerprint"],
        a_quo_core::public_key_fingerprint(&fs::read_to_string(&online_four.public).unwrap())
            .unwrap()
    );
    assert!(chain_report["expected_head_checkpoint"].is_null());
    let expected_head_sha256 = chain_report["last_transition_sha256"].as_str().unwrap();
    let checkpoint_verified = run(aquo()
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
        .args(["--expected-head-sequence", "3", "--expected-head-sha256"])
        .arg(expected_head_sha256)
        .arg("--json"));
    assert_success(
        &checkpoint_verified,
        "checkpointed recovery-aware verification",
    );
    let checkpoint_report: Value = serde_json::from_slice(&checkpoint_verified.stdout).unwrap();
    assert_eq!(checkpoint_report["expected_head_checkpoint"], "verified");
    assert!(
        checkpoint_report["not_established"]
            .as_array()
            .unwrap()
            .contains(&Value::String(
                "whether_a_competing_transition_or_policy_branch_was_also_authorized_or_withheld"
                    .to_owned()
            ))
    );

    let incomplete_checkpoint = run(aquo()
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
        .args(["--expected-head-sequence", "3"]));
    assert!(!incomplete_checkpoint.status.success());

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
        .args([
            "--threshold",
            "2",
            "--valid-days",
            "30",
            "--authorize-terminal-revocation",
        ]);
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
        updated.statement.schema,
        a_quo_core::RECOVERY_POLICY_STATEMENT_SCHEMA_V2
    );
    assert_eq!(
        updated.statement.capabilities,
        vec![
            RecoveryPolicyCapability::KeyRecovery,
            RecoveryPolicyCapability::TerminalRevocation,
        ]
    );
    assert_eq!(
        updated.statement.continuity_checkpoint.transition_sequence,
        3
    );

    let updated_policy_verified = run(aquo()
        .args(["continuity", "recovery-policy-verify"])
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
        &updated_policy_verified,
        "terminal-capable v1-to-v2 policy update verification",
    );
    let updated_policy_report: Value =
        serde_json::from_slice(&updated_policy_verified.stdout).unwrap();
    assert_eq!(
        updated_policy_report["latest_policy_capabilities"],
        serde_json::json!(["key_recovery", "terminal_revocation"])
    );
    assert_eq!(
        updated_policy_report["terminal_revocation_authorized"],
        true
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

#[test]
fn cli_creates_and_verifies_a_terminal_persona_revocation() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let online = key(directory.path(), "terminal_online");
    let authority_one = key(directory.path(), "terminal_authority_one");
    let authority_two = key(directory.path(), "terminal_authority_two");
    let authority_three = key(directory.path(), "terminal_authority_three");
    let denied_successor = key(directory.path(), "terminal_denied_successor");
    let store_path = directory.path().join("terminal-personas.sqlite3");
    let root_path = directory.path().join("terminal-root.json");
    let policy_path = directory.path().join("terminal-policy.json");
    let key_recovery_only_policy_path = directory.path().join("key-recovery-only-policy.json");
    let legacy_policy_path = directory.path().join("legacy-policy.json");
    let terminal_path = directory.path().join("terminal-revocation.json");

    let root_created = run(aquo()
        .args([
            "continuity",
            "root-create",
            "--persona",
            "Ended CLI Persona",
        ])
        .arg("--key")
        .arg(&online.private)
        .arg("--public-key")
        .arg(&online.public)
        .arg("--output")
        .arg(&root_path));
    assert_success(&root_created, "terminal root creation");
    let root_proof: PersonaRootProof =
        serde_json::from_slice(&fs::read(&root_path).unwrap()).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();
    let mut store = PersonaStore::open(&store_path).unwrap();
    let persona = store
        .create_persona("Ended CLI Persona", PersonaPurpose::Project)
        .unwrap();
    let online_public = fs::read_to_string(&online.public).unwrap();
    let online_record = store
        .enroll_key(&persona.id, &online_public, KeyProvider::OpensshFile)
        .unwrap();
    store
        .bind_signing_reference(&online_record.fingerprint, &online.private)
        .unwrap();
    store
        .record_continuity_root(&persona.id, &root_proof, &root.root_statement_sha256)
        .unwrap();
    drop(store);

    let mut policy_command = aquo();
    policy_command
        .args(["continuity", "recovery-policy-create"])
        .arg("--root")
        .arg(&root_path)
        .args([
            "--threshold",
            "2",
            "--valid-days",
            "30",
            "--authorize-terminal-revocation",
        ]);
    for authority in [&authority_one, &authority_two, &authority_three] {
        policy_command
            .arg("--authority-key")
            .arg(&authority.private)
            .arg("--authority-public-key")
            .arg(&authority.public);
    }
    policy_command.arg("--output").arg(&policy_path);
    let policy_created = run(&mut policy_command);
    assert_success(&policy_created, "terminal-capable policy creation");
    assert!(
        String::from_utf8_lossy(&policy_created.stdout)
            .contains("Terminal persona revocation authorized: yes")
    );
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
    assert_success(&policy_verified, "terminal-capable policy verification");
    let policy_report: Value = serde_json::from_slice(&policy_verified.stdout).unwrap();
    assert_eq!(policy_report["terminal_revocation_authorized"], true);

    let mut key_recovery_only_update = aquo();
    key_recovery_only_update
        .args(["continuity", "recovery-policy-update"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .args(["--threshold", "2", "--valid-days", "30"]);
    for authority in [&authority_one, &authority_two] {
        key_recovery_only_update
            .arg("--previous-authority-key")
            .arg(&authority.private)
            .arg("--previous-authority-public-key")
            .arg(&authority.public);
    }
    for authority in [&authority_one, &authority_two, &authority_three] {
        key_recovery_only_update
            .arg("--current-authority-key")
            .arg(&authority.private)
            .arg("--current-authority-public-key")
            .arg(&authority.public);
    }
    key_recovery_only_update
        .arg("--output")
        .arg(&key_recovery_only_policy_path);
    let key_recovery_only_updated = run(&mut key_recovery_only_update);
    assert_success(
        &key_recovery_only_updated,
        "v2 key-recovery-only policy update",
    );
    assert!(
        String::from_utf8_lossy(&key_recovery_only_updated.stdout)
            .contains("Terminal persona revocation authorized: no")
    );
    let key_recovery_only_proof: RecoveryPolicyProof =
        serde_json::from_slice(&fs::read(&key_recovery_only_policy_path).unwrap()).unwrap();
    let key_recovery_only =
        verify_recovery_policy_update_proof(&root, &policy, &key_recovery_only_proof).unwrap();
    assert_eq!(
        key_recovery_only.statement.schema,
        a_quo_core::RECOVERY_POLICY_STATEMENT_SCHEMA_V2
    );
    let key_recovery_only_verified = run(aquo()
        .args(["continuity", "recovery-policy-verify"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--policy")
        .arg(&key_recovery_only_policy_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&key_recovery_only.policy_statement_sha256)
        .arg("--json"));
    assert_success(
        &key_recovery_only_verified,
        "v2 key-recovery-only policy verification",
    );
    let key_recovery_only_report: Value =
        serde_json::from_slice(&key_recovery_only_verified.stdout).unwrap();
    assert_eq!(
        key_recovery_only_report["terminal_revocation_authorized"],
        false
    );
    assert_eq!(
        key_recovery_only_report["latest_policy_capabilities"],
        serde_json::json!(["key_recovery"])
    );

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
    assert_success(&policy_recorded, "terminal-capable policy recording");

    let mut terminal_command = aquo();
    terminal_command
        .args(["continuity", "terminal-revocation-create"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .args([
            "--expected-previous-head-sequence",
            "0",
            "--reason",
            "cessation",
        ]);
    for authority in [&authority_one, &authority_two] {
        terminal_command
            .arg("--authority-key")
            .arg(&authority.private)
            .arg("--authority-public-key")
            .arg(&authority.public);
    }
    terminal_command
        .arg("--output")
        .arg(&terminal_path)
        .arg("--json");
    let terminal_created = run(&mut terminal_command);
    assert_success(&terminal_created, "terminal revocation creation");
    let created_report: Value = serde_json::from_slice(&terminal_created.stdout).unwrap();
    assert_eq!(
        created_report["signed_effect"],
        "persona_permanently_deauthorized"
    );
    assert_eq!(created_report["successor_key_fingerprint"], Value::Null);
    assert_eq!(created_report["live_store_changed"], false);
    let terminal_statement_sha256 = created_report["revocation_statement_sha256"]
        .as_str()
        .unwrap();
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&terminal_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let standalone_verified = run(aquo()
        .args(["continuity", "terminal-revocation-verify"])
        .arg(&terminal_path)
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .arg("--json"));
    assert_success(&standalone_verified, "standalone terminal verification");
    let standalone_report: Value = serde_json::from_slice(&standalone_verified.stdout).unwrap();
    assert_eq!(
        standalone_report["status"],
        "verified_terminal_revocation_authority"
    );
    assert_eq!(standalone_report["ordered_transition_chain"], "not_checked");
    assert_eq!(standalone_report["current_head_position"], "not_checked");
    assert_eq!(standalone_report["live_store_authorization"], "not_checked");
    assert_eq!(standalone_report["successor_key_fingerprint"], Value::Null);

    let unpinned_chain_verified = run(aquo()
        .args(["continuity", "recovery-chain-verify"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--terminal-revocation")
        .arg(&terminal_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .arg("--json"));
    assert_success(
        &unpinned_chain_verified,
        "unpinned terminal recovery-chain verification",
    );
    let unpinned_chain_report: Value =
        serde_json::from_slice(&unpinned_chain_verified.stdout).unwrap();
    assert_eq!(unpinned_chain_report["terminally_revoked"], true);
    assert_eq!(
        unpinned_chain_report["persona_authorization"],
        "permanently_deauthorized_in_supplied_evidence"
    );
    assert_eq!(
        unpinned_chain_report["successor_key_fingerprint"],
        Value::Null
    );

    let chain_verified = run(aquo()
        .args(["continuity", "recovery-chain-verify"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--terminal-revocation")
        .arg(&terminal_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&policy.policy_statement_sha256)
        .args(["--expected-head-sequence", "1"])
        .arg("--expected-head-sha256")
        .arg(terminal_statement_sha256)
        .arg("--json"));
    assert_success(&chain_verified, "terminal recovery-chain verification");
    let chain_report: Value = serde_json::from_slice(&chain_verified.stdout).unwrap();
    assert_eq!(chain_report["terminally_revoked"], true);
    assert_eq!(chain_report["terminal_revocation_count"], 1);
    assert_eq!(chain_report["current_key_fingerprint"], Value::Null);
    assert_eq!(
        chain_report["persona_authorization"],
        "permanently_deauthorized"
    );
    assert_eq!(chain_report["successor_key_fingerprint"], Value::Null);

    let committed = run(&mut terminal_commit_command(
        &store_path,
        &persona.id,
        &terminal_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
    ));
    assert_success(&committed, "terminal revocation commit");
    let committed_report: Value = serde_json::from_slice(&committed.stdout).unwrap();
    assert_eq!(
        committed_report["status"],
        "persona_permanently_deauthorized"
    );
    assert_eq!(
        committed_report["store_status"],
        "new_terminal_revocation_committed"
    );
    assert_eq!(committed_report["state_changed"], true);
    assert_eq!(committed_report["successor_key_fingerprint"], Value::Null);

    let denied_artifact_path = directory.path().join("terminal-signing-denied.txt");
    let denied_proof_path = directory.path().join("terminal-signing-denied.proof.json");
    fs::write(&denied_artifact_path, b"terminal persona cannot sign\n").unwrap();
    let denied_sign = run(aquo()
        .arg("--store")
        .arg(&store_path)
        .arg("sign")
        .arg(&denied_artifact_path)
        .arg("--key")
        .arg(&online.private)
        .arg("--public-key")
        .arg(&online.public)
        .arg("--persona-id")
        .arg(&persona.id)
        .arg("--output")
        .arg(&denied_proof_path));
    assert!(!denied_sign.status.success());
    assert!(String::from_utf8_lossy(&denied_sign.stderr).contains("PERMANENTLY DEAUTHORIZED"));
    assert!(!denied_proof_path.exists());

    let replayed = run(&mut terminal_commit_command(
        &store_path,
        &persona.id,
        &terminal_path,
        &root.root_statement_sha256,
        &policy.policy_statement_sha256,
    ));
    assert_success(&replayed, "terminal revocation exact replay");
    let replayed_report: Value = serde_json::from_slice(&replayed.stdout).unwrap();
    assert_eq!(
        replayed_report["store_status"],
        "already_committed_statement_replay"
    );
    assert_eq!(replayed_report["state_changed"], false);
    assert_eq!(replayed_report["proof_wrapper"], "first_committed");

    let denied_successor_path = directory.path().join("denied-successor.json");
    let denied_successor_request = run(aquo()
        .arg("--store")
        .arg(&store_path)
        .args([
            "continuity",
            "transition-request",
            "--persona-id",
            &persona.id,
        ])
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--next-key")
        .arg(&denied_successor.private)
        .arg("--next-public-key")
        .arg(&denied_successor.public)
        .args(["--next-provider", "openssh-file"])
        .arg("--output")
        .arg(&denied_successor_path));
    assert!(!denied_successor_request.status.success());
    assert!(
        String::from_utf8_lossy(&denied_successor_request.stderr)
            .contains("PERMANENTLY DEAUTHORIZED")
    );
    assert!(!denied_successor_path.exists());

    let terminal_backup_path = directory.path().join("terminal-persona.backup.json");
    let backup_exported = run(aquo()
        .arg("--store")
        .arg(&store_path)
        .args(["persona", "backup-export", "--persona-id", &persona.id])
        .arg("--output")
        .arg(&terminal_backup_path));
    assert_success(&backup_exported, "terminal persona backup export");
    assert!(
        String::from_utf8_lossy(&backup_exported.stdout)
            .contains("PERSONA PERMANENTLY DEAUTHORIZED")
    );

    let imported_store_path = directory.path().join("imported-terminal-evidence.sqlite3");
    let backup_imported = run(aquo()
        .arg("--store")
        .arg(&imported_store_path)
        .args(["persona", "backup-import"])
        .arg(&terminal_backup_path)
        .arg("--json"));
    assert_success(&backup_imported, "terminal evidence backup import");
    let imported_report: Value = serde_json::from_slice(&backup_imported.stdout).unwrap();
    assert_eq!(imported_report["terminally_revoked"], true);
    assert_eq!(
        imported_report["persona_authorization"],
        "permanently_deauthorized_in_supplied_evidence"
    );
    assert_eq!(imported_report["authority_disposition"], "evidence_only");
    assert_eq!(imported_report["disposition"], "evidence_only_quarantined");
    assert_eq!(imported_report["quarantined"], true);

    let imported_list = run(aquo()
        .arg("--store")
        .arg(&imported_store_path)
        .args(["persona", "list", "--json"]));
    assert_success(&imported_list, "imported terminal evidence listing");
    let imported_personas: Value = serde_json::from_slice(&imported_list.stdout).unwrap();
    assert_eq!(
        imported_personas[0]["authority_disposition"],
        "evidence_only"
    );
    assert_eq!(imported_personas[0]["quarantined"], true);

    let mut legacy_policy_command = aquo();
    legacy_policy_command
        .args(["continuity", "recovery-policy-create"])
        .arg("--root")
        .arg(&root_path)
        .args(["--threshold", "2", "--valid-days", "30"]);
    for authority in [&authority_one, &authority_two, &authority_three] {
        legacy_policy_command
            .arg("--authority-key")
            .arg(&authority.private)
            .arg("--authority-public-key")
            .arg(&authority.public);
    }
    legacy_policy_command
        .arg("--output")
        .arg(&legacy_policy_path);
    let legacy_policy_created = run(&mut legacy_policy_command);
    assert_success(&legacy_policy_created, "legacy policy creation");
    let legacy_policy_proof: RecoveryPolicyProof =
        serde_json::from_slice(&fs::read(&legacy_policy_path).unwrap()).unwrap();
    let legacy_policy = verify_initial_recovery_policy_proof(&root, &legacy_policy_proof).unwrap();
    let denied_path = directory.path().join("legacy-terminal-denied.json");
    let mut denied_command = aquo();
    denied_command
        .args(["continuity", "terminal-revocation-create"])
        .arg("--root")
        .arg(&root_path)
        .arg("--policy")
        .arg(&legacy_policy_path)
        .arg("--expected-root-sha256")
        .arg(&root.root_statement_sha256)
        .arg("--expected-policy-sha256")
        .arg(&legacy_policy.policy_statement_sha256)
        .args([
            "--expected-previous-head-sequence",
            "0",
            "--reason",
            "cessation",
        ]);
    for authority in [&authority_one, &authority_two] {
        denied_command
            .arg("--authority-key")
            .arg(&authority.private)
            .arg("--authority-public-key")
            .arg(&authority.public);
    }
    denied_command.arg("--output").arg(&denied_path);
    let denied = run(&mut denied_command);
    assert!(!denied.status.success());
    assert!(
        String::from_utf8_lossy(&denied.stderr)
            .contains("does not explicitly authorize terminal persona revocation")
    );
    assert!(!denied_path.exists());
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

fn recovery_commit_command(
    store_path: &Path,
    persona_id: &str,
    proof_path: &Path,
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
    expected_previous_head_sequence: u32,
    expected_previous_head_sha256: Option<&str>,
) -> Command {
    let mut command = aquo();
    command
        .arg("--store")
        .arg(store_path)
        .args([
            "continuity",
            "recovery-transition-commit",
            "--persona-id",
            persona_id,
        ])
        .arg("--proof")
        .arg(proof_path)
        .arg("--expected-root-sha256")
        .arg(expected_root_sha256)
        .arg("--expected-policy-sha256")
        .arg(expected_policy_sha256)
        .arg("--expected-previous-head-sequence")
        .arg(expected_previous_head_sequence.to_string());
    if let Some(digest) = expected_previous_head_sha256 {
        command.arg("--expected-previous-head-sha256").arg(digest);
    }
    command
}

fn terminal_commit_command(
    store_path: &Path,
    persona_id: &str,
    proof_path: &Path,
    expected_root_sha256: &str,
    expected_policy_sha256: &str,
) -> Command {
    let mut command = aquo();
    command
        .arg("--store")
        .arg(store_path)
        .args([
            "continuity",
            "terminal-revocation-commit",
            "--persona-id",
            persona_id,
        ])
        .arg("--proof")
        .arg(proof_path)
        .arg("--expected-root-sha256")
        .arg(expected_root_sha256)
        .arg("--expected-policy-sha256")
        .arg(expected_policy_sha256)
        .args(["--expected-previous-head-sequence", "0", "--json"]);
    command
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
