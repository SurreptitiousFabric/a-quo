use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use a_quo_core::{
    RecoveryContinuityCheckpoint, RecoverySigner, RecoveryTransitionReason,
    create_initial_recovery_policy_proof, create_persona_root_proof,
    create_recovery_transition_proof, create_routine_transition_proof,
    new_initial_recovery_policy_statement, new_persona_root_statement,
    new_recovery_transition_statement, new_routine_transition_statement,
    verify_initial_recovery_policy_proof, verify_persona_root_proof,
    verify_recovery_transition_proof,
};
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

    let listed = run_success(aquo(&store).args(["persona", "list", "--json"]));
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed[0]["id"], persona_id);
    assert_eq!(listed[0]["lifecycle_status"], "active");
    assert_eq!(listed[0]["authority_disposition"], "not_checked");
    assert_eq!(listed[0]["quarantined"], false);
    let listed_text = run_success(aquo(&store).args(["persona", "list"]));
    let listed_text = String::from_utf8_lossy(&listed_text.stdout);
    assert!(listed_text.contains("authority=not-checked"));
    assert!(!listed_text.contains("authority=operational"));

    let enrolled = run_success(
        aquo(&store)
            .args(["persona", "key-add", "--persona-id", persona_id])
            .arg("--public-key")
            .arg(first_key.with_extension("pub"))
            .args(["--provider", "openssh-file", "--json"]),
    );
    let enrolled: Value = serde_json::from_slice(&enrolled.stdout).unwrap();
    let first_fingerprint = enrolled["fingerprint"].as_str().unwrap();
    let bound = run_success(
        aquo(&store)
            .args([
                "persona",
                "key-bind",
                "--fingerprint",
                first_fingerprint,
                "--signing-key",
            ])
            .arg(&first_key)
            .arg("--json"),
    );
    let bound: Value = serde_json::from_slice(&bound.stdout).unwrap();
    assert_eq!(bound["key_fingerprint"], first_fingerprint);
    assert_eq!(
        bound["locator"],
        first_key.canonicalize().unwrap().to_str().unwrap()
    );
    assert!(bound.get("private_key").is_none());

    let history = run_success(aquo(&store).args([
        "persona",
        "key-binding-history",
        "--fingerprint",
        first_fingerprint,
        "--json",
    ]));
    let history: Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(history[0]["event_type"], "bound");

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

    run_success(
        aquo(&store)
            .args([
                "persona",
                "key-bind",
                "--fingerprint",
                second_fingerprint,
                "--signing-key",
            ])
            .arg(&second_key),
    );

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

    run_success(aquo(&store).args(["persona", "key-unbind", "--fingerprint", second_fingerprint]));
    let binding_history = run_success(aquo(&store).args([
        "persona",
        "key-binding-history",
        "--fingerprint",
        second_fingerprint,
        "--json",
    ]));
    let binding_history: Value = serde_json::from_slice(&binding_history.stdout).unwrap();
    assert_eq!(binding_history[0]["event_type"], "bound");
    assert_eq!(binding_history[1]["event_type"], "unbound");

    let backup = directory.path().join("publisher.a-quo-persona-backup.json");
    run_success(
        aquo(&store)
            .args(["persona", "backup-export", "--persona-id", persona_id])
            .arg("--output")
            .arg(&backup),
    );
    let inspected = run_success(
        aquo(&store)
            .args(["persona", "backup-inspect"])
            .arg(&backup)
            .arg("--json"),
    );
    let inspected: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(
        inspected["status"],
        "internally_consistent_unsigned_metadata"
    );
    assert_eq!(inspected["persona"]["id"], persona_id);
    assert_eq!(inspected["public_key_count"], 2);
    assert_eq!(inspected["lifecycle_event_count"], 4);
    assert_eq!(inspected["signing_authority"], false);
    assert_eq!(inspected["cryptographic_continuity"], false);

    let legacy_backup = directory
        .path()
        .join("publisher.a-quo-persona-backup-v1.json");
    let mut legacy: Value = serde_json::from_slice(&fs::read(&backup).unwrap()).unwrap();
    legacy["schema"] = "urn:a-quo:persona-metadata-backup:v1".into();
    legacy.as_object_mut().unwrap().remove("continuity");
    fs::write(&legacy_backup, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
    let legacy_inspected = run_success(
        aquo(&store)
            .args(["persona", "backup-inspect"])
            .arg(&legacy_backup)
            .arg("--json"),
    );
    let legacy_inspected: Value = serde_json::from_slice(&legacy_inspected.stdout).unwrap();
    assert_eq!(
        legacy_inspected["status"],
        "internally_consistent_unsigned_metadata"
    );
    assert_eq!(legacy_inspected["cryptographic_continuity"], false);
    assert_eq!(legacy_inspected["root_signature"], "not_present");
    assert_eq!(legacy_inspected["persona_label_binding"], "not_present");
    assert_eq!(
        legacy_inspected["persona_metadata"]["label"],
        "unsigned_local_metadata"
    );
    assert_eq!(
        legacy_inspected["persona_metadata"]["lifecycle_timestamps"],
        "unsigned_local_metadata"
    );

    let legacy_inspected_text = run_success(
        aquo(&store)
            .args(["persona", "backup-inspect"])
            .arg(&legacy_backup),
    );
    assert!(
        String::from_utf8_lossy(&legacy_inspected_text.stdout)
            .contains("Persona label/UUID/purpose/lifecycle timestamps: unsigned_local_metadata")
    );

    let restored_store = directory.path().join("restored.sqlite3");
    let imported = run_success(
        aquo(&restored_store)
            .args(["persona", "backup-import"])
            .arg(&legacy_backup)
            .arg("--json"),
    );
    let imported: Value = serde_json::from_slice(&imported.stdout).unwrap();
    assert_eq!(imported["persona"]["id"], persona_id);
    assert_eq!(imported["signer_references_restored"], 0);
    assert_eq!(imported["signing_authority"], false);

    let restored_history = run_success(aquo(&restored_store).args([
        "persona",
        "history",
        "--persona-id",
        persona_id,
        "--json",
    ]));
    let restored_history: Value = serde_json::from_slice(&restored_history.stdout).unwrap();
    assert_eq!(restored_history.as_array().unwrap().len(), 4);
    let restored_binding_history = run_success(aquo(&restored_store).args([
        "persona",
        "key-binding-history",
        "--fingerprint",
        second_fingerprint,
        "--json",
    ]));
    let restored_binding_history: Value =
        serde_json::from_slice(&restored_binding_history.stdout).unwrap();
    assert!(restored_binding_history.as_array().unwrap().is_empty());

    let before_refused_overwrite = fs::read(&backup).unwrap();
    let refused_overwrite = run(aquo(&store)
        .args(["persona", "backup-export", "--persona-id", persona_id])
        .arg("--output")
        .arg(&backup));
    assert!(!refused_overwrite.status.success());
    assert_eq!(fs::read(&backup).unwrap(), before_refused_overwrite);

    #[cfg(unix)]
    for private_file in [&store, &restored_store, &backup] {
        assert_eq!(
            fs::metadata(private_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn archived_v1_persona_is_inspectable_but_cannot_sign() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source_store = directory.path().join("source.sqlite3");
    let archived_store = directory.path().join("archived.sqlite3");
    let archived_text_store = directory.path().join("archived-text.sqlite3");
    let key = directory.path().join("archived_key");
    let artifact = directory.path().join("archived-artifact.bin");
    let proof = directory.path().join("historical-proof.json");
    generate_key(&key);
    fs::write(&artifact, b"historical bytes from an archived persona").unwrap();

    let created = run_success(aquo(&source_store).args([
        "persona",
        "create",
        "--label",
        "Archived publisher",
        "--purpose",
        "project",
        "--json",
    ]));
    let created: Value = serde_json::from_slice(&created.stdout).unwrap();
    let persona_id = created["id"].as_str().unwrap();
    run_success(
        aquo(&source_store)
            .args(["persona", "key-add", "--persona-id", persona_id])
            .arg("--public-key")
            .arg(key.with_extension("pub"))
            .args(["--provider", "openssh-file"]),
    );
    run_success(&mut sign_command(
        &source_store,
        &artifact,
        &key,
        persona_id,
        &proof,
    ));

    let backup_path = directory.path().join("archived-v1.json");
    run_success(
        aquo(&source_store)
            .args(["persona", "backup-export", "--persona-id", persona_id])
            .arg("--output")
            .arg(&backup_path),
    );
    let mut backup: Value = serde_json::from_slice(&fs::read(&backup_path).unwrap()).unwrap();
    backup["schema"] = "urn:a-quo:persona-metadata-backup:v1".into();
    backup.as_object_mut().unwrap().remove("continuity");
    backup["persona"]["archived_at"] = backup["exported_at"].clone();
    fs::write(&backup_path, serde_json::to_vec_pretty(&backup).unwrap()).unwrap();
    let imported = run_success(
        aquo(&archived_store)
            .args(["persona", "backup-import"])
            .arg(&backup_path)
            .arg("--json"),
    );
    let imported: Value = serde_json::from_slice(&imported.stdout).unwrap();
    assert_eq!(imported["lifecycle_status"], "archived");
    assert_eq!(imported["authority_disposition"], "archived");
    assert_eq!(imported["quarantined"], false);

    let imported_text = run_success(
        aquo(&archived_text_store)
            .args(["persona", "backup-import"])
            .arg(&backup_path),
    );
    let imported_text = String::from_utf8_lossy(&imported_text.stdout);
    assert!(imported_text.contains("Disposition: archived/non-operational"));
    assert!(imported_text.contains("Historical verification remains inspectable"));
    assert!(!imported_text.contains("Bind an available signer"));

    let listed = run_success(aquo(&archived_store).args(["persona", "list", "--json"]));
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed[0]["lifecycle_status"], "archived");
    assert_eq!(listed[0]["authority_disposition"], "archived");
    assert_eq!(listed[0]["quarantined"], false);

    let verification = verify_json(&archived_store, &artifact, &proof);
    assert_eq!(verification["signature"], "verified");
    assert_eq!(verification["local_registry"]["status"], "archived");
    assert_eq!(
        verification["local_registry"]["disposition"],
        "archived_non_operational"
    );

    let refused_proof = directory.path().join("refused-archived-proof.json");
    let refused = run(&mut sign_command(
        &archived_store,
        &artifact,
        &key,
        persona_id,
        &refused_proof,
    ));
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("is archived"));
    assert!(!refused_proof.exists());
}

#[test]
fn recovery_archive_is_verified_imported_as_evidence_and_auto_exported() {
    let directory = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source_store = directory.path().join("source.sqlite3");
    let restored_store = directory.path().join("restored.sqlite3");
    let initial_key = directory.path().join("initial_key");
    let recovered_key = directory.path().join("recovered_key");
    let routine_key = directory.path().join("routine_key");
    let replacement_key = directory.path().join("replacement_key");
    let authority_one = directory.path().join("authority_one");
    let authority_two = directory.path().join("authority_two");
    for key in [
        &initial_key,
        &recovered_key,
        &routine_key,
        &replacement_key,
        &authority_one,
        &authority_two,
    ] {
        generate_key(key);
    }

    let created = run_success(aquo(&source_store).args([
        "persona",
        "create",
        "--label",
        "Recovery archive publisher",
        "--purpose",
        "project",
        "--json",
    ]));
    let created: Value = serde_json::from_slice(&created.stdout).unwrap();
    let persona_id = created["id"].as_str().unwrap();
    run_success(
        aquo(&source_store)
            .args(["persona", "key-add", "--persona-id", persona_id])
            .arg("--public-key")
            .arg(initial_key.with_extension("pub"))
            .args(["--provider", "openssh-file"]),
    );

    let initial_public = normalized_test_public_key(&initial_key);
    let recovered_public = normalized_test_public_key(&recovered_key);
    let routine_public = normalized_test_public_key(&routine_key);
    let authority_signers = [&authority_one, &authority_two]
        .into_iter()
        .map(|private_key_path| RecoverySigner {
            private_key_path: private_key_path.to_path_buf(),
            public_key: normalized_test_public_key(private_key_path),
        })
        .collect::<Vec<_>>();
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let root_statement =
        new_persona_root_statement("Recovery archive publisher", issued_at, &initial_public)
            .unwrap();
    let root_proof =
        create_persona_root_proof(root_statement, &initial_key, &initial_public).unwrap();
    let root = verify_persona_root_proof(&root_proof).unwrap();
    let policy_statement = new_initial_recovery_policy_statement(
        &root,
        &authority_signers
            .iter()
            .map(|signer| signer.public_key.clone())
            .collect::<Vec<_>>(),
        2,
        RecoveryContinuityCheckpoint {
            transition_sequence: 0,
            transition_sha256: None,
        },
        issued_at,
        issued_at + 86_400,
    )
    .unwrap();
    let policy_proof =
        create_initial_recovery_policy_proof(policy_statement, &authority_signers).unwrap();
    let policy = verify_initial_recovery_policy_proof(&root, &policy_proof).unwrap();
    let recovery_statement = new_recovery_transition_statement(
        &root,
        1,
        None,
        &root.statement.initial_key_fingerprint,
        &recovered_public,
        &policy,
        issued_at,
        RecoveryTransitionReason::Compromise,
    )
    .unwrap();
    let recovery_proof = create_recovery_transition_proof(
        recovery_statement,
        &policy,
        &authority_signers,
        &recovered_key,
        &recovered_public,
    )
    .unwrap();
    let recovery = verify_recovery_transition_proof(&root, &policy, &recovery_proof).unwrap();
    let routine_statement = new_routine_transition_statement(
        &root,
        2,
        Some(&recovery.transition_statement_sha256),
        &recovered_public,
        &routine_public,
        issued_at,
    )
    .unwrap();
    let routine_proof = create_routine_transition_proof(
        routine_statement,
        &recovered_key,
        &recovered_public,
        &routine_key,
        &routine_public,
    )
    .unwrap();

    let root_path = directory.path().join("root.json");
    let policy_path = directory.path().join("policy.json");
    let transition_path = directory.path().join("recovery-transition.json");
    let routine_transition_path = directory.path().join("routine-transition.json");
    fs::write(&root_path, serde_json::to_vec_pretty(&root_proof).unwrap()).unwrap();
    fs::write(
        &policy_path,
        serde_json::to_vec_pretty(&policy_proof).unwrap(),
    )
    .unwrap();
    fs::write(
        &transition_path,
        serde_json::to_vec_pretty(&recovery_proof).unwrap(),
    )
    .unwrap();
    fs::write(
        &routine_transition_path,
        serde_json::to_vec_pretty(&routine_proof).unwrap(),
    )
    .unwrap();

    run_success(
        aquo(&source_store)
            .args(["persona", "key-rotate", "--persona-id", persona_id])
            .arg("--public-key")
            .arg(recovered_key.with_extension("pub"))
            .args(["--provider", "openssh-file", "--reason", "compromise"]),
    );
    run_success(
        aquo(&source_store)
            .args(["persona", "key-rotate", "--persona-id", persona_id])
            .arg("--public-key")
            .arg(routine_key.with_extension("pub"))
            .args(["--provider", "openssh-file", "--reason", "routine"]),
    );

    let archive = directory.path().join("recovery-archive.json");
    let exported = run_success(
        aquo(&source_store)
            .args(["persona", "backup-export", "--persona-id", persona_id])
            .arg("--root")
            .arg(&root_path)
            .arg("--recovery-policy")
            .arg(&policy_path)
            .arg("--transition")
            .arg(&transition_path)
            .arg("--transition")
            .arg(&routine_transition_path)
            .arg("--output")
            .arg(&archive),
    );
    assert!(
        String::from_utf8_lossy(&exported.stdout).contains("continuity evidence"),
        "unexpected export output: {}",
        String::from_utf8_lossy(&exported.stdout)
    );
    let mut archive_value: Value = serde_json::from_slice(&fs::read(&archive).unwrap()).unwrap();
    assert_eq!(
        archive_value.pointer("/continuity/archive/root/observed_at"),
        Some(&Value::Null)
    );
    let archived_policies = archive_value
        .pointer("/continuity/archive/recovery_policies")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(archived_policies.len(), 1);
    assert_eq!(archived_policies[0]["observed_at"], Value::Null);
    let archived_transitions = archive_value
        .pointer("/continuity/archive/transitions")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(archived_transitions.len(), 2);
    assert_eq!(archived_transitions[0]["proof"]["kind"], "recovery");
    assert_eq!(archived_transitions[1]["proof"]["kind"], "routine");
    assert!(
        archived_transitions
            .iter()
            .all(|transition| transition["observed_at"] == Value::Null)
    );
    archive_value["persona"]["archived_at"] = archive_value["exported_at"].clone();
    fs::write(&archive, serde_json::to_vec_pretty(&archive_value).unwrap()).unwrap();

    let inspected = run_success(
        aquo(&source_store)
            .args(["persona", "backup-inspect"])
            .arg(&archive)
            .arg("--json"),
    );
    let inspected: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(inspected["metadata_consistency"], "verified");
    assert_eq!(inspected["root_signature"], "verified");
    assert_eq!(inspected["persona_label_binding"], "verified");
    assert_eq!(
        inspected["persona_metadata"]["id"],
        "unsigned_local_metadata"
    );
    assert_eq!(
        inspected["persona_metadata"]["purpose"],
        "unsigned_local_metadata"
    );
    assert_eq!(
        inspected["persona_metadata"]["lifecycle_timestamps"],
        "unsigned_local_metadata"
    );
    assert_eq!(inspected["transition_chain"], "verified");
    assert_eq!(inspected["recovery_policy_chain"], "verified");
    assert_eq!(inspected["policy_transition_checkpoints"], "verified");
    assert_eq!(inspected["external_root_pin"], "not_checked");
    assert_eq!(inspected["external_head_pin"], "not_checked");
    assert_eq!(inspected["external_latest_policy_pin"], "not_checked");
    assert_eq!(inspected["latest_policy_time_status"], "active");
    assert!(inspected["checked_at"].is_i64());
    assert_eq!(inspected["signing_authority"], false);
    assert_eq!(inspected["signer_references_restored"], 0);
    assert_eq!(
        inspected["current_authorization_or_non_revocation"],
        "not_established"
    );
    assert_eq!(inspected["recovery_transition_count"], 1);
    assert_eq!(inspected["routine_transition_count"], 1);
    assert_eq!(inspected["transition_count"], 2);
    assert!(inspected["not_established"].as_array().unwrap().iter().any(
        |value| value == "cryptographic_binding_of_persona_id_purpose_or_lifecycle_timestamps"
    ));

    let inspected_text = run_success(
        aquo(&source_store)
            .args(["persona", "backup-inspect"])
            .arg(&archive),
    );
    let inspected_text = String::from_utf8_lossy(&inspected_text.stdout);
    assert!(inspected_text.contains("Latest recovery-policy time status: active"));
    assert!(inspected_text.contains("Policy-time verifier checked_at (Unix):"));
    assert!(inspected_text.contains("External head-checkpoint pin: not_checked"));
    assert!(inspected_text.contains("Persona label binding: verified"));
    assert!(
        inspected_text
            .contains("Persona UUID/purpose/lifecycle timestamps: unsigned_local_metadata")
    );

    let unsigned_metadata_variant = directory.path().join("unsigned-metadata-variant.json");
    let mut unsigned_metadata = archive_value.clone();
    unsigned_metadata["persona"]["id"] = "8e7bbfb4-d776-4404-b514-4ea4ee3c92f4".into();
    unsigned_metadata["persona"]["purpose"] = "personal".into();
    fs::write(
        &unsigned_metadata_variant,
        serde_json::to_vec_pretty(&unsigned_metadata).unwrap(),
    )
    .unwrap();
    let unsigned_metadata = run_success(
        aquo(&source_store)
            .args(["persona", "backup-inspect"])
            .arg(&unsigned_metadata_variant)
            .arg("--json"),
    );
    let unsigned_metadata: Value = serde_json::from_slice(&unsigned_metadata.stdout).unwrap();
    assert_eq!(unsigned_metadata["root_signature"], "verified");
    assert_eq!(unsigned_metadata["persona_label_binding"], "verified");
    assert_eq!(
        unsigned_metadata["persona_metadata"]["id"],
        "unsigned_local_metadata"
    );
    assert_eq!(
        unsigned_metadata["persona_metadata"]["purpose"],
        "unsigned_local_metadata"
    );

    let imported = run_success(
        aquo(&restored_store)
            .args(["persona", "backup-import"])
            .arg(&archive)
            .arg("--json"),
    );
    let imported: Value = serde_json::from_slice(&imported.stdout).unwrap();
    assert_eq!(imported["persona"]["id"], persona_id);
    assert_eq!(imported["disposition"], "evidence_only_quarantined");
    assert_eq!(imported["signer_references_restored"], 0);
    assert_eq!(imported["signing_authority"], false);
    assert_eq!(imported["root_signature"], "verified");

    let listed = run_success(aquo(&restored_store).args(["persona", "list", "--json"]));
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed[0]["id"], persona_id);
    assert_eq!(listed[0]["lifecycle_status"], "archived");
    assert_eq!(listed[0]["authority_disposition"], "evidence_only");
    assert_eq!(listed[0]["quarantined"], true);

    let listed_text = run_success(aquo(&restored_store).args(["persona", "list"]));
    let listed_text = String::from_utf8_lossy(&listed_text.stdout);
    assert!(listed_text.contains("lifecycle=archived"));
    assert!(listed_text.contains("authority=evidence-only/quarantined"));
    assert!(!listed_text.contains("authority=archived/non-operational"));

    let chain_tip = inspected["chain_tip_key_fingerprint"].as_str().unwrap();
    let artifact = directory.path().join("evidence-artifact.bin");
    let source_proof = directory.path().join("source-proof.json");
    fs::write(&artifact, b"exact evidence-only authorization test bytes").unwrap();
    run_success(&mut sign_command(
        &source_store,
        &artifact,
        &routine_key,
        persona_id,
        &source_proof,
    ));

    let verification = verify_json(&restored_store, &artifact, &source_proof);
    assert_eq!(verification["signature"], "verified");
    assert_eq!(verification["local_registry"]["status"], "evidence_only");
    assert_eq!(
        verification["local_registry"]["disposition"],
        "evidence_only_quarantined"
    );
    assert_eq!(verification["local_registry"]["key_status"], "active");
    assert_eq!(
        verification["local_registry"]["persona"]["lifecycle_status"],
        "archived"
    );

    let verification_text = run_success(
        aquo(&restored_store)
            .arg("verify")
            .arg(&artifact)
            .arg("--proof")
            .arg(&source_proof),
    );
    let verification_text = String::from_utf8_lossy(&verification_text.stdout);
    assert!(verification_text.contains("evidence-only/quarantined key"));
    assert!(verification_text.contains("Persona lifecycle: archived"));
    assert!(!verification_text.contains("Local persona registry: active key"));

    let refused_direct_proof = directory.path().join("refused-direct-proof.json");
    assert_evidence_only_failure(run(&mut sign_command(
        &restored_store,
        &artifact,
        &routine_key,
        persona_id,
        &refused_direct_proof,
    )));
    assert!(!refused_direct_proof.exists());

    let refused_requested_proof = directory.path().join("refused-requested-proof.json");
    assert_evidence_only_failure(run(aquo(&restored_store)
        .arg("request-sign")
        .arg(&artifact)
        .arg("--persona-id")
        .arg(persona_id)
        .arg("--output")
        .arg(&refused_requested_proof)
        .arg("--socket")
        .arg(directory.path().join("unreachable-consent.sock"))));
    assert!(!refused_requested_proof.exists());

    let refused_domain_proof = directory.path().join("refused-domain-proof.json");
    assert_evidence_only_failure(run(aquo(&restored_store)
        .args([
            "domain",
            "request-proof",
            "evidence-only.example",
            "--persona-id",
            persona_id,
            "--output",
        ])
        .arg(&refused_domain_proof)
        .arg("--socket")
        .arg(directory.path().join("unreachable-domain-consent.sock"))));
    assert!(!refused_domain_proof.exists());

    assert_evidence_only_failure(run(aquo(&restored_store)
        .args(["persona", "key-bind", "--fingerprint", chain_tip])
        .arg("--signing-key")
        .arg(&routine_key)));
    assert_evidence_only_failure(run(aquo(&restored_store)
        .args(["persona", "key-add", "--persona-id", persona_id])
        .arg("--public-key")
        .arg(replacement_key.with_extension("pub"))
        .args(["--provider", "openssh-file"])));
    assert_evidence_only_failure(run(aquo(&restored_store)
        .args(["persona", "key-rotate", "--persona-id", persona_id])
        .arg("--public-key")
        .arg(replacement_key.with_extension("pub"))
        .args(["--provider", "openssh-file", "--reason", "routine"])));
    assert_evidence_only_failure(run(aquo(&restored_store).args([
        "persona",
        "key-compromise",
        "--fingerprint",
        chain_tip,
        "--actor",
        "test-operator",
        "--policy",
        "test-policy",
    ])));

    let requested_root = directory.path().join("restored-root.json");
    assert_evidence_only_failure(run(aquo(&restored_store)
        .args(["continuity", "root-request", "--persona-id", persona_id])
        .arg("--output")
        .arg(&requested_root)));
    assert!(!requested_root.exists());

    let requested_transition = directory.path().join("restored-transition.json");
    assert_evidence_only_failure(run(aquo(&restored_store)
        .args([
            "continuity",
            "transition-request",
            "--persona-id",
            persona_id,
            "--expected-root-sha256",
            root.root_statement_sha256.as_str(),
        ])
        .arg("--next-key")
        .arg(&replacement_key)
        .arg("--next-public-key")
        .arg(replacement_key.with_extension("pub"))
        .args(["--next-provider", "openssh-file"])
        .arg("--output")
        .arg(&requested_transition)));
    assert!(!requested_transition.exists());

    let binding_history = run_success(aquo(&restored_store).args([
        "persona",
        "key-binding-history",
        "--fingerprint",
        chain_tip,
        "--json",
    ]));
    let binding_history: Value = serde_json::from_slice(&binding_history.stdout).unwrap();
    assert_eq!(binding_history, serde_json::json!([]));

    let reexported = directory.path().join("reexported-archive.json");
    run_success(
        aquo(&restored_store)
            .args(["persona", "backup-export", "--persona-id", persona_id])
            .arg("--output")
            .arg(&reexported),
    );
    let reinspected = run_success(
        aquo(&restored_store)
            .args(["persona", "backup-inspect"])
            .arg(&reexported)
            .arg("--json"),
    );
    let reinspected: Value = serde_json::from_slice(&reinspected.stdout).unwrap();
    assert_eq!(
        reinspected["root_statement_sha256"],
        root.root_statement_sha256
    );
    assert_eq!(reinspected["transition_count"], 2);
    assert_eq!(reinspected["routine_transition_count"], 1);
    assert_eq!(reinspected["recovery_transition_count"], 1);

    let reexported: Value = serde_json::from_slice(&fs::read(&reexported).unwrap()).unwrap();
    assert!(reexported["keys"].as_array().unwrap().iter().any(|key| {
        key["fingerprint"] == root.statement.initial_key_fingerprint
            && key["status"] == "compromised"
    }));
    assert!(
        reexported["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| {
                event["key_fingerprint"] == root.statement.initial_key_fingerprint
                    && event["event_type"] == "compromised"
                    && event["actor"] == "local-user"
                    && event["policy"] == "a-quo:key-rotation:compromise:v1"
            })
    );

    let tampered_path = directory.path().join("tampered-archive.json");
    let mut tampered: Value = serde_json::from_slice(&fs::read(&archive).unwrap()).unwrap();
    let Some(Value::String(payload)) =
        tampered.pointer_mut("/continuity/archive/root/proof/payload")
    else {
        panic!("v2 evidence archive root payload");
    };
    payload.replace_range(..1, if payload.starts_with('A') { "B" } else { "A" });
    fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let rejected = run(aquo(&source_store)
        .args(["persona", "backup-inspect"])
        .arg(&tampered_path)
        .arg("--json"));
    assert!(!rejected.status.success());

    let tampered_store = directory.path().join("tampered.sqlite3");
    let rejected = run(aquo(&tampered_store)
        .args(["persona", "backup-import"])
        .arg(&tampered_path)
        .arg("--json"));
    assert!(!rejected.status.success());
    assert!(
        !tampered_store.exists(),
        "cryptographic rejection must happen before the destination store is opened"
    );

    let populated_before = fs::read(&source_store).unwrap();
    let rejected = run(aquo(&source_store)
        .args(["persona", "backup-import"])
        .arg(&tampered_path)
        .arg("--json"));
    assert!(!rejected.status.success());
    assert_eq!(
        fs::read(&source_store).unwrap(),
        populated_before,
        "cryptographic rejection must not alter an existing destination store"
    );
}

#[test]
fn backup_export_rejects_oversized_evidence_lists_before_file_io() {
    let directory = tempdir().unwrap();
    let store = directory.path().join("personas.sqlite3");
    let missing_root = directory.path().join("missing-root.json");
    let missing_evidence = directory.path().join("missing-evidence.json");

    for (flag, expected) in [
        (
            "--recovery-policy",
            "continuity archive cannot contain more than 256 recovery policies",
        ),
        (
            "--transition",
            "continuity archive cannot contain more than 256 transitions",
        ),
    ] {
        let mut command = aquo(&store);
        command
            .args([
                "persona",
                "backup-export",
                "--persona-id",
                "02cc60fd-a039-4af7-bb51-e96f0591f910",
            ])
            .arg("--root")
            .arg(&missing_root);
        for _ in 0..257 {
            command.arg(flag).arg(&missing_evidence);
        }
        command
            .arg("--output")
            .arg(directory.path().join(format!("oversized-{flag}.json")));

        let rejected = run(&mut command);
        assert!(!rejected.status.success());
        let stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            stderr.contains(expected),
            "unexpected oversized-list error:\n{stderr}"
        );
        assert!(
            !stderr.contains("missing-root.json") && !stderr.contains("missing-evidence.json"),
            "file I/O happened before the count bound:\n{stderr}"
        );
    }
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

fn normalized_test_public_key(private_key_path: &Path) -> String {
    let public_key = fs::read_to_string(private_key_path.with_extension("pub")).unwrap();
    let mut fields = public_key.split_whitespace();
    format!(
        "{} {}",
        fields.next().expect("public-key algorithm"),
        fields.next().expect("public-key data")
    )
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

fn assert_evidence_only_failure(output: Output) {
    assert!(
        !output.status.success(),
        "evidence-only mutation unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("imported continuity evidence"),
        "unexpected evidence-only failure:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
