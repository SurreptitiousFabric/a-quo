use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output};

use a_quo_core::{
    MAX_PERSONA_ROOT_CARD_BYTES, PERSONA_ROOT_LATE_FIRST_CONTACT_WARNING_SECONDS,
    PERSONA_ROOT_PIN_REVIEW_WARNING_SECONDS, PersonaRootTrustBasis,
    canonical_persona_root_card_bytes, parse_persona_root_card_bytes, parse_persona_root_pin_bytes,
};
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn cli_exports_and_compares_portable_root_evidence_without_authority() {
    let directory = tempdir().unwrap();
    secure_directory(directory.path());
    let store = directory.path().join("must-not-be-created.sqlite3");
    let key = directory.path().join("publisher-key");
    let root = directory.path().join("root.json");
    let card_json = directory.path().join("root-card.json");
    let card_json_copy = directory.path().join("root-card-copy.json");
    let card_text = directory.path().join("root-card.txt");
    let card_html = directory.path().join("root-card.html");
    let tofu_pin = directory.path().join("tofu-pin.json");
    let same_channel_pin = directory.path().join("same-channel-pin.json");
    let out_of_band_pin = directory.path().join("out-of-band-pin.json");

    generate_key(&key);
    create_root(&store, &key, &root, "JuniperQuill");
    export_card(&store, &root, "json", &card_json);
    export_card(&store, &root, "json", &card_json_copy);
    export_card(&store, &root, "text", &card_text);
    export_card(&store, &root, "html", &card_html);

    let card_bytes = fs::read(&card_json).unwrap();
    let card = parse_persona_root_card_bytes(&card_bytes).unwrap();
    assert_eq!(
        card_bytes,
        canonical_persona_root_card_bytes(&card).unwrap()
    );
    assert_eq!(fs::read(&card_json_copy).unwrap(), card_bytes);
    assert_eq!(card.persona, "JuniperQuill");
    assert_eq!(card.root_statement_sha256.len(), 64);
    assert_eq!(
        card.pin_uri,
        format!("aquo:persona-root-pin:v1:{}", card.root_statement_sha256)
    );

    let text = fs::read_to_string(&card_text).unwrap();
    assert!(text.contains("SELF-ASSERTED"));
    assert!(text.contains(&card.root_statement_sha256));
    assert!(text.contains(&card.pin_uri));
    assert!(text.contains("not authentication"));

    let html = fs::read_to_string(&card_html).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("<svg"));
    assert!(html.contains("<bdi dir=\"auto\">JuniperQuill</bdi>"));
    assert!(html.contains(&card.root_statement_sha256));
    assert!(html.contains(&card.pin_uri));
    assert!(!html.contains("<script"));
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
    assert!(!html.contains("OPENSSH PRIVATE KEY"));
    assert!(!text.contains("OPENSSH PRIVATE KEY"));
    assert!(!String::from_utf8_lossy(&card_bytes).contains("OPENSSH PRIVATE KEY"));

    let first_observation = card.issued_at + 1;
    let preview = run(aquo(&store)
        .args(["continuity", "root-pin-create", "--from-root"])
        .arg(&root)
        .args([
            "--basis",
            "trust-on-first-use",
            "--channel",
            "file",
            "--at-unix",
        ])
        .arg(first_observation.to_string())
        .arg("--output")
        .arg(&tofu_pin));
    assert!(!preview.status.success());
    assert!(!tofu_pin.exists());
    let preview_stdout = String::from_utf8_lossy(&preview.stdout);
    assert!(preview_stdout.contains("NOTHING WRITTEN YET"));
    assert!(preview_stdout.contains("Identity basis: self-asserted"));
    assert!(preview_stdout.contains("Persona: JuniperQuill"));
    assert!(preview_stdout.contains(&card.initial_key_fingerprint));
    assert!(preview_stdout.contains(&card.issued_at.to_string()));
    assert!(preview_stdout.contains(&card.root_statement_sha256));
    assert!(preview_stdout.contains("Root signature: verified"));
    assert!(preview_stdout.contains("Channel independence: not established"));
    assert!(preview_stdout.contains("Existing pin at requested output: none"));
    assert!(preview_stdout.contains("Trusted time: not established"));
    assert!(preview_stdout.contains("Current continuity history: not established"));
    assert!(preview_stdout.contains("Current signing authority: not established"));
    assert!(preview_stdout.contains("Current recovery authority: not established"));
    assert!(preview_stdout.contains("Legal identity: not established"));
    assert!(preview_stdout.contains("Artifact truth or safety: not established"));
    assert!(preview_stdout.contains("has not been independently authenticated"));
    assert!(String::from_utf8_lossy(&preview.stderr).contains("no pin was written"));

    let wrong_acceptance = run(aquo(&store)
        .args(["continuity", "root-pin-create", "--from-root"])
        .arg(&root)
        .args([
            "--basis",
            "trust-on-first-use",
            "--channel",
            "file",
            "--accept-root-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--output",
        ])
        .arg(&tofu_pin));
    assert!(!wrong_acceptance.status.success());
    assert!(!tofu_pin.exists());

    run_success(
        aquo(&store)
            .args(["continuity", "root-pin-create", "--from-root"])
            .arg(&root)
            .arg("--accept-root-sha256")
            .arg(&card.root_statement_sha256)
            .args([
                "--basis",
                "trust-on-first-use",
                "--channel",
                "file",
                "--at-unix",
            ])
            .arg(first_observation.to_string())
            .arg("--output")
            .arg(&tofu_pin),
    );
    let parsed_tofu = parse_persona_root_pin_bytes(&fs::read(&tofu_pin).unwrap()).unwrap();
    assert_eq!(
        parsed_tofu.trust_basis,
        PersonaRootTrustBasis::TrustOnFirstUse
    );
    assert_eq!(
        parsed_tofu.root_statement_sha256,
        card.root_statement_sha256
    );

    let tofu = run_success(
        aquo(&store)
            .args(["continuity", "root-pin-compare", "--root"])
            .arg(&root)
            .arg("--pin")
            .arg(&tofu_pin)
            .arg("--card")
            .arg(&card_json)
            .arg("--at-unix")
            .arg((first_observation + 1).to_string())
            .arg("--json"),
    );
    let tofu: Value = serde_json::from_slice(&tofu.stdout).unwrap();
    assert_eq!(tofu["root_signature"], "verified");
    assert_eq!(tofu["pin_match"], "matched");
    assert_eq!(tofu["card_match"], "matched");
    assert_eq!(tofu["trust_basis"], "trust_on_first_use");
    assert_eq!(tofu["channel_independence"], "not_established");
    assert_eq!(tofu["current_history_freshness"], "not_established");
    assert_eq!(tofu["legal_identity"], "not_established");
    assert_eq!(tofu["current_signing_authority"], "not_established");
    assert_eq!(tofu["current_recovery_authority"], "not_established");
    assert_eq!(tofu["artifact_truth_or_safety"], "not_established");
    assert_eq!(tofu["root_card_possession_grants_authority"], false);

    let inspected = run_success(
        aquo(&store)
            .args(["continuity", "root-pin-inspect"])
            .arg(&tofu_pin)
            .arg("--json"),
    );
    let inspected: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(inspected["pin_record"], "valid_unsigned_user_metadata");
    assert_eq!(inspected["root_signature"], "not_checked");
    assert_eq!(inspected["current_signing_authority"], "not_established");
    assert_eq!(inspected["current_recovery_authority"], "not_established");
    assert_eq!(inspected["artifact_truth_or_safety"], "not_established");
    assert_eq!(inspected["root_card_possession_grants_authority"], false);

    run_success(
        aquo(&store)
            .args(["continuity", "root-pin-create", "--from-root"])
            .arg(&root)
            .arg("--accept-root-sha256")
            .arg(&card.root_statement_sha256)
            .args([
                "--basis",
                "same-channel-copy",
                "--channel",
                "file",
                "--at-unix",
            ])
            .arg((first_observation + 2).to_string())
            .arg("--output")
            .arg(&same_channel_pin),
    );
    let same_channel = run_success(
        aquo(&store)
            .args(["continuity", "root-pin-compare", "--root"])
            .arg(&root)
            .arg("--pin")
            .arg(&same_channel_pin)
            .arg("--at-unix")
            .arg((first_observation + 3).to_string()),
    );
    assert!(
        String::from_utf8_lossy(&same_channel.stdout)
            .contains("consistency check, not independent pinning")
    );

    run_success(
        aquo(&store)
            .args([
                "continuity",
                "root-pin-create",
                "--pin-uri",
                &card.pin_uri,
                "--basis",
                "out-of-band-user-confirmed",
                "--channel",
                "qr",
                "--at-unix",
            ])
            .arg((first_observation + 4).to_string())
            .arg("--output")
            .arg(&out_of_band_pin),
    );
    let out_of_band = run_success(
        aquo(&store)
            .args(["continuity", "root-pin-compare", "--root"])
            .arg(&root)
            .arg("--pin")
            .arg(&out_of_band_pin)
            .arg("--at-unix")
            .arg((first_observation + 5).to_string())
            .arg("--json"),
    );
    let out_of_band: Value = serde_json::from_slice(&out_of_band.stdout).unwrap();
    assert_eq!(out_of_band["card_match"], "not_checked");
    assert_eq!(out_of_band["trust_basis"], "out_of_band_user_confirmed");
    assert_eq!(
        out_of_band["channel_independence"],
        "user_reported_separate"
    );
    assert_eq!(
        out_of_band["provenance_assurance"],
        "user_recorded_not_cryptographically_verified"
    );

    let laundered = run(aquo(&store)
        .args(["continuity", "root-pin-create", "--from-root"])
        .arg(&root)
        .args([
            "--basis",
            "out-of-band-user-confirmed",
            "--channel",
            "file",
            "--output",
        ])
        .arg(directory.path().join("must-not-exist.json")));
    assert!(!laundered.status.success());
    assert!(
        String::from_utf8_lossy(&laundered.stderr).contains("cannot create an out-of-band pin")
    );

    let uri_as_tofu = run(aquo(&store)
        .args([
            "continuity",
            "root-pin-create",
            "--pin-uri",
            &card.pin_uri,
            "--basis",
            "trust-on-first-use",
            "--channel",
            "qr",
            "--output",
        ])
        .arg(directory.path().join("must-also-not-exist.json")));
    assert!(!uri_as_tofu.status.success());
    assert!(String::from_utf8_lossy(&uri_as_tofu.stderr).contains("reserved for --basis"));

    let uri_with_from_root_acceptance = run(aquo(&store)
        .args([
            "continuity",
            "root-pin-create",
            "--pin-uri",
            &card.pin_uri,
            "--basis",
            "out-of-band-user-confirmed",
            "--channel",
            "qr",
            "--accept-root-sha256",
            &card.root_statement_sha256,
            "--output",
        ])
        .arg(directory.path().join("must-not-mix-sources.json")));
    assert!(!uri_with_from_root_acceptance.status.success());
    assert!(
        String::from_utf8_lossy(&uri_with_from_root_acceptance.stderr)
            .contains("only valid with --from-root")
    );

    let card_before = fs::read(&card_json).unwrap();
    let refused_card_overwrite = run(aquo(&store)
        .args(["continuity", "root-card-export", "--root"])
        .arg(&root)
        .args(["--format", "json", "--output"])
        .arg(&card_json));
    assert!(!refused_card_overwrite.status.success());
    assert_eq!(fs::read(&card_json).unwrap(), card_before);

    let pin_before = fs::read(&tofu_pin).unwrap();
    let refused_pin_overwrite = run(aquo(&store)
        .args(["continuity", "root-pin-create", "--from-root"])
        .arg(&root)
        .arg("--accept-root-sha256")
        .arg(&card.root_statement_sha256)
        .args([
            "--basis",
            "trust-on-first-use",
            "--channel",
            "file",
            "--output",
        ])
        .arg(&tofu_pin));
    assert!(!refused_pin_overwrite.status.success());
    assert_eq!(fs::read(&tofu_pin).unwrap(), pin_before);

    assert!(
        !store.exists(),
        "root distribution must not create persona authority state"
    );
    #[cfg(unix)]
    for output in [
        &card_json,
        &card_text,
        &card_html,
        &tofu_pin,
        &same_channel_pin,
        &out_of_band_pin,
    ] {
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn cli_rejects_substitution_hostile_material_and_misleading_time_claims() {
    let directory = tempdir().unwrap();
    secure_directory(directory.path());
    let store = directory.path().join("must-not-be-created.sqlite3");
    let first_key = directory.path().join("first-key");
    let second_key = directory.path().join("second-key");
    let first_root = directory.path().join("first-root.json");
    let second_root = directory.path().join("second-root.json");
    let first_card_path = directory.path().join("first-card.json");
    let second_card_path = directory.path().join("second-card.json");
    let pin_path = directory.path().join("first-pin.json");

    generate_key(&first_key);
    generate_key(&second_key);
    create_root(&store, &first_key, &first_root, "JuniperQuill");
    create_root(&store, &second_key, &second_root, "JuniperQuill");
    export_card(&store, &first_root, "json", &first_card_path);
    export_card(&store, &second_root, "json", &second_card_path);
    let first_card = parse_persona_root_card_bytes(&fs::read(&first_card_path).unwrap()).unwrap();

    run_success(
        aquo(&store)
            .args(["continuity", "root-pin-create", "--from-root"])
            .arg(&first_root)
            .arg("--accept-root-sha256")
            .arg(&first_card.root_statement_sha256)
            .args([
                "--basis",
                "trust-on-first-use",
                "--channel",
                "file",
                "--at-unix",
            ])
            .arg((first_card.issued_at + 1).to_string())
            .arg("--output")
            .arg(&pin_path),
    );

    let substituted = run(aquo(&store)
        .args(["continuity", "root-pin-compare", "--root"])
        .arg(&second_root)
        .arg("--pin")
        .arg(&pin_path)
        .arg("--at-unix")
        .arg((first_card.issued_at + 2).to_string())
        .arg("--json"));
    assert!(!substituted.status.success());
    let substituted_report: Value = serde_json::from_slice(&substituted.stdout).unwrap();
    assert_eq!(substituted_report["root_signature"], "verified");
    assert_eq!(substituted_report["pin_match"], "mismatched");
    assert_eq!(
        substituted_report["current_signing_authority"],
        "not_established"
    );
    assert_eq!(
        substituted_report["current_recovery_authority"],
        "not_established"
    );
    assert_eq!(
        substituted_report["artifact_truth_or_safety"],
        "not_established"
    );
    assert_eq!(
        substituted_report["root_card_possession_grants_authority"],
        false
    );
    assert!(String::from_utf8_lossy(&substituted.stderr).contains("pin conflicts"));

    let substituted_human = run(aquo(&store)
        .args(["continuity", "root-pin-compare", "--root"])
        .arg(&second_root)
        .arg("--pin")
        .arg(&pin_path)
        .arg("--at-unix")
        .arg((first_card.issued_at + 2).to_string()));
    assert!(!substituted_human.status.success());
    let substituted_human = String::from_utf8_lossy(&substituted_human.stdout);
    assert!(
        substituted_human.contains(
            substituted_report["candidate_root_statement_sha256"]
                .as_str()
                .unwrap()
        )
    );
    assert!(substituted_human.contains(&first_card.root_statement_sha256));

    let wrong_card = run(aquo(&store)
        .args(["continuity", "root-pin-compare", "--root"])
        .arg(&first_root)
        .arg("--pin")
        .arg(&pin_path)
        .arg("--card")
        .arg(&second_card_path)
        .arg("--at-unix")
        .arg((first_card.issued_at + 2).to_string())
        .arg("--json"));
    assert!(!wrong_card.status.success());
    let wrong_card_report: Value = serde_json::from_slice(&wrong_card.stdout).unwrap();
    assert_eq!(wrong_card_report["pin_match"], "matched");
    assert_eq!(wrong_card_report["card_match"], "mismatched");

    let wrong_card_human = run(aquo(&store)
        .args(["continuity", "root-pin-compare", "--root"])
        .arg(&first_root)
        .arg("--pin")
        .arg(&pin_path)
        .arg("--card")
        .arg(&second_card_path)
        .arg("--at-unix")
        .arg((first_card.issued_at + 2).to_string()));
    assert!(!wrong_card_human.status.success());
    let wrong_card_human = String::from_utf8_lossy(&wrong_card_human.stdout);
    assert!(
        wrong_card_human.contains(wrong_card_report["candidate_card_sha256"].as_str().unwrap())
    );
    assert!(wrong_card_human.contains(wrong_card_report["supplied_card_sha256"].as_str().unwrap()));
    assert!(String::from_utf8_lossy(&wrong_card.stderr).contains("card conflicts"));

    let mut hostile_card: Value =
        serde_json::from_slice(&fs::read(&first_card_path).unwrap()).unwrap();
    hostile_card
        .as_object_mut()
        .unwrap()
        .insert("private_key".to_owned(), json!("attacker-controlled"));
    let hostile_card_path = directory.path().join("hostile-card.json");
    fs::write(
        &hostile_card_path,
        serde_json::to_vec(&hostile_card).unwrap(),
    )
    .unwrap();
    let hostile = run(aquo(&store)
        .args(["continuity", "root-pin-compare", "--root"])
        .arg(&first_root)
        .arg("--pin")
        .arg(&pin_path)
        .arg("--card")
        .arg(&hostile_card_path));
    assert!(!hostile.status.success());
    assert!(String::from_utf8_lossy(&hostile.stderr).contains("invalid persona root card"));

    let oversized = directory.path().join("oversized-card.json");
    fs::write(&oversized, vec![b' '; MAX_PERSONA_ROOT_CARD_BYTES + 1]).unwrap();
    let oversized_result = run(aquo(&store)
        .args(["continuity", "root-pin-compare", "--root"])
        .arg(&first_root)
        .arg("--pin")
        .arg(&pin_path)
        .arg("--card")
        .arg(&oversized));
    assert!(!oversized_result.status.success());
    assert!(String::from_utf8_lossy(&oversized_result.stderr).contains("exceeds"));

    for malformed_uri in [
        first_card.pin_uri.to_uppercase(),
        format!("{}?replace=true", first_card.pin_uri),
        first_card.pin_uri[..first_card.pin_uri.len() - 1].to_owned(),
    ] {
        let malformed_output = directory
            .path()
            .join(format!("malformed-{}.json", malformed_uri.len()));
        let rejected = run(aquo(&store)
            .args([
                "continuity",
                "root-pin-create",
                "--pin-uri",
                &malformed_uri,
                "--basis",
                "out-of-band-user-confirmed",
                "--channel",
                "qr",
                "--output",
            ])
            .arg(&malformed_output));
        assert!(!rejected.status.success());
        assert!(!malformed_output.exists());
    }

    let late_pin = directory.path().join("late-pin.json");
    let late_at = first_card.issued_at
        + i64::try_from(PERSONA_ROOT_LATE_FIRST_CONTACT_WARNING_SECONDS).unwrap()
        + 1;
    create_uri_pin(&store, &first_card.pin_uri, late_at, &late_pin);
    let late = run_success(
        aquo(&store)
            .args(["continuity", "root-pin-compare", "--root"])
            .arg(&first_root)
            .arg("--pin")
            .arg(&late_pin)
            .arg("--at-unix")
            .arg(late_at.to_string()),
    );
    assert!(String::from_utf8_lossy(&late.stdout).contains("more than 30 days"));

    let old_pin = directory.path().join("old-pin.json");
    create_uri_pin(
        &store,
        &first_card.pin_uri,
        first_card.issued_at + 1,
        &old_pin,
    );
    let review_at = first_card.issued_at
        + 1
        + i64::try_from(PERSONA_ROOT_PIN_REVIEW_WARNING_SECONDS).unwrap()
        + 1;
    let old = run_success(
        aquo(&store)
            .args(["continuity", "root-pin-compare", "--root"])
            .arg(&first_root)
            .arg("--pin")
            .arg(&old_pin)
            .arg("--at-unix")
            .arg(review_at.to_string()),
    );
    assert!(String::from_utf8_lossy(&old.stdout).contains("more than one year old"));

    let clock_order_pin = directory.path().join("clock-order-pin.json");
    create_uri_pin(
        &store,
        &first_card.pin_uri,
        first_card.issued_at.saturating_sub(1),
        &clock_order_pin,
    );
    let clock_order = run_success(
        aquo(&store)
            .args(["continuity", "root-pin-compare", "--root"])
            .arg(&first_root)
            .arg("--pin")
            .arg(&clock_order_pin)
            .arg("--at-unix")
            .arg((first_card.issued_at + 1).to_string()),
    );
    assert!(
        String::from_utf8_lossy(&clock_order.stdout)
            .contains("self-signed issuance time is later than the local observation")
    );

    #[cfg(unix)]
    {
        let symlink_card = directory.path().join("symlink-card.json");
        symlink(&first_card_path, &symlink_card).unwrap();
        let symlink_result = run(aquo(&store)
            .args(["continuity", "root-pin-compare", "--root"])
            .arg(&first_root)
            .arg("--pin")
            .arg(&pin_path)
            .arg("--card")
            .arg(&symlink_card));
        assert!(!symlink_result.status.success());
    }

    assert!(
        !store.exists(),
        "failed comparisons must not create authority state"
    );
}

fn create_root(store: &Path, key: &Path, root: &Path, persona: &str) {
    run_success(
        aquo(store)
            .args(["continuity", "root-create", "--persona", persona, "--key"])
            .arg(key)
            .arg("--public-key")
            .arg(key.with_extension("pub"))
            .arg("--output")
            .arg(root),
    );
}

fn export_card(store: &Path, root: &Path, format: &str, output: &Path) {
    run_success(
        aquo(store)
            .args(["continuity", "root-card-export", "--root"])
            .arg(root)
            .args(["--format", format, "--output"])
            .arg(output),
    );
}

fn create_uri_pin(store: &Path, uri: &str, recorded_at: i64, output: &Path) {
    run_success(
        aquo(store)
            .args([
                "continuity",
                "root-pin-create",
                "--pin-uri",
                uri,
                "--basis",
                "out-of-band-user-confirmed",
                "--channel",
                "qr",
                "--at-unix",
            ])
            .arg(recorded_at.to_string())
            .arg("--output")
            .arg(output),
    );
}

fn aquo(store: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_a-quo"));
    command.arg("--store").arg(store);
    command
}

fn generate_key(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("OpenSSH ssh-keygen must be installed for the integration test");
    assert!(status.success());
}

fn secure_directory(path: &Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
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
