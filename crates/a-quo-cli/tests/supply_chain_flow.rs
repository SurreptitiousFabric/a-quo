#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::tempdir;

const IDENTITY: &str = "w.vollprecht@gmail.com";
const ISSUER: &str = "https://github.com/login/oauth";

#[test]
fn cosign_v03_blob_verifies_and_tampering_fails_closed() {
    if !sandbox_available() {
        return;
    }
    let Some(fixture) = Fixture::published() else {
        return;
    };

    let verified = run(verification_command(&fixture, IDENTITY));
    assert!(
        verified.status.success(),
        "real Cosign fixture failed: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let report: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["outcome"], "verified");
    assert_eq!(report["evidence"]["artifact_binding"], "verified");
    assert_eq!(report["evidence"]["signature"], "verified");
    assert_eq!(report["evidence"]["certificate_chain_and_sct"], "verified");
    assert_eq!(report["evidence"]["transparency_log_inclusion"], "verified");
    assert_eq!(report["signer_policy"]["match_status"], "verified");
    assert_eq!(report["attestation"]["kind"], "blob_signature");
    assert_eq!(
        report["environment"]["network"],
        "blocked_by_linux_namespace"
    );
    assert_eq!(
        report["environment"]["trust_root_freshness"],
        "not_established"
    );

    let directory = tempdir().unwrap();
    let tampered_artifact = directory.path().join("tampered.txt");
    let mut bytes = fs::read(&fixture.artifact).unwrap();
    bytes[0] ^= 1;
    fs::write(&tampered_artifact, bytes).unwrap();
    let mut command = verification_command(&fixture, IDENTITY);
    replace_artifact(&mut command, &tampered_artifact);
    let tampered = run(command);
    assert!(!tampered.status.success());
    let tampered_report: Value = serde_json::from_slice(&tampered.stdout).unwrap();
    assert_eq!(tampered_report["outcome"], "invalid");
    assert_eq!(tampered_report["failure"], "sigstore_verification_failed");
    assert_eq!(
        tampered_report["evidence"]["artifact_binding"],
        "not_verified"
    );

    let tampered_bundle = directory.path().join("tampered.sigstore.json");
    let mut bundle_json: Value =
        serde_json::from_slice(&fs::read(&fixture.bundle).unwrap()).unwrap();
    let signature = bundle_json["messageSignature"]["signature"]
        .as_str()
        .unwrap();
    let replacement = if signature.starts_with('A') { "B" } else { "A" };
    let mut changed_signature = signature.to_owned();
    changed_signature.replace_range(..1, replacement);
    bundle_json["messageSignature"]["signature"] = Value::String(changed_signature);
    fs::write(&tampered_bundle, serde_json::to_vec(&bundle_json).unwrap()).unwrap();
    let mut command = verification_command(&fixture, IDENTITY);
    replace_bundle(&mut command, &tampered_bundle);
    let tampered = run(command);
    assert!(!tampered.status.success());
    let tampered_report: Value = serde_json::from_slice(&tampered.stdout).unwrap();
    assert_eq!(tampered_report["failure"], "sigstore_verification_failed");
    assert_eq!(tampered_report["evidence"]["signature"], "not_verified");
}

#[test]
fn exact_identity_and_standard_media_type_are_mandatory() {
    if !sandbox_available() {
        return;
    }
    let Some(fixture) = Fixture::published() else {
        return;
    };

    let mismatch = run(verification_command(&fixture, "other@example.test"));
    assert!(!mismatch.status.success());
    let mismatch_report: Value = serde_json::from_slice(&mismatch.stdout).unwrap();
    assert_eq!(mismatch_report["failure"], "signer_identity_mismatch");
    assert_eq!(mismatch_report["evidence"]["signature"], "verified");
    assert_eq!(
        mismatch_report["signer_policy"]["match_status"],
        "not_verified"
    );

    let directory = tempdir().unwrap();
    let legacy_bundle = directory.path().join("legacy.sigstore.json");
    let source = fs::read_to_string(&fixture.bundle).unwrap();
    let legacy = source.replace(
        "application/vnd.dev.sigstore.bundle.v0.3+json",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
    );
    assert_ne!(source, legacy);
    fs::write(&legacy_bundle, legacy).unwrap();
    let mut command = verification_command(&fixture, IDENTITY);
    replace_bundle(&mut command, &legacy_bundle);
    let rejected = run(command);
    assert!(!rejected.status.success());
    let rejected_report: Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(rejected_report["failure"], "unsupported_bundle_format");
    assert_eq!(rejected_report["evidence"]["signature"], "not_verified");
}

struct Fixture {
    artifact: PathBuf,
    bundle: PathBuf,
    trusted_root: PathBuf,
}

impl Fixture {
    fn published() -> Option<Self> {
        let verifier = published_crate_directory("sigstore-verify-0.11.0")?;
        let trust_root = published_crate_directory("sigstore-trust-root-0.11.0")?;
        Some(Self {
            artifact: verifier.join("test_data/bundles/cosign-v3-blob.txt"),
            bundle: verifier.join("test_data/bundles/cosign-v3-blob.sigstore.json"),
            trusted_root: trust_root.join("src/trusted_root.json"),
        })
        .filter(|fixture| {
            fixture.artifact.is_file() && fixture.bundle.is_file() && fixture.trusted_root.is_file()
        })
    }
}

fn published_crate_directory(crate_directory: &str) -> Option<PathBuf> {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))?;
    for registry in fs::read_dir(cargo_home.join("registry/src"))
        .ok()?
        .flatten()
    {
        let candidate = registry.path().join(crate_directory);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

fn verification_command(fixture: &Fixture, identity: &str) -> Command {
    let mut command = aquo();
    command
        .args(["supply-chain", "verify-bundle"])
        .arg(&fixture.artifact)
        .arg("--bundle")
        .arg(&fixture.bundle)
        .arg("--trusted-root")
        .arg(&fixture.trusted_root)
        .arg("--identity")
        .arg(identity)
        .arg("--issuer")
        .arg(ISSUER)
        .arg("--json");
    command
}

fn replace_artifact(command: &mut Command, replacement: &Path) {
    let arguments = command
        .get_args()
        .map(|arg| arg.to_os_string())
        .collect::<Vec<_>>();
    let mut rebuilt = aquo();
    rebuilt
        .args(&arguments[..2])
        .arg(replacement)
        .args(&arguments[3..]);
    *command = rebuilt;
}

fn replace_bundle(command: &mut Command, replacement: &Path) {
    let arguments = command
        .get_args()
        .map(|arg| arg.to_os_string())
        .collect::<Vec<_>>();
    let bundle_index = arguments
        .iter()
        .position(|argument| argument == "--bundle")
        .unwrap()
        + 1;
    let mut rebuilt = aquo();
    rebuilt.args(&arguments[..bundle_index]);
    rebuilt.arg(replacement);
    rebuilt.args(&arguments[bundle_index + 1..]);
    *command = rebuilt;
}

fn sandbox_available() -> bool {
    let output = match Command::new("/usr/bin/bwrap")
        .args([
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--",
            "/usr/bin/true",
        ])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(error) => panic!("Bubblewrap capability check failed: {error}"),
    };
    if output.status.success() {
        return true;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Operation not permitted")
        || stderr.contains("No permissions to create new namespace")
        || stderr.contains("Permission denied")
    {
        return false;
    }
    panic!("Bubblewrap capability check failed unexpectedly: {stderr}");
}

fn aquo() -> Command {
    Command::new(env!("CARGO_BIN_EXE_a-quo"))
}

fn run(mut command: Command) -> Output {
    command.output().expect("run A Quo CLI")
}
