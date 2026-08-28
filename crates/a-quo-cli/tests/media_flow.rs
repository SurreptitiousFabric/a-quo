#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use a_quo_c2pa::C2PA_SDK_VERSION;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn unsigned_media_is_unavailable_and_never_becomes_identity() {
    if !sandbox_available() {
        return;
    }

    let directory = tempdir().unwrap();
    let asset = directory.path().join("unsigned.jpg");
    fs::write(&asset, [0xff, 0xd8, 0xff, 0xd9]).unwrap();

    let output = run(aquo().args(["media", "verify"]).arg(&asset).arg("--json"));
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "unavailable");
    assert_eq!(report["artifact"]["size"], 4);
    assert_eq!(report["claim_signature"]["status"], "not_available");
    assert_eq!(report["cawg_identity"], "not_available");
    assert_eq!(report["a_quo_persona_link"], "not_established");
    assert_eq!(
        report["environment"]["network"],
        "blocked_by_linux_namespace"
    );
    assert_eq!(report["environment"]["certificate_trust"], "not_checked");
}

#[test]
fn signed_media_validates_and_content_tampering_fails_closed() {
    if !sandbox_available() {
        return;
    }
    let Some(fixture) = signed_sdk_fixture() else {
        return;
    };

    let valid = run(aquo().args(["media", "verify"]).arg(&fixture).arg("--json"));
    assert!(
        valid.status.success(),
        "signed fixture failed: {}",
        String::from_utf8_lossy(&valid.stderr)
    );
    let valid_report: Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(valid_report["outcome"], "valid");
    assert_eq!(
        valid_report["claim_signature"]["status"],
        "validated_as_part_of_manifest"
    );
    assert_eq!(valid_report["cawg_identity"], "present_unassessed");
    assert_eq!(valid_report["a_quo_persona_link"], "not_established");
    assert_eq!(
        valid_report["environment"]["certificate_trust"],
        "not_checked"
    );

    let directory = tempdir().unwrap();
    let tampered_path = directory.path().join("tampered.jpg");
    let mut tampered = fs::read(fixture).unwrap();
    tamper_jpeg_scan_data(&mut tampered);
    fs::write(&tampered_path, tampered).unwrap();

    let invalid = run(aquo()
        .args(["media", "verify"])
        .arg(&tampered_path)
        .arg("--json"));
    assert!(!invalid.status.success());
    let invalid_report: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(invalid_report["outcome"], "invalid");
    assert_eq!(
        invalid_report["claim_signature"]["status"],
        "present_but_manifest_invalid"
    );
    assert!(
        invalid_report["validation_failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure == "assertion.dataHash.mismatch"),
        "unexpected invalid report: {invalid_report}"
    );
}

fn tamper_jpeg_scan_data(bytes: &mut [u8]) {
    assert_eq!(&bytes[..2], [0xff, 0xd8]);
    let mut cursor = 2;
    let scan_data_start = loop {
        assert_eq!(bytes[cursor], 0xff, "fixture has a malformed JPEG marker");
        while bytes[cursor] == 0xff {
            cursor += 1;
        }
        let marker = bytes[cursor];
        cursor += 1;
        if marker == 0xda {
            let segment_length = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            break cursor + segment_length;
        }
        if marker == 0x01 || (0xd0..=0xd9).contains(&marker) {
            continue;
        }
        let segment_length = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += segment_length;
    };
    let end_marker = bytes
        .windows(2)
        .rposition(|window| window == [0xff, 0xd9])
        .expect("fixture has a JPEG end marker");
    let midpoint = scan_data_start + (end_marker - scan_data_start) / 2;
    let target = (midpoint..end_marker)
        .chain(scan_data_start..midpoint)
        .find(|&index| !matches!(bytes[index], 0x00 | 0xfe | 0xff))
        .expect("fixture has inert scan data to tamper");
    bytes[target] ^= 1;
}

fn signed_sdk_fixture() -> Option<PathBuf> {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))?;
    let registry_sources = cargo_home.join("registry/src");
    for registry in fs::read_dir(registry_sources).ok()?.flatten() {
        let candidate = registry
            .path()
            .join(format!("c2pa-{C2PA_SDK_VERSION}"))
            .join("src/identity/tests/fixtures/claim_aggregation/ica_validation/success.jpg");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
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

fn run(command: &mut Command) -> Output {
    command.output().expect("run A Quo CLI")
}
