use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use a_quo_ipc::{SealedArtifact, snapshot_stream};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::valid_sha256;

#[derive(Clone, Debug)]
pub(crate) struct ArMember<'a> {
    pub(crate) name: String,
    pub(crate) bytes: &'a [u8],
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_decimal(bytes: &[u8], label: &str) -> Result<u64> {
    let text = std::str::from_utf8(bytes).context("ar numeric field is not ASCII")?;
    let trimmed = text.trim_matches(' ');
    ensure!(
        !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid ar {label}"
    );
    trimmed
        .parse()
        .with_context(|| format!("invalid ar {label}"))
}

pub(crate) fn parse_deb(bytes: &[u8]) -> Result<Vec<ArMember<'_>>> {
    ensure!(bytes.starts_with(b"!<arch>\n"), "invalid Debian ar magic");
    let mut offset = 8_usize;
    let mut members = Vec::with_capacity(3);
    while offset < bytes.len() {
        ensure!(members.len() < 3, "Debian archive has too many members");
        let end = offset.checked_add(60).context("ar header overflow")?;
        ensure!(end <= bytes.len(), "truncated ar header");
        let header = &bytes[offset..end];
        ensure!(&header[58..60] == b"`\n", "invalid ar header trailer");
        let raw_name = std::str::from_utf8(&header[..16]).context("ar name is not ASCII")?;
        let name = raw_name
            .trim_matches(' ')
            .strip_suffix('/')
            .unwrap_or(raw_name.trim_matches(' '));
        ensure!(
            !name.is_empty()
                && name.len() <= 32
                && name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                }),
            "invalid ar member name"
        );
        let size = parse_decimal(&header[48..58], "member size")?;
        let size = usize::try_from(size).context("ar member size does not fit memory")?;
        offset = end;
        let member_end = offset.checked_add(size).context("ar member overflow")?;
        ensure!(member_end <= bytes.len(), "truncated ar member");
        members.push(ArMember {
            name: name.to_owned(),
            bytes: &bytes[offset..member_end],
        });
        offset = member_end;
        if size % 2 == 1 {
            ensure!(
                bytes.get(offset) == Some(&b'\n'),
                "invalid ar alignment byte"
            );
            offset += 1;
        }
    }
    ensure!(offset == bytes.len(), "Debian archive has trailing bytes");
    ensure!(
        members.len() == 3,
        "Debian archive is not exactly three members"
    );
    Ok(members)
}

pub(crate) fn decompress_zstd(bytes: &[u8], maximum: u64) -> Result<SealedArtifact> {
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(bytes))
        .context("cannot initialize zstd decoder")?;
    snapshot_stream(decoder, maximum).context("cannot snapshot bounded decompressed tar")
}

pub(crate) fn verify_receipt(bytes: &[u8], expected_size: u64) -> Result<()> {
    ensure!(
        bytes.len() as u64 == expected_size,
        "APT receipt has the wrong size"
    );
    verify_receipt_semantics(bytes)
}

pub(crate) fn verify_receipt_semantics(bytes: &[u8]) -> Result<()> {
    const REQUIRED: &[&str] = &[
        "format=a-quo-omarchy-ubuntu-apt-candidate-v1",
        "status=complete-candidate",
        "authority=none",
        "profile_id=a-quo-omarchy4-aarch64-dec29fa-v2",
        "profile_sha256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6",
        "snapshot_id=20260831T000000Z",
        "snapshot_selection_authority=caller-supplied-none",
        "original_archive=http://ports.ubuntu.com/ubuntu-ports/",
        "effective_snapshot_archive=https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/",
        "archive_equivalence_to_original_ports=not-established",
        "ubuntu_archive_signature_verification=performed-by-apt-not-independently-replayed",
        "object_count=122",
        "index_count=19",
        "package_count=93",
        "object_manifest_sha256=731cde75cece74a2b22cb22e24484951420b44321453fe1abd898b16744ebdaf",
        "apt_solver_execution=reported-by-acquirer-not-replayed",
        "apt_solver_reexecution=false",
        "transitive_closure_independently_recomputed=false",
        "package_installation=false",
        "dpkg_transaction=false",
        "maintainer_scripts_executed=false",
        "publisher_authentication=not-established",
        "trusted_time=not-established",
        "freshness=not-established",
        "safety=not-established",
        "build_authorization=not-established",
        "final_builder_image=not-established",
        "vm_started=false",
    ];
    ensure!(
        bytes.last() == Some(&b'\n'),
        "APT receipt lacks its final LF"
    );
    let text = std::str::from_utf8(bytes).context("APT receipt is not UTF-8")?;
    ensure!(
        text.lines().count() == 38,
        "APT receipt has the wrong line count"
    );
    for required in REQUIRED {
        ensure!(
            text.lines().any(|line| line == *required),
            "APT receipt lacks required conservative state: {required}"
        );
    }
    Ok(())
}

pub(crate) fn verify_manifest(
    bytes: &[u8],
    expected_size: u64,
    expected_records: &[&str],
) -> Result<()> {
    ensure!(
        bytes.len() as u64 == expected_size,
        "APT manifest has the wrong size"
    );
    verify_manifest_semantics(bytes, expected_records)
}

pub(crate) fn verify_manifest_semantics(bytes: &[u8], expected_records: &[&str]) -> Result<()> {
    ensure!(
        !expected_records.is_empty() && expected_records.len() <= 8,
        "APT manifest expectation count is outside the closed bound"
    );
    let expected = expected_records.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        expected.len() == expected_records.len(),
        "APT manifest expectations repeat a record"
    );
    ensure!(
        bytes.last() == Some(&b'\n'),
        "APT manifest lacks its final LF"
    );
    ensure!(
        bytes
            .iter()
            .all(|byte| *byte == b'\n' || (0x20..=0x7e).contains(byte)),
        "APT manifest contains a forbidden byte"
    );
    let text = std::str::from_utf8(bytes).context("APT manifest is not UTF-8")?;
    let mut lines = text.lines();
    ensure!(
        lines.next() == Some("format=a-quo-omarchy-ubuntu-apt-object-manifest-v1"),
        "APT manifest format is wrong"
    );
    let mut paths = BTreeSet::new();
    let mut records = 0_usize;
    let mut indexes = 0_usize;
    let mut packages = 0_usize;
    let mut targets = BTreeMap::<&str, usize>::new();
    for line in lines {
        let parts = line.split('|').collect::<Vec<_>>();
        ensure!(
            parts.len() == 4,
            "APT manifest record has the wrong field count"
        );
        ensure!(
            parts[2].parse::<u64>().is_ok_and(|size| size > 0),
            "APT manifest record has an invalid size"
        );
        ensure!(
            valid_sha256(parts[3]),
            "APT manifest record has an invalid SHA-256"
        );
        ensure!(
            paths.insert(parts[1]),
            "APT manifest repeats an object path"
        );
        records += 1;
        indexes += usize::from(parts[0] == "index");
        packages += usize::from(parts[0] == "package");
        if expected.contains(line) {
            *targets.entry(line).or_default() += 1;
        }
    }
    ensure!(records == 122, "APT manifest does not contain 122 objects");
    ensure!(indexes == 19, "APT manifest does not contain 19 indexes");
    ensure!(packages == 93, "APT manifest does not contain 93 packages");
    ensure!(
        expected
            .iter()
            .all(|record| targets.get(record).copied() == Some(1)),
        "APT manifest does not bind every exact package record once"
    );
    Ok(())
}

pub(crate) fn canonical_tar_path(path: &[u8]) -> bool {
    path.starts_with(b"./")
        && !path.contains(&0)
        && !path.windows(2).any(|window| window == b"//")
        && !path.windows(4).any(|window| window == b"/../")
        && !path.ends_with(b"/..")
        && path.len() <= 255
}
