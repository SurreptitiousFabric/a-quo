#![forbid(unsafe_code)]

pub mod aavmf;
pub mod alarm_rootfs;
pub mod apt;
#[cfg(target_os = "linux")]
mod debian;
#[cfg(target_os = "linux")]
pub mod gpgv_isolation;
pub mod gpgv_runtime;
mod model;
pub mod qemu;
#[cfg(target_os = "linux")]
mod snapshot;

use model::{
    ExecutionState, ExpectedObjectSpec, LockAuthority, LockRecord, NonClaimState, ReportField,
    TargetBinding, VerificationMode, parse_lock_fields, parse_object_specs,
};
pub use model::{ExternalLockExpectation, ObjectSpec, VerificationReport};

use std::collections::BTreeMap;
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};

pub const MAX_LOCK_BYTES: u64 = 64 * 1024;
pub const MAX_PROFILE_BYTES: u64 = 64 * 1024;
pub const MAX_JSON_BYTES: u64 = 1024 * 1024;
pub const MAX_COMPRESSED_LAYER_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_UNCOMPRESSED_LAYER_BYTES: u64 = 512 * 1024 * 1024;
const CANONICAL_V2_PROFILE: &str =
    include_str!("../../../packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile");

const OCI_LOCK_KEYS: &[&str] = &[
    "review_context_receipt_format",
    "review_context_receipt_sha256",
    "review_context_receipt_authority",
    "review_context_required",
    "subject_repository",
    "platform",
    "variant",
    "object_count",
    "object_01",
    "object_02",
    "object_03",
    "object_04",
    "descriptor_chain",
    "diff_id",
    "selected_input_scope",
    "final_builder_image",
    "unresolved_input_count",
    "publisher_authentication",
    "source_to_image_provenance",
    "freshness",
    "safety",
    "verifier_network_access",
    "vm_execution",
];

pub type InputLock = LockRecord;

pub fn parse_input_lock(bytes: &[u8]) -> Result<InputLock> {
    let fields = parse_lock_fields(bytes, OCI_LOCK_KEYS, "input lock")?;
    require(
        &fields,
        "review_context_receipt_format",
        "a-quo-omarchy-ubuntu-oci-candidate-v1",
    )?;
    require(&fields, "review_context_receipt_authority", "none")?;
    require(&fields, "review_context_required", "false")?;
    require(&fields, "subject_repository", "docker.io/library/ubuntu")?;
    require(&fields, "descriptor_chain", "index-manifest-config-layer")?;
    require(
        &fields,
        "selected_input_scope",
        "builder-base-oci-object-bytes-only",
    )?;
    require(&fields, "final_builder_image", "not-established")?;
    require(&fields, "unresolved_input_count", "10")?;
    for key in [
        "publisher_authentication",
        "source_to_image_provenance",
        "freshness",
        "safety",
    ] {
        require(&fields, key, "not-established")?;
    }
    require(&fields, "verifier_network_access", "forbidden")?;
    require(&fields, "vm_execution", "forbidden")?;
    require(
        &fields,
        "review_context_receipt_sha256",
        "330874fa539c10a591fdd206d28f990bb4e29a8c4eca62410e31fcb44b50543e",
    )?;
    ensure!(
        valid_sha256(field(&fields, "review_context_receipt_sha256")?),
        "review_context_receipt_sha256 is not one lowercase SHA-256"
    );
    ensure!(
        field(&fields, "diff_id")?
            .strip_prefix("sha256:")
            .is_some_and(valid_sha256),
        "diff_id is not one lowercase SHA-256 descriptor"
    );
    const EXPECTED_OBJECTS: &[ExpectedObjectSpec] = &[
        ExpectedObjectSpec {
            role: "index",
            path: "index.json",
            media_type: "application/vnd.oci.image.index.v1+json",
            size: 6_688,
            sha256: "33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
        },
        ExpectedObjectSpec {
            role: "manifest",
            path: "manifest.json",
            media_type: "application/vnd.oci.image.manifest.v1+json",
            size: 424,
            sha256: "95fa486768020359141f1318720f43e7982ef926c792891d984aef9aaf05e7ea",
        },
        ExpectedObjectSpec {
            role: "config",
            path: "config.json",
            media_type: "application/vnd.oci.image.config.v1+json",
            size: 2_067,
            sha256: "5b8c0c14690ed170da4e663fe0bae0d58efe59661e791296ffab28ed2113b650",
        },
        ExpectedObjectSpec {
            role: "layer",
            path: "layer-01.tar.gz",
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip",
            size: 28_887_235,
            sha256: "0b613318ea879878918380aa3aeb220dfe824e311b83bc955cb8a1d4319650ab",
        },
    ];
    let objects = parse_object_specs(&fields, EXPECTED_OBJECTS, "OCI")?;
    for object in &objects {
        ensure!(object.size > 0, "locked OCI object is empty");
        let maximum = if object.role == "layer" {
            MAX_COMPRESSED_LAYER_BYTES
        } else {
            MAX_JSON_BYTES
        };
        ensure!(
            object.size <= maximum,
            "locked OCI object exceeds its byte bound"
        );
    }
    LockRecord::new(
        fields,
        objects,
        "a-quo-omarchy-ubuntu-oci-input-lock-v1",
        "a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1",
        LockAuthority::ExactBytes,
        "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock",
        TargetBinding::UBUNTU_OCI,
    )
}

fn parse_ordered_record(
    bytes: &[u8],
    expected_keys: &[&str],
    label: &str,
) -> Result<BTreeMap<String, String>> {
    ensure!(!bytes.is_empty(), "{label} is empty");
    ensure!(
        bytes.len() as u64 <= MAX_LOCK_BYTES,
        "{label} exceeds its byte bound"
    );
    ensure!(bytes.last() == Some(&b'\n'), "{label} must end with one LF");
    ensure!(
        bytes
            .iter()
            .all(|byte| *byte == b'\n' || (0x20..=0x7e).contains(byte)),
        "{label} contains a control, carriage-return, NUL, or non-ASCII byte"
    );
    let text = std::str::from_utf8(bytes).context("record is not UTF-8")?;
    let lines = text
        .strip_suffix('\n')
        .expect("final LF checked")
        .split('\n');
    let mut fields = BTreeMap::new();
    let mut count = 0_usize;
    for (line, expected_key) in lines.zip(expected_keys.iter().copied()) {
        count += 1;
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("{label} line {count} has no separator"))?;
        ensure!(
            !value.contains('='),
            "{label} line {count} has an extra separator"
        );
        ensure!(
            key == expected_key,
            "{label} field order is invalid at line {count}"
        );
        ensure!(
            !value.is_empty() && value.len() <= 4096,
            "{label} line {count} has invalid bounds"
        );
        ensure!(
            fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "{label} repeats {key}"
        );
    }
    ensure!(
        count == expected_keys.len(),
        "{label} does not have the exact field count"
    );
    ensure!(
        text.lines().count() == expected_keys.len(),
        "{label} has an extra field"
    );
    Ok(fields)
}

fn parse_profile(bytes: &[u8], expected_count: usize) -> Result<BTreeMap<String, String>> {
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_PROFILE_BYTES,
        "profile exceeds its byte bound"
    );
    ensure!(bytes.last() == Some(&b'\n'), "profile must end with one LF");
    ensure!(
        bytes
            .iter()
            .all(|byte| *byte == b'\n' || (0x20..=0x7e).contains(byte)),
        "profile contains a control, carriage-return, NUL, or non-ASCII byte"
    );
    let text = std::str::from_utf8(bytes).context("profile is not UTF-8")?;
    let expected_keys = CANONICAL_V2_PROFILE
        .lines()
        .map(|line| line.split_once('=').expect("canonical profile syntax").0)
        .collect::<Vec<_>>();
    ensure!(
        expected_count == expected_keys.len(),
        "profile field count does not match the closed v2 schema"
    );
    let mut fields = BTreeMap::new();
    for (index, line) in text
        .strip_suffix('\n')
        .expect("final LF checked")
        .split('\n')
        .enumerate()
    {
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("profile line {} has no separator", index + 1))?;
        ensure!(
            !value.contains('='),
            "profile line {} has an extra separator",
            index + 1
        );
        ensure!(
            key.len() <= 64
                && key
                    .bytes()
                    .enumerate()
                    .all(|(offset, byte)| if offset == 0 {
                        byte.is_ascii_lowercase()
                    } else {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    }),
            "profile line {} has an invalid key",
            index + 1
        );
        ensure!(
            !value.is_empty() && value.len() <= 4096 && value.trim_matches(' ') == value,
            "profile line {} has invalid value bounds",
            index + 1
        );
        ensure!(
            expected_keys.get(index).copied() == Some(key),
            "profile field order or key is invalid at line {}",
            index + 1
        );
        ensure!(
            fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "profile repeats {key}"
        );
    }
    ensure!(
        fields.len() == expected_count && text.lines().count() == expected_count,
        "profile does not have the exact closed-v2 field sequence"
    );
    Ok(fields)
}

fn field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    fields
        .get(key)
        .map(String::as_str)
        .with_context(|| format!("missing field {key}"))
}

fn require(fields: &BTreeMap<String, String>, key: &str, expected: &str) -> Result<()> {
    ensure!(
        field(fields, key)? == expected,
        "unexpected value for {key}"
    );
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_relative_path(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 255,
        "path is outside the closed bound"
    );
    let path = Path::new(value);
    ensure!(!path.is_absolute(), "absolute path is forbidden");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "path traversal or non-normal component is forbidden"
    );
    ensure!(
        !value.contains("//") && !value.ends_with('/'),
        "noncanonical path is forbidden"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use std::collections::BTreeMap;
    use std::io::{BufReader, Read, Seek, SeekFrom};
    use std::path::Path;

    use a_quo_ipc::SealedArtifact;
    use anyhow::{Context, Result, bail, ensure};
    use flate2::bufread::GzDecoder;
    use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde_json::Number;
    use sha2::{Digest, Sha256};

    use super::{
        ExecutionState, InputLock, MAX_JSON_BYTES, MAX_LOCK_BYTES, MAX_PROFILE_BYTES,
        MAX_UNCOMPRESSED_LAYER_BYTES, NonClaimState, ReportField, VerificationMode,
        VerificationReport, field, parse_input_lock, parse_profile, require,
    };
    use crate::snapshot::{snapshot_bytes, snapshot_exact_input_directory, snapshot_path};

    #[derive(Clone, Debug)]
    enum StrictJson {
        Null,
        Bool,
        Number(Number),
        String(String),
        Array(Vec<StrictJson>),
        Object(BTreeMap<String, StrictJson>),
    }

    impl<'de> Deserialize<'de> for StrictJson {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct StrictVisitor;
            impl<'de> Visitor<'de> for StrictVisitor {
                type Value = StrictJson;
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("JSON without duplicate object keys")
                }
                fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
                    let _ = value;
                    Ok(StrictJson::Bool)
                }
                fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
                    Ok(StrictJson::Number(value.into()))
                }
                fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
                    Ok(StrictJson::Number(value.into()))
                }
                fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Number::from_f64(value)
                        .map(StrictJson::Number)
                        .ok_or_else(|| E::custom("non-finite JSON number"))
                }
                fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
                    Ok(StrictJson::String(value.to_owned()))
                }
                fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
                    Ok(StrictJson::String(value))
                }
                fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(StrictJson::Null)
                }
                fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                    Ok(StrictJson::Null)
                }
                fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let mut values = Vec::new();
                    while let Some(value) = sequence.next_element()? {
                        values.push(value);
                    }
                    Ok(StrictJson::Array(values))
                }
                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut values = BTreeMap::new();
                    while let Some((key, value)) = map.next_entry::<String, StrictJson>()? {
                        if values.insert(key.clone(), value).is_some() {
                            return Err(serde::de::Error::custom(format!(
                                "duplicate JSON key: {key}"
                            )));
                        }
                    }
                    Ok(StrictJson::Object(values))
                }
            }
            deserializer.deserialize_any(StrictVisitor)
        }
    }

    impl StrictJson {
        fn object(&self) -> Result<&BTreeMap<String, StrictJson>> {
            match self {
                Self::Object(value) => Ok(value),
                _ => bail!("expected JSON object"),
            }
        }
        fn array(&self) -> Result<&[StrictJson]> {
            match self {
                Self::Array(value) => Ok(value),
                _ => bail!("expected JSON array"),
            }
        }
        fn string(&self) -> Result<&str> {
            match self {
                Self::String(value) => Ok(value),
                _ => bail!("expected JSON string"),
            }
        }
        fn u64(&self) -> Result<u64> {
            match self {
                Self::Number(value) => value.as_u64().context("expected unsigned JSON integer"),
                _ => bail!("expected JSON number"),
            }
        }
        fn get(&self, key: &str) -> Result<&StrictJson> {
            self.object()?
                .get(key)
                .with_context(|| format!("missing JSON field {key}"))
        }
    }

    fn parse_json(bytes: &[u8], label: &str) -> Result<StrictJson> {
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_JSON_BYTES,
            "{label} exceeds its byte bound"
        );
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let value = StrictJson::deserialize(&mut deserializer)
            .with_context(|| format!("invalid {label} JSON"))?;
        deserializer
            .end()
            .with_context(|| format!("{label} has trailing JSON data"))?;
        Ok(value)
    }

    fn validate_external_expectation(expectation: &super::ExternalLockExpectation) -> Result<()> {
        expectation.validate(
            "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock",
            "Ubuntu OCI",
        )
    }

    pub fn inspect_lock(
        lock_path: &Path,
        expectation: &super::ExternalLockExpectation,
        profile_path: &Path,
    ) -> Result<VerificationReport> {
        validate_external_expectation(expectation)?;
        let lock_snapshot = snapshot_path(lock_path, MAX_LOCK_BYTES)?;
        ensure!(
            lock_snapshot.descriptor().digest.value == expectation.sha256,
            "lock bytes do not match the externally expected SHA-256"
        );
        let lock = parse_input_lock(&snapshot_bytes(&lock_snapshot, MAX_LOCK_BYTES)?)?;
        require(&lock.fields, "lock_repository", &expectation.repository)?;
        require(&lock.fields, "lock_path", &expectation.path)?;
        let profile_snapshot = snapshot_path(profile_path, MAX_PROFILE_BYTES)?;
        ensure!(
            profile_snapshot.descriptor().digest.value == field(&lock.fields, "profile_sha256")?,
            "profile bytes do not match the lock"
        );
        verify_profile(
            &lock,
            &snapshot_bytes(&profile_snapshot, MAX_PROFILE_BYTES)?,
        )?;
        Ok(report(&lock, expectation, VerificationMode::LockAndProfile))
    }

    pub fn verify_inputs(
        lock_path: &Path,
        expectation: &super::ExternalLockExpectation,
        profile_path: &Path,
        input_directory: &Path,
    ) -> Result<VerificationReport> {
        validate_external_expectation(expectation)?;
        let lock_snapshot = snapshot_path(lock_path, MAX_LOCK_BYTES)?;
        ensure!(
            lock_snapshot.descriptor().digest.value == expectation.sha256,
            "lock bytes do not match the externally expected SHA-256"
        );
        let lock = parse_input_lock(&snapshot_bytes(&lock_snapshot, MAX_LOCK_BYTES)?)?;
        require(&lock.fields, "lock_repository", &expectation.repository)?;
        require(&lock.fields, "lock_path", &expectation.path)?;
        let profile_snapshot = snapshot_path(profile_path, MAX_PROFILE_BYTES)?;
        ensure!(
            profile_snapshot.descriptor().digest.value == field(&lock.fields, "profile_sha256")?,
            "profile bytes do not match the lock"
        );
        let profile = verify_profile(
            &lock,
            &snapshot_bytes(&profile_snapshot, MAX_PROFILE_BYTES)?,
        )?;

        let _snapshots = verify_input_directory(&lock, &profile, input_directory)?;
        Ok(report(&lock, expectation, VerificationMode::InputSelection))
    }

    fn verify_input_directory(
        lock: &InputLock,
        profile: &BTreeMap<String, String>,
        input_directory: &Path,
    ) -> Result<Vec<SealedArtifact>> {
        let specifications = lock
            .objects
            .iter()
            .map(|object| {
                (
                    object.role.as_str(),
                    object.path.as_str(),
                    object.size,
                    object.sha256.as_str(),
                )
            })
            .collect::<Vec<_>>();
        let snapshots = snapshot_exact_input_directory(input_directory, &specifications)?;
        verify_oci_semantics(lock, profile, &snapshots)?;
        Ok(snapshots)
    }

    fn report(
        lock: &InputLock,
        expectation: &super::ExternalLockExpectation,
        mode: VerificationMode,
    ) -> VerificationReport {
        let complete = mode.complete();
        let mut report = VerificationReport::for_lock(lock, expectation, mode, false);
        report.extend([
            ReportField::boolean("object_bytes_verified", complete),
            ReportField::text(
                "descriptor_bindings",
                if complete {
                    "verified-from-sealed-snapshots"
                } else {
                    "not-run"
                },
            ),
            ReportField::text(
                "locked_diff_id",
                field(&lock.fields, "diff_id").expect("validated lock"),
            ),
            ReportField::boolean("diff_id_verified", complete),
            ReportField::boolean("review_context_receipt_required", false),
            ReportField::boolean("external_lock_authentication_required", true),
            ReportField::boolean(
                "external_lock_authentication_established_by_verifier",
                false,
            ),
            ReportField::nonclaim("durable_retention", NonClaimState::Unestablished),
            ReportField::nonclaim("build_authorization", lock.envelope.build_authorization),
            ReportField::execution("runnable", lock.envelope.runnable),
            ReportField::nonclaim("publisher_authentication", NonClaimState::Unestablished),
            ReportField::nonclaim("source_to_image_provenance", NonClaimState::Unestablished),
            ReportField::nonclaim("freshness", NonClaimState::Unestablished),
            ReportField::nonclaim("safety", NonClaimState::Unestablished),
            ReportField::execution("verifier_network_activity", ExecutionState::NotPerformed),
            ReportField::nonclaim(
                "whole_machine_network_silence",
                NonClaimState::Unestablished,
            ),
            ReportField::execution("vm_execution", ExecutionState::NotPerformed),
        ]);
        report
    }

    fn verify_profile(lock: &InputLock, bytes: &[u8]) -> Result<BTreeMap<String, String>> {
        let count = field(&lock.fields, "profile_field_count")?
            .parse::<usize>()
            .context("invalid profile field count")?;
        let profile = parse_profile(bytes, count)?;
        require(
            &profile,
            "format",
            "a-quo-omarchy-evaluation-target-profile-v2",
        )?;
        require(&profile, "profile_id", field(&lock.fields, "profile_id")?)?;
        require(&profile, "state", field(&lock.fields, "profile_state")?)?;
        require(&profile, "armable", field(&lock.fields, "profile_armable")?)?;
        require(
            &profile,
            "profile_authentication",
            "external-pinned-git-object-required",
        )?;
        require(&profile, "self_authentication", "none")?;
        require(&profile, "release_claim", "not-established")?;
        require(&profile, "support_claim", "not-established")?;
        require(&profile, "reproducibility_claim", "not-established")?;
        require(&profile, "clean_system_claim", "not-established")?;
        require(&profile, "retained_input_authority", "none")?;
        require(
            &profile,
            "builder_base_oci_repository",
            field(&lock.fields, "subject_repository")?,
        )?;
        require(
            &profile,
            "builder_base_oci_platform",
            field(&lock.fields, "platform")?,
        )?;
        require(
            &profile,
            "builder_base_oci_variant",
            field(&lock.fields, "variant")?,
        )?;
        require(
            &profile,
            "builder_base_oci_integrity",
            "content-addressed-descriptor-chain",
        )?;
        require(&profile, "builder_base_oci_discovery_tag_authority", "none")?;
        require(&profile, "builder_base_oci_layer_count", "1")?;
        require(&profile, "builder_base_oci_diff_id_count", "1")?;
        require(
            &profile,
            "builder_base_oci_publisher_authentication",
            "not-established",
        )?;
        require(
            &profile,
            "builder_base_oci_source_to_image_provenance",
            "not-established",
        )?;
        require(
            &profile,
            "builder_base_oci_retention",
            "required-not-retained",
        )?;
        require(
            &profile,
            "unresolved_input_count",
            field(&lock.fields, "unresolved_input_count")?,
        )?;
        require(
            &profile,
            "unresolved_input_01",
            "builder-oci-retained-archive-and-final-image",
        )?;
        let profile_keys = [
            ("builder_base_oci_index_media_type", 0),
            ("builder_base_oci_manifest_media_type", 1),
            ("builder_base_oci_config_media_type", 2),
            ("builder_base_oci_layer_01_media_type", 3),
        ];
        for (key, index) in profile_keys {
            require(&profile, key, &lock.objects[index].media_type)?;
        }
        let size_keys = [
            "builder_base_oci_index_size",
            "builder_base_oci_manifest_size",
            "builder_base_oci_config_size",
            "builder_base_oci_layer_01_size",
        ];
        let digest_keys = [
            "builder_base_oci_index_digest",
            "builder_base_oci_manifest_digest",
            "builder_base_oci_config_digest",
            "builder_base_oci_layer_01_digest",
        ];
        for index in 0..4 {
            require(
                &profile,
                size_keys[index],
                &lock.objects[index].size.to_string(),
            )?;
            require(
                &profile,
                digest_keys[index],
                &format!("sha256:{}", lock.objects[index].sha256),
            )?;
        }
        require(
            &profile,
            "builder_base_oci_diff_id_01",
            field(&lock.fields, "diff_id")?,
        )?;
        Ok(profile)
    }

    fn verify_oci_semantics(
        lock: &InputLock,
        profile: &BTreeMap<String, String>,
        snapshots: &[SealedArtifact],
    ) -> Result<()> {
        ensure!(snapshots.len() == 4, "OCI input set is not four objects");
        let index = parse_json(&snapshot_bytes(&snapshots[0], MAX_JSON_BYTES)?, "index")?;
        let manifest = parse_json(&snapshot_bytes(&snapshots[1], MAX_JSON_BYTES)?, "manifest")?;
        let config = parse_json(&snapshot_bytes(&snapshots[2], MAX_JSON_BYTES)?, "config")?;
        ensure!(
            index.get("schemaVersion")?.u64()? == 2,
            "index schema version is not 2"
        );
        ensure!(
            index.get("mediaType")?.string()? == lock.objects[0].media_type,
            "index media type differs from the lock"
        );
        let matching = index
            .get("manifests")?
            .array()?
            .iter()
            .filter(|entry| {
                entry
                    .get("platform")
                    .and_then(|platform| platform.get("os"))
                    .and_then(StrictJson::string)
                    .ok()
                    == Some("linux")
                    && entry
                        .get("platform")
                        .and_then(|platform| platform.get("architecture"))
                        .and_then(StrictJson::string)
                        .ok()
                        == Some("arm64")
                    && entry
                        .get("platform")
                        .and_then(|platform| platform.get("variant"))
                        .and_then(StrictJson::string)
                        .ok()
                        == Some("v8")
            })
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "index does not select exactly one linux/arm64/v8 manifest"
        );
        let selected = matching[0];
        ensure!(
            selected.get("mediaType")?.string()? == lock.objects[1].media_type,
            "selected manifest media type differs from the lock"
        );
        ensure!(
            selected.get("digest")?.string()? == format!("sha256:{}", lock.objects[1].sha256),
            "selected manifest digest differs from the lock"
        );
        ensure!(
            selected.get("size")?.u64()? == lock.objects[1].size,
            "selected manifest size differs from the lock"
        );
        let annotations = selected.get("annotations")?;
        ensure!(
            annotations
                .get("com.docker.official-images.bashbrew.arch")?
                .string()?
                == "arm64v8",
            "selected manifest architecture annotation is wrong"
        );
        ensure!(
            annotations
                .get("org.opencontainers.image.source")?
                .string()?
                == field(profile, "builder_base_oci_source_repository_assertion")?,
            "selected manifest source annotation differs from the profile"
        );
        ensure!(
            annotations
                .get("org.opencontainers.image.revision")?
                .string()?
                == field(profile, "builder_base_oci_source_revision_assertion")?,
            "selected manifest revision annotation differs from the profile"
        );
        ensure!(
            annotations
                .get("org.opencontainers.image.version")?
                .string()?
                == field(profile, "builder_base_oci_source_version_assertion")?,
            "selected manifest version annotation differs from the profile"
        );
        let serial = field(profile, "builder_base_oci_source_serial_assertion")?;
        ensure!(serial.len() == 8, "profile source serial is malformed");
        let expected_created = format!(
            "{}-{}-{}T00:00:00Z",
            &serial[0..4],
            &serial[4..6],
            &serial[6..8]
        );
        ensure!(
            annotations
                .get("org.opencontainers.image.created")?
                .string()?
                == expected_created,
            "selected manifest date annotation differs from the profile"
        );

        ensure!(
            manifest.get("schemaVersion")?.u64()? == 2,
            "manifest schema version is not 2"
        );
        ensure!(
            manifest.get("mediaType")?.string()? == lock.objects[1].media_type,
            "manifest media type differs from the lock"
        );
        let config_descriptor = manifest.get("config")?;
        ensure!(
            config_descriptor.get("mediaType")?.string()? == lock.objects[2].media_type,
            "config media type differs from the lock"
        );
        ensure!(
            config_descriptor.get("size")?.u64()? == lock.objects[2].size,
            "config size differs from the lock"
        );
        ensure!(
            config_descriptor.get("digest")?.string()?
                == format!("sha256:{}", lock.objects[2].sha256),
            "config digest differs from the lock"
        );
        let layers = manifest.get("layers")?.array()?;
        ensure!(
            layers.len() == 1,
            "manifest does not contain exactly one layer"
        );
        ensure!(
            layers[0].get("mediaType")?.string()? == lock.objects[3].media_type,
            "layer media type differs from the lock"
        );
        ensure!(
            layers[0].get("size")?.u64()? == lock.objects[3].size,
            "layer size differs from the lock"
        );
        ensure!(
            layers[0].get("digest")?.string()? == format!("sha256:{}", lock.objects[3].sha256),
            "layer digest differs from the lock"
        );

        ensure!(
            config.get("os")?.string()? == "linux",
            "config OS is not Linux"
        );
        ensure!(
            config.get("architecture")?.string()? == "arm64",
            "config architecture is not ARM64"
        );
        ensure!(
            config.get("variant")?.string()? == "v8",
            "config variant is not v8"
        );
        let rootfs = config.get("rootfs")?;
        ensure!(
            rootfs.get("type")?.string()? == "layers",
            "config rootfs type is not layers"
        );
        let diff_ids = rootfs.get("diff_ids")?.array()?;
        ensure!(
            diff_ids.len() == 1 && diff_ids[0].string()? == field(&lock.fields, "diff_id")?,
            "config does not contain the one locked DiffID"
        );
        ensure!(
            config
                .get("config")?
                .get("Labels")?
                .get("org.opencontainers.image.version")?
                .string()?
                == field(profile, "builder_base_oci_source_version_assertion")?,
            "config version label differs from the profile"
        );
        let observed_diff_id = gzip_diff_id(&snapshots[3], MAX_UNCOMPRESSED_LAYER_BYTES)?;
        ensure!(
            observed_diff_id == field(&lock.fields, "diff_id")?,
            "uncompressed layer DiffID differs from the lock"
        );
        Ok(())
    }

    fn gzip_diff_id(snapshot: &SealedArtifact, maximum: u64) -> Result<String> {
        let mut file = snapshot
            .file()
            .try_clone()
            .context("cannot clone sealed layer descriptor")?;
        file.seek(SeekFrom::Start(0))
            .context("cannot rewind sealed layer")?;
        let mut decoder = GzDecoder::new(BufReader::new(file));
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = decoder
                .read(&mut buffer)
                .context("cannot decompress locked layer")?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .context("uncompressed byte count overflow")?;
            ensure!(
                total <= maximum,
                "uncompressed layer exceeds its byte bound"
            );
            hasher.update(&buffer[..read]);
        }
        ensure!(total > 0, "uncompressed layer is empty");
        let mut inner = decoder.into_inner();
        let logical_position = inner
            .stream_position()
            .context("cannot inspect compressed stream position")?;
        ensure!(
            logical_position == snapshot.descriptor().size,
            "compressed layer has trailing bytes or multiple streams"
        );
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::model::{LockAuthority, LockEnvelope, TargetBinding};
        use crate::snapshot::{expected_inventory, snapshot_input};
        use std::fs::File;
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::path::PathBuf;

        use a_quo_ipc::snapshot_artifact;
        use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, mknodat, open};
        use serde_json::json;
        use tempfile::TempDir;

        fn repository_path(relative: &str) -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(relative)
        }

        fn sha256(bytes: &[u8]) -> String {
            format!("{:x}", Sha256::digest(bytes))
        }

        fn gzip(bytes: &[u8]) -> Vec<u8> {
            use flate2::{Compression, write::GzEncoder};
            use std::io::Write;
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        }

        fn sealed(bytes: &[u8]) -> SealedArtifact {
            use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
            use std::io::Write;
            let fd = memfd_create(
                "input-lock-test",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .unwrap();
            let mut file = File::from(fd);
            file.write_all(bytes).unwrap();
            fcntl_add_seals(
                &file,
                SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
            )
            .unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            snapshot_artifact(file.into(), bytes.len() as u64).unwrap()
        }

        fn write_synthetic_directory(oci: &SyntheticOci) -> TempDir {
            let temporary = TempDir::new().unwrap();
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            for (object, bytes) in oci.lock.objects.iter().zip(&oci.bytes) {
                let path = temporary.path().join(&object.path);
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
            temporary
        }

        struct SyntheticOci {
            lock: InputLock,
            profile: BTreeMap<String, String>,
            bytes: Vec<Vec<u8>>,
        }

        fn synthetic_oci(selected_count: usize, layer_plaintext: &[u8]) -> SyntheticOci {
            let layer = gzip(layer_plaintext);
            let diff_id = format!("sha256:{}", sha256(layer_plaintext));
            let config = serde_json::to_vec(&json!({
                "architecture": "arm64",
                "config": {"Labels": {"org.opencontainers.image.version": "24.04"}},
                "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": [&diff_id]},
                "variant": "v8"
            }))
            .unwrap();
            let manifest = serde_json::to_vec(&json!({
                "config": {
                    "digest": format!("sha256:{}", sha256(&config)),
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "size": config.len()
                },
                "layers": [{
                    "digest": format!("sha256:{}", sha256(&layer)),
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": layer.len()
                }],
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "schemaVersion": 2
            }))
            .unwrap();
            let selected = json!({
                "annotations": {
                    "com.docker.official-images.bashbrew.arch": "arm64v8",
                    "org.opencontainers.image.created": "2026-08-10T00:00:00Z",
                    "org.opencontainers.image.revision": "73ecb123318a4fa4b264fae169d4773bc4c9c9c6",
                    "org.opencontainers.image.source": "https://git.launchpad.net/cloud-images/+oci/ubuntu-base",
                    "org.opencontainers.image.version": "24.04"
                },
                "digest": format!("sha256:{}", sha256(&manifest)),
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
                "size": manifest.len()
            });
            let index = serde_json::to_vec(&json!({
                "manifests": vec![selected; selected_count],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2
            }))
            .unwrap();
            let bytes = vec![index, manifest, config, layer];
            let media = [
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.oci.image.config.v1+json",
                "application/vnd.oci.image.layer.v1.tar+gzip",
            ];
            let roles = ["index", "manifest", "config", "layer"];
            let paths = [
                "index.json",
                "manifest.json",
                "config.json",
                "layer-01.tar.gz",
            ];
            let objects = bytes
                .iter()
                .enumerate()
                .map(|(index, object)| super::super::ObjectSpec {
                    role: roles[index].to_owned(),
                    path: paths[index].to_owned(),
                    media_type: media[index].to_owned(),
                    size: object.len() as u64,
                    sha256: sha256(object),
                })
                .collect();
            let fields = BTreeMap::from([
                ("lock_id".to_owned(), "synthetic".to_owned()),
                ("profile_id".to_owned(), "synthetic".to_owned()),
                ("profile_sha256".to_owned(), "0".repeat(64)),
                ("diff_id".to_owned(), diff_id),
            ]);
            let profile = BTreeMap::from([
                (
                    "builder_base_oci_source_repository_assertion".to_owned(),
                    "https://git.launchpad.net/cloud-images/+oci/ubuntu-base".to_owned(),
                ),
                (
                    "builder_base_oci_source_revision_assertion".to_owned(),
                    "73ecb123318a4fa4b264fae169d4773bc4c9c9c6".to_owned(),
                ),
                (
                    "builder_base_oci_source_version_assertion".to_owned(),
                    "24.04".to_owned(),
                ),
                (
                    "builder_base_oci_source_serial_assertion".to_owned(),
                    "20260810".to_owned(),
                ),
            ]);
            SyntheticOci {
                lock: InputLock {
                    fields,
                    envelope: LockEnvelope {
                        lock_id: "synthetic".to_owned(),
                        authority: LockAuthority::ExactBytes,
                        build_authorization: NonClaimState::Unestablished,
                        runnable: ExecutionState::NotPerformed,
                        profile_id: "synthetic".to_owned(),
                        profile_sha256: "0".repeat(64),
                        target: TargetBinding::UBUNTU_OCI,
                    },
                    objects,
                },
                profile,
                bytes,
            }
        }

        #[test]
        fn strict_json_rejects_duplicate_keys() {
            assert!(parse_json(br#"{"a":1,"a":2}"#, "duplicate").is_err());
        }

        #[test]
        fn gzip_bound_and_trailing_bytes_fail() {
            let compressed = gzip(b"bounded bytes");
            let snapshot = sealed(&compressed);
            assert!(gzip_diff_id(&snapshot, 4).is_err());
            assert!(gzip_diff_id(&snapshot, 64).is_ok());
            let mut trailing = compressed;
            trailing.push(0);
            assert!(gzip_diff_id(&sealed(&trailing), 64).is_err());
            let mut multiple = gzip(b"first");
            multiple.extend(gzip(b"second"));
            assert!(gzip_diff_id(&sealed(&multiple), 64).is_err());
        }

        #[test]
        fn synthetic_oci_semantics_accept_exact_bytes_and_reject_substitutions() {
            let exact = synthetic_oci(1, b"synthetic rootfs");
            let snapshots = exact
                .bytes
                .iter()
                .map(|bytes| sealed(bytes))
                .collect::<Vec<_>>();
            verify_oci_semantics(&exact.lock, &exact.profile, &snapshots).unwrap();

            let ambiguous = synthetic_oci(2, b"synthetic rootfs");
            let ambiguous_snapshots = ambiguous
                .bytes
                .iter()
                .map(|bytes| sealed(bytes))
                .collect::<Vec<_>>();
            assert!(
                verify_oci_semantics(&ambiguous.lock, &ambiguous.profile, &ambiguous_snapshots)
                    .is_err()
            );

            let mut manifest_mismatch = synthetic_oci(1, b"synthetic rootfs");
            manifest_mismatch.bytes[1] = String::from_utf8(manifest_mismatch.bytes[1].clone())
                .unwrap()
                .replacen("sha256:", "sha256:0", 1)
                .into_bytes();
            let mismatch_snapshots = manifest_mismatch
                .bytes
                .iter()
                .map(|bytes| sealed(bytes))
                .collect::<Vec<_>>();
            assert!(
                verify_oci_semantics(
                    &manifest_mismatch.lock,
                    &manifest_mismatch.profile,
                    &mismatch_snapshots
                )
                .is_err()
            );

            let mut layer_descriptor_mismatch = synthetic_oci(1, b"synthetic rootfs");
            let mut manifest_value: serde_json::Value =
                serde_json::from_slice(&layer_descriptor_mismatch.bytes[1]).unwrap();
            manifest_value["layers"][0]["digest"] =
                serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
            layer_descriptor_mismatch.bytes[1] = serde_json::to_vec(&manifest_value).unwrap();
            let mismatch_snapshots = layer_descriptor_mismatch
                .bytes
                .iter()
                .map(|bytes| sealed(bytes))
                .collect::<Vec<_>>();
            assert!(
                verify_oci_semantics(
                    &layer_descriptor_mismatch.lock,
                    &layer_descriptor_mismatch.profile,
                    &mismatch_snapshots
                )
                .is_err()
            );

            let mut config_mismatch = synthetic_oci(1, b"synthetic rootfs");
            let mut config_value: serde_json::Value =
                serde_json::from_slice(&config_mismatch.bytes[2]).unwrap();
            config_value["rootfs"]["diff_ids"][0] =
                serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
            config_mismatch.bytes[2] = serde_json::to_vec(&config_value).unwrap();
            let mismatch_snapshots = config_mismatch
                .bytes
                .iter()
                .map(|bytes| sealed(bytes))
                .collect::<Vec<_>>();
            assert!(
                verify_oci_semantics(
                    &config_mismatch.lock,
                    &config_mismatch.profile,
                    &mismatch_snapshots
                )
                .is_err()
            );

            let exact = synthetic_oci(1, b"synthetic rootfs");
            let mut wrong_layer = exact.bytes.clone();
            wrong_layer[3] = gzip(b"different rootfs");
            let wrong_layer_snapshots = wrong_layer
                .iter()
                .map(|bytes| sealed(bytes))
                .collect::<Vec<_>>();
            assert!(
                verify_oci_semantics(&exact.lock, &exact.profile, &wrong_layer_snapshots).is_err()
            );
        }

        #[test]
        fn directory_seam_accepts_exact_set_and_rejects_permissions_symlink_and_hash_change() {
            let exact = synthetic_oci(1, b"synthetic rootfs");
            let directory = write_synthetic_directory(&exact);
            let snapshots =
                verify_input_directory(&exact.lock, &exact.profile, directory.path()).unwrap();
            assert_eq!(snapshots.len(), 4);

            let index_path = directory.path().join("index.json");
            std::fs::set_permissions(&index_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(verify_input_directory(&exact.lock, &exact.profile, directory.path()).is_err());
            std::fs::set_permissions(&index_path, std::fs::Permissions::from_mode(0o400)).unwrap();

            let mut changed = exact.bytes[0].clone();
            changed[0] ^= 1;
            std::fs::set_permissions(&index_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(&index_path, changed).unwrap();
            std::fs::set_permissions(&index_path, std::fs::Permissions::from_mode(0o400)).unwrap();
            assert!(verify_input_directory(&exact.lock, &exact.profile, directory.path()).is_err());

            let links = TempDir::new().unwrap();
            let directory_link = links.path().join("objects");
            symlink(directory.path(), &directory_link).unwrap();
            assert!(verify_input_directory(&exact.lock, &exact.profile, &directory_link).is_err());
        }

        #[test]
        fn external_lock_and_profile_pins_are_mandatory() {
            let lock_path = repository_path(
                "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock",
            );
            let profile_path = repository_path(
                "packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile",
            );
            let lock_bytes = std::fs::read(&lock_path).unwrap();
            let lock_hash = sha256(&lock_bytes);
            let expectation = super::super::ExternalLockExpectation {
                repository: "https://github.com/SurreptitiousFabric/a-quo.git".to_owned(),
                commit: "1".repeat(40),
                path: "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock".to_owned(),
                sha256: lock_hash,
            };
            let mut wrong_sha = expectation.clone();
            wrong_sha.sha256 = "0".repeat(64);
            assert!(inspect_lock(&lock_path, &wrong_sha, &profile_path).is_err());
            let mut wrong_repository = expectation.clone();
            wrong_repository.repository = "https://example.invalid/a-quo.git".to_owned();
            assert!(inspect_lock(&lock_path, &wrong_repository, &profile_path).is_err());
            let mut wrong_path = expectation.clone();
            wrong_path.path = "packaging/evaluation-input-locks/other.lock".to_owned();
            assert!(inspect_lock(&lock_path, &wrong_path, &profile_path).is_err());
            let mut malformed_commit = expectation.clone();
            malformed_commit.commit = "A".repeat(40);
            assert!(inspect_lock(&lock_path, &malformed_commit, &profile_path).is_err());
            let temporary = TempDir::new().unwrap();
            let changed_profile = temporary.path().join("profile");
            let mut profile_bytes = std::fs::read(&profile_path).unwrap();
            profile_bytes[0] ^= 1;
            std::fs::write(&changed_profile, profile_bytes).unwrap();
            assert!(inspect_lock(&lock_path, &expectation, &changed_profile).is_err());
        }

        #[test]
        fn input_inventory_and_file_types_fail_closed() {
            let temporary = TempDir::new().unwrap();
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let file = temporary.path().join("index.json");
            std::fs::write(&file, b"exact").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
            let directory = open(
                temporary.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let stat = fstat(&directory).unwrap();
            expected_inventory(&directory, &["index.json"]).unwrap();
            let snapshot = snapshot_input(&directory, stat.st_dev, "index.json", 5).unwrap();
            assert_eq!(snapshot.descriptor().digest.value, sha256(b"exact"));
            assert!(snapshot_input(&directory, stat.st_dev, "index.json", 6).is_err());

            std::fs::write(temporary.path().join("extra"), b"x").unwrap();
            assert!(expected_inventory(&directory, &["index.json"]).is_err());
            std::fs::remove_file(temporary.path().join("extra")).unwrap();
            std::fs::remove_file(&file).unwrap();
            assert!(expected_inventory(&directory, &["index.json"]).is_err());
            symlink("target", &file).unwrap();
            assert!(snapshot_input(&directory, stat.st_dev, "index.json", 5).is_err());
            std::fs::remove_file(&file).unwrap();
            mknodat(CWD, &file, FileType::Fifo, Mode::from_raw_mode(0o400), 0).unwrap();
            assert!(snapshot_input(&directory, stat.st_dev, "index.json", 5).is_err());
            std::fs::remove_file(&file).unwrap();
            let target = temporary.path().join("target");
            std::fs::write(&target, b"exact").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400)).unwrap();
            std::fs::hard_link(&target, &file).unwrap();
            assert!(snapshot_input(&directory, stat.st_dev, "index.json", 5).is_err());
        }

        #[test]
        fn sealed_snapshot_survives_post_open_path_replacement() {
            let temporary = TempDir::new().unwrap();
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let file = temporary.path().join("index.json");
            std::fs::write(&file, b"first").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
            let directory = open(
                temporary.path(),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .unwrap();
            let stat = fstat(&directory).unwrap();
            let snapshot = snapshot_input(&directory, stat.st_dev, "index.json", 5).unwrap();
            let replacement = temporary.path().join("replacement");
            std::fs::write(&replacement, b"later").unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o400)).unwrap();
            std::fs::rename(&replacement, &file).unwrap();
            assert_eq!(snapshot_bytes(&snapshot, 5).unwrap(), b"first");
        }

        #[test]
        fn inspect_and_complete_outputs_keep_distinct_claims() {
            let lock = synthetic_oci(1, b"root").lock;
            let expectation = super::super::ExternalLockExpectation {
                repository: "https://github.com/SurreptitiousFabric/a-quo.git".to_owned(),
                commit: "1".repeat(40),
                path: "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock".to_owned(),
                sha256: "0".repeat(64),
            };
            let inspect = report(&lock, &expectation, VerificationMode::LockAndProfile).render();
            assert!(inspect.contains("verification_status=verified-lock-and-profile-only"));
            assert!(inspect.contains("object_bytes_verified=false"));
            assert!(inspect.contains("descriptor_bindings=not-run"));
            assert!(inspect.contains("locked_diff_id="));
            assert!(inspect.contains("diff_id_verified=false"));
            assert!(!inspect.contains("\ndiff_id="));
            let complete = report(&lock, &expectation, VerificationMode::InputSelection).render();
            assert!(complete.contains("verification_status=verified-input-selection"));
            assert!(complete.contains("object_bytes_verified=true"));
            assert!(complete.contains("diff_id_verified=true"));
            for forbidden in [
                "runnable=true",
                "safety=safe",
                "publisher_authentication=verified",
                "build_authorization=established",
            ] {
                assert!(!complete.contains(forbidden));
            }
        }

        #[test]
        fn canonical_inspection_report_is_byte_stable() {
            let lock_path = repository_path(
                "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock",
            );
            let profile_path = repository_path(
                "packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile",
            );
            let expectation = super::super::ExternalLockExpectation {
                repository: "https://github.com/SurreptitiousFabric/a-quo.git".to_owned(),
                commit: "0000000000000000000000000000000000000000".to_owned(),
                path: "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock".to_owned(),
                sha256: "667545062b9c34b990f1d6441b749a11f01f13bdf3f4aeb87ad9f0fb4a03c878"
                    .to_owned(),
            };
            let report = inspect_lock(&lock_path, &expectation, &profile_path)
                .unwrap()
                .render();
            assert_eq!(
                report,
                include_str!("../tests/fixtures/ubuntu-oci-inspect.report")
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{inspect_lock, verify_inputs};

#[cfg(not(target_os = "linux"))]
pub fn inspect_lock(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
) -> Result<VerificationReport> {
    anyhow::bail!("the exact-descriptor Omarchy input-lock verifier requires Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn verify_inputs(
    _lock_path: &Path,
    _expectation: &ExternalLockExpectation,
    _profile_path: &Path,
    _input_directory: &Path,
) -> Result<VerificationReport> {
    anyhow::bail!("the exact-descriptor Omarchy input-lock verifier requires Linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_lock() -> Vec<u8> {
        std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock")).unwrap()
    }

    #[test]
    fn canonical_lock_is_closed_and_non_authorizing() {
        let lock = parse_input_lock(&canonical_lock()).unwrap();
        assert_eq!(lock.objects.len(), 4);
        assert_eq!(
            field(&lock.fields, "build_authorization").unwrap(),
            "not-established"
        );
        assert_eq!(field(&lock.fields, "runnable").unwrap(), "false");
        assert_eq!(
            field(&lock.fields, "review_context_required").unwrap(),
            "false"
        );
    }

    #[test]
    fn lock_rejects_reordering_unknown_fields_and_claim_escalation() {
        let original = String::from_utf8(canonical_lock()).unwrap();
        let mut lines = original.lines().collect::<Vec<_>>();
        lines.swap(0, 1);
        assert!(parse_input_lock(format!("{}\n", lines.join("\n")).as_bytes()).is_err());
        assert!(parse_input_lock(format!("{original}trusted=true\n").as_bytes()).is_err());
        assert!(
            parse_input_lock(
                original
                    .replace(
                        "build_authorization=not-established",
                        "build_authorization=established"
                    )
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_input_lock(
                original
                    .replace("runnable=false", "runnable=true")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_input_lock(
                original
                    .replace("safety=not-established", "safety=safe")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_input_lock(
                original
                    .replace("object_count=4", "object_count=04")
                    .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn lock_rejects_duplicate_roles_paths_and_traversal() {
        let original = String::from_utf8(canonical_lock()).unwrap();
        assert!(
            parse_input_lock(
                original
                    .replace(
                        "object_02=manifest|manifest.json",
                        "object_02=index|manifest.json"
                    )
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_input_lock(
                original
                    .replace(
                        "object_02=manifest|manifest.json",
                        "object_02=manifest|index.json"
                    )
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_input_lock(
                original
                    .replace(
                        "object_02=manifest|manifest.json",
                        "object_02=manifest|../manifest.json"
                    )
                    .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn shared_envelope_rejects_cross_profile_and_noncanonical_counts() {
        type Parser = fn(&[u8]) -> Result<InputLock>;
        let cases: &[(&[u8], Parser)] = &[
            (
                include_bytes!(
                    "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock"
                ),
                parse_input_lock,
            ),
            (
                include_bytes!(
                    "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-aavmf-v1.lock"
                ),
                aavmf::parse_aavmf_lock,
            ),
            (
                include_bytes!(
                    "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-alarm-rootfs-v1.lock"
                ),
                alarm_rootfs::parse_alarm_rootfs_lock,
            ),
            (
                include_bytes!(
                    "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-qemu-v1.lock"
                ),
                qemu::parse_qemu_lock,
            ),
        ];
        for (bytes, parse) in cases {
            let lock = std::str::from_utf8(bytes).unwrap();
            let cross_profile = lock.replace(
                "profile_id=a-quo-omarchy4-aarch64-dec29fa-v2",
                "profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1",
            );
            assert!(parse(cross_profile.as_bytes()).is_err());

            let count = lock
                .lines()
                .find_map(|line| line.strip_prefix("object_count="))
                .unwrap();
            let noncanonical_count = lock.replace(
                &format!("object_count={count}"),
                &format!("object_count=0{count}"),
            );
            assert!(parse(noncanonical_count.as_bytes()).is_err());
        }
    }

    #[test]
    fn profile_parser_requires_the_closed_v2_key_sequence() {
        let canonical = CANONICAL_V2_PROFILE.as_bytes();
        assert!(parse_profile(canonical, 129).is_ok());
        assert!(parse_profile(canonical, 128).is_err());

        let text = CANONICAL_V2_PROFILE;
        let renamed = text.replacen("purpose=", "purposf=", 1);
        assert!(parse_profile(renamed.as_bytes(), 129).is_err());
        let spaced = text.replacen("purpose=evaluation-only", "purpose= evaluation-only", 1);
        assert!(parse_profile(spaced.as_bytes(), 129).is_err());
        let mut lines = text.lines().collect::<Vec<_>>();
        lines.swap(0, 1);
        assert!(parse_profile(format!("{}\n", lines.join("\n")).as_bytes(), 129).is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_entry_points_fail_closed() {
        let expectation = ExternalLockExpectation {
            repository: String::new(),
            commit: String::new(),
            path: String::new(),
            sha256: String::new(),
        };
        assert!(inspect_lock(Path::new("lock"), &expectation, Path::new("profile")).is_err());
        assert!(
            verify_inputs(
                Path::new("lock"),
                &expectation,
                Path::new("profile"),
                Path::new("objects")
            )
            .is_err()
        );
    }
}
