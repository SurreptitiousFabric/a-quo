use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use anyhow::{Context, Result, ensure};

use crate::{field, parse_ordered_record, require, valid_sha256, validate_relative_path};

pub(crate) const CANONICAL_REPOSITORY: &str = "https://github.com/SurreptitiousFabric/a-quo.git";
const CANONICAL_PROFILE_COMMIT: &str = "e13e74dca3472e54501b35c9b57ee89f57c6aed3";
const CANONICAL_PROFILE_PATH: &str =
    "packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile";
const CANONICAL_PROFILE_SHA256: &str =
    "3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6";
const CANONICAL_PROFILE_ID: &str = "a-quo-omarchy4-aarch64-dec29fa-v2";
const LOCK_ENVELOPE_KEYS: &[&str] = &[
    "format",
    "lock_id",
    "state",
    "lock_authority",
    "build_authorization",
    "runnable",
    "retention",
    "durable_retention",
    "lock_authentication",
    "self_authentication",
    "lock_repository",
    "lock_path",
    "profile_repository",
    "profile_commit",
    "profile_path",
    "profile_sha256",
    "profile_id",
    "profile_state",
    "profile_armable",
    "profile_field_count",
];

pub(crate) fn parse_lock_fields(
    bytes: &[u8],
    class_keys: &[&str],
    label: &str,
) -> Result<BTreeMap<String, String>> {
    let keys = LOCK_ENVELOPE_KEYS
        .iter()
        .chain(class_keys)
        .copied()
        .collect::<Vec<_>>();
    parse_ordered_record(bytes, &keys, label)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Architecture {
    Aarch64,
}

impl Architecture {
    fn as_str(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceNamespace {
    PhaseAAarch64Dec29fa,
}

impl EvidenceNamespace {
    fn as_str(self) -> &'static str {
        match self {
            Self::PhaseAAarch64Dec29fa => "phase-a-aarch64-dec29fa",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputClass {
    UbuntuOci,
    AlarmRootfs,
    AavmfFirmware,
    QemuBinariesAndMachineConfig,
}

impl InputClass {
    fn lock_value(self) -> Option<&'static str> {
        match self {
            Self::UbuntuOci => None,
            Self::AlarmRootfs => Some("04-alarm-rootfs-bytes-signature-and-key-blob"),
            Self::AavmfFirmware => Some("07-aavmf-firmware"),
            Self::QemuBinariesAndMachineConfig => Some("06-qemu-binaries-and-machine-config"),
        }
    }

    fn verification_status(self, mode: VerificationMode) -> &'static str {
        match (self, mode) {
            (Self::UbuntuOci, VerificationMode::LockAndProfile) => "verified-lock-and-profile-only",
            (Self::UbuntuOci, VerificationMode::InputSelection) => "verified-input-selection",
            (Self::AlarmRootfs, VerificationMode::LockAndProfile) => {
                "verified-alarm-rootfs-lock-and-profile-only"
            }
            (Self::AlarmRootfs, VerificationMode::InputSelection) => {
                "verified-alarm-rootfs-input-selection"
            }
            (Self::AavmfFirmware, VerificationMode::LockAndProfile) => {
                "verified-aavmf-lock-and-profile-only"
            }
            (Self::AavmfFirmware, VerificationMode::InputSelection) => {
                "verified-aavmf-input-selection"
            }
            (Self::QemuBinariesAndMachineConfig, VerificationMode::LockAndProfile) => {
                "verified-qemu-lock-and-profile-only"
            }
            (Self::QemuBinariesAndMachineConfig, VerificationMode::InputSelection) => {
                "verified-qemu-input-selection"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockAuthority {
    ExactBytes,
    DetachedSignature,
    DebFirmwareMembers,
    QemuElfMachine,
}

impl LockAuthority {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExactBytes => "exact-byte-selection-only",
            Self::DetachedSignature => "exact-byte-and-detached-signature-selection-only",
            Self::DebFirmwareMembers => "exact-deb-and-firmware-member-selection-only",
            Self::QemuElfMachine => "exact-qemu-package-elf-and-machine-config-selection-only",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NonClaimState {
    Unestablished,
    NotIndependentlyReplayed,
    NotLocked,
}

impl NonClaimState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unestablished => "not-established",
            Self::NotIndependentlyReplayed => "not-independently-replayed",
            Self::NotLocked => "not-locked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutionState {
    NotPerformed,
    NotExecuted,
}

impl ExecutionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotPerformed => "false",
            Self::NotExecuted => "not-executed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VerificationMode {
    LockAndProfile,
    InputSelection,
}

impl VerificationMode {
    pub(crate) fn complete(self) -> bool {
        self == Self::InputSelection
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TargetBinding {
    pub(crate) architecture: Architecture,
    pub(crate) evidence_namespace: EvidenceNamespace,
    pub(crate) input_class: InputClass,
}

impl TargetBinding {
    pub(crate) const UBUNTU_OCI: Self = Self {
        architecture: Architecture::Aarch64,
        evidence_namespace: EvidenceNamespace::PhaseAAarch64Dec29fa,
        input_class: InputClass::UbuntuOci,
    };
    pub(crate) const ALARM_ROOTFS: Self = Self {
        architecture: Architecture::Aarch64,
        evidence_namespace: EvidenceNamespace::PhaseAAarch64Dec29fa,
        input_class: InputClass::AlarmRootfs,
    };
    pub(crate) const AAVMF: Self = Self {
        architecture: Architecture::Aarch64,
        evidence_namespace: EvidenceNamespace::PhaseAAarch64Dec29fa,
        input_class: InputClass::AavmfFirmware,
    };
    pub(crate) const QEMU: Self = Self {
        architecture: Architecture::Aarch64,
        evidence_namespace: EvidenceNamespace::PhaseAAarch64Dec29fa,
        input_class: InputClass::QemuBinariesAndMachineConfig,
    };

    fn validate(self, fields: &BTreeMap<String, String>) -> Result<()> {
        match self.input_class {
            InputClass::UbuntuOci => {
                require(fields, "platform", "linux/arm64")?;
                require(fields, "variant", "v8")?;
            }
            _ => {
                require(fields, "target_kind", "virtual-reference-target")?;
                require(fields, "architecture", self.architecture.as_str())?;
                require(
                    fields,
                    "evidence_namespace",
                    self.evidence_namespace.as_str(),
                )?;
                require(
                    fields,
                    "input_class",
                    self.input_class
                        .lock_value()
                        .expect("non-OCI input class has a lock value"),
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectSpec {
    pub role: String,
    pub path: String,
    pub media_type: String,
    pub size: u64,
    pub sha256: String,
}

impl ObjectSpec {
    fn record(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.role, self.path, self.media_type, self.size, self.sha256
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockEnvelope {
    pub(crate) lock_id: String,
    pub(crate) authority: LockAuthority,
    pub(crate) build_authorization: NonClaimState,
    pub(crate) runnable: ExecutionState,
    pub(crate) profile_id: String,
    pub(crate) profile_sha256: String,
    pub(crate) target: TargetBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockRecord {
    pub fields: BTreeMap<String, String>,
    pub(crate) envelope: LockEnvelope,
    pub objects: Vec<ObjectSpec>,
}

impl LockRecord {
    pub(crate) fn new(
        fields: BTreeMap<String, String>,
        objects: Vec<ObjectSpec>,
        expected_format: &str,
        expected_lock_id: &str,
        authority: LockAuthority,
        expected_lock_path: &str,
        target: TargetBinding,
    ) -> Result<Self> {
        for (key, expected) in [
            ("format", expected_format),
            ("lock_id", expected_lock_id),
            ("state", "reviewed-input-selection"),
            ("lock_authority", authority.as_str()),
            ("build_authorization", "not-established"),
            ("runnable", "false"),
            ("retention", "caller-supplied-local-exact-bytes-required"),
            ("durable_retention", "not-established"),
            ("lock_authentication", "external-pinned-git-object-required"),
            ("self_authentication", "none"),
            ("lock_repository", CANONICAL_REPOSITORY),
            ("lock_path", expected_lock_path),
            ("profile_repository", CANONICAL_REPOSITORY),
            ("profile_commit", CANONICAL_PROFILE_COMMIT),
            ("profile_path", CANONICAL_PROFILE_PATH),
            ("profile_sha256", CANONICAL_PROFILE_SHA256),
            ("profile_id", CANONICAL_PROFILE_ID),
            ("profile_state", "bootstrap-unarmed"),
            ("profile_armable", "false"),
            ("profile_field_count", "129"),
        ] {
            require(&fields, key, expected)?;
        }
        ensure!(
            valid_sha256(field(&fields, "profile_sha256")?),
            "invalid profile SHA-256"
        );
        let profile_commit = field(&fields, "profile_commit")?;
        ensure!(
            profile_commit.len() == 40
                && profile_commit
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "profile commit is not one lowercase Git object identifier"
        );
        target.validate(&fields)?;
        require(&fields, "object_count", &objects.len().to_string())?;
        Ok(Self {
            envelope: LockEnvelope {
                lock_id: expected_lock_id.to_owned(),
                authority,
                build_authorization: NonClaimState::Unestablished,
                runnable: ExecutionState::NotPerformed,
                profile_id: CANONICAL_PROFILE_ID.to_owned(),
                profile_sha256: CANONICAL_PROFILE_SHA256.to_owned(),
                target,
            },
            fields,
            objects,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ExpectedObjectSpec {
    pub role: &'static str,
    pub path: &'static str,
    pub media_type: &'static str,
    pub size: u64,
    pub sha256: &'static str,
}

pub(crate) fn parse_object_specs(
    fields: &BTreeMap<String, String>,
    expected: &[ExpectedObjectSpec],
    label: &str,
) -> Result<Vec<ObjectSpec>> {
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut objects = Vec::with_capacity(expected.len());
    for (index, expected) in expected.iter().enumerate() {
        let key = format!("object_{:02}", index + 1);
        let parts = field(fields, &key)?.split('|').collect::<Vec<_>>();
        ensure!(parts.len() == 5, "{key} has the wrong field count");
        let size = parts[3]
            .parse::<u64>()
            .with_context(|| format!("{key} has an invalid size"))?;
        ensure!(
            parts[0] == expected.role
                && parts[1] == expected.path
                && parts[2] == expected.media_type
                && size == expected.size
                && parts[4] == expected.sha256,
            "{key} differs from the reviewed {label} object policy"
        );
        validate_relative_path(parts[1])?;
        ensure!(valid_sha256(parts[4]), "{key} has an invalid SHA-256");
        ensure!(roles.insert(parts[0]), "object role is duplicated");
        ensure!(paths.insert(parts[1]), "object path is duplicated");
        objects.push(ObjectSpec {
            role: parts[0].to_owned(),
            path: parts[1].to_owned(),
            media_type: parts[2].to_owned(),
            size,
            sha256: parts[4].to_owned(),
        });
    }
    Ok(objects)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalLockExpectation {
    pub repository: String,
    pub commit: String,
    pub path: String,
    pub sha256: String,
}

impl ExternalLockExpectation {
    pub(crate) fn validate(&self, expected_path: &str, label: &str) -> Result<()> {
        ensure!(
            self.repository == CANONICAL_REPOSITORY,
            "external lock repository is not the canonical A Quo repository"
        );
        ensure!(
            self.path == expected_path,
            "external lock path is not the canonical {label} lock path"
        );
        ensure!(
            self.commit.len() == 40
                && self
                    .commit
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "external lock commit is not one lowercase Git object identifier"
        );
        ensure!(
            valid_sha256(&self.sha256),
            "externally expected lock SHA-256 is malformed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReportValue {
    Text(String),
    Count(usize),
    Boolean(bool),
    NonClaim(NonClaimState),
    Execution(ExecutionState),
}

impl ReportValue {
    fn render(&self) -> String {
        match self {
            Self::Text(value) => value.clone(),
            Self::Count(value) => value.to_string(),
            Self::Boolean(value) => value.to_string(),
            Self::NonClaim(value) => value.as_str().to_owned(),
            Self::Execution(value) => value.as_str().to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReportField {
    key: String,
    value: ReportValue,
}

impl ReportField {
    pub(crate) fn text(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: ReportValue::Text(value.into()),
        }
    }

    pub(crate) fn count(key: impl Into<String>, value: usize) -> Self {
        Self {
            key: key.into(),
            value: ReportValue::Count(value),
        }
    }

    pub(crate) fn boolean(key: impl Into<String>, value: bool) -> Self {
        Self {
            key: key.into(),
            value: ReportValue::Boolean(value),
        }
    }

    pub(crate) fn nonclaim(key: impl Into<String>, value: NonClaimState) -> Self {
        Self {
            key: key.into(),
            value: ReportValue::NonClaim(value),
        }
    }

    pub(crate) fn execution(key: impl Into<String>, value: ExecutionState) -> Self {
        Self {
            key: key.into(),
            value: ReportValue::Execution(value),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    fields: Vec<ReportField>,
}

impl VerificationReport {
    pub(crate) fn for_lock(
        lock: &LockRecord,
        expectation: &ExternalLockExpectation,
        mode: VerificationMode,
        include_explicit_target: bool,
    ) -> Self {
        let complete = mode.complete();
        let mut fields = vec![
            ReportField::text(
                "verification_status",
                lock.envelope.target.input_class.verification_status(mode),
            ),
            ReportField::text("lock_authority", lock.envelope.authority.as_str()),
            ReportField::text("external_lock_repository", &expectation.repository),
            ReportField::text("external_lock_commit", &expectation.commit),
            ReportField::text("external_lock_path", &expectation.path),
            ReportField::text("lock_id", &lock.envelope.lock_id),
            ReportField::text("lock_sha256", &expectation.sha256),
            ReportField::text("profile_id", &lock.envelope.profile_id),
            ReportField::text("profile_sha256", &lock.envelope.profile_sha256),
        ];
        if include_explicit_target {
            fields.extend([
                ReportField::text("architecture", lock.envelope.target.architecture.as_str()),
                ReportField::text(
                    "evidence_namespace",
                    lock.envelope.target.evidence_namespace.as_str(),
                ),
                ReportField::text(
                    "input_class",
                    lock.envelope
                        .target
                        .input_class
                        .lock_value()
                        .expect("explicit report target has an input class value"),
                ),
            ]);
        }
        fields.extend([
            ReportField::count("locked_object_count", lock.objects.len()),
            ReportField::count(
                "verified_object_count",
                if complete { lock.objects.len() } else { 0 },
            ),
        ]);
        if complete {
            fields.extend(lock.objects.iter().enumerate().map(|(index, object)| {
                ReportField::text(format!("object_{:02}", index + 1), object.record())
            }));
        }
        Self { fields }
    }

    pub(crate) fn extend(&mut self, fields: impl IntoIterator<Item = ReportField>) {
        self.fields.extend(fields);
    }

    pub fn render(&self) -> String {
        let mut keys = BTreeSet::new();
        let mut output = String::new();
        for field in &self.fields {
            assert!(
                !field.key.is_empty()
                    && field.key.bytes().enumerate().all(|(index, byte)| {
                        if index == 0 {
                            byte.is_ascii_lowercase()
                        } else {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        }
                    }),
                "report field has an invalid key"
            );
            assert!(keys.insert(&field.key), "report repeats {}", field.key);
            let value = field.value.render();
            assert!(
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'='),
                "report field {} has an invalid value",
                field.key
            );
            writeln!(output, "{}={value}", field.key).expect("writing to a String cannot fail");
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_serializer_rejects_duplicate_or_unrepresentable_fields() {
        let duplicate = VerificationReport {
            fields: vec![
                ReportField::text("state", "first"),
                ReportField::text("state", "second"),
            ],
        };
        assert!(std::panic::catch_unwind(|| duplicate.render()).is_err());

        let invalid = VerificationReport {
            fields: vec![ReportField::text("state", "line\nbreak")],
        };
        assert!(std::panic::catch_unwind(|| invalid.render()).is_err());
    }
}
