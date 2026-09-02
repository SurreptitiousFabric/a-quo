use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::model::{
    ExecutionState, ExpectedObjectSpec, LockAuthority, LockRecord, NonClaimState, ReportField,
    TargetBinding, VerificationMode, VerificationReport, parse_lock_fields, parse_object_specs,
};
use crate::{
    CANONICAL_V2_PROFILE, ExternalLockExpectation, MAX_LOCK_BYTES, MAX_PROFILE_BYTES, field,
    parse_profile, require,
};

const CANONICAL_LOCK_PATH: &str =
    "packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-apt-v1.lock";

const APT_LOCK_KEYS: &[&str] = &[
    "target_kind",
    "architecture",
    "evidence_namespace",
    "input_class",
    "selected_input_scope",
    "candidate_status",
    "snapshot_id",
    "original_archive",
    "effective_snapshot_archive",
    "archive_equivalence_to_original_ports",
    "selected_signing_key_material",
    "ubuntu_archive_signature_verification",
    "apt_solver_execution",
    "apt_solver_reexecution",
    "transitive_closure_independently_recomputed",
    "object_manifest_record_count",
    "index_count",
    "package_count",
    "state_record_count",
    "ca_bundle_count",
    "candidate_file_count",
    "candidate_byte_count",
    "object_count",
    "object_01",
    "object_02",
    "object_03",
    "object_04",
    "object_05",
    "object_06",
    "candidate_byte_verifier",
    "candidate_byte_verifier_commit",
    "candidate_byte_verifier_result",
    "publisher_authentication",
    "current_publisher_authorization",
    "trusted_time",
    "freshness",
    "source_to_binary_provenance",
    "safety",
    "network_access",
    "package_installation",
    "maintainer_scripts_executed",
    "vm_execution",
];

pub type AptLock = LockRecord;
pub type AptVerificationReport = VerificationReport;

pub fn parse_apt_lock(bytes: &[u8]) -> Result<AptLock> {
    let fields = parse_lock_fields(bytes, APT_LOCK_KEYS, "APT input lock")?;
    for (key, expected) in [
        (
            "selected_input_scope",
            "ubuntu-snapshot-index-package-state-and-ca-candidate",
        ),
        ("candidate_status", "complete-candidate-no-authority"),
        ("snapshot_id", "20260831T000000Z"),
        ("original_archive", "http://ports.ubuntu.com/ubuntu-ports/"),
        (
            "effective_snapshot_archive",
            "https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/",
        ),
        ("archive_equivalence_to_original_ports", "not-established"),
        ("selected_signing_key_material", "not-retained"),
        (
            "ubuntu_archive_signature_verification",
            "performed-by-apt-not-independently-replayed",
        ),
        ("apt_solver_execution", "reported-by-acquirer-not-replayed"),
        ("apt_solver_reexecution", "false"),
        ("transitive_closure_independently_recomputed", "false"),
        ("object_manifest_record_count", "122"),
        ("index_count", "19"),
        ("package_count", "93"),
        ("state_record_count", "9"),
        ("ca_bundle_count", "1"),
        ("candidate_file_count", "128"),
        ("candidate_byte_count", "110637976"),
        (
            "candidate_byte_verifier",
            "scripts/verify-omarchy-ubuntu-apt-candidate.sh",
        ),
        (
            "candidate_byte_verifier_commit",
            "983a458a3606ab44e769fc0d14689df3ddfd8fc7",
        ),
        (
            "candidate_byte_verifier_result",
            "two-complete-local-observations",
        ),
        ("publisher_authentication", "not-established"),
        ("current_publisher_authorization", "not-established"),
        ("trusted_time", "not-established"),
        ("freshness", "not-established"),
        ("source_to_binary_provenance", "not-established"),
        ("safety", "not-established"),
        ("network_access", "forbidden"),
        ("package_installation", "false"),
        ("maintainer_scripts_executed", "false"),
        ("vm_execution", "false"),
    ] {
        require(&fields, key, expected)?;
    }
    const OBJECTS: &[ExpectedObjectSpec] = &[
        ExpectedObjectSpec {
            role: "apt-candidate-receipt",
            path: "receipt.apt.v1",
            media_type: "text/plain",
            size: 1_688,
            sha256: "c99f29429d8d6f87c0651154dee28153af4b6d6c0c47908ca767067d3f1f5d13",
        },
        ExpectedObjectSpec {
            role: "apt-object-manifest",
            path: "objects.manifest",
            media_type: "text/plain",
            size: 14_988,
            sha256: "731cde75cece74a2b22cb22e24484951420b44321453fe1abd898b16744ebdaf",
        },
        ExpectedObjectSpec {
            role: "profile-snapshot",
            path: "prerequisites/profile.snapshot",
            media_type: "text/plain",
            size: 10_526,
            sha256: "3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6",
        },
        ExpectedObjectSpec {
            role: "ubuntu-oci-lock-snapshot",
            path: "prerequisites/ubuntu-oci.lock.snapshot",
            media_type: "text/plain",
            size: 2_286,
            sha256: "667545062b9c34b990f1d6441b749a11f01f13bdf3f4aeb87ad9f0fb4a03c878",
        },
        ExpectedObjectSpec {
            role: "builder-context-lock-snapshot",
            path: "prerequisites/builder-context.lock.snapshot",
            media_type: "text/plain",
            size: 6_300,
            sha256: "4865e1c9bf4159541afff7d138dee41edc215d988862a0b2d30ed81b09b53f8d",
        },
        ExpectedObjectSpec {
            role: "completion-marker",
            path: "COMPLETE",
            media_type: "text/plain",
            size: 19,
            sha256: "a91c5bb6f5441dc94de72d43bd7bc6ba99bbef762dcc775fd0b779528dba7d67",
        },
    ];
    let objects = parse_object_specs(&fields, OBJECTS, "APT candidate control")?;
    LockRecord::new(
        fields,
        objects,
        "a-quo-omarchy-ubuntu-apt-input-lock-v1",
        "a-quo-omarchy4-aarch64-dec29fa-ubuntu-apt-v1",
        LockAuthority::AptCandidate,
        CANONICAL_LOCK_PATH,
        TargetBinding::UBUNTU_APT,
    )
}

fn verify_profile(lock: &AptLock, bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    ensure!(
        bytes == CANONICAL_V2_PROFILE.as_bytes(),
        "profile bytes differ from the canonical frozen v2 profile"
    );
    let profile = parse_profile(bytes, 129)?;
    for (key, expected) in [
        ("format", "a-quo-omarchy-evaluation-target-profile-v2"),
        ("profile_id", field(&lock.fields, "profile_id")?),
        ("state", field(&lock.fields, "profile_state")?),
        ("armable", field(&lock.fields, "profile_armable")?),
        ("expectation_scope", "reviewed-metadata-only"),
        ("retained_input_authority", "none"),
        ("purpose", "evaluation-only"),
        ("architecture", field(&lock.fields, "architecture")?),
        (
            "profile_authentication",
            "external-pinned-git-object-required",
        ),
        ("self_authentication", "none"),
        ("builder_apt_snapshot_and_closure", "required-not-retained"),
        ("builder_apt_top_level_request_count", "14"),
        (
            "builder_apt_top_level_requests",
            "ca-certificates,curl,dosfstools,e2fsprogs,fdisk,gnupg,libarchive-tools,openssh-client,parted,qemu-efi-aarch64,qemu-system-arm,qemu-utils,socat,udev",
        ),
        ("release_claim", "not-established"),
        ("support_claim", "not-established"),
        ("reproducibility_claim", "not-established"),
        ("clean_system_claim", "not-established"),
        (
            "unresolved_input_02",
            "ubuntu-apt-snapshot-and-package-lock",
        ),
        ("unresolved_input_count", "10"),
    ] {
        require(&profile, key, expected)?;
    }
    Ok(profile)
}

fn parsed_count(fields: &BTreeMap<String, String>, key: &str) -> Result<usize> {
    field(fields, key)?
        .parse::<usize>()
        .with_context(|| format!("{key} is not a count"))
}

fn report(
    lock: &AptLock,
    expectation: &ExternalLockExpectation,
    profile: &BTreeMap<String, String>,
) -> Result<AptVerificationReport> {
    let top_level_request_count = parsed_count(profile, "builder_apt_top_level_request_count")?;
    let unresolved_input_count = parsed_count(profile, "unresolved_input_count")?;
    let remaining_input_count = unresolved_input_count
        .checked_sub(1)
        .context("unresolved input count cannot account for adoption of this lock")?;
    let mut report =
        VerificationReport::for_lock(lock, expectation, VerificationMode::LockAndProfile, true);
    report.extend([
        ReportField::text(
            "locked_state",
            field(&lock.fields, "state").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_retention",
            field(&lock.fields, "retention").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_lock_authentication",
            field(&lock.fields, "lock_authentication").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_self_authentication",
            field(&lock.fields, "self_authentication").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_profile_repository",
            field(&lock.fields, "profile_repository").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_profile_commit",
            field(&lock.fields, "profile_commit").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_profile_path",
            field(&lock.fields, "profile_path").expect("validated APT lock"),
        ),
        ReportField::text(
            "profile_reporting_scope",
            "class-02-binding-and-target-readiness-subset",
        ),
        ReportField::text(
            "profile_state",
            field(profile, "state").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_armable",
            field(profile, "armable").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_expectation_scope",
            field(profile, "expectation_scope").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_retained_input_authority",
            field(profile, "retained_input_authority").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_purpose",
            field(profile, "purpose").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_authentication",
            field(profile, "profile_authentication").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_self_authentication",
            field(profile, "self_authentication").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_builder_apt_snapshot_and_closure",
            field(profile, "builder_apt_snapshot_and_closure").expect("validated APT profile"),
        ),
        ReportField::count(
            "profile_builder_apt_top_level_request_count",
            top_level_request_count,
        ),
        ReportField::text(
            "profile_builder_apt_top_level_requests",
            field(profile, "builder_apt_top_level_requests").expect("validated APT profile"),
        ),
        ReportField::count("profile_unresolved_input_count", unresolved_input_count),
        ReportField::text(
            "profile_unresolved_input_02",
            field(profile, "unresolved_input_02").expect("validated APT profile"),
        ),
        ReportField::count(
            "remaining_input_count_if_lock_is_adopted",
            remaining_input_count,
        ),
        ReportField::text(
            "profile_release_claim",
            field(profile, "release_claim").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_support_claim",
            field(profile, "support_claim").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_reproducibility_claim",
            field(profile, "reproducibility_claim").expect("validated APT profile"),
        ),
        ReportField::text(
            "profile_clean_system_claim",
            field(profile, "clean_system_claim").expect("validated APT profile"),
        ),
        ReportField::text(
            "locked_target_kind",
            field(&lock.fields, "target_kind").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_selected_input_scope",
            field(&lock.fields, "selected_input_scope").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_snapshot_id",
            field(&lock.fields, "snapshot_id").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_original_archive",
            field(&lock.fields, "original_archive").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_effective_snapshot_archive",
            field(&lock.fields, "effective_snapshot_archive").expect("validated APT lock"),
        ),
        ReportField::boolean("candidate_object_bytes_verified", false),
        ReportField::text(
            "locked_candidate_status",
            field(&lock.fields, "candidate_status").expect("validated APT lock"),
        ),
        ReportField::count(
            "locked_candidate_file_count",
            parsed_count(&lock.fields, "candidate_file_count")?,
        ),
        ReportField::count(
            "locked_candidate_byte_count",
            parsed_count(&lock.fields, "candidate_byte_count")?,
        ),
        ReportField::count(
            "locked_manifest_object_count",
            parsed_count(&lock.fields, "object_manifest_record_count")?,
        ),
        ReportField::count(
            "locked_index_count",
            parsed_count(&lock.fields, "index_count")?,
        ),
        ReportField::count(
            "locked_package_count",
            parsed_count(&lock.fields, "package_count")?,
        ),
        ReportField::count(
            "locked_state_record_count",
            parsed_count(&lock.fields, "state_record_count")?,
        ),
        ReportField::count(
            "locked_ca_bundle_count",
            parsed_count(&lock.fields, "ca_bundle_count")?,
        ),
        ReportField::text(
            "locked_candidate_byte_verifier",
            field(&lock.fields, "candidate_byte_verifier").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_candidate_byte_verifier_commit",
            field(&lock.fields, "candidate_byte_verifier_commit").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_candidate_byte_verifier_result",
            field(&lock.fields, "candidate_byte_verifier_result").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_apt_solver_execution",
            field(&lock.fields, "apt_solver_execution")
                .expect("parsed APT lock has apt_solver_execution"),
        ),
        ReportField::text(
            "locked_apt_solver_reexecution",
            field(&lock.fields, "apt_solver_reexecution")
                .expect("parsed APT lock has apt_solver_reexecution"),
        ),
        ReportField::text(
            "locked_transitive_closure_independently_recomputed",
            field(&lock.fields, "transitive_closure_independently_recomputed")
                .expect("parsed APT lock has transitive_closure_independently_recomputed"),
        ),
        ReportField::text("selected_signing_key_material", "not-retained"),
        ReportField::nonclaim(
            "archive_equivalence_to_original_ports",
            NonClaimState::Unestablished,
        ),
        ReportField::text(
            "locked_ubuntu_archive_signature_verification",
            field(&lock.fields, "ubuntu_archive_signature_verification")
                .expect("validated APT lock"),
        ),
        ReportField::nonclaim(
            "apt_signature_replay",
            NonClaimState::NotIndependentlyReplayed,
        ),
        ReportField::boolean("external_lock_authentication_required", true),
        ReportField::boolean(
            "external_lock_authentication_established_by_verifier",
            false,
        ),
        ReportField::nonclaim("durable_retention", NonClaimState::Unestablished),
        ReportField::nonclaim("build_authorization", NonClaimState::Unestablished),
        ReportField::execution("runnable", ExecutionState::NotPerformed),
        ReportField::nonclaim("publisher_authentication", NonClaimState::Unestablished),
        ReportField::nonclaim(
            "current_publisher_authorization",
            NonClaimState::Unestablished,
        ),
        ReportField::nonclaim("trusted_time", NonClaimState::Unestablished),
        ReportField::nonclaim("freshness", NonClaimState::Unestablished),
        ReportField::nonclaim("source_to_binary_provenance", NonClaimState::Unestablished),
        ReportField::nonclaim("safety", NonClaimState::Unestablished),
        ReportField::text(
            "locked_network_access",
            field(&lock.fields, "network_access").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_package_installation",
            field(&lock.fields, "package_installation").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_maintainer_scripts_executed",
            field(&lock.fields, "maintainer_scripts_executed").expect("validated APT lock"),
        ),
        ReportField::text(
            "locked_vm_execution",
            field(&lock.fields, "vm_execution").expect("validated APT lock"),
        ),
        ReportField::execution("verifier_network_activity", ExecutionState::NotPerformed),
        ReportField::nonclaim(
            "whole_machine_network_silence",
            NonClaimState::Unestablished,
        ),
        ReportField::execution(
            "archive_filesystem_extraction",
            ExecutionState::NotPerformed,
        ),
        ReportField::execution("package_manager_execution", ExecutionState::NotPerformed),
        ReportField::execution("package_installation", ExecutionState::NotPerformed),
        ReportField::execution("maintainer_scripts_executed", ExecutionState::NotPerformed),
        ReportField::execution("mount_execution", ExecutionState::NotPerformed),
        ReportField::execution("vm_execution", ExecutionState::NotPerformed),
    ]);
    Ok(report)
}

#[cfg(target_os = "linux")]
pub fn inspect_apt_lock(
    lock_path: &Path,
    expectation: &ExternalLockExpectation,
    profile_path: &Path,
) -> Result<AptVerificationReport> {
    use crate::snapshot::{snapshot_bytes, snapshot_path};
    expectation.validate(CANONICAL_LOCK_PATH, "APT")?;
    let lock_snapshot = snapshot_path(lock_path, MAX_LOCK_BYTES)?;
    ensure!(
        lock_snapshot.descriptor().digest.value == expectation.sha256,
        "lock bytes do not match the externally expected SHA-256"
    );
    let lock = parse_apt_lock(&snapshot_bytes(&lock_snapshot, MAX_LOCK_BYTES)?)?;
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
    report(&lock, expectation, &profile)
}

#[cfg(not(target_os = "linux"))]
pub fn inspect_apt_lock(
    _: &Path,
    _: &ExternalLockExpectation,
    _: &Path,
) -> Result<AptVerificationReport> {
    anyhow::bail!("APT lock inspection requires Linux sealed-file verification")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    const LOCK: &[u8] = include_bytes!(
        "../../../packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-apt-v1.lock"
    );
    const LOCK_SHA256: &str = "ae00a08a2f4176f891cc2178f9ccc5c1193068b61235c26c64035e4ccc0396ea";

    const OBJECT_OMISSION: &str = "the six exact object records remain available through the exact lock digest; the report states verified_object_count=0 and candidate_object_bytes_verified=false";
    const LOCK_SAME: &[&str] = &[
        "lock_id",
        "lock_authority",
        "build_authorization",
        "runnable",
        "durable_retention",
        "profile_sha256",
        "profile_id",
        "architecture",
        "evidence_namespace",
        "input_class",
        "archive_equivalence_to_original_ports",
        "selected_signing_key_material",
        "publisher_authentication",
        "current_publisher_authorization",
        "trusted_time",
        "freshness",
        "source_to_binary_provenance",
        "safety",
    ];
    const LOCK_RENAMED: &[(&str, &str)] = &[
        ("state", "locked_state"),
        ("retention", "locked_retention"),
        ("lock_authentication", "locked_lock_authentication"),
        ("self_authentication", "locked_self_authentication"),
        ("profile_repository", "locked_profile_repository"),
        ("profile_commit", "locked_profile_commit"),
        ("profile_path", "locked_profile_path"),
        ("target_kind", "locked_target_kind"),
        ("selected_input_scope", "locked_selected_input_scope"),
        ("candidate_status", "locked_candidate_status"),
        ("snapshot_id", "locked_snapshot_id"),
        ("original_archive", "locked_original_archive"),
        (
            "effective_snapshot_archive",
            "locked_effective_snapshot_archive",
        ),
        (
            "ubuntu_archive_signature_verification",
            "locked_ubuntu_archive_signature_verification",
        ),
        ("apt_solver_execution", "locked_apt_solver_execution"),
        ("apt_solver_reexecution", "locked_apt_solver_reexecution"),
        (
            "transitive_closure_independently_recomputed",
            "locked_transitive_closure_independently_recomputed",
        ),
        (
            "object_manifest_record_count",
            "locked_manifest_object_count",
        ),
        ("index_count", "locked_index_count"),
        ("package_count", "locked_package_count"),
        ("state_record_count", "locked_state_record_count"),
        ("ca_bundle_count", "locked_ca_bundle_count"),
        ("candidate_file_count", "locked_candidate_file_count"),
        ("candidate_byte_count", "locked_candidate_byte_count"),
        ("object_count", "locked_object_count"),
        ("candidate_byte_verifier", "locked_candidate_byte_verifier"),
        (
            "candidate_byte_verifier_commit",
            "locked_candidate_byte_verifier_commit",
        ),
        (
            "candidate_byte_verifier_result",
            "locked_candidate_byte_verifier_result",
        ),
        ("network_access", "locked_network_access"),
        ("package_installation", "locked_package_installation"),
        (
            "maintainer_scripts_executed",
            "locked_maintainer_scripts_executed",
        ),
        ("vm_execution", "locked_vm_execution"),
    ];
    const LOCK_DERIVED: &[(&str, &str)] = &[
        ("lock_repository", "external_lock_repository"),
        ("lock_path", "external_lock_path"),
        ("profile_state", "profile_state"),
        ("profile_armable", "profile_armable"),
    ];
    const LOCK_OMITTED: &[(&str, &str)] = &[
        (
            "format",
            "closed by parser acceptance and identified by the exact lock digest and verification status",
        ),
        (
            "profile_field_count",
            "checked by the closed profile parser",
        ),
        ("object_01", OBJECT_OMISSION),
        ("object_02", OBJECT_OMISSION),
        ("object_03", OBJECT_OMISSION),
        ("object_04", OBJECT_OMISSION),
        ("object_05", OBJECT_OMISSION),
        ("object_06", OBJECT_OMISSION),
    ];

    const BOUNDED_PROFILE_SOURCE_SET: &[&str] = &[
        "format",
        "profile_id",
        "architecture",
        "state",
        "armable",
        "expectation_scope",
        "retained_input_authority",
        "purpose",
        "profile_authentication",
        "self_authentication",
        "builder_apt_snapshot_and_closure",
        "builder_apt_top_level_request_count",
        "builder_apt_top_level_requests",
        "unresolved_input_count",
        "unresolved_input_02",
        "release_claim",
        "support_claim",
        "reproducibility_claim",
        "clean_system_claim",
    ];
    const PROFILE_SAME: &[(&str, &str)] = &[
        ("profile_id", "a-quo-omarchy4-aarch64-dec29fa-v2"),
        ("architecture", "aarch64"),
        (
            "profile_authentication",
            "external-pinned-git-object-required",
        ),
    ];
    const PROFILE_RENAMED: &[(&str, &str, &str)] = &[
        ("state", "bootstrap-unarmed", "profile_state"),
        ("armable", "false", "profile_armable"),
        (
            "expectation_scope",
            "reviewed-metadata-only",
            "profile_expectation_scope",
        ),
        (
            "retained_input_authority",
            "none",
            "profile_retained_input_authority",
        ),
        ("purpose", "evaluation-only", "profile_purpose"),
        ("self_authentication", "none", "profile_self_authentication"),
        (
            "builder_apt_snapshot_and_closure",
            "required-not-retained",
            "profile_builder_apt_snapshot_and_closure",
        ),
        (
            "builder_apt_top_level_request_count",
            "14",
            "profile_builder_apt_top_level_request_count",
        ),
        (
            "builder_apt_top_level_requests",
            "ca-certificates,curl,dosfstools,e2fsprogs,fdisk,gnupg,libarchive-tools,openssh-client,parted,qemu-efi-aarch64,qemu-system-arm,qemu-utils,socat,udev",
            "profile_builder_apt_top_level_requests",
        ),
        (
            "unresolved_input_count",
            "10",
            "profile_unresolved_input_count",
        ),
        (
            "unresolved_input_02",
            "ubuntu-apt-snapshot-and-package-lock",
            "profile_unresolved_input_02",
        ),
        ("release_claim", "not-established", "profile_release_claim"),
        ("support_claim", "not-established", "profile_support_claim"),
        (
            "reproducibility_claim",
            "not-established",
            "profile_reproducibility_claim",
        ),
        (
            "clean_system_claim",
            "not-established",
            "profile_clean_system_claim",
        ),
    ];
    const PROFILE_OMITTED: &[(&str, &str, &str)] = &[(
        "format",
        "a-quo-omarchy-evaluation-target-profile-v2",
        "exact profile bytes, profile SHA-256 and closed parser acceptance identify the format",
    )];

    const CURRENT_OPERATION_ACCOUNTING: &[(&str, &str)] = &[
        ("verified_object_count", "0"),
        ("candidate_object_bytes_verified", "false"),
        ("verifier_network_activity", "false"),
        ("whole_machine_network_silence", "not-established"),
        ("archive_filesystem_extraction", "false"),
        ("package_manager_execution", "false"),
        ("package_installation", "false"),
        ("maintainer_scripts_executed", "false"),
        ("mount_execution", "false"),
        ("vm_execution", "false"),
    ];

    fn expectation() -> ExternalLockExpectation {
        ExternalLockExpectation {
            repository: crate::model::CANONICAL_REPOSITORY.to_owned(),
            commit: "0000000000000000000000000000000000000000".to_owned(),
            path: CANONICAL_LOCK_PATH.to_owned(),
            sha256: LOCK_SHA256.to_owned(),
        }
    }

    fn rendered_fields(report: &str) -> BTreeMap<&str, &str> {
        let mut fields = BTreeMap::new();
        for line in report.lines() {
            let (key, value) = line.split_once('=').expect("report field syntax");
            assert!(
                fields.insert(key, value).is_none(),
                "duplicate report key {key}"
            );
        }
        fields
    }

    fn assert_lock_accounting(lock: &AptLock, report: &BTreeMap<&str, &str>) {
        const ALLOWED_OMISSIONS: &[&str] = &[
            "format",
            "profile_field_count",
            "object_01",
            "object_02",
            "object_03",
            "object_04",
            "object_05",
            "object_06",
        ];
        let allowed = ALLOWED_OMISSIONS.iter().copied().collect::<BTreeSet<_>>();
        let mut sources = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        let mut omissions = BTreeSet::new();
        for &(source, destination) in LOCK_RENAMED {
            assert_ne!(source, destination, "ambiguous rename for {source}");
        }
        let mappings = LOCK_SAME
            .iter()
            .map(|source| (*source, *source))
            .chain(LOCK_RENAMED.iter().copied())
            .chain(LOCK_DERIVED.iter().copied());
        for (source, destination) in mappings {
            assert!(
                sources.insert(source),
                "duplicate source accounting for {}",
                source
            );
            assert!(
                destinations.insert(destination),
                "duplicate report destination {destination}"
            );
            assert_eq!(
                report.get(destination).copied(),
                Some(field(&lock.fields, source).expect("accounted source field")),
                "wrong report value for {source} -> {destination}"
            );
        }
        for &(source, rationale) in LOCK_OMITTED {
            assert!(
                sources.insert(source),
                "duplicate source accounting for {source}"
            );
            assert!(
                !rationale.is_empty(),
                "empty omission rationale for {source}"
            );
            assert!(allowed.contains(source), "unapproved omission of {source}");
            assert!(omissions.insert(source), "duplicate omission of {source}");
            field(&lock.fields, source).expect("accounted omitted source field");
        }
        assert_eq!(sources.len(), 62);
        assert_eq!(sources, lock.fields.keys().map(String::as_str).collect());
        assert_eq!(omissions, allowed);
    }

    fn assert_profile_accounting(
        lock: &AptLock,
        profile: &BTreeMap<String, String>,
        report: &BTreeMap<&str, &str>,
    ) {
        let canonical = std::str::from_utf8(CANONICAL_V2_PROFILE.as_bytes()).unwrap();
        let bounded_sources = BOUNDED_PROFILE_SOURCE_SET
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(bounded_sources.len(), BOUNDED_PROFILE_SOURCE_SET.len());
        let mut sources = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        let mappings = PROFILE_SAME
            .iter()
            .map(|(source, expected)| (*source, *expected, *source))
            .chain(PROFILE_RENAMED.iter().copied());
        for (source, expected, destination) in mappings {
            assert!(
                sources.insert(source),
                "duplicate profile source {}",
                source
            );
            assert!(
                destinations.insert(destination),
                "duplicate profile destination {}",
                destination
            );
            assert_eq!(field(profile, source).unwrap(), expected);
            assert_eq!(report.get(destination).copied(), Some(expected));
            let original = format!("{source}={expected}");
            let changed = canonical.replacen(&original, &format!("{source}=unexpected"), 1);
            assert_ne!(
                changed, canonical,
                "missing canonical profile field {}",
                source
            );
            assert!(
                verify_profile(lock, changed.as_bytes()).is_err(),
                "profile verification accepted changed {}",
                source
            );
        }
        for &(source, expected, rationale) in PROFILE_OMITTED {
            assert!(sources.insert(source), "duplicate profile source {source}");
            assert!(
                !rationale.is_empty(),
                "empty profile omission rationale for {source}"
            );
            assert_eq!(field(profile, source).unwrap(), expected);
            assert!(
                !report.contains_key(source),
                "omitted profile source was rendered: {source}"
            );
            let original = format!("{source}={expected}");
            let changed = canonical.replacen(&original, &format!("{source}=unexpected"), 1);
            assert_ne!(
                changed, canonical,
                "missing canonical profile field {source}"
            );
            assert!(
                verify_profile(lock, changed.as_bytes()).is_err(),
                "profile verification accepted changed {source}"
            );
        }
        assert_eq!(profile.len(), 129);
        assert_eq!(sources.len(), 19);
        assert_eq!(sources, bounded_sources);
        assert!(!profile.contains_key("profile_reporting_scope"));
        assert_eq!(
            report.get("profile_reporting_scope").copied(),
            Some("class-02-binding-and-target-readiness-subset")
        );
        for excluded in [
            "profile_unresolved_input_01",
            "profile_unresolved_input_03",
            "profile_unresolved_input_04",
            "profile_unresolved_input_05",
            "profile_unresolved_input_06",
            "profile_unresolved_input_07",
            "profile_unresolved_input_08",
            "profile_unresolved_input_09",
            "profile_unresolved_input_10",
        ] {
            assert!(
                !report.contains_key(excluded),
                "unrelated profile input was rendered: {excluded}"
            );
        }
        let remaining = field(profile, "unresolved_input_count")
            .unwrap()
            .parse::<usize>()
            .unwrap()
            .checked_sub(1)
            .unwrap()
            .to_string();
        assert_eq!(
            report
                .get("remaining_input_count_if_lock_is_adopted")
                .copied(),
            Some(remaining.as_str())
        );
    }

    #[test]
    fn canonical_lock_and_profile_are_closed() {
        let lock = parse_apt_lock(LOCK).unwrap();
        let profile = verify_profile(&lock, CANONICAL_V2_PROFILE.as_bytes()).unwrap();
        let rendered = report(&lock, &expectation(), &profile).unwrap().render();
        assert_eq!(
            rendered,
            include_str!("../tests/fixtures/apt-inspect.report")
        );
        let fields = rendered_fields(&rendered);
        assert_lock_accounting(&lock, &fields);
        assert_profile_accounting(&lock, &profile, &fields);
        for &(key, expected) in CURRENT_OPERATION_ACCOUNTING {
            assert_eq!(
                fields.get(key).copied(),
                Some(expected),
                "wrong current-operation boundary for {key}"
            );
        }
        assert_eq!(lock.objects.len(), 6);
    }

    #[test]
    fn authority_and_missing_key_nonclaims_are_closed() {
        let text = std::str::from_utf8(LOCK).unwrap();
        for (from, to) in [
            (
                "selected_signing_key_material=not-retained",
                "selected_signing_key_material=retained",
            ),
            (
                "build_authorization=not-established",
                "build_authorization=established",
            ),
        ] {
            let changed = text.replacen(from, to, 1);
            assert!(parse_apt_lock(changed.as_bytes()).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_inspection_is_lock_and_profile_only() {
        use crate::debian::sha256;
        use crate::model::CANONICAL_REPOSITORY;

        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let lock_path = repository.join(CANONICAL_LOCK_PATH);
        let profile_path = repository
            .join("packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile");
        let expectation = ExternalLockExpectation {
            repository: CANONICAL_REPOSITORY.to_owned(),
            commit: "0000000000000000000000000000000000000000".to_owned(),
            path: CANONICAL_LOCK_PATH.to_owned(),
            sha256: sha256(LOCK),
        };
        let report = inspect_apt_lock(&lock_path, &expectation, &profile_path)
            .unwrap()
            .render();
        assert_eq!(report, include_str!("../tests/fixtures/apt-inspect.report"));

        let mut wrong_digest = expectation.clone();
        wrong_digest.sha256 = "0".repeat(64);
        assert!(inspect_apt_lock(&lock_path, &wrong_digest, &profile_path).is_err());
        let mut wrong_repository = expectation.clone();
        wrong_repository.repository = "https://example.invalid/a-quo.git".to_owned();
        assert!(inspect_apt_lock(&lock_path, &wrong_repository, &profile_path).is_err());
        let mut wrong_path = expectation;
        wrong_path.path = "packaging/evaluation-input-locks/wrong.lock".to_owned();
        assert!(inspect_apt_lock(&lock_path, &wrong_path, &profile_path).is_err());
    }

    #[test]
    fn implementation_has_no_execution_network_or_extraction_surface() {
        let production = include_str!("apt.rs").split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "Command::new(",
            "std::process",
            "std::net",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "unpack(",
            "unpack_in(",
            "Command::new(\"mount\")",
            "Command::new(\"qemu-system",
            "Command::new(\"dpkg\")",
            "Command::new(\"apt-get\")",
            "Command::new(\"pacman\")",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden APT surface: {forbidden}"
            );
        }
    }
}
