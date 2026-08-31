#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-x86-package-needed-observation-lock.sh"
readonly LOCK="${REPOSITORY_ROOT}/packaging/evaluation-input-locks/a-quo-x86_64-needed-observation-cbbe29b6-v1.lock"
readonly EXPECTED_VERIFIER_SHA256=6f0d8f2ae41f73e094b7d16182e99ef285012eabea4acb894a46cc2ad2491f73
readonly EXPECTED_LOCK_SHA256=216ec3cd2e0698fd42390ade8394e0077ea9a915382de87ae1fe5e864966c9b0

fail_contract() {
  printf 'x86_64 NEEDED observation lock contract failed: %s\n' "$1" >&2
  exit 1
}

for required_tool in chmod cp id ln mktemp mv rm sed sha256sum stat; do
  command -v "${required_tool}" >/dev/null ||
    fail_contract "required contract tool is unavailable: ${required_tool}"
done
[[ -f "${VERIFIER}" && ! -L "${VERIFIER}" && -x "${VERIFIER}" ]] ||
  fail_contract 'lock verifier is unavailable or unsafe'
[[ -f "${LOCK}" && ! -L "${LOCK}" ]] ||
  fail_contract 'canonical lock is unavailable or unsafe'
file_sha256() {
  local digest
  digest="$(sha256sum -- "$1")" || return 1
  printf '%s\n' "${digest%% *}"
}
[[ "$(file_sha256 "${VERIFIER}")" == "${EXPECTED_VERIFIER_SHA256}" ]] ||
  fail_contract 'lock verifier bytes differ from the reviewed contract'
[[ "$(file_sha256 "${LOCK}")" == "${EXPECTED_LOCK_SHA256}" ]] ||
  fail_contract 'lock bytes differ from the reviewed contract'

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-x86-needed-lock-contract.XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_ROOT_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
  fail_contract 'temporary contract directory identity is unavailable'
readonly TEMPORARY_ROOT_IDENTITY
cleanup() {
  local exit_status="$?"
  local current_identity
  trap - EXIT
  case "${TEMPORARY_ROOT}" in
    "${TMPDIR:-/tmp}/a-quo-x86-needed-lock-contract."??????) ;;
    *) fail_contract 'unsafe temporary contract cleanup target' ;;
  esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] ||
    fail_contract 'temporary contract cleanup target changed type'
  current_identity="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
    fail_contract 'temporary contract cleanup identity is unavailable'
  [[ "${current_identity}" == "${TEMPORARY_ROOT_IDENTITY}" ]] ||
    fail_contract 'temporary contract cleanup target was substituted'
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${exit_status}"
}
trap cleanup EXIT

SUCCESS_OUTPUT="$("${VERIFIER}" "${LOCK}")"
readonly SUCCESS_OUTPUT
for required_receipt in \
  'x86_64 NEEDED observation lock passed exact reviewed-byte checks' \
  "lock_sha256=${EXPECTED_LOCK_SHA256}" \
  'observation_authority=none' \
  'observation_source_commit=cbbe29b6bc76949182777d7ec10dc73a219f7592' \
  'observation_run_id=33447883884' \
  'observation_artifact_id=9778938759' \
  'observation_artifact_zip_sha256=97e2dac4a83e8f43f540199bb3b140532159001442ece926b32c9c3d829af394' \
  'observation_package_sha256=52394e2115b0b235dcad849bb91856725e945579266628f0f74fd9e5d64fa264' \
  'architecture=x86_64' \
  'elf_machine=EM_X86_64' \
  'elf_machine_bytes_le=3e00' \
  'elf_interpreter=/lib64/ld-linux-x86-64.so.2' \
  'cli_needed=ld-linux-x86-64.so.2,libc.so.6,libgcc_s.so.1,libm.so.6' \
  'consent_needed=ld-linux-x86-64.so.2,libc.so.6,libgcc_s.so.1,libm.so.6,libwayland-client.so.0' \
  'historical_package_static_acceptance=false' \
  'historical_needed_observation_accepted_as_policy=false' \
  'native_hardware_claim=not-established' \
  'physical_target_evidence=false' \
  'package_source_to_binary_provenance_established=false' \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  [[ "${SUCCESS_OUTPUT}" == *"${required_receipt}"* ]] ||
    fail_contract "lock verification receipt lost field: ${required_receipt}"
done

assert_refused() {
  local label="$1"
  local path="$2"
  local expected="$3"
  local output status
  set +e
  output="$("${VERIFIER}" "${path}" 2>&1)"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && "${output}" == \
    "x86_64 NEEDED observation lock refused: ${expected}" ]] ||
    fail_contract "hostile lock was not refused exactly: label=${label} status=${status} output=${output}"
}

assert_mutation_refused() {
  local label="$1"
  local expression="$2"
  local mutant="${TEMPORARY_ROOT}/${label}.lock"
  sed "${expression}" "${LOCK}" >"${mutant}"
  chmod 0600 -- "${mutant}"
  assert_refused "${label}" "${mutant}" \
    'lock bytes differ from the reviewed observation record'
}

assert_mutation_refused format \
  's/^format=.*/format=a-quo-x86_64-needed-observation-lock-v2/'
assert_mutation_refused role \
  's/^record_role=.*/record_role=authoritative-package-policy/'
assert_mutation_refused review-decision \
  's/^review_decision=.*/review_decision=accept-all-x86-packages/'
assert_mutation_refused authority \
  's/^observation_authority=.*/observation_authority=authoritative/'
assert_mutation_refused repository \
  's#^observation_repository=.*#observation_repository=other/a-quo#'
assert_mutation_refused source-commit \
  's/^observation_source_commit=.*/observation_source_commit=0000000000000000000000000000000000000000/'
assert_mutation_refused run \
  's/^observation_run_id=.*/observation_run_id=1/'
assert_mutation_refused artifact-id \
  's/^observation_artifact_id=.*/observation_artifact_id=1/'
assert_mutation_refused artifact-digest \
  's/^observation_artifact_zip_sha256=.*/observation_artifact_zip_sha256=0000000000000000000000000000000000000000000000000000000000000000/'
assert_mutation_refused package-digest \
  's/^observation_package_sha256=.*/observation_package_sha256=0000000000000000000000000000000000000000000000000000000000000000/'
assert_mutation_refused source-digest \
  's/^observation_source_archive_sha256=.*/observation_source_archive_sha256=0000000000000000000000000000000000000000000000000000000000000000/'
assert_mutation_refused profile \
  's/^profile_id=.*/profile_id=a-quo-omarchy4-aarch64-dec29fa-v2/'
assert_mutation_refused profile-digest \
  's/^profile_sha256=.*/profile_sha256=0000000000000000000000000000000000000000000000000000000000000000/'
assert_mutation_refused namespace \
  's/^evidence_namespace=.*/evidence_namespace=phase-a-aarch64-dec29fa/'
assert_mutation_refused architecture \
  's/^architecture=.*/architecture=aarch64/'
assert_mutation_refused rust-host \
  's/^rust_host=.*/rust_host=aarch64-unknown-linux-gnu/'
assert_mutation_refused repository-snapshot \
  's/^arch_repository_snapshot=.*/arch_repository_snapshot=latest/'
assert_mutation_refused image \
  's/^arch_base_image=.*/arch_base_image=archlinux:latest/'
assert_mutation_refused build-environment \
  's/^build_environment=.*/build_environment=native-hardware/'
assert_mutation_refused elf-class \
  's/^elf_class=.*/elf_class=ELF32/'
assert_mutation_refused elf-data \
  's/^elf_data=.*/elf_data=big-endian/'
assert_mutation_refused elf-machine \
  's/^elf_machine=.*/elf_machine=EM_AARCH64/'
assert_mutation_refused machine-bytes \
  's/^elf_machine_bytes_le=.*/elf_machine_bytes_le=b700/'
assert_mutation_refused interpreter \
  's#^elf_interpreter=.*#elf_interpreter=/lib/ld-linux-aarch64.so.1#'
assert_mutation_refused cli-needed \
  's/^needed_usr_bin_a-quo=.*/needed_usr_bin_a-quo=libc.so.6/'
assert_mutation_refused daemon-needed \
  's/^needed_usr_bin_a-quo-daemon=.*/needed_usr_bin_a-quo-daemon=libc.so.6/'
assert_mutation_refused consent-needed \
  's/^needed_usr_lib_a-quo_a-quo-consent=.*/needed_usr_lib_a-quo_a-quo-consent=libc.so.6/'
assert_mutation_refused historical-acceptance \
  's/^historical_package_static_acceptance=.*/historical_package_static_acceptance=true/'
assert_mutation_refused historical-policy \
  's/^historical_needed_observation_accepted_as_policy=.*/historical_needed_observation_accepted_as_policy=true/'
assert_mutation_refused stage-4 \
  's/^historical_stage_4_completed=.*/historical_stage_4_completed=true/'
assert_mutation_refused stage-5 \
  's/^historical_stage_5_executed=.*/historical_stage_5_executed=true/'
assert_mutation_refused stage-6 \
  's/^historical_stage_6_authorized=.*/historical_stage_6_authorized=true/'
assert_mutation_refused native-hardware \
  's/^native_hardware_claim=.*/native_hardware_claim=verified/'
assert_mutation_refused physical-target \
  's/^physical_target_evidence=.*/physical_target_evidence=true/'
assert_mutation_refused provenance \
  's/^package_source_to_binary_provenance_established=.*/package_source_to_binary_provenance_established=true/'
assert_mutation_refused signature \
  's/^artifact_signature_verified=.*/artifact_signature_verified=true/'
assert_mutation_refused cross-profile \
  's/^cross_profile_evidence_accepted=.*/cross_profile_evidence_accepted=true/'
assert_mutation_refused aarch-gate \
  's/^aarch64_gate_satisfied_by_x86_64=.*/aarch64_gate_satisfied_by_x86_64=true/'

assert_refused missing "${TEMPORARY_ROOT}/missing.lock" \
  'lock must be one regular non-symlink file'
ln -s -- "${LOCK}" "${TEMPORARY_ROOT}/lock-link"
assert_refused symlink "${TEMPORARY_ROOT}/lock-link" \
  'lock must be one regular non-symlink file'

cp -- "${VERIFIER}" "${TEMPORARY_ROOT}/substituted-verifier"
printf '%s\n' '# inserted early-success candidate' >>"${TEMPORARY_ROOT}/substituted-verifier"
[[ "$(file_sha256 "${TEMPORARY_ROOT}/substituted-verifier")" != \
  "${EXPECTED_VERIFIER_SHA256}" ]] ||
  fail_contract 'whole-file verifier pin did not detect source substitution'

printf '%s\n' \
  'x86_64 NEEDED observation lock passed its offline hostile contract' \
  'observation_authority=none' \
  'historical_package_static_acceptance=false' \
  'physical_target_evidence=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false'
