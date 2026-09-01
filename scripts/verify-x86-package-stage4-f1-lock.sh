#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

fail_lock() {
  printf 'x86_64 stage-4 F1 lock refused: %s\n' "$1" >&2
  exit 1
}

[[ "$#" -eq 0 ]] || {
  printf 'usage: %s\n' "${0##*/}" >&2
  exit 2
}

for required_tool in cut id readlink sha256sum stat tr wc; do
  command -v "${required_tool}" >/dev/null ||
    fail_lock "required verifier tool is unavailable: ${required_tool}"
done

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly LOCK_RELATIVE_PATH='packaging/evaluation-input-locks/a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock'
readonly LOCK="${REPOSITORY_ROOT}/${LOCK_RELATIVE_PATH}"
readonly EXPECTED_LOCK_SHA256=333c9ae548e0f9c269a62859d11a4ccaf0ea4a88c7b0ed0c9a4f19ed785d5d48
readonly MAXIMUM_LOCK_BYTES=8192
readonly EXPECTED_FIELD_COUNT=33
readonly -a EXPECTED_KEYS=(
  format repository profile_id profile_sha256 architecture evidence_namespace
  stage4_source_commit workflow_run_id artifact_id artifact_name
  artifact_zip_sha256 artifact_zip_bytes artifact_member_count
  artifact_member_inventory_sha256 package_filename package_sha256
  static_acceptance_sha256 verifier_receipt_sha256 hosted_acceptance_sha256
  outer_manifest_sha256 stage4_review_issue stage4_review_comment_id
  observation_authority package_static_acceptance stage_4_completed
  stage_5_executed stage_6_authorized native_hardware_claim
  physical_target_evidence cross_profile_evidence_accepted
  aarch64_gate_satisfied_by_x86_64
  package_source_to_binary_provenance_established publication_performed
)

[[ -f "${LOCK}" && ! -L "${LOCK}" ]] ||
  fail_lock 'canonical F1 lock is unavailable or unsafe'
[[ "$(readlink -f -- "${LOCK}")" == "${LOCK}" ]] ||
  fail_lock 'canonical F1 lock path is not stable'
[[ "$(stat -c '%u:%a:%h:%F' -- "${LOCK}")" == \
  "$(id -u):644:1:regular file" ]] ||
  fail_lock 'canonical F1 lock metadata is unsafe'

set +e
IFS= read -r -d '' -n $((MAXIMUM_LOCK_BYTES + 1)) LOCK_BYTES <"${LOCK}"
read_status="$?"
set -e
readonly LOCK_BYTES read_status
[[ "${read_status}" -eq 1 ]] ||
  fail_lock 'F1 lock contains NUL or exceeds its closed byte bound'
LOCK_SIZE="${#LOCK_BYTES}"
readonly LOCK_SIZE
(( LOCK_SIZE > 0 && LOCK_SIZE <= MAXIMUM_LOCK_BYTES )) ||
  fail_lock 'F1 lock is empty or exceeds its closed byte bound'
[[ "${LOCK_BYTES}" == *$'\n' && "${LOCK_BYTES}" != *$'\n\n' ]] ||
  fail_lock 'F1 lock must have exactly one final LF and no blank final field'
[[ "$(printf '%s' "${LOCK_BYTES}" | tr -cd '\11\12\40-\176' | wc -c)" == \
  "${LOCK_SIZE}" ]] || fail_lock 'F1 lock contains a forbidden byte'
LOCK_SHA256="$(printf '%s' "${LOCK_BYTES}" | sha256sum | cut -d ' ' -f 1)"
readonly LOCK_SHA256
[[ "${LOCK_SHA256}" == "${EXPECTED_LOCK_SHA256}" ]] ||
  fail_lock 'F1 lock bytes differ from the reviewed immutable policy'

declare -A field=()
field_index=0
while IFS='=' read -r key value; do
  [[ "${field_index}" -lt "${EXPECTED_FIELD_COUNT}" &&
    "${key}" == "${EXPECTED_KEYS[${field_index}]}" && -n "${value}" &&
    "${value}" != *'='* ]] ||
    fail_lock 'F1 lock fields are missing, duplicated, reordered, or malformed'
  field["${key}"]="${value}"
  ((field_index += 1))
done <<<"${LOCK_BYTES%$'\n'}"
[[ "${field_index}" -eq "${EXPECTED_FIELD_COUNT}" ]] ||
  fail_lock 'F1 lock has the wrong field count'

[[ "${field[format]}" == a-quo-x86_64-stage4-f1-lock-v1 &&
  "${field[repository]}" == SurreptitiousFabric/a-quo &&
  "${field[profile_id]}" == a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1 &&
  "${field[profile_sha256]}" =~ ^[0-9a-f]{64}$ &&
  "${field[architecture]}" == x86_64 &&
  "${field[evidence_namespace]}" == physical-x86_64-official-omarchy-4.0.2 &&
  "${field[stage4_source_commit]}" =~ ^[0-9a-f]{40}$ &&
  "${field[workflow_run_id]}" == 33456949816 &&
  "${field[artifact_id]}" == 9781997778 &&
  "${field[artifact_name]}" == x86-static-acceptance-ee47d7f1e4432ea3b3edab25dc0875b7133d5733-1 &&
  "${field[artifact_zip_sha256]}" =~ ^[0-9a-f]{64}$ &&
  "${field[artifact_zip_bytes]}" =~ ^[1-9][0-9]*$ &&
  "${field[artifact_member_count]}" == 15 &&
  "${field[artifact_member_inventory_sha256]}" =~ ^[0-9a-f]{64}$ &&
  "${field[package_filename]}" =~ ^a-quo-[0-9A-Za-z._+-]+-x86_64\.pkg\.tar\.zst$ &&
  "${field[package_sha256]}" =~ ^[0-9a-f]{64}$ &&
  "${field[static_acceptance_sha256]}" =~ ^[0-9a-f]{64}$ &&
  "${field[verifier_receipt_sha256]}" =~ ^[0-9a-f]{64}$ &&
  "${field[hosted_acceptance_sha256]}" =~ ^[0-9a-f]{64}$ &&
  "${field[outer_manifest_sha256]}" =~ ^[0-9a-f]{64}$ &&
  "${field[stage4_review_issue]}" == 36 &&
  "${field[stage4_review_comment_id]}" == 5487053185 ]] ||
  fail_lock 'F1 lock identity fields violate the reviewed closed mapping'

[[ "${field[observation_authority]}" == none &&
  "${field[package_static_acceptance]}" == true &&
  "${field[stage_4_completed]}" == true &&
  "${field[stage_5_executed]}" == false &&
  "${field[stage_6_authorized]}" == false &&
  "${field[native_hardware_claim]}" == not-established &&
  "${field[physical_target_evidence]}" == false &&
  "${field[cross_profile_evidence_accepted]}" == false &&
  "${field[aarch64_gate_satisfied_by_x86_64]}" == false &&
  "${field[package_source_to_binary_provenance_established]}" == false &&
  "${field[publication_performed]}" == false ]] ||
  fail_lock 'F1 lock acceptance or nonclaim fields changed'

printf '%s' "${LOCK_BYTES}"
printf 'f1_lock_sha256=%s\n' "${LOCK_SHA256}"
