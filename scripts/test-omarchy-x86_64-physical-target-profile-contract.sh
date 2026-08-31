#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh"
readonly PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly EXPECTED_PROFILE_SHA256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-x86-profile-contract.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

assert_refused() {
  local label="$1"
  local expected="$2"
  shift 2
  local output
  local status
  set +e
  output="$("${VERIFIER}" "$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != *"${expected}"* ]]; then
    printf 'x86 profile mutation was not refused: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

replace_field() {
  local input="$1"
  local output="$2"
  local key="$3"
  local value="$4"
  awk -v key="${key}" -v value="${value}" \
    'BEGIN { FS = OFS = "=" } $1 == key { $0 = key OFS value } { print }' \
    "${input}" >"${output}"
}

EXPECTED_OUTPUT="$(printf '%s\n' \
  'profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  "profile_sha256=${EXPECTED_PROFILE_SHA256}" \
  'evidence_namespace=physical-x86_64-official-omarchy-4.0.2' \
  'architecture=x86_64' \
  'state=reported-baseline-frozen-unarmed' \
  'formal_read_only_repeat=required' \
  'physical_target_mutation_authorized=false' \
  'maximum_authorized_stage=5' \
  'network_activity=false' \
  'package_or_service_state_changed=false')"
readonly EXPECTED_OUTPUT
OBSERVED_OUTPUT="$("${VERIFIER}")"
readonly OBSERVED_OUTPUT
[[ "${OBSERVED_OUTPUT}" == "${EXPECTED_OUTPUT}" ]] || {
  printf 'canonical x86 profile output mismatch: %q\n' "${OBSERVED_OUTPUT}" >&2
  exit 1
}

assert_refused require-runnable \
  'profile is unarmed and authorizes no physical-target mutation' \
  --require-runnable "${PROFILE}"

set +e
USAGE_OUTPUT="$("${VERIFIER}" one two three 2>&1)"
USAGE_STATUS="$?"
set -e
[[ "${USAGE_STATUS}" -eq 2 && "${USAGE_OUTPUT}" == usage:* ]] || {
  printf 'x86 profile verifier usage refusal mismatch: %s %q\n' \
    "${USAGE_STATUS}" "${USAGE_OUTPUT}" >&2
  exit 1
}

mkdir -- "${TEMPORARY_ROOT}/directory"
assert_refused directory 'profile must be one existing regular non-symlink file' \
  "${TEMPORARY_ROOT}/directory"
ln -s -- "${PROFILE}" "${TEMPORARY_ROOT}/profile-link"
assert_refused symlink 'profile must be one existing regular non-symlink file' \
  "${TEMPORARY_ROOT}/profile-link"
mkfifo -- "${TEMPORARY_ROOT}/profile-fifo"
assert_refused fifo 'profile must be one existing regular non-symlink file' \
  "${TEMPORARY_ROOT}/profile-fifo"
dd if=/dev/zero of="${TEMPORARY_ROOT}/oversized" bs=16385 count=1 status=none
assert_refused oversized 'profile size is outside the closed bound' \
  "${TEMPORARY_ROOT}/oversized"
head -c -1 -- "${PROFILE}" >"${TEMPORARY_ROOT}/missing-final-lf"
assert_refused missing-final-lf 'profile must end with one LF byte' \
  "${TEMPORARY_ROOT}/missing-final-lf"
awk 'NR == 1 { printf "%s\r\n", $0; next } { print }' \
  "${PROFILE}" >"${TEMPORARY_ROOT}/carriage-return"
assert_refused carriage-return 'profile contains a control' \
  "${TEMPORARY_ROOT}/carriage-return"
cp -- "${PROFILE}" "${TEMPORARY_ROOT}/duplicate"
head -n 1 -- "${PROFILE}" >>"${TEMPORARY_ROOT}/duplicate"
assert_refused duplicate 'duplicate key: format' "${TEMPORARY_ROOT}/duplicate"
cp -- "${PROFILE}" "${TEMPORARY_ROOT}/unknown"
printf '%s\n' 'unknown=value' >>"${TEMPORARY_ROOT}/unknown"
assert_refused unknown 'profile does not have the exact field count' \
  "${TEMPORARY_ROOT}/unknown"
awk 'NR == 1 { first = $0; next } NR == 2 { print; print first; next } { print }' \
  "${PROFILE}" >"${TEMPORARY_ROOT}/reordered"
assert_refused reordered 'profile bytes do not match the reviewed canonical profile' \
  "${TEMPORARY_ROOT}/reordered"

for mutation in \
  'architecture|aarch64' \
  'profile_id|a-quo-omarchy4-aarch64-dec29fa-v2' \
  'evidence_namespace|phase-a-aarch64' \
  'observation_authority|authoritative' \
  'observation_date|2026-09-01' \
  'observation_time_authority|trusted' \
  'omarchy_source_repository|https://github.com/basecamp/omarchy.git' \
  'omarchy_source_commit|0000000000000000000000000000000000000000' \
  'omarchy_package_source_to_binary_provenance|established' \
  'armable|true' \
  'clean_system_claim|established' \
  'aarch64_claim|established' \
  'physical_target_mutation_authorized|true' \
  'maximum_authorized_stage|6' \
  'stage_6_owner_decision|approved' \
  'formal_read_only_repeat|complete'; do
  key="${mutation%%|*}"
  value="${mutation#*|}"
  replace_field "${PROFILE}" "${TEMPORARY_ROOT}/${key}" "${key}" "${value}"
  assert_refused "${key}" \
    'profile bytes do not match the reviewed canonical profile' \
    "${TEMPORARY_ROOT}/${key}"
done

if grep -Eq '^[[:space:]]*(source|eval)[[:space:]]' "${VERIFIER}"; then
  printf '%s\n' 'x86 profile verifier executes source or eval' >&2
  exit 1
fi
if grep -Eq '(^|[;&|[:space:]/])(curl|wget|gh|docker|podman|qemu-system|pacman|systemctl|mount|sudo|mise)([;&|[:space:]]|$)' \
  "${VERIFIER}"; then
  printf '%s\n' 'x86 profile verifier contains a mutating or update-capable command' >&2
  exit 1
fi

printf '%s\n' \
  'x86_64 physical Omarchy profile passed offline immutable hostile-input checks'
