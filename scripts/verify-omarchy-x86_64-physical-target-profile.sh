#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly CANONICAL_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly EXPECTED_PROFILE_SHA256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d
readonly EXPECTED_FIELD_COUNT=86
readonly MAXIMUM_PROFILE_BYTES=16384

fail() {
  printf 'Omarchy x86_64 physical target profile refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--require-runnable] [PROFILE]\n' "${0##*/}" >&2
  exit 2
}

require_runnable=false
profile_path="${CANONICAL_PROFILE}"
case "$#" in
  0) ;;
  1)
    if [[ "$1" == --require-runnable ]]; then
      require_runnable=true
    elif [[ "$1" == --* ]]; then
      usage
    else
      profile_path="$1"
    fi
    ;;
  2)
    [[ "$1" == --require-runnable && "$2" != --* ]] || usage
    require_runnable=true
    profile_path="$2"
    ;;
  *) usage ;;
esac
readonly require_runnable profile_path

for required_tool in od sha256sum stat tail tr wc; do
  command -v "${required_tool}" >/dev/null ||
    fail "required offline verifier tool is unavailable: ${required_tool}"
done

[[ -f "${profile_path}" && ! -L "${profile_path}" ]] ||
  fail 'profile must be one existing regular non-symlink file'
PROFILE_METADATA_BEFORE="$(stat -c '%d:%i:%s:%f:%Y' -- "${profile_path}")" ||
  fail 'profile metadata is unavailable'
readonly PROFILE_METADATA_BEFORE
PROFILE_SIZE="$(stat -c '%s' -- "${profile_path}")" ||
  fail 'profile size is unavailable'
readonly PROFILE_SIZE
if [[ ! "${PROFILE_SIZE}" =~ ^[1-9][0-9]*$ ]] ||
  (( PROFILE_SIZE > MAXIMUM_PROFILE_BYTES )); then
  fail 'profile size is outside the closed bound'
fi
PRINTABLE_SIZE="$(tr -cd '\12\40-\176' <"${profile_path}" | wc -c)"
readonly PRINTABLE_SIZE
[[ "${PRINTABLE_SIZE}" == "${PROFILE_SIZE}" ]] ||
  fail 'profile contains a control, carriage-return, NUL, or non-ASCII byte'
LAST_BYTE="$(tail -c 1 -- "${profile_path}" | od -An -tu1 | tr -d '[:space:]')"
readonly LAST_BYTE
[[ "${LAST_BYTE}" == 10 ]] || fail 'profile must end with one LF byte'

declare -A fields=()
line_number=0
while IFS= read -r line; do
  ((line_number += 1))
  [[ -n "${line}" ]] || fail "blank line at line ${line_number}"
  [[ "${line}" == *=* ]] ||
    fail "missing key/value separator at line ${line_number}"
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${value}" != *'='* ]] ||
    fail "extra key/value separator at line ${line_number}"
  [[ "${key}" =~ ^[a-z][a-z0-9_]{0,63}$ ]] ||
    fail "invalid key at line ${line_number}"
  [[ -n "${value}" && ${#value} -le 1024 && "${value}" != ' '* &&
    "${value}" != *' ' ]] || fail "invalid value bounds at line ${line_number}"
  [[ ! -v "fields[${key}]" ]] || fail "duplicate key: ${key}"
  fields["${key}"]="${value}"
done <"${profile_path}"
readonly line_number
[[ "${line_number}" -eq "${EXPECTED_FIELD_COUNT}" ]] ||
  fail 'profile does not have the exact field count'

PROFILE_METADATA_AFTER="$(stat -c '%d:%i:%s:%f:%Y' -- "${profile_path}")" ||
  fail 'profile metadata became unavailable'
readonly PROFILE_METADATA_AFTER
[[ "${PROFILE_METADATA_AFTER}" == "${PROFILE_METADATA_BEFORE}" ]] ||
  fail 'profile metadata changed during verification'
PROFILE_SHA256="$(sha256sum -- "${profile_path}")"
PROFILE_SHA256="${PROFILE_SHA256%% *}"
readonly PROFILE_SHA256
[[ "${PROFILE_SHA256}" == "${EXPECTED_PROFILE_SHA256}" ]] ||
  fail 'profile bytes do not match the reviewed canonical profile'

assert_field() {
  local key="$1"
  local expected="$2"
  [[ -v "fields[${key}]" ]] || fail "required key is absent: ${key}"
  [[ "${fields[${key}]}" == "${expected}" ]] ||
    fail "unexpected value for ${key}"
}

assert_field format a-quo-omarchy-physical-target-profile-v1
assert_field profile_id a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1
assert_field state reported-baseline-frozen-unarmed
assert_field armable false
assert_field purpose evaluation-only
assert_field target_kind physical-bare-metal
assert_field evidence_namespace physical-x86_64-official-omarchy-4.0.2
assert_field observation_source user-supplied-codex-report
assert_field observation_authority none
assert_field observation_date 2026-08-31
assert_field observation_time_authority none
assert_field profile_authentication external-pinned-git-object-required
assert_field self_authentication none
assert_field architecture x86_64
assert_field package_architecture x86_64
assert_field rust_host x86_64-unknown-linux-gnu
assert_field elf_machine EM_X86_64
assert_field elf_machine_bytes_le 3e00
assert_field elf_interpreter /lib64/ld-linux-x86-64.so.2
assert_field omarchy_package_query 'omarchy 4.0.2-1'
assert_field omarchy_package_architecture any
assert_field omarchy_settings_package_query 'omarchy-settings 4.0.2-1'
assert_field omarchy_settings_package_architecture any
assert_field omarchy_source_repository not-established
assert_field omarchy_source_commit not-established
assert_field omarchy_package_source_to_binary_provenance not-established
assert_field a_quo_installed_state absent
assert_field a_quo_runtime_state absent
assert_field a_quo_evaluator_state absent
assert_field formal_read_only_repeat required
assert_field reconnaissance_side_effect mise-latest-version-cache-file-written
assert_field baseline_claim fresh-working-installation-not-pristine
assert_field clean_system_claim not-established
assert_field reproducibility_claim not-established
assert_field support_claim not-established
assert_field aarch64_claim not-established
assert_field maximum_authorized_stage 5
assert_field physical_target_mutation_authorized false
assert_field stage_6_owner_decision required

if "${require_runnable}"; then
  fail 'profile is unarmed and authorizes no physical-target mutation'
fi

printf '%s\n' \
  "profile_id=${fields[profile_id]}" \
  "profile_sha256=${PROFILE_SHA256}" \
  "evidence_namespace=${fields[evidence_namespace]}" \
  "architecture=${fields[architecture]}" \
  "state=${fields[state]}" \
  "formal_read_only_repeat=${fields[formal_read_only_repeat]}" \
  'physical_target_mutation_authorized=false' \
  'maximum_authorized_stage=5' \
  'network_activity=false' \
  'package_or_service_state_changed=false'
