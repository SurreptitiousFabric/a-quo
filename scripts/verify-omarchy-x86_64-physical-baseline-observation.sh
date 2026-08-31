#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly CANONICAL_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh"
readonly CANONICAL_COLLECTOR="${SCRIPT_DIRECTORY}/collect-omarchy-x86_64-physical-baseline.sh"
readonly MAXIMUM_OBSERVATION_BYTES=65536

fail() {
  printf 'Omarchy x86_64 physical baseline observation refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s OBSERVATION [PROFILE]\n' "${0##*/}" >&2
  exit 2
}

[[ "$#" -ge 1 && "$#" -le 2 ]] || usage
readonly OBSERVATION_INPUT="$1"
readonly PROFILE_INPUT="${2:-${CANONICAL_PROFILE}}"

for required_tool in sha256sum stat tr wc; do
  command -v "${required_tool}" >/dev/null ||
    fail "required offline verification tool is unavailable: ${required_tool}"
done
for committed_input in "${CANONICAL_PROFILE}" "${PROFILE_VERIFIER}" \
  "${CANONICAL_COLLECTOR}"; do
  [[ -f "${committed_input}" && ! -L "${committed_input}" ]] ||
    fail "committed verification input is unavailable or unsafe: ${committed_input}"
done
[[ -x "${PROFILE_VERIFIER}" && -x "${CANONICAL_COLLECTOR}" ]] ||
  fail 'committed profile verifier or collector is not executable'
[[ "${PROFILE_INPUT}" == "${CANONICAL_PROFILE}" ]] ||
  fail 'only the canonical physical x86_64 profile is accepted'
"${PROFILE_VERIFIER}" "${CANONICAL_PROFILE}" >/dev/null ||
  fail 'canonical physical x86_64 profile did not verify'

[[ -f "${OBSERVATION_INPUT}" && ! -L "${OBSERVATION_INPUT}" ]] ||
  fail 'observation must be one regular non-symlink file'
OBSERVATION_METADATA_BEFORE="$(stat -c '%d:%i:%s:%f:%Y:%h' -- "${OBSERVATION_INPUT}")" ||
  fail 'observation metadata is unavailable'
readonly OBSERVATION_METADATA_BEFORE
[[ "${OBSERVATION_METADATA_BEFORE##*:}" == 1 ]] ||
  fail 'observation must have exactly one hard link'
set +e
IFS= read -r -d '' -n $((MAXIMUM_OBSERVATION_BYTES + 1)) \
  OBSERVATION_BYTES <"${OBSERVATION_INPUT}"
OBSERVATION_READ_STATUS="$?"
set -e
readonly OBSERVATION_BYTES OBSERVATION_READ_STATUS
[[ "${OBSERVATION_READ_STATUS}" -eq 1 ]] ||
  fail 'observation contains NUL or exceeds the closed size bound'
readonly OBSERVATION_SIZE="${#OBSERVATION_BYTES}"
(( OBSERVATION_SIZE >= 1 && OBSERVATION_SIZE <= MAXIMUM_OBSERVATION_BYTES )) ||
  fail 'observation size is outside the closed bound'
PRINTABLE_SIZE="$(printf '%s' "${OBSERVATION_BYTES}" | tr -cd '\12\40-\176' | wc -c)"
readonly PRINTABLE_SIZE
[[ "${PRINTABLE_SIZE}" == "${OBSERVATION_SIZE}" ]] ||
  fail 'observation contains a control, CR, NUL, or non-ASCII byte'
[[ "${OBSERVATION_BYTES: -1}" == $'\n' ]] ||
  fail 'observation must end with one LF byte'
readonly OBSERVATION_BODY="${OBSERVATION_BYTES%$'\n'}"
[[ "${OBSERVATION_BODY}" != *$'\n' ]] ||
  fail 'observation must end with exactly one LF byte'

readonly -a EXPECTED_KEYS=(
  format profile_id profile_sha256 evidence_namespace collector_repository_path
  collector_sha256 observation_source observation_authority observation_time
  observation_time_authority profile_authentication execution_privilege
  architecture hardware_vendor hardware_model cpu_model cpu_core_count
  cpu_thread_count os_name os_version os_release_sha256 kernel_release
  glibc_version pacman_version pacman_architecture pacman_repository_name_set
  pacman_database_consistency pacman_lock_state installed_package_count
  installed_package_query_sha256 omarchy_package_query
  omarchy_package_architecture omarchy_package_archive_sha256
  omarchy_settings_package_query omarchy_settings_package_architecture
  omarchy_settings_package_archive_sha256 omarchy_package_altered_file_count
  omarchy_settings_observed_altered_file_count
  omarchy_settings_root_only_unverified_file_count hyprland_version
  quickshell_version uwsm_version systemd_version session_type wayland_display
  graphical_session_target runtime_directory runtime_directory_owner_uid
  runtime_directory_mode runtime_directory_filesystem user_manager_environment_set
  omarchy_path user_state_filesystem omarchy_plugin_validate_metadata
  omarchy_shell_metadata omarchy_shell_rescan_plugins
  omarchy_plugin_directory_state omarchy_shell_configuration_schema
  omarchy_shell_configuration_mode omarchy_shell_configuration_sha256
  a_quo_installed_state a_quo_runtime_state a_quo_evaluator_state
  formal_read_only_repeat collector_mise_invoked collector_network_command_invoked
  collector_update_capable_command_invoked physical_target_mutation_requested
  relevant_state_before_after profile_match_claim clean_system_claim
  reproducibility_claim source_to_binary_provenance aarch64_gate_satisfied
  maximum_authorized_stage stage_6_owner_decision
)
declare -A observed=()
line_index=0
while IFS= read -r line; do
  [[ "${line_index}" -lt "${#EXPECTED_KEYS[@]}" ]] ||
    fail 'observation has extra fields'
  [[ -n "${line}" && "${line}" == *=* ]] ||
    fail "observation line $((line_index + 1)) is malformed"
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${key}" == "${EXPECTED_KEYS[${line_index}]}" ]] ||
    fail "observation field is missing or reordered at line $((line_index + 1))"
  [[ "${key}" =~ ^[a-z][a-z0-9_]{0,63}$ && -n "${value}" &&
    ${#value} -le 4096 && "${value}" != *'='* && "${value}" != ' '* &&
    "${value}" != *' ' ]] || fail "observation value is malformed: ${key}"
  [[ ! -v "observed[${key}]" ]] || fail "duplicate observation field: ${key}"
  observed["${key}"]="${value}"
  ((line_index += 1))
done <<<"${OBSERVATION_BODY}"
[[ "${line_index}" -eq "${#EXPECTED_KEYS[@]}" ]] ||
  fail 'observation does not have the exact field count'

OBSERVATION_METADATA_AFTER="$(stat -c '%d:%i:%s:%f:%Y:%h' -- "${OBSERVATION_INPUT}")" ||
  fail 'observation metadata became unavailable'
readonly OBSERVATION_METADATA_AFTER
[[ "${OBSERVATION_METADATA_AFTER}" == "${OBSERVATION_METADATA_BEFORE}" ]] ||
  fail 'observation metadata changed during verification'
OBSERVATION_SHA256="$(printf '%s' "${OBSERVATION_BYTES}" | sha256sum)"
OBSERVATION_SHA256="${OBSERVATION_SHA256%% *}"
readonly OBSERVATION_SHA256
[[ "${OBSERVATION_SHA256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'observation hash is malformed'

declare -A profile=()
while IFS= read -r line; do
  profile["${line%%=*}"]="${line#*=}"
done <"${CANONICAL_PROFILE}"
PROFILE_SHA256="$(sha256sum -- "${CANONICAL_PROFILE}")"
PROFILE_SHA256="${PROFILE_SHA256%% *}"
readonly PROFILE_SHA256
COLLECTOR_SHA256="$(sha256sum -- "${CANONICAL_COLLECTOR}")"
COLLECTOR_SHA256="${COLLECTOR_SHA256%% *}"
readonly COLLECTOR_SHA256

assert_value() {
  local key="$1"
  local expected="$2"
  [[ "${observed[${key}]}" == "${expected}" ]] ||
    fail "unexpected observation value: ${key}"
}

assert_profile_value() {
  local key="$1"
  local profile_key="${2:-$1}"
  [[ -v "profile[${profile_key}]" ]] ||
    fail "canonical profile lacks required comparison field: ${profile_key}"
  assert_value "${key}" "${profile[${profile_key}]}"
}

assert_value format a-quo-omarchy-x86_64-read-only-observation-v1
assert_profile_value profile_id
assert_value profile_sha256 "${PROFILE_SHA256}"
assert_profile_value evidence_namespace
assert_value collector_repository_path scripts/collect-omarchy-x86_64-physical-baseline.sh
assert_value collector_sha256 "${COLLECTOR_SHA256}"
assert_value observation_source direct-tool-local-execution
assert_value observation_authority none
assert_value observation_time not-recorded
assert_value observation_time_authority none
assert_value profile_authentication external-pinned-git-object-required
assert_value execution_privilege ordinary-desktop-user

for profile_bound_key in \
  architecture hardware_vendor hardware_model cpu_model cpu_core_count \
  cpu_thread_count os_name os_version os_release_sha256 kernel_release \
  glibc_version pacman_version pacman_architecture pacman_repository_name_set \
  pacman_database_consistency pacman_lock_state installed_package_count \
  installed_package_query_sha256 omarchy_package_query \
  omarchy_package_architecture omarchy_package_archive_sha256 \
  omarchy_settings_package_query omarchy_settings_package_architecture \
  omarchy_settings_package_archive_sha256 omarchy_package_altered_file_count \
  omarchy_settings_observed_altered_file_count \
  omarchy_settings_root_only_unverified_file_count hyprland_version \
  quickshell_version uwsm_version systemd_version session_type wayland_display \
  graphical_session_target runtime_directory runtime_directory_owner_uid \
  runtime_directory_mode runtime_directory_filesystem user_manager_environment_set \
  omarchy_path user_state_filesystem omarchy_plugin_validate_metadata \
  omarchy_shell_metadata omarchy_shell_rescan_plugins \
  omarchy_plugin_directory_state omarchy_shell_configuration_schema \
  omarchy_shell_configuration_mode omarchy_shell_configuration_sha256 \
  a_quo_installed_state a_quo_runtime_state a_quo_evaluator_state; do
  assert_profile_value "${profile_bound_key}"
done

assert_value formal_read_only_repeat completed-non-authoritative
assert_value collector_mise_invoked false
assert_value collector_network_command_invoked false
assert_value collector_update_capable_command_invoked false
assert_value physical_target_mutation_requested false
assert_value relevant_state_before_after unchanged
assert_value profile_match_claim not-evaluated-by-collector
assert_value clean_system_claim not-established
assert_value reproducibility_claim not-established
assert_value source_to_binary_provenance not-established
assert_value aarch64_gate_satisfied false
assert_value maximum_authorized_stage 5
assert_value stage_6_owner_decision required

printf '%s\n' \
  'format=a-quo-omarchy-x86_64-read-only-observation-verification-v1' \
  "observation_sha256=${OBSERVATION_SHA256}" \
  "collector_sha256=${COLLECTOR_SHA256}" \
  "profile_id=${observed[profile_id]}" \
  "profile_sha256=${PROFILE_SHA256}" \
  "evidence_namespace=${observed[evidence_namespace]}" \
  "architecture=${observed[architecture]}" \
  'profile_binding_role=physical-baseline-observation' \
  'profile_match=verified-non-authoritative' \
  'observation_authority=none' \
  'authenticated_physical_target_match=false' \
  'physical_target_execution=claimed-by-unauthenticated-receipt' \
  'formal_read_only_repeat=verified-receipt-non-authoritative' \
  'relevant_state_before_after=unchanged' \
  'physical_target_mutation_requested=false' \
  'stage_4_package_evidence=false' \
  'stage_5_lifecycle_evidence=false' \
  'aarch64_gate_satisfied_by_x86_64=false' \
  'maximum_authorized_stage=5' \
  'stage_6_owner_decision=required'
