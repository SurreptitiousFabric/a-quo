#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_LAZY_FETCH=1
umask 077

fail() {
  printf 'x86_64 package NEEDED observation bundle refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s EXPECTED_SOURCE_COMMIT\n' "${0##*/}" >&2
  exit 2
}

for git_environment_override in \
  GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_CEILING_DIRECTORIES \
  GIT_COMMON_DIR \
  GIT_CONFIG \
  GIT_CONFIG_COUNT \
  GIT_CONFIG_GLOBAL \
  GIT_CONFIG_NOSYSTEM \
  GIT_CONFIG_PARAMETERS \
  GIT_CONFIG_SYSTEM \
  GIT_DIR \
  GIT_DISCOVERY_ACROSS_FILESYSTEM \
  GIT_EXEC_PATH \
  GIT_GRAFT_FILE \
  GIT_INDEX_FILE \
  GIT_NAMESPACE \
  GIT_OBJECT_DIRECTORY \
  GIT_OPTIONAL_LOCKS \
  GIT_QUARANTINE_PATH \
  GIT_REPLACE_REF_BASE \
  GIT_SHALLOW_FILE \
  GIT_WORK_TREE; do
  [[ ! -v "${git_environment_override}" ]] ||
    fail "inherited Git repository override: ${git_environment_override}"
done
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_OPTIONAL_LOCKS=0

[[ "$#" -eq 1 ]] || usage
readonly EXPECTED_SOURCE_COMMIT="$1"
[[ "${EXPECTED_SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'expected source commit must be one full lowercase Git object ID'

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly TARGET_RESOLVER="${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh"
readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh"
readonly PACKAGE_VERIFIER="${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh"
readonly EXPECTED_TARGET_RESOLVER_SHA256=60cc574be2340c94c8da353489c104ac6fc202f10b2b9d983d368852c392ffea
readonly EXPECTED_PROFILE_VERIFIER_SHA256=af95814e6844362afce6e5cc1a4275abc18b3202f62776e19f17c87a699dc2fc
readonly EXPECTED_PACKAGE_VERIFIER_SHA256=f0427319b1d6903261903c3756d1c2bf77b261be9a298b413fe317c41d495c92
readonly MAXIMUM_PACKAGE_BYTES=268435456
readonly MAXIMUM_SOURCE_ARCHIVE_BYTES=67108864
readonly MAXIMUM_TEXT_BYTES=1048576

for required_tool in \
  chmod cmp dd find git grep head mkdir mktemp realpath rm sed sha256sum sort \
  stat tr wc; do
  command -v "${required_tool}" >/dev/null ||
    fail "required offline bundle-verification tool is unavailable: ${required_tool}"
done
for committed_input in \
  "${PROFILE}" "${TARGET_RESOLVER}" "${PROFILE_VERIFIER}" \
  "${PACKAGE_VERIFIER}"; do
  [[ -f "${committed_input}" && ! -L "${committed_input}" ]] ||
    fail "committed bundle-verification input is unavailable or unsafe: ${committed_input}"
done
[[ -x "${TARGET_RESOLVER}" && -x "${PROFILE_VERIFIER}" && \
  -x "${PACKAGE_VERIFIER}" ]] ||
  fail 'committed resolver or verifier input is not executable'
file_sha256() {
  local path="$1"
  local digest
  digest="$(sha256sum -- "${path}")" || return 1
  printf '%s\n' "${digest%% *}"
}
TARGET_RESOLVER_SHA256="$(file_sha256 "${TARGET_RESOLVER}")"
PROFILE_VERIFIER_SHA256="$(file_sha256 "${PROFILE_VERIFIER}")"
PACKAGE_VERIFIER_SHA256="$(file_sha256 "${PACKAGE_VERIFIER}")"
readonly TARGET_RESOLVER_SHA256 PROFILE_VERIFIER_SHA256
readonly PACKAGE_VERIFIER_SHA256
[[ "${TARGET_RESOLVER_SHA256}" == "${EXPECTED_TARGET_RESOLVER_SHA256}" ]] ||
  fail 'package-target resolver bytes differ from the reviewed baseline'
[[ "${PROFILE_VERIFIER_SHA256}" == "${EXPECTED_PROFILE_VERIFIER_SHA256}" ]] ||
  fail 'x86_64 profile verifier bytes differ from the reviewed baseline'
[[ "${PACKAGE_VERIFIER_SHA256}" == "${EXPECTED_PACKAGE_VERIFIER_SHA256}" ]] ||
  fail 'accepted package verifier bytes differ from the reviewed baseline'

GIT_COMMON_DIRECTORY="$(
  git -C "${REPOSITORY_ROOT}" rev-parse \
    --path-format=absolute --git-common-dir
)" || fail 'source checkout Git common directory could not be inspected'
readonly GIT_COMMON_DIRECTORY
[[ -d "${GIT_COMMON_DIRECTORY}" && ! -L "${GIT_COMMON_DIRECTORY}" ]] ||
  fail 'source checkout Git common directory is unavailable or unsafe'
[[ ! -e "${GIT_COMMON_DIRECTORY}/info/grafts" && \
  ! -L "${GIT_COMMON_DIRECTORY}/info/grafts" ]] ||
  fail 'source checkout contains a legacy graft file'
for alternate_file in \
  "${GIT_COMMON_DIRECTORY}/objects/info/alternates" \
  "${GIT_COMMON_DIRECTORY}/objects/info/http-alternates"; do
  [[ ! -e "${alternate_file}" && ! -L "${alternate_file}" ]] ||
    fail 'source checkout uses an alternate Git object store'
done
[[ "$(git -C "${REPOSITORY_ROOT}" rev-parse --is-shallow-repository)" == false ]] ||
  fail 'bundle verification requires complete non-shallow Git history'
set +e
PARTIAL_CLONE_CONFIGURATION="$(
  git -C "${REPOSITORY_ROOT}" config --local --get-regexp \
    '^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$'
)"
PARTIAL_CLONE_STATUS="$?"
set -e
readonly PARTIAL_CLONE_CONFIGURATION PARTIAL_CLONE_STATUS
[[ "${PARTIAL_CLONE_STATUS}" -eq 1 && \
  -z "${PARTIAL_CLONE_CONFIGURATION}" ]] ||
  fail 'source checkout has partial-clone or promisor configuration'
REPLACEMENT_REF="$(
  git -C "${REPOSITORY_ROOT}" for-each-ref --count=1 \
    --format='%(refname)' refs/replace
)" || fail 'source checkout replacement refs could not be inspected'
readonly REPLACEMENT_REF
[[ -z "${REPLACEMENT_REF}" ]] ||
  fail 'source checkout contains replacement refs'
SOURCE_HEAD="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)" ||
  fail 'source checkout HEAD could not be inspected'
readonly SOURCE_HEAD
[[ "${SOURCE_HEAD}" == "${EXPECTED_SOURCE_COMMIT}" ]] ||
  fail 'expected source commit is not the current checkout HEAD'
SOURCE_STATUS="$(
  git -C "${REPOSITORY_ROOT}" -c core.fsmonitor=false \
    status --porcelain=v1 --untracked-files=normal
)" || fail 'source checkout cleanliness could not be inspected'
readonly SOURCE_STATUS
[[ -z "${SOURCE_STATUS}" ]] ||
  fail 'source checkout must be clean at the expected source commit'
git -C "${REPOSITORY_ROOT}" cat-file -e \
  "${EXPECTED_SOURCE_COMMIT}^{commit}" 2>/dev/null ||
  fail 'expected source commit is unavailable'

TARGET_MAPPING="$("${TARGET_RESOLVER}" "${PROFILE}")" ||
  fail 'canonical x86_64 package target did not resolve'
readonly TARGET_MAPPING
declare -A target=()
readonly -a TARGET_KEYS=(
  profile_id profile_repository_path profile_sha256 target_kind architecture
  rust_host elf_machine elf_machine_bytes_le elf_interpreter package_suffix
  evidence_namespace output_layout build_environment cli_needed consent_needed
  needed_evidence
)
target_index=0
while IFS='=' read -r key value; do
  [[ "${target_index}" -lt "${#TARGET_KEYS[@]}" &&
    "${key}" == "${TARGET_KEYS[${target_index}]}" && -n "${value}" &&
    "${value}" != *'='* ]] ||
    fail 'package-target resolver returned a malformed or reordered mapping'
  target["${key}"]="${value}"
  ((target_index += 1))
done <<<"${TARGET_MAPPING}"
[[ "${target_index}" -eq "${#TARGET_KEYS[@]}" ]] ||
  fail 'package-target resolver returned an incomplete mapping'
[[ "${target[architecture]}|${target[evidence_namespace]}|${target[needed_evidence]}" == \
  'x86_64|physical-x86_64-official-omarchy-4.0.2|unconfirmed-architecture-matched-x86_64-package-required' ]] ||
  fail 'closed x86_64 target is no longer the unconfirmed observation tuple'

SOURCE_COMMIT_COUNT="$(git -C "${REPOSITORY_ROOT}" rev-list --count \
  "${EXPECTED_SOURCE_COMMIT}")"
readonly SOURCE_COMMIT_COUNT
[[ "${SOURCE_COMMIT_COUNT}" =~ ^[1-9][0-9]*$ ]] ||
  fail 'expected source commit count is malformed'
WORKSPACE_VERSION="$(
  git -C "${REPOSITORY_ROOT}" show "${EXPECTED_SOURCE_COMMIT}:Cargo.toml" |
    sed -n 's/^version = "\([^"]*\)"$/\1/p' | head -n 1
)"
readonly WORKSPACE_VERSION
[[ "${WORKSPACE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail 'committed workspace version is malformed'
readonly PACKAGE_VERSION="${WORKSPACE_VERSION}.r${SOURCE_COMMIT_COUNT}.g${EXPECTED_SOURCE_COMMIT:0:12}-1"
readonly PACKAGE_NAME="a-quo-${PACKAGE_VERSION}-x86_64.pkg.tar.zst"
readonly SOURCE_ARCHIVE_NAME="a-quo-${EXPECTED_SOURCE_COMMIT}.tar"
readonly BUNDLE_ROOT="${REPOSITORY_ROOT}/target/arch-package-needed-observations/${target[evidence_namespace]}"
readonly BUNDLE="${BUNDLE_ROOT}/${EXPECTED_SOURCE_COMMIT}"
[[ -d "${BUNDLE}" && ! -L "${BUNDLE}" ]] ||
  fail 'fixed observation bundle directory is unavailable or unsafe'
[[ "$(realpath -e -- "${BUNDLE}")" == "${BUNDLE}" ]] ||
  fail 'observation bundle does not resolve to its fixed canonical path'

TEMPORARY_ROOT="$(mktemp -d "${REPOSITORY_ROOT}/target/.a-quo-needed-bundle-verify.XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_ROOT_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
  fail 'temporary verifier directory identity is unavailable'
readonly TEMPORARY_ROOT_IDENTITY
cleanup() {
  local exit_status="$?"
  local current_identity
  trap - EXIT
  case "${TEMPORARY_ROOT}" in
    "${REPOSITORY_ROOT}/target/.a-quo-needed-bundle-verify."??????) ;;
    *) fail 'unsafe temporary verifier cleanup target' ;;
  esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] ||
    fail 'temporary verifier cleanup target changed type'
  current_identity="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
    fail 'temporary verifier cleanup target identity is unavailable'
  [[ "${current_identity}" == "${TEMPORARY_ROOT_IDENTITY}" ]] ||
    fail 'temporary verifier cleanup target was substituted'
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${exit_status}"
}
trap cleanup EXIT

readonly EXPECTED_INVENTORY="${TEMPORARY_ROOT}/expected-inventory"
readonly OBSERVED_INVENTORY="${TEMPORARY_ROOT}/observed-inventory"
printf '%s\n' \
  .SRCINFO \
  BUILDER-OBSERVATION.txt \
  OBSERVATION-NONACCEPTING \
  PKGBUILD \
  SHA256SUMS \
  VERIFIER-OBSERVATION.stderr \
  VERIFIER-OBSERVATION.txt \
  "${PACKAGE_NAME}" \
  "${SOURCE_ARCHIVE_NAME}" | sort >"${EXPECTED_INVENTORY}"
find "${BUNDLE}" -mindepth 1 -maxdepth 1 -printf '%f\n' |
  sort >"${OBSERVED_INVENTORY}"
cmp -- "${EXPECTED_INVENTORY}" "${OBSERVED_INVENTORY}" ||
  fail 'observation bundle differs from the closed file inventory'

while IFS= read -r entry; do
  entry_path="${BUNDLE}/${entry}"
  [[ -f "${entry_path}" && ! -L "${entry_path}" ]] ||
    fail "bundle entry is not one regular non-symlink file: ${entry}"
  [[ "$(stat -c '%a:%h:%F' -- "${entry_path}")" == \
    '644:1:regular file' ]] ||
    fail "bundle entry metadata is unsafe: ${entry}"
done <"${EXPECTED_INVENTORY}"

readonly BUNDLE_PACKAGE="${BUNDLE}/${PACKAGE_NAME}"
readonly BUNDLE_SOURCE_ARCHIVE="${BUNDLE}/${SOURCE_ARCHIVE_NAME}"
PACKAGE_SIZE="$(stat -c '%s' -- "${BUNDLE_PACKAGE}")"
SOURCE_ARCHIVE_SIZE="$(stat -c '%s' -- "${BUNDLE_SOURCE_ARCHIVE}")"
readonly PACKAGE_SIZE SOURCE_ARCHIVE_SIZE
if [[ ! "${PACKAGE_SIZE}" =~ ^[1-9][0-9]*$ ]] ||
  (( PACKAGE_SIZE > MAXIMUM_PACKAGE_BYTES )); then
  fail 'observed package is empty or exceeds the closed 256 MiB bound'
fi
if [[ ! "${SOURCE_ARCHIVE_SIZE}" =~ ^[1-9][0-9]*$ ]] ||
  (( SOURCE_ARCHIVE_SIZE > MAXIMUM_SOURCE_ARCHIVE_BYTES )); then
  fail 'source archive is empty or exceeds the closed 64 MiB bound'
fi
for text_entry in \
  .SRCINFO BUILDER-OBSERVATION.txt OBSERVATION-NONACCEPTING PKGBUILD \
  SHA256SUMS VERIFIER-OBSERVATION.stderr VERIFIER-OBSERVATION.txt; do
  text_size="$(stat -c '%s' -- "${BUNDLE}/${text_entry}")"
  if [[ ! "${text_size}" =~ ^[1-9][0-9]*$ ]] ||
    (( text_size > MAXIMUM_TEXT_BYTES )); then
    fail "text bundle entry is empty or too large: ${text_entry}"
  fi
done

readonly CHECKSUMS="${BUNDLE}/SHA256SUMS"
[[ "$(wc -l <"${CHECKSUMS}")" -eq 8 ]] ||
  fail 'bundle checksum manifest does not have the exact entry count'
if grep -Ev '^([0-9a-f]{64})  \./([^/]+)$' "${CHECKSUMS}" | grep -q .; then
  fail 'bundle checksum manifest contains a malformed record'
fi
if grep -Fq '  ./SHA256SUMS' "${CHECKSUMS}"; then
  fail 'bundle checksum manifest recursively includes itself'
fi
readonly EXPECTED_CHECKSUM_ENTRIES="${TEMPORARY_ROOT}/expected-checksum-entries"
readonly OBSERVED_CHECKSUM_ENTRIES="${TEMPORARY_ROOT}/observed-checksum-entries"
grep -Fvx SHA256SUMS "${EXPECTED_INVENTORY}" | sed 's|^|./|' |
  sort >"${EXPECTED_CHECKSUM_ENTRIES}"
sed -n 's/^[0-9a-f]\{64\}  //p' "${CHECKSUMS}" |
  sort >"${OBSERVED_CHECKSUM_ENTRIES}"
cmp -- "${EXPECTED_CHECKSUM_ENTRIES}" "${OBSERVED_CHECKSUM_ENTRIES}" ||
  fail 'bundle checksum manifest does not cover the exact closed inventory'
(
  cd -- "${BUNDLE}"
  sha256sum --check --strict SHA256SUMS >/dev/null
) || fail 'bundle checksum verification failed'

readonly SNAPSHOT_DIRECTORY="${TEMPORARY_ROOT}/snapshots"
mkdir -m 0700 -- "${SNAPSHOT_DIRECTORY}"
snapshot_bounded_file() {
  local label="$1"
  local source="$2"
  local destination="$3"
  local maximum_mebibytes="$4"
  local metadata_before
  local metadata_after
  local snapshot_size
  metadata_before="$(stat -c '%d:%i:%s:%f:%Y:%Z:%h' -- "${source}")" ||
    fail "${label} metadata is unavailable before snapshot"
  [[ "${metadata_before##*:}" == 1 ]] ||
    fail "${label} must have exactly one hard link"
  dd if="${source}" of="${destination}" bs=1048576 \
    count="$((maximum_mebibytes + 1))" iflag=fullblock,nofollow,nonblock \
    status=none || fail "${label} bounded snapshot failed"
  metadata_after="$(stat -c '%d:%i:%s:%f:%Y:%Z:%h' -- "${source}")" ||
    fail "${label} metadata is unavailable after snapshot"
  [[ "${metadata_after}" == "${metadata_before}" ]] ||
    fail "${label} changed while its private snapshot was created"
  snapshot_size="$(stat -c '%s' -- "${destination}")"
  if [[ ! "${snapshot_size}" =~ ^[1-9][0-9]*$ ]] ||
    (( snapshot_size > maximum_mebibytes * 1048576 )); then
    fail "${label} private snapshot exceeds its closed bound"
  fi
  chmod 0400 -- "${destination}"
}

readonly PACKAGE_PATH="${SNAPSHOT_DIRECTORY}/${PACKAGE_NAME}"
readonly SOURCE_ARCHIVE="${SNAPSHOT_DIRECTORY}/${SOURCE_ARCHIVE_NAME}"
snapshot_bounded_file package "${BUNDLE_PACKAGE}" "${PACKAGE_PATH}" 256
snapshot_bounded_file source-archive "${BUNDLE_SOURCE_ARCHIVE}" \
  "${SOURCE_ARCHIVE}" 64

snapshot_text() {
  local path="$1"
  local bytes_name="$2"
  local body_name="$3"
  local metadata_before
  local metadata_after
  local bytes
  local status
  metadata_before="$(stat -c '%d:%i:%s:%f:%Y:%h' -- "${path}")" || return 1
  set +e
  IFS= read -r -d '' -n $((MAXIMUM_TEXT_BYTES + 1)) bytes <"${path}"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && ${#bytes} -ge 1 &&
    ${#bytes} -le MAXIMUM_TEXT_BYTES ]] || return 1
  [[ "$(printf '%s' "${bytes}" | tr -cd '\12\40-\176' | wc -c)" -eq "${#bytes}" ]] ||
    return 1
  [[ "${bytes: -1}" == $'\n' ]] || return 1
  local body="${bytes%$'\n'}"
  [[ -n "${body}" && "${body}" != *$'\n' ]] || return 1
  metadata_after="$(stat -c '%d:%i:%s:%f:%Y:%h' -- "${path}")" || return 1
  [[ "${metadata_after}" == "${metadata_before}" ]] || return 1
  printf -v "${bytes_name}" '%s' "${bytes}"
  printf -v "${body_name}" '%s' "${body}"
}

parse_receipt() {
  local body="$1"
  local keys_name="$2"
  local values_name="$3"
  local -n expected_keys="${keys_name}"
  local -n values="${values_name}"
  local index=0
  local line key value
  while IFS= read -r line; do
    [[ "${index}" -lt "${#expected_keys[@]}" && "${line}" == *=* ]] ||
      return 1
    key="${line%%=*}"
    value="${line#*=}"
    [[ "${key}" == "${expected_keys[${index}]}" &&
      "${key}" =~ ^[a-z][a-z0-9_-]{0,63}$ && -n "${value}" &&
      ${#value} -le 4096 && "${value}" != *'='* &&
      "${value}" != ' '* && "${value}" != *' ' &&
      ! -v "values[${key}]" ]] || return 1
    values["${key}"]="${value}"
    ((index += 1))
  done <<<"${body}"
  [[ "${index}" -eq "${#expected_keys[@]}" ]]
}

BUILDER_BYTES=''
BUILDER_BODY=''
VERIFIER_BYTES=''
VERIFIER_BODY=''
VERIFIER_ERROR_BYTES=''
VERIFIER_ERROR_BODY=''
MARKER_BYTES=''
MARKER_BODY=''
snapshot_text "${BUNDLE}/BUILDER-OBSERVATION.txt" BUILDER_BYTES BUILDER_BODY ||
  fail 'builder observation is not one bounded canonical text snapshot'
snapshot_text "${BUNDLE}/VERIFIER-OBSERVATION.txt" VERIFIER_BYTES VERIFIER_BODY ||
  fail 'verifier observation is not one bounded canonical text snapshot'
snapshot_text "${BUNDLE}/VERIFIER-OBSERVATION.stderr" \
  VERIFIER_ERROR_BYTES VERIFIER_ERROR_BODY ||
  fail 'verifier refusal is not one bounded canonical text snapshot'
snapshot_text "${BUNDLE}/OBSERVATION-NONACCEPTING" MARKER_BYTES MARKER_BODY ||
  fail 'non-acceptance marker is not one bounded canonical text snapshot'
readonly BUILDER_BYTES BUILDER_BODY VERIFIER_BYTES VERIFIER_BODY
readonly VERIFIER_ERROR_BYTES VERIFIER_ERROR_BODY MARKER_BYTES MARKER_BODY

# ShellCheck cannot see these arrays through parse_receipt's namerefs.
# shellcheck disable=SC2034
readonly -a BUILDER_KEYS=(
  format observation_authority package_sha256 expected_source_commit
  source_archive source_archive_sha256 profile_id profile_sha256
  profile_binding_role package_target_kind architecture evidence_namespace
  build_environment build_host_architecture rust_host_observed
  rust_toolchain_expected rust_toolchain_observed build_host_profile_match
  native_hardware_claim physical_target_evidence verifier_stdout_sha256
  verifier_stderr_sha256 package_static_acceptance
  needed_observation_accepted_as_policy stage_4_completed stage_5_executed
  stage_6_authorized stage_6_owner_decision cross_profile_evidence_accepted
  aarch64_gate_satisfied_by_x86_64 publication_performed
)
declare -A builder=()
parse_receipt "${BUILDER_BODY}" BUILDER_KEYS builder ||
  fail 'builder observation fields are missing, duplicated, or reordered'
# shellcheck disable=SC2034
readonly -a VERIFIER_KEYS=(
  format observation_authority package_sha256 expected_source_commit profile_id
  profile_sha256 profile_binding_role package_target_kind architecture
  evidence_namespace verification_host_architecture
  verification_host_profile_match native_hardware_claim physical_target_evidence
  cross_profile_evidence_accepted aarch64_gate_satisfied_by_x86_64
  observed_needed_usr_bin_a-quo observed_needed_usr_bin_a-quo-daemon
  observed_needed_usr_lib_a-quo_a-quo-consent
  needed_observation_accepted_as_policy
)
declare -A verifier=()
parse_receipt "${VERIFIER_BODY}" VERIFIER_KEYS verifier ||
  fail 'verifier observation fields are missing, duplicated, or reordered'

PACKAGE_SHA256="$(sha256sum -- "${PACKAGE_PATH}")"
PACKAGE_SHA256="${PACKAGE_SHA256%% *}"
SOURCE_ARCHIVE_SHA256="$(sha256sum -- "${SOURCE_ARCHIVE}")"
SOURCE_ARCHIVE_SHA256="${SOURCE_ARCHIVE_SHA256%% *}"
VERIFIER_STDOUT_SHA256="$(printf '%s' "${VERIFIER_BYTES}" | sha256sum)"
VERIFIER_STDOUT_SHA256="${VERIFIER_STDOUT_SHA256%% *}"
VERIFIER_STDERR_SHA256="$(printf '%s' "${VERIFIER_ERROR_BYTES}" | sha256sum)"
VERIFIER_STDERR_SHA256="${VERIFIER_STDERR_SHA256%% *}"
BUILDER_RECEIPT_SHA256="$(printf '%s' "${BUILDER_BYTES}" | sha256sum)"
BUILDER_RECEIPT_SHA256="${BUILDER_RECEIPT_SHA256%% *}"
NONACCEPTANCE_MARKER_SHA256="$(printf '%s' "${MARKER_BYTES}" | sha256sum)"
NONACCEPTANCE_MARKER_SHA256="${NONACCEPTANCE_MARKER_SHA256%% *}"
readonly PACKAGE_SHA256 SOURCE_ARCHIVE_SHA256
readonly VERIFIER_STDOUT_SHA256 VERIFIER_STDERR_SHA256
readonly BUILDER_RECEIPT_SHA256 NONACCEPTANCE_MARKER_SHA256

assert_builder() {
  local key="$1"
  local expected="$2"
  [[ "${builder[${key}]}" == "${expected}" ]] ||
    fail "unexpected builder observation value: ${key}"
}
assert_verifier() {
  local key="$1"
  local expected="$2"
  [[ "${verifier[${key}]}" == "${expected}" ]] ||
    fail "unexpected verifier observation value: ${key}"
}

assert_builder format a-quo-arch-package-needed-observation-builder-v1
assert_builder observation_authority none
assert_builder package_sha256 "${PACKAGE_SHA256}"
assert_builder expected_source_commit "${EXPECTED_SOURCE_COMMIT}"
assert_builder source_archive "${SOURCE_ARCHIVE_NAME}"
assert_builder source_archive_sha256 "${SOURCE_ARCHIVE_SHA256}"
assert_builder profile_id "${target[profile_id]}"
assert_builder profile_sha256 "${target[profile_sha256]}"
assert_builder profile_binding_role package-target-policy
assert_builder package_target_kind "${target[target_kind]}"
assert_builder architecture x86_64
assert_builder evidence_namespace "${target[evidence_namespace]}"
assert_builder build_environment "${target[build_environment]}"
assert_builder build_host_architecture x86_64
assert_builder rust_host_observed "${target[rust_host]}"
assert_builder rust_toolchain_expected 1.98.0
assert_builder rust_toolchain_observed 1.98.0
assert_builder build_host_profile_match not-established
assert_builder native_hardware_claim not-established
assert_builder physical_target_evidence false
assert_builder verifier_stdout_sha256 "${VERIFIER_STDOUT_SHA256}"
assert_builder verifier_stderr_sha256 "${VERIFIER_STDERR_SHA256}"
for false_builder_field in \
  package_static_acceptance needed_observation_accepted_as_policy \
  stage_4_completed stage_5_executed stage_6_authorized \
  cross_profile_evidence_accepted aarch64_gate_satisfied_by_x86_64 \
  publication_performed; do
  assert_builder "${false_builder_field}" false
done
assert_builder stage_6_owner_decision required

assert_verifier format a-quo-arch-package-needed-observation-v1
assert_verifier observation_authority none
assert_verifier package_sha256 "${PACKAGE_SHA256}"
assert_verifier expected_source_commit "${EXPECTED_SOURCE_COMMIT}"
assert_verifier profile_id "${target[profile_id]}"
assert_verifier profile_sha256 "${target[profile_sha256]}"
assert_verifier profile_binding_role package-target-policy
assert_verifier package_target_kind "${target[target_kind]}"
assert_verifier architecture x86_64
assert_verifier evidence_namespace "${target[evidence_namespace]}"
assert_verifier verification_host_architecture x86_64
assert_verifier verification_host_profile_match not-established
assert_verifier native_hardware_claim not-established
assert_verifier physical_target_evidence false
assert_verifier cross_profile_evidence_accepted false
assert_verifier aarch64_gate_satisfied_by_x86_64 false
assert_verifier needed_observation_accepted_as_policy false
for needed_field in \
  observed_needed_usr_bin_a-quo observed_needed_usr_bin_a-quo-daemon \
  observed_needed_usr_lib_a-quo_a-quo-consent; do
  [[ "${verifier[${needed_field}]}" =~ ^[A-Za-z0-9_.+-]+(,[A-Za-z0-9_.+-]+)*$ ]] ||
    fail "observed NEEDED set is malformed: ${needed_field}"
done
[[ "${VERIFIER_ERROR_BODY}" == \
  'x86_64 NEEDED observation completed but cannot accept the package until policy is reviewed and frozen' ]] ||
  fail 'retained verifier refusal differs from the exact non-accepting error'

EXPECTED_MARKER="$(printf '%s\n' \
  'format=a-quo-arch-package-needed-observation-nonacceptance-v1' \
  'observation_authority=none' \
  'package_static_acceptance=false' \
  'needed_observation_accepted_as_policy=false' \
  'physical_target_evidence=false' \
  'stage_4_completed=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false')"
readonly EXPECTED_MARKER
[[ "${MARKER_BODY}" == "${EXPECTED_MARKER}" ]] ||
  fail 'non-acceptance marker differs from the exact false-claim record'

readonly REPLAY_STDOUT="${TEMPORARY_ROOT}/verifier.stdout"
readonly REPLAY_STDERR="${TEMPORARY_ROOT}/verifier.stderr"
set +e
A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${PACKAGE_VERIFIER}" --observe-unconfirmed-needed \
  "${PACKAGE_PATH}" "${EXPECTED_SOURCE_COMMIT}" "${PROFILE}" \
  >"${REPLAY_STDOUT}" 2>"${REPLAY_STDERR}"
REPLAY_STATUS="$?"
set -e
readonly REPLAY_STATUS
[[ "${REPLAY_STATUS}" -eq 1 ]] ||
  fail 'package verifier did not retain its non-accepting observation status'
REPLAY_STDOUT_BYTES=''
REPLAY_STDOUT_BODY=''
REPLAY_STDERR_BYTES=''
REPLAY_STDERR_BODY=''
snapshot_text "${REPLAY_STDOUT}" REPLAY_STDOUT_BYTES REPLAY_STDOUT_BODY ||
  fail 'replayed verifier stdout is not bounded canonical text'
snapshot_text "${REPLAY_STDERR}" REPLAY_STDERR_BYTES REPLAY_STDERR_BODY ||
  fail 'replayed verifier stderr is not bounded canonical text'
[[ "${REPLAY_STDOUT_BYTES}" == "${VERIFIER_BYTES}" ]] ||
  fail 'retained verifier stdout is not an exact replay for this package'
[[ "${REPLAY_STDERR_BYTES}" == "${VERIFIER_ERROR_BYTES}" ]] ||
  fail 'retained verifier stderr is not an exact replay for this package'
[[ "${REPLAY_STDOUT_BODY}" == "${VERIFIER_BODY}" &&
  "${REPLAY_STDERR_BODY}" == "${VERIFIER_ERROR_BODY}" ]] ||
  fail 'replayed verifier text bodies differ from retained observations'

POST_REPLAY_PACKAGE_SHA256="$(file_sha256 "${PACKAGE_PATH}")"
POST_REPLAY_SOURCE_ARCHIVE_SHA256="$(file_sha256 "${SOURCE_ARCHIVE}")"
POST_REPLAY_TARGET_RESOLVER_SHA256="$(file_sha256 "${TARGET_RESOLVER}")"
POST_REPLAY_PROFILE_VERIFIER_SHA256="$(file_sha256 "${PROFILE_VERIFIER}")"
POST_REPLAY_PACKAGE_VERIFIER_SHA256="$(file_sha256 "${PACKAGE_VERIFIER}")"
readonly POST_REPLAY_PACKAGE_SHA256 POST_REPLAY_SOURCE_ARCHIVE_SHA256
readonly POST_REPLAY_TARGET_RESOLVER_SHA256 POST_REPLAY_PROFILE_VERIFIER_SHA256
readonly POST_REPLAY_PACKAGE_VERIFIER_SHA256
[[ "${POST_REPLAY_PACKAGE_SHA256}" == "${PACKAGE_SHA256}" && \
  "${POST_REPLAY_SOURCE_ARCHIVE_SHA256}" == "${SOURCE_ARCHIVE_SHA256}" ]] ||
  fail 'private package or source snapshot changed during exact replay'
[[ "${POST_REPLAY_TARGET_RESOLVER_SHA256}" == "${TARGET_RESOLVER_SHA256}" && \
  "${POST_REPLAY_PROFILE_VERIFIER_SHA256}" == "${PROFILE_VERIFIER_SHA256}" && \
  "${POST_REPLAY_PACKAGE_VERIFIER_SHA256}" == "${PACKAGE_VERIFIER_SHA256}" ]] ||
  fail 'executed resolver or verifier bytes changed during exact replay'

printf '%s\n' \
  'verified non-accepting x86_64 package NEEDED observation bundle' \
  "builder_receipt_sha256=${BUILDER_RECEIPT_SHA256}" \
  "nonacceptance_marker_sha256=${NONACCEPTANCE_MARKER_SHA256}" \
  "package_sha256=${PACKAGE_SHA256}" \
  "expected_source_commit=${EXPECTED_SOURCE_COMMIT}" \
  "profile_id=${target[profile_id]}" \
  "profile_sha256=${target[profile_sha256]}" \
  "target_resolver_sha256=${TARGET_RESOLVER_SHA256}" \
  "profile_verifier_sha256=${PROFILE_VERIFIER_SHA256}" \
  "package_verifier_sha256=${PACKAGE_VERIFIER_SHA256}" \
  'profile_binding_role=package-target-policy' \
  'architecture=x86_64' \
  "evidence_namespace=${target[evidence_namespace]}" \
  'observation_authority=none' \
  'package_static_acceptance=false' \
  'needed_observation_accepted_as_policy=false' \
  'physical_target_evidence=false' \
  'stage_4_completed=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false'
