#!/usr/bin/env bash

set +x
set -euo pipefail
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin
umask 077
ulimit -c 0

fail() {
  printf 'Omarchy Ubuntu APT candidate refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--emit-observations|--pre-completion] --profile PROFILE --externally-expected-profile-sha256 SHA256 --oci-lock LOCK --externally-expected-oci-lock-sha256 SHA256 --builder-lock LOCK --externally-expected-builder-lock-sha256 SHA256 --candidate DIRECTORY\n' \
    "${0##*/}" >&2
  exit 2
}

emit_observations=false
pre_completion=false
profile_path=''
expected_profile_sha256=''
oci_lock_path=''
expected_oci_lock_sha256=''
builder_lock_path=''
expected_builder_lock_sha256=''
candidate_directory=''
while (( $# > 0 )); do
  case "$1" in
    --emit-observations)
      [[ "${emit_observations}" == false && "${pre_completion}" == false ]] || usage
      emit_observations=true
      shift
      ;;
    --pre-completion)
      [[ "${pre_completion}" == false && "${emit_observations}" == false ]] || usage
      pre_completion=true
      shift
      ;;
    --profile)
      [[ -z "${profile_path}" && $# -ge 2 ]] || usage
      profile_path="$2"
      shift 2
      ;;
    --externally-expected-profile-sha256)
      [[ -z "${expected_profile_sha256}" && $# -ge 2 ]] || usage
      expected_profile_sha256="$2"
      shift 2
      ;;
    --oci-lock)
      [[ -z "${oci_lock_path}" && $# -ge 2 ]] || usage
      oci_lock_path="$2"
      shift 2
      ;;
    --externally-expected-oci-lock-sha256)
      [[ -z "${expected_oci_lock_sha256}" && $# -ge 2 ]] || usage
      expected_oci_lock_sha256="$2"
      shift 2
      ;;
    --builder-lock)
      [[ -z "${builder_lock_path}" && $# -ge 2 ]] || usage
      builder_lock_path="$2"
      shift 2
      ;;
    --externally-expected-builder-lock-sha256)
      [[ -z "${expected_builder_lock_sha256}" && $# -ge 2 ]] || usage
      expected_builder_lock_sha256="$2"
      shift 2
      ;;
    --candidate)
      [[ -z "${candidate_directory}" && $# -ge 2 ]] || usage
      candidate_directory="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
readonly emit_observations pre_completion profile_path expected_profile_sha256
readonly oci_lock_path expected_oci_lock_sha256 builder_lock_path
readonly expected_builder_lock_sha256 candidate_directory

[[ -n "${profile_path}" && -n "${expected_profile_sha256}" && \
  -n "${oci_lock_path}" && -n "${expected_oci_lock_sha256}" && \
  -n "${builder_lock_path}" && -n "${expected_builder_lock_sha256}" && \
  -n "${candidate_directory}" ]] || usage
for expected_digest in \
  "${expected_profile_sha256}" \
  "${expected_oci_lock_sha256}" \
  "${expected_builder_lock_sha256}"; do
  [[ "${expected_digest}" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'an externally expected digest is not one lowercase SHA-256'
done

readonly AWK=/usr/bin/awk
readonly CMP=/usr/bin/cmp
readonly DATE=/usr/bin/date
readonly FIND=/usr/bin/find
readonly OD=/usr/bin/od
readonly SHA256SUM=/usr/bin/sha256sum
readonly SORT=/usr/bin/sort
readonly STAT=/usr/bin/stat
readonly TAIL=/usr/bin/tail
readonly TR=/usr/bin/tr
readonly UNAME=/usr/bin/uname
readonly WC=/usr/bin/wc
for required_tool in \
  "${AWK}" "${CMP}" "${DATE}" "${FIND}" "${OD}" "${SHA256SUM}" "${SORT}" \
  "${STAT}" "${TAIL}" "${TR}" "${UNAME}" "${WC}"; do
  [[ -x "${required_tool}" && -f "${required_tool}" ]] ||
    fail "required offline verifier tool is unavailable or not a regular file: ${required_tool}"
done
[[ "$(${UNAME} -s)" == Linux ]] ||
  fail 'offline Ubuntu APT candidate verification requires Linux'

readonly MAXIMUM_PROFILE_BYTES=65536
readonly MAXIMUM_LOCK_BYTES=65536
readonly MAXIMUM_MANIFEST_BYTES=1048576
readonly MAXIMUM_RECEIPT_BYTES=65536
readonly MAXIMUM_STATE_BYTES=16777216
readonly MAXIMUM_OBJECT_BYTES=536870912
readonly MAXIMUM_TOTAL_OBJECT_BYTES=4294967296
readonly MAXIMUM_OBJECT_COUNT=4096

validate_bounded_text() {
  local label="$1"
  local path="$2"
  local maximum_bytes="$3"
  local size
  local printable_size
  local last_byte
  size="$(${STAT} -c '%s' -- "${path}")" || fail "${label} size is unavailable"
  [[ "${size}" =~ ^[0-9]+$ ]] || fail "${label} size is malformed"
  (( size > 0 && size <= maximum_bytes )) ||
    fail "${label} size is outside the closed bound"
  printable_size="$(${TR} -cd '\12\40-\176' <"${path}" | ${WC} -c)"
  [[ "${printable_size}" == "${size}" ]] ||
    fail "${label} contains a control, carriage-return, NUL, or non-ASCII byte"
  last_byte="$(${TAIL} -c 1 -- "${path}" | ${OD} -An -tu1 | ${TR} -d '[:space:]')"
  [[ "${last_byte}" == 10 ]] || fail "${label} must end with one LF byte"
}

file_digest() {
  local digest
  digest="$(${SHA256SUM} -- "$1")"
  printf '%s\n' "${digest%% *}"
}

validate_external_file() {
  local label="$1"
  local path="$2"
  local expected_digest="$3"
  local maximum_bytes="$4"
  local metadata_before
  [[ -f "${path}" && ! -L "${path}" ]] ||
    fail "${label} must be one regular non-symlink file"
  metadata_before="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${path}")"
  validate_bounded_text "${label}" "${path}" "${maximum_bytes}"
  [[ "$(file_digest "${path}")" == "${expected_digest}" ]] ||
    fail "${label} bytes do not match the caller-supplied expected digest"
  [[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${path}")" == "${metadata_before}" ]] ||
    fail "${label} metadata changed during verification"
}

validate_external_file profile "${profile_path}" "${expected_profile_sha256}" \
  "${MAXIMUM_PROFILE_BYTES}"
validate_external_file 'OCI input lock' "${oci_lock_path}" \
  "${expected_oci_lock_sha256}" "${MAXIMUM_LOCK_BYTES}"
validate_external_file 'builder-context input lock' "${builder_lock_path}" \
  "${expected_builder_lock_sha256}" "${MAXIMUM_LOCK_BYTES}"

declare -A profile_fields=()
profile_line_count=0
while IFS= read -r line; do
  ((profile_line_count += 1))
  [[ -n "${line}" && "${line}" == *=* ]] ||
    fail "profile line ${profile_line_count} is not one nonempty key/value record"
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${value}" != *'='* && "${key}" =~ ^[a-z][a-z0-9_]{0,63}$ && \
    -n "${value}" && ${#value} -le 4096 && ! -v "profile_fields[${key}]" ]] ||
    fail "profile line ${profile_line_count} has invalid or duplicate fields"
  profile_fields["${key}"]="${value}"
done <"${profile_path}"
[[ "${profile_line_count}" -eq 129 ]] || fail 'profile does not have exactly 129 fields'
[[ "${profile_fields[format]:-}" == a-quo-omarchy-evaluation-target-profile-v2 && \
  "${profile_fields[profile_id]:-}" == a-quo-omarchy4-aarch64-dec29fa-v2 && \
  "${profile_fields[state]:-}" == bootstrap-unarmed && \
  "${profile_fields[armable]:-}" == false && \
  "${profile_fields[architecture]:-}" == aarch64 && \
  "${profile_fields[builder_apt_top_level_request_count]:-}" == 14 && \
  "${profile_fields[builder_apt_snapshot_and_closure]:-}" == required-not-retained && \
  "${profile_fields[unresolved_input_02]:-}" == ubuntu-apt-snapshot-and-package-lock ]] ||
  fail 'profile is not the exact unarmed class-02 APT boundary'

[[ -d "${candidate_directory}" && ! -L "${candidate_directory}" ]] ||
  fail 'candidate must be one directory and not a symlink'
[[ "$(${STAT} -c '%a:%u' -- "${candidate_directory}")" == "700:${EUID}" ]] ||
  fail 'candidate directory must be caller-owned with mode 0700'
candidate_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${candidate_directory}")"

declare -a snapshot_paths=(
  prerequisites/profile.snapshot
  prerequisites/ubuntu-oci.lock.snapshot
  prerequisites/builder-context.lock.snapshot
)
declare -a external_paths=(
  "${profile_path}"
  "${oci_lock_path}"
  "${builder_lock_path}"
)
declare -a external_digests=(
  "${expected_profile_sha256}"
  "${expected_oci_lock_sha256}"
  "${expected_builder_lock_sha256}"
)
declare -a snapshot_metadata=()
for index in "${!snapshot_paths[@]}"; do
  snapshot_path="${candidate_directory}/${snapshot_paths[index]}"
  [[ -f "${snapshot_path}" && ! -L "${snapshot_path}" && \
    "$(${STAT} -c '%a:%h:%u' -- "${snapshot_path}")" == "400:1:${EUID}" ]] ||
    fail "candidate prerequisite snapshot has unsafe identity: ${snapshot_paths[index]}"
  snapshot_metadata[index]="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${snapshot_path}")"
  [[ "$(file_digest "${snapshot_path}")" == "${external_digests[index]}" ]] ||
    fail "candidate prerequisite snapshot digest differs: ${snapshot_paths[index]}"
  ${CMP} -s -- "${external_paths[index]}" "${snapshot_path}" ||
    fail "candidate prerequisite snapshot bytes differ: ${snapshot_paths[index]}"
done

readonly manifest_path="${candidate_directory}/objects.manifest"
[[ -f "${manifest_path}" && ! -L "${manifest_path}" && \
  "$(${STAT} -c '%a:%h:%u' -- "${manifest_path}")" == "400:1:${EUID}" ]] ||
  fail 'object manifest must be caller-owned, mode 0400, and singly linked'
manifest_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${manifest_path}")"
validate_bounded_text 'object manifest' "${manifest_path}" "${MAXIMUM_MANIFEST_BYTES}"
manifest_sha256="$(file_digest "${manifest_path}")"

declare -A object_paths_seen=()
declare -A required_roles_seen=()
declare -A object_metadata=()
declare -a manifest_paths=()
object_count=0
index_count=0
package_count=0
total_object_bytes=0
manifest_line=0
transport_ca_bundle_sha256=''
while IFS= read -r line; do
  ((manifest_line += 1))
  if (( manifest_line == 1 )); then
    [[ "${line}" == format=a-quo-omarchy-ubuntu-apt-object-manifest-v1 ]] ||
      fail 'object manifest has the wrong format record'
    continue
  fi
  IFS='|' read -r role relative_path declared_size declared_sha256 extra <<<"${line}"
  [[ -z "${extra}" && "${role}" =~ ^[a-z][a-z0-9-]{0,47}$ && \
    "${relative_path}" =~ ^[A-Za-z0-9][A-Za-z0-9._+/%:~-]{0,255}$ && \
    "${relative_path}" != *'//'* && "${relative_path}" != *'/./'* && \
    "${relative_path}" != *'/../'* && "${relative_path}" != */ && \
    "${declared_size}" =~ ^[1-9][0-9]*$ && \
    "${declared_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "object manifest record ${manifest_line} is malformed"
  [[ ! -v "object_paths_seen[${relative_path}]" ]] ||
    fail "object manifest repeats a path: ${relative_path}"
  object_paths_seen["${relative_path}"]=1
  manifest_paths+=("${relative_path}")
  ((object_count += 1))
  (( object_count <= MAXIMUM_OBJECT_COUNT )) || fail 'object count exceeds the closed bound'
  (( declared_size <= MAXIMUM_OBJECT_BYTES )) || fail 'one object exceeds the closed byte bound'
  ((total_object_bytes += declared_size))
  (( total_object_bytes <= MAXIMUM_TOTAL_OBJECT_BYTES )) ||
    fail 'aggregate object bytes exceed the closed bound'

  case "${role}" in
    index)
      [[ "${relative_path}" =~ ^indexes/[A-Za-z0-9][A-Za-z0-9._+:%-]{0,200}$ ]] ||
        fail 'index object path is outside the closed grammar'
      ((index_count += 1))
      ;;
    package)
      [[ "${relative_path}" =~ ^packages/[A-Za-z0-9][A-Za-z0-9._+:%~-]{0,200}\.deb$ ]] ||
        fail 'package object path is outside the closed grammar'
      ((package_count += 1))
      ;;
    transport-ca-bundle)
      [[ "${relative_path}" == transport/ca-certificates.crt && \
        ! -v "required_roles_seen[${role}]" && declared_size -le 1048576 ]] ||
        fail 'transport CA bundle is repeated, misplaced, or oversized'
      required_roles_seen["${role}"]=1
      transport_ca_bundle_sha256="${declared_sha256}"
      ;;
    apt-version|snapshot-id|sources|apt-configuration|base-package-state|requested-packages|index-targets|solver-plan|final-package-state)
      expected_state_path=''
      case "${role}" in
        apt-version) expected_state_path=state/apt-version.txt ;;
        snapshot-id) expected_state_path=state/snapshot-id.txt ;;
        sources) expected_state_path=state/sources.txt ;;
        apt-configuration) expected_state_path=state/apt-configuration.txt ;;
        base-package-state) expected_state_path=state/base-packages.txt ;;
        requested-packages) expected_state_path=state/requested-packages.txt ;;
        index-targets) expected_state_path=state/index-targets.txt ;;
        solver-plan) expected_state_path=state/solver-plan.txt ;;
        final-package-state) expected_state_path=state/final-packages.txt ;;
      esac
      [[ "${relative_path}" == "${expected_state_path}" && \
        ! -v "required_roles_seen[${role}]" && declared_size -le MAXIMUM_STATE_BYTES ]] ||
        fail "required state role is repeated, misplaced, or oversized: ${role}"
      required_roles_seen["${role}"]=1
      ;;
    *) fail "object manifest has an unsupported role: ${role}" ;;
  esac

  object_path="${candidate_directory}/${relative_path}"
  [[ -f "${object_path}" && ! -L "${object_path}" && \
    "$(${STAT} -c '%a:%h:%u' -- "${object_path}")" == "400:1:${EUID}" ]] ||
    fail "candidate object has unsafe identity: ${relative_path}"
  object_metadata["${relative_path}"]="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${object_path}")"
  [[ "$(${STAT} -c '%s' -- "${object_path}")" == "${declared_size}" && \
    "$(file_digest "${object_path}")" == "${declared_sha256}" ]] ||
    fail "candidate object does not match its manifest record: ${relative_path}"
done <"${manifest_path}"

[[ "${object_count}" -ge 12 && "${index_count}" -ge 1 && "${package_count}" -ge 1 ]] ||
  fail 'candidate must retain all state roles and at least one index and package'
for role in \
  apt-version snapshot-id sources apt-configuration base-package-state \
  requested-packages index-targets solver-plan final-package-state \
  transport-ca-bundle; do
  [[ -v "required_roles_seen[${role}]" ]] || fail "candidate is missing required role: ${role}"
done

for state_path in \
  state/apt-version.txt state/snapshot-id.txt state/sources.txt \
  state/apt-configuration.txt state/base-packages.txt \
  state/requested-packages.txt state/index-targets.txt \
  state/solver-plan.txt state/final-packages.txt; do
  validate_bounded_text "${state_path}" "${candidate_directory}/${state_path}" \
    "${MAXIMUM_STATE_BYTES}"
done

[[ "$(<"${candidate_directory}/state/apt-version.txt")" == apt_version=2.8.3 ]] ||
  fail 'captured APT version is not the locked base version 2.8.3'
snapshot_record="$(<"${candidate_directory}/state/snapshot-id.txt")"
[[ "${snapshot_record}" =~ ^snapshot_id=([0-9]{8}T[0-9]{6}Z)$ ]] ||
  fail 'captured snapshot ID is malformed'
snapshot_id="${BASH_REMATCH[1]}"
snapshot_date="${snapshot_id%%T*}"
(( 10#${snapshot_date} >= 20230301 )) || fail 'captured snapshot predates the service boundary'
snapshot_canonical="$(${DATE} -u -d \
  "${snapshot_id:0:4}-${snapshot_id:4:2}-${snapshot_id:6:2} ${snapshot_id:9:2}:${snapshot_id:11:2}:${snapshot_id:13:2} UTC" \
  '+%Y%m%dT%H%M%SZ' 2>/dev/null)" ||
  fail 'captured snapshot is not one real UTC calendar timestamp'
[[ "${snapshot_canonical}" == "${snapshot_id}" ]] ||
  fail 'captured snapshot is not one canonical UTC calendar timestamp'

# This is an awk program, not a shell expression.
# shellcheck disable=SC2016
source_records_output="$(${AWK} '
  BEGIN { phase = "set"; record = 0; source_set = "" }
  phase == "done" { exit 73 }
  phase == "set" {
    if ($0 != "source_set=original-locked-oci" &&
        $0 != "source_set=effective-timestamped-main-archive") exit 73
    source_set = substr($0, 12)
    phase = "path"
    next
  }
  phase == "path" {
    if ($0 !~ /^path=\/[A-Za-z0-9._\/-]+$/) exit 73
    path = substr($0, 6)
    phase = "size"
    next
  }
  phase == "size" {
    if ($0 !~ /^size=[1-9][0-9]*$/) exit 73
    size = substr($0, 6)
    phase = "sha"
    next
  }
  phase == "sha" {
    if ($0 !~ /^sha256=[0-9a-f]{64}$/) exit 73
    digest = substr($0, 8)
    phase = "begin"
    next
  }
  phase == "begin" {
    if ($0 != "content-begin") exit 73
    phase = "content"
    next
  }
  phase == "content" {
    if ($0 == "content-begin") exit 73
    if ($0 == "content-end") {
      record += 1
      print source_set "|" path "|" size "|" digest
      if (record == 2) phase = "set"
      else if (record == 4) phase = "done"
      else phase = "path"
    }
    next
  }
  END { if (record != 4 || phase != "done") exit 73 }
' "${candidate_directory}/state/sources.txt")" ||
  fail 'captured APT sources do not have the exact four-record structure'
mapfile -t source_records <<<"${source_records_output}"
[[ "${#source_records[@]}" -eq 4 ]] ||
  fail 'captured APT sources do not have exactly four file records'
declare -a expected_source_sets=(
  original-locked-oci original-locked-oci
  effective-timestamped-main-archive effective-timestamped-main-archive
)
declare -a expected_source_paths=(
  /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources
  /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources
)
declare -a declared_source_sizes=()
declare -a declared_source_digests=()
extract_source_content() {
  local wanted_block="$1"
  # This is an awk program, not a shell expression.
  # shellcheck disable=SC2016
  ${AWK} -v wanted_block="${wanted_block}" '
    $0 == "content-begin" { block += 1; next }
    $0 == "content-end" { if (block == wanted_block) exit; next }
    block == wanted_block { print }
  ' "${candidate_directory}/state/sources.txt"
}
for index in "${!source_records[@]}"; do
  IFS='|' read -r source_set source_path source_size source_digest extra \
    <<<"${source_records[index]}"
  [[ -z "${extra}" && \
    "${source_set}" == "${expected_source_sets[index]}" && \
    "${source_path}" == "${expected_source_paths[index]}" && \
    "${source_size}" =~ ^[1-9][0-9]*$ && source_size -le 65536 && \
    "${source_digest}" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'captured APT source record order or metadata is invalid'
  content_size="$(extract_source_content "$((index + 1))" | ${WC} -c)"
  content_digest="$(extract_source_content "$((index + 1))" | ${SHA256SUM})"
  content_digest="${content_digest%% *}"
  [[ "${content_size}" == "${source_size}" && \
    "${content_digest}" == "${source_digest}" ]] ||
    fail 'captured APT source content differs from its declared metadata'
  declared_source_sizes[index]="${source_size}"
  declared_source_digests[index]="${source_digest}"
done
[[ "${declared_source_sizes[0]}" == "${declared_source_sizes[2]}" && \
  "${declared_source_digests[0]}" == "${declared_source_digests[2]}" ]] ||
  fail 'effective source capture changed the legacy sources.list bytes'

effective_source_digest="$({
  printf '%s\n' \
    'Types: deb' \
    "URIs: https://snapshot.ubuntu.com/ubuntu/${snapshot_id}/" \
    'Suites: noble noble-updates noble-backports' \
    'Components: main universe restricted multiverse' \
    'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
    '' \
    'Types: deb' \
    "URIs: https://snapshot.ubuntu.com/ubuntu/${snapshot_id}/" \
    'Suites: noble-security' \
    'Components: main universe restricted multiverse' \
    'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg'
} | ${SHA256SUM})"
effective_source_digest="${effective_source_digest%% *}"
[[ "${declared_source_sizes[3]}" == 420 && \
  "${declared_source_digests[3]}" == "${effective_source_digest}" ]] ||
  fail 'effective APT source is not the exact timestamped main-archive source'
# This is an awk program, not a shell expression.
# shellcheck disable=SC2016
source_semantics="$(${AWK} '
  $0 == "content-begin" { block += 1; next }
  $0 == "content-end" { next }
  block == 2 && /^URIs:/ { original_uri_total += 1 }
  block == 2 && $0 == "URIs: http://ports.ubuntu.com/ubuntu-ports/" {
    original_uri_exact += 1
  }
  block == 2 && /^Types:/ { original_types_total += 1 }
  block == 2 && $0 == "Types: deb" { original_types_exact += 1 }
  block == 2 && /^Suites:/ { original_suites_total += 1 }
  block == 2 && ($0 == "Suites: noble noble-updates noble-backports" ||
                 $0 == "Suites: noble-security") { original_suites_exact += 1 }
  block == 2 && /^Components:/ { original_components_total += 1 }
  block == 2 && $0 == "Components: main universe restricted multiverse" {
    original_components_exact += 1
  }
  block == 2 && /^Signed-By:/ { original_signed_by_total += 1 }
  block == 2 && $0 == "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" {
    original_signed_by_exact += 1
  }
  END {
    printf "%d:%d:%d:%d:%d:%d:%d:%d:%d:%d\n",
      original_uri_total, original_uri_exact,
      original_types_total, original_types_exact,
      original_suites_total, original_suites_exact,
      original_components_total, original_components_exact,
      original_signed_by_total, original_signed_by_exact
  }
' "${candidate_directory}/state/sources.txt")"
[[ "${source_semantics}" == '2:2:2:2:2:2:2:2:2:2' ]] ||
  fail 'original APT source is not the exact ports archive stanza shape'

declare -a required_apt_configuration=(
  'APT::Architecture "arm64";'
  'APT::Architectures:: "arm64";'
  'APT::Sandbox::User "_apt";'
  'Acquire::AllowInsecureRepositories "0";'
  'Acquire::AllowWeakRepositories "0";'
  'Acquire::AllowDowngradeToInsecureRepositories "0";'
  'Dir::State::lists "lists/";'
  'Dir::Cache::archives "archives/";'
  'Dir::Etc "etc/apt";'
)
declare -A apt_configuration_counts=()
while IFS= read -r configuration_line; do
  [[ "${configuration_line}" != *Proxy* ]] ||
    fail 'captured APT configuration contains a proxy route'
  for expected_configuration in "${required_apt_configuration[@]}"; do
    if [[ "${configuration_line}" == "${expected_configuration}" ]]; then
      ((apt_configuration_counts["${expected_configuration}"] += 1))
    fi
  done
done <"${candidate_directory}/state/apt-configuration.txt"
for expected_configuration in "${required_apt_configuration[@]}"; do
  [[ "${apt_configuration_counts[${expected_configuration}]:-0}" -eq 1 ]] ||
    fail 'captured APT configuration omits or repeats a required security boundary'
done

IFS=',' read -r -a requested_from_profile <<<"${profile_fields[builder_apt_top_level_requests]}"
mapfile -t requested_from_candidate <"${candidate_directory}/state/requested-packages.txt"
[[ "${#requested_from_profile[@]}" -eq 14 && \
  "${#requested_from_candidate[@]}" -eq 14 ]] ||
  fail 'top-level APT request count is not exactly 14'
for index in "${!requested_from_profile[@]}"; do
  [[ "${requested_from_profile[index]}" == "${requested_from_candidate[index]}" ]] ||
    fail 'captured top-level APT requests differ from the frozen profile'
done

declare -A index_targets_seen=()
index_target_count=0
while IFS= read -r index_target; do
  ((index_target_count += 1))
  IFS='|' read -r identifier description uri filename extra <<<"${index_target}"
  expected_description_prefix="https://snapshot.ubuntu.com/ubuntu/${snapshot_id} "
  [[ -z "${extra}" && "${identifier}" == Packages && \
    "${description}" == "${expected_description_prefix}"* ]] ||
    fail 'captured APT index target has an invalid record shape'
  suite_component="${description#"${expected_description_prefix}"}"
  [[ "${suite_component}" =~ ^(noble|noble-updates|noble-backports|noble-security)/(main|universe|restricted|multiverse)\ arm64\ Packages$ ]] ||
    fail 'captured APT index target is not one allowed ARM64 package index'
  suite="${BASH_REMATCH[1]}"
  component="${BASH_REMATCH[2]}"
  target_key="${suite}/${component}"
  [[ ! -v "index_targets_seen[${target_key}]" && \
    "${uri}" == "https://snapshot.ubuntu.com/ubuntu/${snapshot_id}/dists/${suite}/${component}/binary-arm64/Packages" && \
    "${filename}" == "/var/lib/apt/lists/snapshot.ubuntu.com_ubuntu_${snapshot_id}_dists_${suite}_${component}_binary-arm64_Packages.lz4" ]] ||
    fail 'captured APT index target is duplicated or not snapshot-bound'
  index_targets_seen["${target_key}"]=1
  (( index_target_count <= 16 )) ||
    fail 'captured APT index-target count exceeds the closed component matrix'
done <"${candidate_directory}/state/index-targets.txt"
for required_target in noble/main noble-updates/main noble-security/main; do
  [[ -v "index_targets_seen[${required_target}]" ]] ||
    fail "captured APT index targets omit required target ${required_target}"
done
(( index_target_count >= 3 )) ||
  fail 'captured APT index-target count is below the closed minimum'

validate_package_state() {
  local label="$1"
  local path="$2"
  local previous=''
  local count=0
  while IFS= read -r record; do
    ((count += 1))
    IFS='|' read -r package_name package_version package_arch extra <<<"${record}"
    [[ -z "${extra}" && \
      "${package_name}" =~ ^[a-z0-9][a-z0-9+.-]{0,127}$ && \
      "${package_version}" =~ ^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,191}$ && \
      "${package_arch}" =~ ^(arm64|all)$ && \
      ( -z "${previous}" || "${record}" > "${previous}" ) ]] ||
      fail "${label} has a malformed, duplicate, or unsorted record"
    previous="${record}"
  done <"${path}"
  (( count > 0 && count <= 4096 )) || fail "${label} count is outside the closed bound"
}
validate_package_state 'base package state' "${candidate_directory}/state/base-packages.txt"
validate_package_state 'final package state' "${candidate_directory}/state/final-packages.txt"

# This is an awk program, not a shell expression.
# shellcheck disable=SC2016
solver_install_record_count="$(${AWK} '
  $1 == "Inst" { install_records += 1 }
  $1 == "Remv" || $1 == "Purg" { forbidden_records += 1 }
  END {
    if (forbidden_records != 0) exit 73
    print install_records + 0
  }
' "${candidate_directory}/state/solver-plan.txt")" ||
  fail 'solver plan contains a removal or purge record'
[[ "${solver_install_record_count}" =~ ^[1-9][0-9]*$ && \
  "${solver_install_record_count}" -eq "${package_count}" ]] ||
  fail 'solver install record count differs from retained package count'

declare -a expected_paths=(
  prerequisites
  prerequisites/profile.snapshot
  prerequisites/ubuntu-oci.lock.snapshot
  prerequisites/builder-context.lock.snapshot
  indexes
  packages
  state
  transport
  transport/ca-certificates.crt
  objects.manifest
  state/apt-version.txt
  state/snapshot-id.txt
  state/sources.txt
  state/apt-configuration.txt
  state/base-packages.txt
  state/requested-packages.txt
  state/index-targets.txt
  state/solver-plan.txt
  state/final-packages.txt
)
expected_paths+=("${manifest_paths[@]}")
if [[ "${emit_observations}" == true ]]; then
  expected_paths+=(INCOMPLETE)
elif [[ "${pre_completion}" == true ]]; then
  expected_paths+=(receipt.apt.v1 INCOMPLETE)
else
  expected_paths+=(receipt.apt.v1 COMPLETE)
fi
mapfile -t expected_paths_sorted < <(printf '%s\n' "${expected_paths[@]}" | ${SORT} -u)
mapfile -t observed_paths < <(${FIND} "${candidate_directory}" -xdev -mindepth 1 \
  -printf '%P\n' | ${SORT})
[[ "${#expected_paths_sorted[@]}" -eq "${#observed_paths[@]}" ]] ||
  fail 'candidate inventory has an unexpected path count'
for index in "${!expected_paths_sorted[@]}"; do
  [[ "${expected_paths_sorted[index]}" == "${observed_paths[index]}" ]] ||
    fail "candidate inventory differs at ${observed_paths[index]:-missing}"
done
for directory in prerequisites indexes packages state transport; do
  directory_path="${candidate_directory}/${directory}"
  [[ -d "${directory_path}" && ! -L "${directory_path}" && \
    "$(${STAT} -c '%a:%u' -- "${directory_path}")" == "700:${EUID}" ]] ||
    fail "candidate subdirectory has unsafe identity: ${directory}"
done

if [[ "${emit_observations}" == true || "${pre_completion}" == true ]]; then
  marker_path="${candidate_directory}/INCOMPLETE"
  [[ "$(<"${marker_path}")" == incomplete-candidate ]] ||
    fail 'INCOMPLETE marker content is invalid'
else
  marker_path="${candidate_directory}/COMPLETE"
  [[ "$(<"${marker_path}")" == complete-candidate ]] ||
    fail 'COMPLETE marker content is invalid'
fi
[[ -f "${marker_path}" && ! -L "${marker_path}" && \
  "$(${STAT} -c '%a:%h:%u' -- "${marker_path}")" == "400:1:${EUID}" ]] ||
  fail 'completion marker has unsafe identity'
marker_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${marker_path}")"

declare -a expected_receipt=(
  'format=a-quo-omarchy-ubuntu-apt-candidate-v1'
  'status=complete-candidate'
  'authority=none'
  "profile_id=${profile_fields[profile_id]}"
  "profile_sha256=${expected_profile_sha256}"
  "ubuntu_oci_lock_sha256=${expected_oci_lock_sha256}"
  "builder_context_lock_sha256=${expected_builder_lock_sha256}"
  "snapshot_id=${snapshot_id}"
  'snapshot_selection_authority=caller-supplied-none'
  'original_archive=http://ports.ubuntu.com/ubuntu-ports/'
  "effective_snapshot_archive=https://snapshot.ubuntu.com/ubuntu/${snapshot_id}/"
  'archive_equivalence_to_original_ports=not-established'
  'apt_version=2.8.3'
  'apt_sandbox_user=root-in-private-single-uid-user-namespace'
  "transport_ca_bundle_sha256=${transport_ca_bundle_sha256}"
  'transport_ca_bundle_source=caller-host-not-authenticated'
  'ubuntu_archive_signature_verification=performed-by-apt-not-independently-replayed'
  'top_level_request_count=14'
  "object_count=${object_count}"
  "index_count=${index_count}"
  "package_count=${package_count}"
  "object_manifest_sha256=${manifest_sha256}"
  'captured_byte_identity=verified-non-authoritative'
  'apt_solver_execution=reported-by-acquirer-not-replayed'
  'apt_solver_reexecution=false'
  'transitive_closure_independently_recomputed=false'
  'package_installation=false'
  'dpkg_transaction=false'
  'maintainer_scripts_executed=false'
  'publisher_authentication=not-established'
  'trusted_time=not-established'
  'freshness=not-established'
  'safety=not-established'
  'build_authorization=not-established'
  'final_builder_image=not-established'
  'acquisition_network_activity=true'
  'network_destination_allowlist=not-established'
  'vm_started=false'
)
if [[ "${emit_observations}" == false ]]; then
  receipt_path="${candidate_directory}/receipt.apt.v1"
  [[ -f "${receipt_path}" && ! -L "${receipt_path}" && \
    "$(${STAT} -c '%a:%h:%u' -- "${receipt_path}")" == "400:1:${EUID}" ]] ||
    fail 'receipt has unsafe identity'
  receipt_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${receipt_path}")"
  validate_bounded_text receipt "${receipt_path}" "${MAXIMUM_RECEIPT_BYTES}"
  mapfile -t receipt_lines <"${receipt_path}"
  [[ "${#receipt_lines[@]}" -eq "${#expected_receipt[@]}" ]] ||
    fail 'receipt does not have the exact field count'
  for index in "${!expected_receipt[@]}"; do
    [[ "${receipt_lines[index]}" == "${expected_receipt[index]}" ]] ||
      fail "receipt field order or value is invalid at line $((index + 1))"
  done
  [[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${receipt_path}")" == "${receipt_metadata}" ]] ||
    fail 'receipt metadata changed during verification'
fi

for index in "${!snapshot_paths[@]}"; do
  [[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- \
    "${candidate_directory}/${snapshot_paths[index]}")" == "${snapshot_metadata[index]}" ]] ||
    fail "candidate prerequisite metadata changed: ${snapshot_paths[index]}"
done
for relative_path in "${!object_metadata[@]}"; do
  [[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- \
    "${candidate_directory}/${relative_path}")" == "${object_metadata[${relative_path}]}" ]] ||
    fail "candidate object metadata changed: ${relative_path}"
done
[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${manifest_path}")" == "${manifest_metadata}" ]] ||
  fail 'object manifest metadata changed during verification'
[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${marker_path}")" == "${marker_metadata}" ]] ||
  fail 'completion marker metadata changed during verification'
[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${candidate_directory}")" == "${candidate_metadata}" ]] ||
  fail 'candidate directory metadata changed during verification'

if [[ "${emit_observations}" == true || "${pre_completion}" == true ]]; then
  candidate_status=verified-incomplete-non-authoritative
else
  candidate_status=verified-non-authoritative
fi
printf '%s\n' \
  "candidate_status=${candidate_status}" \
  'authority=none' \
  "profile_id=${profile_fields[profile_id]}" \
  "profile_sha256=${expected_profile_sha256}" \
  "snapshot_id=${snapshot_id}" \
  "object_count=${object_count}" \
  "index_count=${index_count}" \
  "package_count=${package_count}" \
  "solver_install_record_count=${solver_install_record_count}" \
  "object_manifest_sha256=${manifest_sha256}" \
  "transport_ca_bundle_sha256=${transport_ca_bundle_sha256}" \
  'captured_byte_identity=verified-non-authoritative' \
  'apt_solver_reexecution=false' \
  'transitive_closure_independently_recomputed=false' \
  'package_installation=false' \
  'dpkg_transaction=false' \
  'publisher_authentication=not-established' \
  'trusted_time=not-established' \
  'freshness=not-established' \
  'safety=not-established' \
  'build_authorization=not-established' \
  'final_builder_image=not-established' \
  'network_activity=false' \
  'vm_started=false'
