#!/usr/bin/env bash

set +x
set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 077

fail() {
  printf 'Omarchy Ubuntu OCI candidate refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--emit-observations|--pre-completion] --profile PROFILE --externally-expected-profile-sha256 SHA256 --externally-expected-profile-repository HTTPS_GIT_URL --externally-expected-profile-commit COMMIT --externally-expected-profile-path REPOSITORY_PATH --candidate DIRECTORY\n' \
    "${0##*/}" >&2
  exit 2
}

emit_observations=false
pre_completion=false
profile_path=''
expected_profile_sha256=''
expected_profile_repository=''
expected_profile_commit=''
expected_profile_path=''
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
    --externally-expected-profile-repository)
      [[ -z "${expected_profile_repository}" && $# -ge 2 ]] || usage
      expected_profile_repository="$2"
      shift 2
      ;;
    --externally-expected-profile-commit)
      [[ -z "${expected_profile_commit}" && $# -ge 2 ]] || usage
      expected_profile_commit="$2"
      shift 2
      ;;
    --externally-expected-profile-path)
      [[ -z "${expected_profile_path}" && $# -ge 2 ]] || usage
      expected_profile_path="$2"
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
readonly expected_profile_repository expected_profile_commit expected_profile_path
readonly candidate_directory

[[ -n "${profile_path}" && -n "${expected_profile_sha256}" && \
  -n "${expected_profile_repository}" && -n "${expected_profile_commit}" && \
  -n "${expected_profile_path}" && -n "${candidate_directory}" ]] || usage
[[ "${expected_profile_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'externally expected profile digest is not one lowercase SHA-256'
profile_repository_suffix="${expected_profile_repository#https://}"
[[ "${expected_profile_repository}" == https://* && \
  "${profile_repository_suffix}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\.git$ && \
  "${profile_repository_suffix}" != *'..'* && \
  "${profile_repository_suffix}" != *'//'* && \
  "${profile_repository_suffix}" != *'/./'* && \
  "${profile_repository_suffix}" != *'/../'* ]] ||
  fail 'externally expected profile repository is not one exact HTTPS .git locator'
[[ "${expected_profile_commit}" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'externally expected profile commit is not one lowercase Git object identifier'
[[ "${expected_profile_path}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\.profile$ && \
  "${expected_profile_path}" != */ && "${expected_profile_path}" != *'//'* && \
  "${expected_profile_path}" != *'/./'* && \
  "${expected_profile_path}" != *'/../'* ]] ||
  fail 'externally expected profile path is not one safe repository-relative profile path'

readonly AWK=/usr/bin/awk
readonly CMP=/usr/bin/cmp
readonly FIND=/usr/bin/find
readonly GZIP=/usr/bin/gzip
readonly HEAD=/usr/bin/head
readonly JQ=/usr/bin/jq
readonly OD=/usr/bin/od
readonly SHA256SUM=/usr/bin/sha256sum
readonly STAT=/usr/bin/stat
readonly TAIL=/usr/bin/tail
readonly TIMEOUT=/usr/bin/timeout
readonly TR=/usr/bin/tr
readonly UNAME=/usr/bin/uname
readonly WC=/usr/bin/wc
for required_tool in \
  "${AWK}" "${CMP}" "${FIND}" "${GZIP}" "${HEAD}" "${JQ}" "${OD}" \
  "${SHA256SUM}" "${STAT}" "${TAIL}" "${TIMEOUT}" "${TR}" "${UNAME}" \
  "${WC}"; do
  [[ -x "${required_tool}" && -f "${required_tool}" ]] ||
    fail "required offline verifier tool is unavailable or not a regular file: ${required_tool}"
done
[[ "$(${UNAME} -s)" == Linux ]] || fail 'offline OCI candidate verification requires Linux'

readonly MAXIMUM_PROFILE_BYTES=65536
readonly EXPECTED_PROFILE_FIELD_COUNT=129
readonly EXPECTED_PROFILE_KEY_SEQUENCE_SHA256='aa3513bf6fe9c7013ef3c352aaf8b36f1f554406e7b2a8c3266f2845f7d0824f'
readonly MAXIMUM_JSON_BYTES=1048576
readonly MAXIMUM_COMPRESSED_LAYER_BYTES=67108864
readonly MAXIMUM_UNCOMPRESSED_LAYER_BYTES=536870912
readonly DECOMPRESSION_TIMEOUT_SECONDS=60
readonly MAXIMUM_RECEIPT_BYTES=65536

validate_bounded_text() {
  local label="$1"
  local path="$2"
  local maximum_bytes="$3"
  local size
  local printable_size
  local last_byte
  size="$(${STAT} -c '%s' -- "${path}")" || fail "${label} size is unavailable"
  [[ "${size}" =~ ^[0-9]+$ ]] || fail "${label} size is malformed"
  (( size > 0 && size <= maximum_bytes )) || fail "${label} size is outside the closed bound"
  printable_size="$(${TR} -cd '\12\40-\176' <"${path}" | ${WC} -c)"
  [[ "${printable_size}" == "${size}" ]] ||
    fail "${label} contains a control, carriage-return, NUL, or non-ASCII byte"
  last_byte="$(${TAIL} -c 1 -- "${path}" | ${OD} -An -tu1 | ${TR} -d '[:space:]')"
  [[ "${last_byte}" == 10 ]] || fail "${label} must end with one LF byte"
}

[[ -f "${profile_path}" && ! -L "${profile_path}" ]] ||
  fail 'external profile must be one regular non-symlink file'
profile_metadata_before="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${profile_path}")"
validate_bounded_text profile "${profile_path}" "${MAXIMUM_PROFILE_BYTES}"

declare -A fields=()
line_count=0
while IFS= read -r line; do
  ((line_count += 1))
  [[ -n "${line}" && "${line}" == *=* ]] ||
    fail "profile line ${line_count} is not one nonempty key/value record"
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${value}" != *'='* ]] || fail "profile line ${line_count} has an extra separator"
  [[ "${key}" =~ ^[a-z][a-z0-9_]{0,63}$ && -n "${value}" && \
    ${#value} -le 4096 && "${value}" != ' '* && "${value}" != *' ' ]] ||
    fail "profile line ${line_count} has invalid bounds"
  [[ ! -v "fields[${key}]" ]] || fail "profile has duplicate key: ${key}"
  fields["${key}"]="${value}"
done <"${profile_path}"
readonly line_count
[[ "${line_count}" -eq "${EXPECTED_PROFILE_FIELD_COUNT}" ]] ||
  fail 'profile does not have exactly 129 fields'
# This is an awk program, not a shell expression.
# shellcheck disable=SC2016
profile_key_sequence_sha256="$(${AWK} -F= '{ print $1 }' "${profile_path}" | ${SHA256SUM})"
profile_key_sequence_sha256="${profile_key_sequence_sha256%% *}"
[[ "${profile_key_sequence_sha256}" == "${EXPECTED_PROFILE_KEY_SEQUENCE_SHA256}" ]] ||
  fail 'profile does not have the exact closed v2 key sequence'

require_field() {
  local key="$1"
  local expected="$2"
  [[ -v "fields[${key}]" && "${fields[${key}]}" == "${expected}" ]] ||
    fail "profile has an unexpected value for ${key}"
}

require_prefixed_sha256_field() {
  local key="$1"
  [[ -v "fields[${key}]" && "${fields[${key}]}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "profile field is not one lowercase descriptor SHA-256: ${key}"
}

require_bounded_size_field() {
  local key="$1"
  local maximum="$2"
  local numeric_value
  [[ -v "fields[${key}]" && "${fields[${key}]}" =~ ^[1-9][0-9]*$ ]] ||
    fail "profile field is not one positive decimal size: ${key}"
  numeric_value="${fields[${key}]}"
  (( numeric_value <= maximum )) || fail "profile size exceeds the closed bound: ${key}"
}

require_field format a-quo-omarchy-evaluation-target-profile-v2
require_field profile_id a-quo-omarchy4-aarch64-dec29fa-v2
require_field state bootstrap-unarmed
require_field armable false
require_field expectation_scope reviewed-metadata-only
require_field retained_input_authority none
require_field purpose evaluation-only
require_field architecture aarch64
require_field builder_base_oci_repository docker.io/library/ubuntu
require_field builder_base_oci_platform linux/arm64
require_prefixed_sha256_field builder_base_oci_index_digest
require_prefixed_sha256_field builder_base_oci_manifest_digest
require_field builder_base_oci_discovery_tag_authority none
require_field builder_base_oci_variant v8
require_field builder_base_oci_index_media_type application/vnd.oci.image.index.v1+json
require_field builder_base_oci_manifest_media_type application/vnd.oci.image.manifest.v1+json
require_field builder_base_oci_config_media_type application/vnd.oci.image.config.v1+json
require_bounded_size_field builder_base_oci_index_size "${MAXIMUM_JSON_BYTES}"
require_bounded_size_field builder_base_oci_manifest_size "${MAXIMUM_JSON_BYTES}"
require_bounded_size_field builder_base_oci_config_size "${MAXIMUM_JSON_BYTES}"
require_prefixed_sha256_field builder_base_oci_config_digest
require_field builder_base_oci_layer_count 1
require_field builder_base_oci_layer_01_media_type application/vnd.oci.image.layer.v1.tar+gzip
require_bounded_size_field builder_base_oci_layer_01_size "${MAXIMUM_COMPRESSED_LAYER_BYTES}"
require_prefixed_sha256_field builder_base_oci_layer_01_digest
require_field builder_base_oci_diff_id_count 1
require_prefixed_sha256_field builder_base_oci_diff_id_01
[[ "${fields[builder_base_oci_discovery_tag]}" =~ ^noble-([0-9]{8})$ ]] ||
  fail 'profile discovery tag does not encode one bounded noble date selector'
discovery_serial="${BASH_REMATCH[1]}"
[[ "${fields[builder_base_oci_source_serial_assertion]}" == "${discovery_serial}" ]] ||
  fail 'profile source serial assertion does not match the discovery tag date'
[[ "${fields[builder_base_oci_source_repository_assertion]}" == https://* && \
  "${fields[builder_base_oci_source_repository_assertion]}" != *'?'* && \
  "${fields[builder_base_oci_source_repository_assertion]}" != *'#'* ]] ||
  fail 'profile source repository assertion is not one exact HTTPS locator'
[[ "${fields[builder_base_oci_source_revision_assertion]}" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'profile source revision assertion is not one lowercase Git object identifier'
[[ "${fields[builder_base_oci_source_version_assertion]}" =~ ^[0-9]+\.[0-9]+$ ]] ||
  fail 'profile source version assertion is malformed'
require_field builder_base_oci_integrity content-addressed-descriptor-chain
require_field builder_base_oci_publisher_authentication not-established
require_field builder_base_oci_source_to_image_provenance not-established
require_field builder_base_oci_retention required-not-retained
require_field profile_authentication external-pinned-git-object-required
require_field self_authentication none
require_field release_claim not-established
require_field support_claim not-established
require_field reproducibility_claim not-established
require_field clean_system_claim not-established
require_field a_quo_release_provenance not-established
require_field unresolved_input_count 10
require_field unresolved_input_01 builder-oci-retained-archive-and-final-image

profile_sha256="$(${SHA256SUM} -- "${profile_path}")"
profile_sha256="${profile_sha256%% *}"
profile_metadata_after="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${profile_path}")"
[[ "${profile_metadata_after}" == "${profile_metadata_before}" ]] ||
  fail 'external profile metadata changed during verification'
[[ "${profile_sha256}" == "${expected_profile_sha256}" ]] ||
  fail 'external profile bytes do not match the caller-supplied expected digest'
readonly profile_sha256 discovery_serial

[[ -d "${candidate_directory}" && ! -L "${candidate_directory}" ]] ||
  fail 'candidate must be one directory and not a symlink'
[[ "$(${STAT} -c '%a:%u' -- "${candidate_directory}")" == "700:${EUID}" ]] ||
  fail 'candidate directory must be owned by the caller with mode 0700'
candidate_directory_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${candidate_directory}")"

readonly candidate_profile="${candidate_directory}/profile.snapshot"
[[ -f "${candidate_profile}" && ! -L "${candidate_profile}" ]] ||
  fail 'candidate profile snapshot is missing or not a regular file'
[[ "$(${STAT} -c '%a:%h:%u' -- "${candidate_profile}")" == "400:1:${EUID}" ]] ||
  fail 'candidate profile snapshot must be caller-owned, mode 0400, and singly linked'
candidate_profile_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${candidate_profile}")"
validate_bounded_text 'candidate profile snapshot' "${candidate_profile}" "${MAXIMUM_PROFILE_BYTES}"
snapshot_profile_sha256="$(${SHA256SUM} -- "${candidate_profile}")"
snapshot_profile_sha256="${snapshot_profile_sha256%% *}"
[[ "${snapshot_profile_sha256}" == "${expected_profile_sha256}" ]] ||
  fail 'candidate profile snapshot does not match the externally expected digest'
${CMP} -s -- "${profile_path}" "${candidate_profile}" ||
  fail 'candidate profile snapshot differs from the external profile bytes'
[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${candidate_profile}")" == \
  "${candidate_profile_metadata}" ]] ||
  fail 'candidate profile snapshot metadata changed during verification'

declare -a object_roles=(index manifest config layer)
declare -a object_paths=(
  objects/index.json
  objects/manifest.json
  objects/config.json
  objects/layer-01.tar.gz
)
declare -a object_sizes=(
  "${fields[builder_base_oci_index_size]}"
  "${fields[builder_base_oci_manifest_size]}"
  "${fields[builder_base_oci_config_size]}"
  "${fields[builder_base_oci_layer_01_size]}"
)
declare -a object_hashes=(
  "${fields[builder_base_oci_index_digest]#sha256:}"
  "${fields[builder_base_oci_manifest_digest]#sha256:}"
  "${fields[builder_base_oci_config_digest]#sha256:}"
  "${fields[builder_base_oci_layer_01_digest]#sha256:}"
)
declare -a expected_paths=(objects profile.snapshot)
declare -a expected_types=(directory file)
for object_path in "${object_paths[@]}"; do
  expected_paths+=("${object_path}")
  expected_types+=(file)
done
if [[ "${emit_observations}" == true ]]; then
  expected_paths+=(INCOMPLETE)
  expected_types+=(file)
elif [[ "${pre_completion}" == true ]]; then
  expected_paths+=(receipt.oci.v1 INCOMPLETE)
  expected_types+=(file file)
else
  expected_paths+=(receipt.oci.v1 COMPLETE)
  expected_types+=(file file)
fi
declare -a seen_expected_entries=()

entry_count=0
while IFS= read -r -d '' relative_path && IFS= read -r -d '' entry_type; do
  ((entry_count += 1))
  matching_index=-1
  for index in "${!expected_paths[@]}"; do
    if [[ "${relative_path}" == "${expected_paths[index]}" ]]; then
      matching_index="${index}"
      break
    fi
  done
  (( matching_index >= 0 )) || fail "candidate contains an unexpected entry: ${relative_path@Q}"
  [[ "${seen_expected_entries[matching_index]:-false}" == false ]] ||
    fail "candidate inventory repeated an entry: ${relative_path@Q}"
  seen_expected_entries[matching_index]=true
  expected_type="${expected_types[matching_index]}"
  if [[ "${expected_type}" == directory ]]; then
    [[ "${entry_type}" == d ]] || fail "candidate directory has the wrong type: ${relative_path}"
    [[ "$(${STAT} -c '%a:%u' -- "${candidate_directory}/${relative_path}")" == "700:${EUID}" ]] ||
      fail "candidate directory has the wrong owner or mode: ${relative_path}"
  else
    [[ "${entry_type}" == f ]] || fail "candidate file has the wrong type: ${relative_path}"
    [[ "$(${STAT} -c '%a:%h:%u' -- "${candidate_directory}/${relative_path}")" == "400:1:${EUID}" ]] ||
      fail "candidate file has the wrong owner, mode, or link count: ${relative_path}"
  fi
done < <(${FIND} -P "${candidate_directory}" -xdev -mindepth 1 -printf '%P\0%y\0')
readonly entry_count
[[ "${entry_count}" -eq "${#expected_paths[@]}" ]] ||
  fail 'candidate is missing one or more required entries'
for index in "${!expected_paths[@]}"; do
  [[ "${seen_expected_entries[index]:-false}" == true ]] ||
    fail "candidate is missing a required entry: ${expected_paths[index]}"
done
objects_directory_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- \
  "${candidate_directory}/objects")"

if [[ "${emit_observations}" == true || "${pre_completion}" == true ]]; then
  marker_path="${candidate_directory}/INCOMPLETE"
  marker_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${marker_path}")"
  [[ "$(${STAT} -c '%s' -- "${candidate_directory}/INCOMPLETE")" == 21 && \
    "$(<"${candidate_directory}/INCOMPLETE")" == incomplete-candidate ]] ||
    fail 'INCOMPLETE marker content is invalid'
else
  marker_path="${candidate_directory}/COMPLETE"
  marker_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${marker_path}")"
  [[ "$(${STAT} -c '%s' -- "${candidate_directory}/COMPLETE")" == 19 && \
    "$(<"${candidate_directory}/COMPLETE")" == complete-candidate ]] ||
    fail 'COMPLETE marker content is invalid'
fi
readonly marker_path marker_metadata

declare -a object_records=()
declare -a object_metadata=()
for index in "${!object_paths[@]}"; do
  path="${candidate_directory}/${object_paths[index]}"
  object_metadata[index]="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${path}")"
  observed_size="$(${STAT} -c '%s' -- "${path}")"
  [[ "${observed_size}" == "${object_sizes[index]}" ]] ||
    fail "object has the wrong size: ${object_paths[index]}"
  observed_hash="$(${SHA256SUM} -- "${path}")"
  observed_hash="${observed_hash%% *}"
  metadata_after_hash="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${path}")"
  [[ "${metadata_after_hash}" == "${object_metadata[index]}" ]] ||
    fail "object metadata changed while hashing: ${object_paths[index]}"
  [[ "${observed_hash}" == "${object_hashes[index]}" ]] ||
    fail "object has the wrong SHA-256: ${object_paths[index]}"
  object_records[index]="${object_roles[index]}|${object_paths[index]}|${observed_size}|${observed_hash}"
done

readonly index_path="${candidate_directory}/${object_paths[0]}"
readonly manifest_path="${candidate_directory}/${object_paths[1]}"
readonly config_path="${candidate_directory}/${object_paths[2]}"
readonly layer_path="${candidate_directory}/${object_paths[3]}"
created_date="${discovery_serial:0:4}-${discovery_serial:4:2}-${discovery_serial:6:2}T00:00:00Z"
readonly created_date

# The following single-quoted text is a jq program.
# shellcheck disable=SC2016
${JQ} -s -e \
  --arg index_media "${fields[builder_base_oci_index_media_type]}" \
  --arg manifest_media "${fields[builder_base_oci_manifest_media_type]}" \
  --arg manifest_digest "${fields[builder_base_oci_manifest_digest]}" \
  --argjson manifest_size "${fields[builder_base_oci_manifest_size]}" \
  --arg variant "${fields[builder_base_oci_variant]}" \
  --arg source "${fields[builder_base_oci_source_repository_assertion]}" \
  --arg revision "${fields[builder_base_oci_source_revision_assertion]}" \
  --arg version "${fields[builder_base_oci_source_version_assertion]}" \
  --arg created "${created_date}" '
    length == 1 and
    (.[0] |
      type == "object" and
      .schemaVersion == 2 and
      .mediaType == $index_media and
      (.manifests | type == "array") and
      ([.manifests[] |
        select(.platform.os == "linux" and
          .platform.architecture == "arm64" and
          .platform.variant == $variant)] | length) == 1 and
      ([.manifests[] |
        select(.platform.os == "linux" and
          .platform.architecture == "arm64" and
          .platform.variant == $variant)][0] |
        .mediaType == $manifest_media and
        .digest == $manifest_digest and
        .size == $manifest_size and
        .annotations["com.docker.official-images.bashbrew.arch"] == "arm64v8" and
        .annotations["org.opencontainers.image.created"] == $created and
        .annotations["org.opencontainers.image.revision"] == $revision and
        .annotations["org.opencontainers.image.source"] == $source and
        .annotations["org.opencontainers.image.version"] == $version))
  ' "${index_path}" >/dev/null 2>&1 ||
  fail 'index JSON does not bind the expected ARM64/v8 manifest and named source assertions'

# The following single-quoted text is a jq program.
# shellcheck disable=SC2016
${JQ} -s -e \
  --arg manifest_media "${fields[builder_base_oci_manifest_media_type]}" \
  --arg config_media "${fields[builder_base_oci_config_media_type]}" \
  --arg config_digest "${fields[builder_base_oci_config_digest]}" \
  --argjson config_size "${fields[builder_base_oci_config_size]}" \
  --arg layer_media "${fields[builder_base_oci_layer_01_media_type]}" \
  --arg layer_digest "${fields[builder_base_oci_layer_01_digest]}" \
  --argjson layer_size "${fields[builder_base_oci_layer_01_size]}" '
    length == 1 and
    (.[0] |
      type == "object" and
      .schemaVersion == 2 and
      .mediaType == $manifest_media and
      .config.mediaType == $config_media and
      .config.digest == $config_digest and
      .config.size == $config_size and
      (.layers | type == "array") and
      (.layers | length) == 1 and
      .layers[0].mediaType == $layer_media and
      .layers[0].digest == $layer_digest and
      .layers[0].size == $layer_size)
  ' "${manifest_path}" >/dev/null 2>&1 ||
  fail 'manifest JSON does not bind the expected config and compressed layer descriptors'

# The following single-quoted text is a jq program.
# shellcheck disable=SC2016
${JQ} -s -e \
  --arg diff_id "${fields[builder_base_oci_diff_id_01]}" \
  --arg version "${fields[builder_base_oci_source_version_assertion]}" '
    length == 1 and
    (.[0] |
      type == "object" and
      .architecture == "arm64" and
      .os == "linux" and
      .rootfs.type == "layers" and
      (.rootfs.diff_ids | type == "array") and
      (.rootfs.diff_ids | length) == 1 and
      .rootfs.diff_ids[0] == $diff_id and
      .config.Labels["org.opencontainers.image.version"] == $version)
  ' "${config_path}" >/dev/null 2>&1 ||
  fail 'config JSON does not bind the expected platform, version, and one DiffID'

${TIMEOUT} --signal=TERM --kill-after=5 "${DECOMPRESSION_TIMEOUT_SECONDS}" \
  "${GZIP}" -t -- "${layer_path}" >/dev/null 2>&1 ||
  fail 'compressed layer is not one accepted gzip byte stream within the time bound'
set +e
decompressed_size="$({
  set -o pipefail
  "${TIMEOUT}" --signal=TERM --kill-after=5 "${DECOMPRESSION_TIMEOUT_SECONDS}" \
    "${GZIP}" -dc -- "${layer_path}" 2>/dev/null |
    "${HEAD}" -c "$((MAXIMUM_UNCOMPRESSED_LAYER_BYTES + 1))" |
    "${WC}" -c
})"
decompressed_size_status=$?
set -e
[[ "${decompressed_size_status}" -eq 0 && "${decompressed_size}" =~ ^[0-9]+$ && \
  "${decompressed_size}" -le "${MAXIMUM_UNCOMPRESSED_LAYER_BYTES}" ]] ||
  fail 'uncompressed layer exceeds the byte or time bound'
set +e
observed_diff_id="$({
  set -o pipefail
  "${TIMEOUT}" --signal=TERM --kill-after=5 "${DECOMPRESSION_TIMEOUT_SECONDS}" \
    "${GZIP}" -dc -- "${layer_path}" 2>/dev/null |
    "${HEAD}" -c "$((MAXIMUM_UNCOMPRESSED_LAYER_BYTES + 1))" |
    "${SHA256SUM}"
})"
diff_id_status=$?
set -e
[[ "${diff_id_status}" -eq 0 ]] || fail 'uncompressed layer hashing failed within the closed bounds'
observed_diff_id="sha256:${observed_diff_id%% *}"
[[ "${observed_diff_id}" == "${fields[builder_base_oci_diff_id_01]}" ]] ||
  fail 'uncompressed layer DiffID does not match the profile'

for index in "${!object_paths[@]}"; do
  metadata_after_semantics="$(${STAT} -c '%d:%i:%s:%f:%Y' -- \
    "${candidate_directory}/${object_paths[index]}")"
  [[ "${metadata_after_semantics}" == "${object_metadata[index]}" ]] ||
    fail "object metadata changed during semantic verification: ${object_paths[index]}"
done

declare -a expected_receipt=(
  'format=a-quo-omarchy-ubuntu-oci-candidate-v1'
  'status=complete-candidate'
  'authority=none'
  "profile_id=${fields[profile_id]}"
  "profile_sha256=${profile_sha256}"
  "profile_repository=${expected_profile_repository}"
  "profile_commit=${expected_profile_commit}"
  "profile_path=${expected_profile_path}"
  'profile_external_authentication=required-not-established-by-this-receipt'
  'acquisition_history=not-authenticated-by-this-receipt'
  "subject_repository=${fields[builder_base_oci_repository]}"
  "discovery_tag=${fields[builder_base_oci_discovery_tag]}"
  'discovery_tag_authority=none'
  "platform=${fields[builder_base_oci_platform]}"
  "variant=${fields[builder_base_oci_variant]}"
  'object_count=4'
  "object_01=${object_records[0]}"
  "object_02=${object_records[1]}"
  "object_03=${object_records[2]}"
  "object_04=${object_records[3]}"
  'descriptor_bindings=verified-non-authoritative'
  "diff_id=${observed_diff_id}"
  'publisher_authentication=not-established'
  'source_to_image_provenance=not-established'
  'freshness=not-established'
  'safety=not-established'
  'byte_identity=verified-non-authoritative'
)

if [[ "${emit_observations}" == false ]]; then
  readonly receipt_path="${candidate_directory}/receipt.oci.v1"
  receipt_metadata="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${receipt_path}")"
  validate_bounded_text receipt "${receipt_path}" "${MAXIMUM_RECEIPT_BYTES}"
  mapfile -t receipt_lines <"${receipt_path}"
  [[ "${#receipt_lines[@]}" -eq "${#expected_receipt[@]}" ]] ||
    fail 'receipt does not have the exact field count'
  for index in "${!expected_receipt[@]}"; do
    [[ "${receipt_lines[index]}" == "${expected_receipt[index]}" ]] ||
      fail "receipt field order or value is invalid at line $((index + 1))"
  done
  [[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${receipt_path}")" == \
    "${receipt_metadata}" ]] || fail 'receipt metadata changed during verification'
fi

[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${candidate_directory}/objects")" == \
  "${objects_directory_metadata}" ]] ||
  fail 'candidate objects directory metadata changed during verification'
[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${candidate_directory}")" == \
  "${candidate_directory_metadata}" ]] ||
  fail 'candidate directory metadata changed during verification'
[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${marker_path}")" == \
  "${marker_metadata}" ]] || fail 'candidate completion marker metadata changed during verification'
[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${candidate_profile}")" == \
  "${candidate_profile_metadata}" ]] ||
  fail 'candidate profile snapshot metadata changed during semantic verification'
[[ "$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${profile_path}")" == \
  "${profile_metadata_before}" ]] ||
  fail 'external profile metadata changed during semantic verification'

if [[ "${emit_observations}" == true || "${pre_completion}" == true ]]; then
  candidate_status=verified-incomplete-non-authoritative
else
  candidate_status=verified-non-authoritative
fi
printf '%s\n' \
  "candidate_status=${candidate_status}" \
  'authority=none' \
  "profile_id=${fields[profile_id]}" \
  "profile_sha256=${profile_sha256}" \
  'object_count=4' \
  "object_01=${object_records[0]}" \
  "object_02=${object_records[1]}" \
  "object_03=${object_records[2]}" \
  "object_04=${object_records[3]}" \
  'descriptor_bindings=verified-non-authoritative' \
  "diff_id=${observed_diff_id}" \
  'publisher_authentication=not-established' \
  'source_to_image_provenance=not-established' \
  'freshness=not-established' \
  'safety=not-established' \
  'byte_identity=verified-non-authoritative' \
  'network_activity=false' \
  'vm_started=false'
