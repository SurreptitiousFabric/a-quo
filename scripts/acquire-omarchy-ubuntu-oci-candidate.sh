#!/usr/bin/env bash

set +x
set -euo pipefail
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin
umask 077
ulimit -c 0

registry_bearer=''
token_body=''
private_redirect=''
curl_redirect_url=''

scrub_credentials() {
  registry_bearer=''
  token_body=''
  private_redirect=''
  curl_redirect_url=''
}

interrupted() {
  scrub_credentials
  exit 130
}

trap scrub_credentials EXIT
trap interrupted HUP INT TERM

fail() {
  printf 'Omarchy Ubuntu OCI acquisition refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s --profile CANONICAL_V2 --output NEW_RUN_DIRECTORY --acknowledge-networked-candidate-only\n' \
    "${0##*/}" >&2
  exit 2
}

profile_path=''
output_directory=''
acknowledged=false
while (( $# > 0 )); do
  case "$1" in
    --profile)
      [[ -z "${profile_path}" && $# -ge 2 ]] || usage
      profile_path="$2"
      shift 2
      ;;
    --output)
      [[ -z "${output_directory}" && $# -ge 2 ]] || usage
      output_directory="$2"
      shift 2
      ;;
    --acknowledge-networked-candidate-only)
      [[ "${acknowledged}" == false ]] || usage
      acknowledged=true
      shift
      ;;
    *) usage ;;
  esac
done
readonly profile_path output_directory acknowledged
[[ -n "${profile_path}" && -n "${output_directory}" && \
  "${acknowledged}" == true ]] || usage
if (( EUID == 0 )); then
  fail 'networked candidate acquisition must not run as root'
fi

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly CANONICAL_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-evaluation-target-profile.sh"
readonly CANDIDATE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-ubuntu-oci-candidate.sh"
readonly EXPECTED_PROFILE_SHA256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6
readonly PROFILE_REPOSITORY=https://github.com/SurreptitiousFabric/a-quo.git
readonly PROFILE_COMMIT=e13e74dca3472e54501b35c9b57ee89f57c6aed3
readonly PROFILE_REPOSITORY_PATH=packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile
readonly OBSERVATION_ROOT="${REPOSITORY_ROOT}/target/omarchy-evaluation-input-observations"

readonly SUBJECT_REPOSITORY=docker.io/library/ubuntu
readonly SUBJECT_PLATFORM=linux/arm64
readonly SUBJECT_VARIANT=v8
readonly DISCOVERY_TAG=noble-20260810
readonly INDEX_DIGEST=sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
readonly MANIFEST_DIGEST=sha256:95fa486768020359141f1318720f43e7982ef926c792891d984aef9aaf05e7ea
readonly CONFIG_DIGEST=sha256:5b8c0c14690ed170da4e663fe0bae0d58efe59661e791296ffab28ed2113b650
readonly LAYER_DIGEST=sha256:0b613318ea879878918380aa3aeb220dfe824e311b83bc955cb8a1d4319650ab
readonly DIFF_ID=sha256:646eea22414270d74b0c9e9d6d3b9550701ae62e658a099825d4d15045a3630b
readonly INDEX_MEDIA_TYPE=application/vnd.oci.image.index.v1+json
readonly MANIFEST_MEDIA_TYPE=application/vnd.oci.image.manifest.v1+json
readonly CONFIG_MEDIA_TYPE=application/vnd.oci.image.config.v1+json
readonly LAYER_MEDIA_TYPE=application/vnd.oci.image.layer.v1.tar+gzip
readonly INDEX_SIZE=6688
readonly MANIFEST_SIZE=424
readonly CONFIG_SIZE=2067
readonly LAYER_SIZE=28887235
readonly TOKEN_URL='https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Alibrary%2Fubuntu%3Apull'
readonly REGISTRY_BASE=https://registry-1.docker.io/v2/library/ubuntu

[[ "${profile_path}" == "${CANONICAL_PROFILE}" ]] ||
  fail 'profile must be the canonical v2 profile'
[[ -f "${profile_path}" && ! -L "${profile_path}" ]] ||
  fail 'canonical v2 profile is missing or is a symlink'
for verifier in "${PROFILE_VERIFIER}" "${CANDIDATE_VERIFIER}"; do
  [[ -x "${verifier}" && -f "${verifier}" && ! -L "${verifier}" ]] ||
    fail "required repository verifier is missing, non-executable, or a symlink: ${verifier}"
done

readonly AWK=/usr/bin/awk
readonly CHMOD=/usr/bin/chmod
readonly CURL=/usr/bin/curl
readonly DD=/usr/bin/dd
readonly ENV=/usr/bin/env
readonly JQ=/usr/bin/jq
readonly MKDIR=/usr/bin/mkdir
readonly MKTEMP=/usr/bin/mktemp
readonly MV=/usr/bin/mv
readonly RM=/usr/bin/rm
readonly SHA256SUM=/usr/bin/sha256sum
readonly STAT=/usr/bin/stat
readonly SYNC=/usr/bin/sync
for required_tool in \
  "${AWK}" "${CHMOD}" "${CURL}" "${DD}" "${ENV}" "${JQ}" \
  "${MKDIR}" "${MKTEMP}" "${MV}" "${RM}" "${SHA256SUM}" \
  "${STAT}" "${SYNC}"; do
  [[ -x "${required_tool}" && -f "${required_tool}" ]] ||
    fail "required acquisition tool is unavailable or does not resolve to a regular file: ${required_tool}"
done

# shellcheck disable=SC2016
curl_version="$(${CURL} --version | ${AWK} 'NR == 1 { print $2 }')"
readonly curl_version
[[ "${curl_version}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([-+].*)?$ ]] ||
  fail 'curl did not report a parseable semantic version'
curl_version_major="${BASH_REMATCH[1]}"
curl_version_minor="${BASH_REMATCH[2]}"
readonly curl_version_major curl_version_minor
(( curl_version_major > 8 || \
  (curl_version_major == 8 && curl_version_minor >= 4) )) ||
  fail 'curl 8.4 or newer is required for bounded response bodies'

[[ "${output_directory}" == /* && "${output_directory}" != */ ]] ||
  fail 'output must be one absolute path without a trailing slash'
output_name="${output_directory##*/}"
readonly output_name
[[ "${output_name}" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ && \
  "${output_name}" != . && "${output_name}" != .. ]] ||
  fail 'output run name is outside the closed filename grammar'
[[ "${output_directory}" == "${OBSERVATION_ROOT}/${output_name}" ]] ||
  fail 'output must be one direct child of target/omarchy-evaluation-input-observations'

readonly target_root="${REPOSITORY_ROOT}/target"
if [[ ! -e "${target_root}" && ! -L "${target_root}" ]]; then
  ${MKDIR} -m 0755 -- "${target_root}" ||
    fail 'could not create repository target directory'
  ${SYNC} -- "${REPOSITORY_ROOT}"
fi
[[ -d "${target_root}" && ! -L "${target_root}" ]] ||
  fail 'repository target path must be one non-symlink directory'
if [[ ! -e "${OBSERVATION_ROOT}" && ! -L "${OBSERVATION_ROOT}" ]]; then
  ${MKDIR} -m 0700 -- "${OBSERVATION_ROOT}" ||
    fail 'could not create private OCI observation root'
  ${SYNC} -- "${target_root}"
fi
[[ -d "${OBSERVATION_ROOT}" && ! -L "${OBSERVATION_ROOT}" && \
  "$(${STAT} -c '%a' -- "${OBSERVATION_ROOT}")" == 700 ]] ||
  fail 'OCI observation root must be one mode-0700 non-symlink directory'
[[ ! -e "${output_directory}" && ! -L "${output_directory}" ]] ||
  fail 'output already exists'
${MKDIR} -m 0700 -- "${output_directory}" ||
  fail 'could not create fresh output run directory'
${SYNC} -- "${OBSERVATION_ROOT}"
[[ -d "${output_directory}" && ! -L "${output_directory}" && \
  "$(${STAT} -c '%a' -- "${output_directory}")" == 700 ]] ||
  fail 'fresh output run directory did not retain its private identity'

create_exclusive_text_file() {
  local path="$1"
  local content="$2"
  local parent="${path%/*}"
  (
    set -o noclobber
    printf '%s\n' "${content}" >"${path}"
  ) 2>/dev/null || fail "could not exclusively create ${path##*/}"
  ${CHMOD} 0400 -- "${path}"
  [[ -f "${path}" && ! -L "${path}" && \
    "$(${STAT} -c '%a:%h' -- "${path}")" == 400:1 ]] ||
    fail "exclusive file publication failed for ${path##*/}"
  ${SYNC} -- "${path}"
  ${SYNC} -- "${parent}"
}

publish_private_file() {
  local temporary_path="$1"
  local final_path="$2"
  local final_parent="${final_path%/*}"
  [[ -f "${temporary_path}" && ! -L "${temporary_path}" && \
    "$(${STAT} -c '%h' -- "${temporary_path}")" == 1 ]] ||
    fail 'temporary acquisition object lost its regular-file identity'
  [[ ! -e "${final_path}" && ! -L "${final_path}" ]] ||
    fail "refusing to replace candidate object: ${final_path##*/}"
  ${CHMOD} 0400 -- "${temporary_path}"
  ${SYNC} -- "${temporary_path}"
  ${MV} -T --no-clobber -- "${temporary_path}" "${final_path}" ||
    fail "no-clobber candidate publication failed: ${final_path##*/}"
  [[ ! -e "${temporary_path}" && ! -L "${temporary_path}" && \
    -f "${final_path}" && ! -L "${final_path}" && \
    "$(${STAT} -c '%a:%h' -- "${final_path}")" == 400:1 ]] ||
    fail "published candidate object has the wrong identity: ${final_path##*/}"
  ${SYNC} -- "${final_parent}"
}

create_exclusive_text_file "${output_directory}/INCOMPLETE" incomplete-candidate
${MKDIR} -m 0700 -- "${output_directory}/objects"
${SYNC} -- "${output_directory}"

profile_temporary="$(${MKTEMP} "${output_directory}/.profile.snapshot.XXXXXX")"
readonly profile_temporary
exec {profile_fd}<"${profile_path}"
${DD} if="/proc/self/fd/${profile_fd}" of="${profile_temporary}" \
  bs=65537 count=1 status=none
exec {profile_fd}<&-
profile_size="$(${STAT} -c '%s' -- "${profile_temporary}")"
profile_digest="$(${SHA256SUM} -- "${profile_temporary}")"
profile_digest="${profile_digest%% *}"
readonly profile_size profile_digest
(( profile_size > 0 && profile_size <= 65536 )) ||
  fail 'profile snapshot is outside the closed byte bound'
[[ "${profile_digest}" == "${EXPECTED_PROFILE_SHA256}" ]] ||
  fail 'profile snapshot does not match the externally pinned canonical v2 digest'
"${PROFILE_VERIFIER}" "${profile_temporary}" >/dev/null
publish_private_file "${profile_temporary}" "${output_directory}/profile.snapshot"

token_metadata="$(${MKTEMP} "${output_directory}/.token-metadata.XXXXXX")"
readonly token_metadata
set +e
token_body="$(${ENV} \
  -u ALL_PROXY -u HTTPS_PROXY -u HTTP_PROXY -u NO_PROXY \
  -u all_proxy -u https_proxy -u http_proxy -u no_proxy \
  -u CURL_CA_BUNDLE -u CURL_HOME -u SSL_CERT_FILE -u SSL_CERT_DIR \
  -u SSLKEYLOGFILE \
  "${CURL}" -q \
  --silent --show-error --fail \
  --globoff \
  --proto '=https' --proto-redir '=https' \
  --tlsv1.2 \
  --proxy '' --noproxy '*' \
  --connect-timeout 20 --max-time 60 \
  --speed-limit 1 --speed-time 20 \
  --max-redirs 0 --max-filesize 16384 \
  --header 'Accept: application/json' \
  --header 'Accept-Encoding: identity' \
  --user-agent 'a-quo-ubuntu-oci-candidate/1' \
  --write-out "%output{${token_metadata}}%{http_code}\n%{redirect_url}" \
  -- "${TOKEN_URL}" 2>/dev/null)"
token_request_status="$?"
set -e
(( token_request_status == 0 )) ||
  fail 'anonymous registry-token transport failed; incomplete output was retained'
# shellcheck disable=SC2016
token_transport="$(${AWK} 'NR == 1 { status = $0; next } NR == 2 { redirect = $0; next } { extra = 1 } END { if (extra || status !~ /^[0-9]{3}$/) exit 73; print status "|" redirect }' "${token_metadata}")" ||
  fail 'anonymous registry-token transport metadata was malformed'
${RM} -f -- "${token_metadata}"
[[ "${token_transport}" == '200|' ]] ||
  fail 'anonymous registry-token endpoint was not one direct HTTPS 200 response'
registry_bearer="$(
  printf '%s' \
    "${token_body}" | ${JQ} -er '
  if type == "object" and
      (.token | type) == "string" and
      (.token | length) >= 64 and
      (.token | length) <= 8192 and
      (.token | test("^[A-Za-z0-9._~-]+$")) and
      ((has("access_token") | not) or .access_token == .token)
  then .token
  else error("closed anonymous token response required")
  end
')" || fail 'anonymous registry-token response was outside the closed form'
token_body=''
[[ "${registry_bearer}" =~ ^[A-Za-z0-9._~-]{64,8192}$ ]] ||
  fail 'anonymous registry bearer token was outside the closed grammar'

curl_status=''
curl_content_type=''
registry_request() {
  local input_mode="$1"
  local input_value="$2"
  local output_path="$3"
  local maximum_bytes="$4"
  local accept_type="$5"
  local metadata
  local curl_status_code
  local curl_status_value
  local remainder
  local config_fd
  local -a input_arguments=()
  if [[ "${input_mode}" == authorized-public-url ]]; then
    exec {config_fd}< <(
      printf 'header = "Authorization: Bearer %s"\n' \
        "${registry_bearer}"
    )
    input_arguments=(--config "/proc/self/fd/${config_fd}" -- "${input_value}")
  elif [[ "${input_mode}" == unauthenticated-private-config ]]; then
    exec {config_fd}< <(printf 'url = "%s"\n' "${input_value}")
    input_arguments=(--config "/proc/self/fd/${config_fd}")
  else
    fail 'internal registry-request input mode is invalid'
  fi
  set +e
  metadata="$(${ENV} \
    -u ALL_PROXY -u HTTPS_PROXY -u HTTP_PROXY -u NO_PROXY \
    -u all_proxy -u https_proxy -u http_proxy -u no_proxy \
    -u CURL_CA_BUNDLE -u CURL_HOME -u SSL_CERT_FILE -u SSL_CERT_DIR \
    -u SSLKEYLOGFILE \
    "${CURL}" -q \
    --silent --show-error \
    --globoff \
    --proto '=https' --proto-redir '=https' \
    --tlsv1.2 \
    --proxy '' --noproxy '*' \
    --connect-timeout 20 --max-time 600 \
    --speed-limit 1024 --speed-time 60 \
    --max-redirs 0 --max-filesize "${maximum_bytes}" \
    --header "Accept: ${accept_type}" \
    --header 'Accept-Encoding: identity' \
    --user-agent 'a-quo-ubuntu-oci-candidate/1' \
    --output "${output_path}" \
    --write-out '%{http_code}\n%{redirect_url}\n%{content_type}' \
    "${input_arguments[@]}" 2>/dev/null)"
  curl_status_code="$?"
  exec {config_fd}<&-
  set -e
  (( curl_status_code == 0 )) || return 1
  [[ "${metadata}" == *$'\n'* ]] || return 1
  curl_status_value="${metadata%%$'\n'*}"
  remainder="${metadata#*$'\n'}"
  [[ "${remainder}" == *$'\n'* ]] || return 1
  curl_redirect_url="${remainder%%$'\n'*}"
  curl_content_type="${remainder#*$'\n'}"
  [[ "${curl_status_value}" =~ ^[0-9]{3}$ && \
    "${curl_content_type}" != *$'\n'* ]] || return 1
  curl_status="${curl_status_value}"
  return 0
}

validate_blob_redirect() {
  local redirect_url="$1"
  local digest="$2"
  local digest_hex="${digest#sha256:}"
  (( ${#redirect_url} > 0 && ${#redirect_url} <= 4096 )) || return 1
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ && \
    ! "${redirect_url}" =~ [[:cntrl:][:space:]] && \
    "${redirect_url}" != *\"* && "${redirect_url}" != *\\* && \
    "${redirect_url}" != *'#'* ]] || return 1
  [[ "${redirect_url}" == \
    "https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/${digest_hex:0:2}/${digest_hex}/data?"* ]] || return 1
  return 0
}

declare -a object_roles=(index manifest config layer)
declare -a object_paths=(
  objects/index.json
  objects/manifest.json
  objects/config.json
  objects/layer-01.tar.gz
)
declare -a object_urls=(
  "${REGISTRY_BASE}/manifests/${INDEX_DIGEST}"
  "${REGISTRY_BASE}/manifests/${MANIFEST_DIGEST}"
  "${REGISTRY_BASE}/blobs/${CONFIG_DIGEST}"
  "${REGISTRY_BASE}/blobs/${LAYER_DIGEST}"
)
declare -a object_sizes=(
  "${INDEX_SIZE}"
  "${MANIFEST_SIZE}"
  "${CONFIG_SIZE}"
  "${LAYER_SIZE}"
)
declare -a object_hashes=(
  "${INDEX_DIGEST#sha256:}"
  "${MANIFEST_DIGEST#sha256:}"
  "${CONFIG_DIGEST#sha256:}"
  "${LAYER_DIGEST#sha256:}"
)
declare -a object_media_types=(
  "${INDEX_MEDIA_TYPE}"
  "${MANIFEST_MEDIA_TYPE}"
  "${CONFIG_MEDIA_TYPE}"
  "${LAYER_MEDIA_TYPE}"
)
readonly object_roles object_paths object_urls object_sizes object_hashes object_media_types

for index in {0..3}; do
  transfer_path="$(${MKTEMP} "${output_directory}/.transfer.$(printf '%02d' "$((index + 1))").XXXXXX")"
  if ! registry_request authorized-public-url "${object_urls[index]}" \
    "${transfer_path}" "${object_sizes[index]}" "${object_media_types[index]}"; then
    fail "transport failed for OCI ${object_roles[index]}; incomplete output was retained"
  fi
  if (( index < 2 )); then
    [[ "${curl_status}" == 200 && -z "${curl_redirect_url}" && \
      "${curl_content_type}" == "${object_media_types[index]}" ]] ||
      fail "OCI ${object_roles[index]} transport was not one direct exact-media HTTPS 200 response"
  elif [[ "${curl_status}" == 200 && -z "${curl_redirect_url}" ]]; then
    [[ "${curl_content_type}" == application/octet-stream || \
      "${curl_content_type}" == "${object_media_types[index]}" ]] ||
      fail "direct OCI ${object_roles[index]} response had an unexpected media type"
  elif [[ "${curl_status}" == 307 ]] && \
    validate_blob_redirect "${curl_redirect_url}" \
      "sha256:${object_hashes[index]}"; then
    private_redirect="${curl_redirect_url}"
    curl_redirect_url=''
    ${RM} -f -- "${transfer_path}"
    transfer_path="$(${MKTEMP} "${output_directory}/.transfer.$(printf '%02d' "$((index + 1))").XXXXXX")"
    if ! registry_request unauthenticated-private-config "${private_redirect}" \
      "${transfer_path}" "${object_sizes[index]}" "${object_media_types[index]}"; then
      private_redirect=''
      fail "redirect transport failed for OCI ${object_roles[index]}; incomplete output was retained"
    fi
    private_redirect=''
    [[ "${curl_status}" == 200 && -z "${curl_redirect_url}" && \
      ( "${curl_content_type}" == application/octet-stream || \
        "${curl_content_type}" == "${object_media_types[index]}" ) ]] ||
      fail "OCI ${object_roles[index]} redirect target was not one terminal exact-media HTTPS 200 response"
  else
    fail "OCI ${object_roles[index]} transport was outside the closed direct-or-one-blob-redirect policy"
  fi
  curl_redirect_url=''
  observed_size="$(${STAT} -c '%s' -- "${transfer_path}")"
  observed_hash="$(${SHA256SUM} -- "${transfer_path}")"
  observed_hash="${observed_hash%% *}"
  [[ "${observed_size}" == "${object_sizes[index]}" ]] ||
    fail "OCI ${object_roles[index]} did not match the expected byte count"
  [[ "${observed_hash}" == "${object_hashes[index]}" ]] ||
    fail "OCI ${object_roles[index]} did not match the requested SHA-256 digest"
  publish_private_file "${transfer_path}" \
    "${output_directory}/${object_paths[index]}"
done
registry_bearer=''

observation_output="$("${CANDIDATE_VERIFIER}" --emit-observations \
  --profile "${output_directory}/profile.snapshot" \
  --externally-expected-profile-sha256 "${EXPECTED_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${PROFILE_COMMIT}" \
  --externally-expected-profile-path "${PROFILE_REPOSITORY_PATH}" \
  --candidate "${output_directory}")" ||
  fail 'downloaded OCI candidate objects failed offline descriptor verification'
readonly observation_output
declare -A observations=()
observation_line_count=0
while IFS= read -r line; do
  ((observation_line_count += 1))
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${line}" == *=* && "${value}" != *'='* && \
    "${key}" =~ ^(candidate_status|authority|profile_id|profile_sha256|object_count|object_0[1-4]|descriptor_bindings|diff_id|publisher_authentication|source_to_image_provenance|freshness|safety|byte_identity|network_activity|vm_started)$ && \
    ! -v "observations[${key}]" ]] ||
    fail 'offline OCI verifier emitted a malformed observation record'
  observations["${key}"]="${value}"
done <<<"${observation_output}"
readonly observation_line_count
[[ "${observation_line_count}" -eq 18 && \
  "${observations[candidate_status]:-}" == verified-incomplete-non-authoritative && \
  "${observations[authority]:-}" == none && \
  "${observations[profile_id]:-}" == a-quo-omarchy4-aarch64-dec29fa-v2 && \
  "${observations[profile_sha256]:-}" == "${EXPECTED_PROFILE_SHA256}" && \
  "${observations[object_count]:-}" == 4 && \
  "${observations[descriptor_bindings]:-}" == verified-non-authoritative && \
  "${observations[diff_id]:-}" == "${DIFF_ID}" && \
  "${observations[publisher_authentication]:-}" == not-established && \
  "${observations[source_to_image_provenance]:-}" == not-established && \
  "${observations[freshness]:-}" == not-established && \
  "${observations[safety]:-}" == not-established && \
  "${observations[byte_identity]:-}" == verified-non-authoritative && \
  "${observations[network_activity]:-}" == false && \
  "${observations[vm_started]:-}" == false ]] ||
  fail 'offline OCI verifier observations were not the exact closed non-authoritative result'

receipt_temporary="$(${MKTEMP} "${output_directory}/.receipt.oci.v1.XXXXXX")"
readonly receipt_temporary
{
  printf '%s\n' \
    'format=a-quo-omarchy-ubuntu-oci-candidate-v1' \
    'status=complete-candidate' \
    'authority=none' \
    "profile_id=${observations[profile_id]}" \
    "profile_sha256=${observations[profile_sha256]}" \
    "profile_repository=${PROFILE_REPOSITORY}" \
    "profile_commit=${PROFILE_COMMIT}" \
    "profile_path=${PROFILE_REPOSITORY_PATH}" \
    'profile_external_authentication=required-not-established-by-this-receipt' \
    'acquisition_history=not-authenticated-by-this-receipt' \
    "subject_repository=${SUBJECT_REPOSITORY}" \
    "discovery_tag=${DISCOVERY_TAG}" \
    'discovery_tag_authority=none' \
    "platform=${SUBJECT_PLATFORM}" \
    "variant=${SUBJECT_VARIANT}" \
    'object_count=4' \
    "object_01=${observations[object_01]}" \
    "object_02=${observations[object_02]}" \
    "object_03=${observations[object_03]}" \
    "object_04=${observations[object_04]}" \
    "descriptor_bindings=${observations[descriptor_bindings]}" \
    "diff_id=${observations[diff_id]}" \
    "publisher_authentication=${observations[publisher_authentication]}" \
    "source_to_image_provenance=${observations[source_to_image_provenance]}" \
    "freshness=${observations[freshness]}" \
    "safety=${observations[safety]}" \
    "byte_identity=${observations[byte_identity]}"
} >"${receipt_temporary}"
publish_private_file "${receipt_temporary}" "${output_directory}/receipt.oci.v1"

"${CANDIDATE_VERIFIER}" --pre-completion \
  --profile "${output_directory}/profile.snapshot" \
  --externally-expected-profile-sha256 "${EXPECTED_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${PROFILE_COMMIT}" \
  --externally-expected-profile-path "${PROFILE_REPOSITORY_PATH}" \
  --candidate "${output_directory}" >/dev/null ||
  fail 'full OCI candidate receipt failed before completion publication'

complete_temporary="$(${MKTEMP} "${output_directory}/.complete.XXXXXX")"
readonly complete_temporary
printf '%s\n' complete-candidate >"${complete_temporary}"
publish_private_file "${complete_temporary}" "${output_directory}/COMPLETE"
${RM} -f -- "${output_directory}/INCOMPLETE"
${SYNC} -- "${output_directory}"

set +e
final_verification_output="$("${CANDIDATE_VERIFIER}" \
  --profile "${output_directory}/profile.snapshot" \
  --externally-expected-profile-sha256 "${EXPECTED_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${PROFILE_COMMIT}" \
  --externally-expected-profile-path "${PROFILE_REPOSITORY_PATH}" \
  --candidate "${output_directory}" 2>&1)"
final_verification_status="$?"
set -e
if (( final_verification_status != 0 )); then
  create_exclusive_text_file "${output_directory}/INCOMPLETE" incomplete-candidate
  ${RM} -f -- "${output_directory}/COMPLETE"
  ${SYNC} -- "${output_directory}"
  fail 'completed OCI candidate failed final offline verification and returned to incomplete state'
fi

printf '%s\n' \
  "candidate_directory=${output_directory}" \
  'candidate_authority=none' \
  'acquisition_network_activity=true' \
  'signed_does_not_mean_safe=true' \
  "${final_verification_output}"
