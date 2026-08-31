#!/usr/bin/env bash

set +x
set -euo pipefail
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin
umask 077
ulimit -c 0

fail() {
  printf 'Omarchy bootstrap acquisition refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s --profile CANONICAL_PROFILE --output NEW_RUN_DIRECTORY --acknowledge-networked-candidate-only\n' \
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
(( EUID != 0 )) || fail 'networked candidate acquisition must not run as root'

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly CANONICAL_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile"
readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-evaluation-target-profile.sh"
readonly CANDIDATE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-bootstrap-candidate.sh"
readonly EXPECTED_PROFILE_SHA256=84f23e93c4d240aef5c0b8e01769d9245cbdb1757eb5da7acd4a3130246949da
readonly PROFILE_REPOSITORY=https://github.com/SurreptitiousFabric/a-quo.git
readonly PROFILE_COMMIT=3dcd52f3a0a4c678b0c2e015efd811164cc256bc
readonly PROFILE_REPOSITORY_PATH=packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile
readonly OBSERVATION_ROOT="${REPOSITORY_ROOT}/target/omarchy-evaluation-observations"

[[ "${profile_path}" == "${CANONICAL_PROFILE}" ]] ||
  fail 'only the canonical frozen profile path is accepted'
[[ -f "${profile_path}" && ! -L "${profile_path}" ]] ||
  fail 'canonical profile is missing or is a symlink'
for verifier in "${PROFILE_VERIFIER}" "${CANDIDATE_VERIFIER}"; do
  [[ -x "${verifier}" && -f "${verifier}" && ! -L "${verifier}" ]] ||
    fail "required repository verifier is missing, non-executable, or a symlink: ${verifier}"
done

readonly AWK=/usr/bin/awk
readonly CHMOD=/usr/bin/chmod
readonly CURL=/usr/bin/curl
readonly DD=/usr/bin/dd
readonly ENV=/usr/bin/env
readonly GPG=/usr/bin/gpg
readonly LN=/usr/bin/ln
readonly MKDIR=/usr/bin/mkdir
readonly MKTEMP=/usr/bin/mktemp
readonly RM=/usr/bin/rm
readonly SHA256SUM=/usr/bin/sha256sum
readonly STAT=/usr/bin/stat
readonly SYNC=/usr/bin/sync
for required_tool in \
  "${AWK}" "${CHMOD}" "${CURL}" "${DD}" "${ENV}" "${GPG}" \
  "${LN}" "${MKDIR}" "${MKTEMP}" "${RM}" \
  "${SHA256SUM}" "${STAT}" "${SYNC}"; do
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
  fail 'output must be one direct child of target/omarchy-evaluation-observations'

readonly target_root="${REPOSITORY_ROOT}/target"
if [[ ! -e "${target_root}" && ! -L "${target_root}" ]]; then
  ${MKDIR} -m 0755 -- "${target_root}" || fail 'could not create repository target directory'
  ${SYNC} -- "${REPOSITORY_ROOT}"
fi
[[ -d "${target_root}" && ! -L "${target_root}" ]] ||
  fail 'repository target path must be one non-symlink directory'
if [[ ! -e "${OBSERVATION_ROOT}" && ! -L "${OBSERVATION_ROOT}" ]]; then
  ${MKDIR} -m 0700 -- "${OBSERVATION_ROOT}" || fail 'could not create private observation root'
  ${SYNC} -- "${target_root}"
fi
[[ -d "${OBSERVATION_ROOT}" && ! -L "${OBSERVATION_ROOT}" && \
  "$(${STAT} -c '%a' -- "${OBSERVATION_ROOT}")" == 700 ]] ||
  fail 'observation root must be one mode-0700 non-symlink directory'
[[ ! -e "${output_directory}" && ! -L "${output_directory}" ]] ||
  fail 'output run directory already exists'
${MKDIR} -m 0700 -- "${output_directory}" || fail 'could not create fresh output run directory'
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
  ${LN} -T -- "${temporary_path}" "${final_path}" ||
    fail "no-clobber candidate publication failed: ${final_path##*/}"
  ${RM} -f -- "${temporary_path}"
  [[ -f "${final_path}" && ! -L "${final_path}" && \
    "$(${STAT} -c '%a:%h' -- "${final_path}")" == 400:1 ]] ||
    fail "published candidate object has the wrong identity: ${final_path##*/}"
  ${SYNC} -- "${final_parent}"
}

create_exclusive_text_file "${output_directory}/INCOMPLETE" incomplete-candidate
${MKDIR} -m 0700 -- \
  "${output_directory}/objects" \
  "${output_directory}/objects/stable" \
  "${output_directory}/objects/bundle"
${SYNC} -- "${output_directory}/objects"
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
  fail 'profile snapshot does not match the externally pinned canonical digest'
"${PROFILE_VERIFIER}" "${profile_temporary}" >/dev/null
publish_private_file "${profile_temporary}" "${output_directory}/profile.snapshot"

profile_field() {
  local key="$1"
  # shellcheck disable=SC2016
  ${AWK} -v key="${key}" '
    index($0, key "=") == 1 { print substr($0, length(key) + 2); found += 1 }
    END { if (found != 1) exit 73 }
  ' "${output_directory}/profile.snapshot"
}

declare -a object_paths=()
declare -a object_urls=()
declare -a object_sizes=()
declare -a object_hashes=()
object_paths[1]=objects/omarchy-release.gpg
object_urls[1]="$(profile_field omarchy_release_key_url)"
object_sizes[1]="$(profile_field omarchy_release_key_size)"
object_hashes[1]="$(profile_field omarchy_release_key_sha256)"
stable_download_base="$(profile_field omarchy_stable_download_base)"
bundle_download_base="$(profile_field omarchy_bundle_download_base)"
readonly stable_download_base bundle_download_base
[[ "${object_urls[1]}" =~ ^https://raw\.githubusercontent\.com/maralcbr/omarchy-mx-mac/[0-9a-f]{40}/default/omarchy-release\.gpg$ ]] ||
  fail 'release-key URL is outside the closed raw-GitHub path'
[[ "${stable_download_base}" == \
  https://github.com/maralcbr/omarchy-mx-mac/releases/download/v4.0.0-mac.11/ ]] ||
  fail 'stable release base is not the reviewed exact-tag locator'
[[ "${bundle_download_base}" == \
  https://github.com/maralcbr/omarchy-pkgs/releases/download/asahi-quattro-dec29fa9/ ]] ||
  fail 'bundle release base is not the reviewed exact-tag locator'

object_index=1
expected_total_size="${object_sizes[1]}"
for asset_index in 1 2 3 4 5 6 7; do
  printf -v asset_key 'release_asset_%02d' "${asset_index}"
  asset_record="$(profile_field "${asset_key}")"
  IFS='|' read -r \
    asset_base asset_role data_filename data_size data_hash \
    signature_filename signature_size signature_hash extra \
    <<<"${asset_record}"
  [[ -z "${extra:-}" && ( "${asset_base}" == stable || "${asset_base}" == bundle ) ]] ||
    fail "profile bootstrap asset ${asset_index} is malformed"
  [[ "${asset_role}" =~ ^[a-z][a-z0-9-]{0,63}$ ]] ||
    fail "profile bootstrap asset ${asset_index} has an invalid role"
  for filename in "${data_filename}" "${signature_filename}"; do
    [[ "${filename}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
      fail "profile bootstrap asset ${asset_index} contains an unsafe filename"
  done
  [[ "${data_size}" =~ ^[0-9]+$ && "${signature_size}" =~ ^[0-9]+$ && \
    "${data_hash}" =~ ^[0-9a-f]{64}$ && \
    "${signature_hash}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "profile bootstrap asset ${asset_index} has invalid size or digest fields"
  if [[ "${asset_base}" == stable ]]; then
    download_base="${stable_download_base}"
  else
    download_base="${bundle_download_base}"
  fi
  ((object_index += 1))
  object_paths[object_index]="objects/${asset_base}/${data_filename}"
  object_urls[object_index]="${download_base}${data_filename}"
  object_sizes[object_index]="${data_size}"
  object_hashes[object_index]="${data_hash}"
  ((object_index += 1))
  object_paths[object_index]="objects/${asset_base}/${signature_filename}"
  object_urls[object_index]="${download_base}${signature_filename}"
  object_sizes[object_index]="${signature_size}"
  object_hashes[object_index]="${signature_hash}"
  ((expected_total_size += data_size + signature_size))
done
readonly object_index expected_total_size
[[ "${object_index}" -eq 15 && "${expected_total_size}" -eq 50718 ]] ||
  fail 'bootstrap scope is not the reviewed key plus seven signed pairs'

curl_status=''
curl_redirect_url=''
curl_request() {
  local input_mode="$1"
  local input_value="$2"
  local output_path="$3"
  local maximum_bytes="$4"
  local metadata
  local curl_status_code
  local curl_status_value
  local -a input_arguments=()
  if [[ "${input_mode}" == public-url ]]; then
    input_arguments=(-- "${input_value}")
  elif [[ "${input_mode}" == private-config-fd ]]; then
    input_arguments=(--config "/proc/self/fd/${input_value}")
  else
    fail 'internal curl input mode is invalid'
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
    --connect-timeout 20 --max-time 120 \
    --speed-limit 1 --speed-time 30 \
    --max-redirs 0 --max-filesize "${maximum_bytes}" \
    --header 'Accept-Encoding: identity' \
    --user-agent 'a-quo-bootstrap-candidate/1' \
    --output "${output_path}" \
    --write-out '%{http_code}\n%{redirect_url}' \
    "${input_arguments[@]}" 2>/dev/null)"
  curl_status_code="$?"
  set -e
  (( curl_status_code == 0 )) || return 1
  if [[ "${metadata}" == *$'\n'* ]]; then
    curl_status_value="${metadata%%$'\n'*}"
    curl_redirect_url="${metadata#*$'\n'}"
  else
    curl_status_value="${metadata}"
    curl_redirect_url=''
  fi
  [[ "${curl_status_value}" =~ ^[0-9]{3}$ ]] || return 1
  curl_status="${curl_status_value}"
  return 0
}

validate_private_redirect() {
  local redirect_url="$1"
  (( ${#redirect_url} > 0 && ${#redirect_url} <= 4096 )) || return 1
  [[ ! "${redirect_url}" =~ [[:cntrl:][:space:]] && \
    "${redirect_url}" != *\"* && "${redirect_url}" != *\\* && \
    "${redirect_url}" != *'#'* ]] || return 1
  case "${redirect_url}" in
    https://release-assets.githubusercontent.com/*)
      redirect_host=release-assets.githubusercontent.com
      ;;
    https://objects.githubusercontent.com/*)
      redirect_host=objects.githubusercontent.com
      ;;
    *) return 1 ;;
  esac
  [[ "${redirect_url}" == *'?'* ]] || return 1
  return 0
}

declare -a transport_classes=()
declare -a redirect_hosts=()
declare -a redirect_counts=()
for index in {1..15}; do
  transfer_path="$(${MKTEMP} "${output_directory}/.transfer.$(printf '%02d' "${index}").XXXXXX")"
  maximum_initial_bytes=$((object_sizes[index] + 4096))
  if ! curl_request public-url "${object_urls[index]}" \
    "${transfer_path}" "${maximum_initial_bytes}"; then
    fail "transport failed for bootstrap object ${index}; incomplete output was retained"
  fi
  if (( index == 1 )); then
    [[ "${curl_status}" == 200 && -z "${curl_redirect_url}" ]] ||
      fail 'release-key transport was not one direct HTTPS 200 response'
    transport_classes[index]=raw-direct
    redirect_hosts[index]=none
    redirect_counts[index]=0
  else
    transport_classes[index]=github-release
    if [[ "${curl_status}" == 200 && -z "${curl_redirect_url}" ]]; then
      redirect_hosts[index]=none
      redirect_counts[index]=0
    elif [[ "${curl_status}" == 302 ]] && validate_private_redirect "${curl_redirect_url}"; then
      ${RM} -f -- "${transfer_path}"
      transfer_path="$(${MKTEMP} "${output_directory}/.transfer.$(printf '%02d' "${index}").XXXXXX")"
      exec {redirect_config_fd}< <(printf 'url = "%s"\n' "${curl_redirect_url}")
      if ! curl_request private-config-fd "${redirect_config_fd}" \
        "${transfer_path}" "${object_sizes[index]}"; then
        exec {redirect_config_fd}<&-
        fail "redirect transport failed for bootstrap object ${index}; incomplete output was retained"
      fi
      exec {redirect_config_fd}<&-
      [[ "${curl_status}" == 200 && -z "${curl_redirect_url}" ]] ||
        fail "redirect target was not one terminal HTTPS 200 response for bootstrap object ${index}"
      redirect_hosts[index]="${redirect_host}"
      redirect_counts[index]=1
    else
      fail "release transport was not direct HTTPS 200 or one allowed HTTPS 302 for bootstrap object ${index}"
    fi
  fi
  observed_size="$(${STAT} -c '%s' -- "${transfer_path}")"
  observed_hash="$(${SHA256SUM} -- "${transfer_path}")"
  observed_hash="${observed_hash%% *}"
  [[ "${observed_size}" == "${object_sizes[index]}" ]] ||
    fail "bootstrap object ${index} did not match the expected byte count"
  [[ "${observed_hash}" == "${object_hashes[index]}" ]] ||
    fail "bootstrap object ${index} did not match the expected SHA-256"
  publish_private_file "${transfer_path}" \
    "${output_directory}/${object_paths[index]}"
done

observation_output="$("${CANDIDATE_VERIFIER}" --emit-observations \
  --profile "${output_directory}/profile.snapshot" \
  --externally-expected-profile-sha256 "${EXPECTED_PROFILE_SHA256}" \
  --candidate "${output_directory}")" ||
  fail 'downloaded candidate objects failed offline cryptographic verification'
readonly observation_output
declare -A observations=()
observation_line_count=0
while IFS= read -r line; do
  ((observation_line_count += 1))
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${line}" == *=* && "${value}" != *'='* && \
    "${key}" =~ ^(object_(0[1-9]|1[0-5])|signature_0[1-7])$ && \
    ! -v "observations[${key}]" ]] ||
    fail 'offline verifier emitted a malformed observation record'
  observations["${key}"]="${value}"
done <<<"${observation_output}"
readonly observation_line_count
[[ "${observation_line_count}" -eq 22 ]] ||
  fail 'offline verifier emitted the wrong observation count'

curl_hash="$(${SHA256SUM} -- "${CURL}")"
curl_hash="${curl_hash%% *}"
gpg_hash="$(${SHA256SUM} -- "${GPG}")"
gpg_hash="${gpg_hash%% *}"
readonly curl_hash gpg_hash

receipt_temporary="$(${MKTEMP} "${output_directory}/.receipt.v1.XXXXXX")"
readonly receipt_temporary
{
  printf '%s\n' \
    'format=a-quo-omarchy-bootstrap-candidate-v1' \
    'status=complete-candidate' \
    'authority=none' \
    'scope=signed-bootstrap-assets-01-through-07' \
    "profile_repository=${PROFILE_REPOSITORY}" \
    "profile_commit=${PROFILE_COMMIT}" \
    "profile_path=${PROFILE_REPOSITORY_PATH}" \
    "observed_profile_sha256=${profile_digest}" \
    'profile_external_authentication=required-not-established-by-this-receipt' \
    'object_count=15'
  for index in {1..15}; do
    printf -v object_key 'object_%02d' "${index}"
    printf '%s=%s|%s|%s|%s\n' \
      "${object_key}" "${observations[${object_key}]}" \
      "${transport_classes[index]}" "${redirect_hosts[index]}" \
      "${redirect_counts[index]}"
  done
  printf '%s\n' 'signature_count=7'
  for index in {1..7}; do
    printf -v signature_key 'signature_%02d' "${index}"
    printf '%s=%s\n' "${signature_key}" "${observations[${signature_key}]}"
  done
  printf '%s\n' \
    "curl_path=${CURL}" \
    "curl_sha256=${curl_hash}" \
    "gpg_path=${GPG}" \
    "gpg_sha256=${gpg_hash}"
} >"${receipt_temporary}"
publish_private_file "${receipt_temporary}" "${output_directory}/receipt.v1"

"${CANDIDATE_VERIFIER}" --pre-completion \
  --profile "${output_directory}/profile.snapshot" \
  --externally-expected-profile-sha256 "${EXPECTED_PROFILE_SHA256}" \
  --candidate "${output_directory}" >/dev/null ||
  fail 'full candidate receipt failed before completion publication'

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
  --candidate "${output_directory}" 2>&1)"
final_verification_status="$?"
set -e
if (( final_verification_status != 0 )); then
  create_exclusive_text_file "${output_directory}/INCOMPLETE" incomplete-candidate
  ${RM} -f -- "${output_directory}/COMPLETE"
  ${SYNC} -- "${output_directory}"
  fail 'completed candidate failed its final offline verification and was returned to incomplete state'
fi

printf '%s\n' \
  "candidate_directory=${output_directory}" \
  'candidate_authority=none' \
  'network_activity=true' \
  'signed_does_not_mean_safe=true' \
  "${final_verification_output}"
