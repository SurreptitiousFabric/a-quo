#!/usr/bin/env bash

set +x
set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 077

fail() {
  printf 'Omarchy bootstrap candidate refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--emit-observations|--pre-completion] --profile PROFILE --externally-expected-profile-sha256 SHA256 --candidate DIRECTORY\n' \
    "${0##*/}" >&2
  exit 2
}

emit_observations=false
pre_completion=false
profile_path=''
expected_profile_sha256=''
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
    --candidate)
      [[ -z "${candidate_directory}" && $# -ge 2 ]] || usage
      candidate_directory="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
readonly emit_observations pre_completion profile_path expected_profile_sha256 candidate_directory

[[ -n "${profile_path}" && -n "${expected_profile_sha256}" && \
  -n "${candidate_directory}" ]] || usage
[[ "${expected_profile_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'externally expected profile digest is not one lowercase SHA-256'

readonly AWK=/usr/bin/awk
readonly CMP=/usr/bin/cmp
readonly FIND=/usr/bin/find
readonly GPG=/usr/bin/gpg
readonly MKTEMP=/usr/bin/mktemp
readonly OD=/usr/bin/od
readonly RM=/usr/bin/rm
readonly SHA256SUM=/usr/bin/sha256sum
readonly STAT=/usr/bin/stat
readonly TAIL=/usr/bin/tail
readonly TR=/usr/bin/tr
readonly WC=/usr/bin/wc
for required_tool in \
  "${AWK}" "${CMP}" "${FIND}" "${GPG}" "${MKTEMP}" \
  "${OD}" "${RM}" "${SHA256SUM}" "${STAT}" "${TAIL}" "${TR}" "${WC}"; do
  [[ -x "${required_tool}" && -f "${required_tool}" ]] ||
    fail "required verifier tool is unavailable or does not resolve to a regular file: ${required_tool}"
done

[[ -f "${profile_path}" && ! -L "${profile_path}" ]] ||
  fail 'external profile must be one regular non-symlink file'
[[ -d "${candidate_directory}" && ! -L "${candidate_directory}" ]] ||
  fail 'candidate must be one directory and not a symlink'
[[ "$(${STAT} -c '%a' -- "${candidate_directory}")" == 700 ]] ||
  fail 'candidate directory mode must be 0700'

readonly candidate_profile="${candidate_directory}/profile.snapshot"
[[ -f "${candidate_profile}" && ! -L "${candidate_profile}" ]] ||
  fail 'candidate profile snapshot is missing or not a regular file'
[[ "$(${STAT} -c '%a:%h' -- "${candidate_profile}")" == 400:1 ]] ||
  fail 'candidate profile snapshot must have mode 0400 and one link'

validate_profile_bytes() {
  local path="$1"
  local size
  local printable_size
  local last_byte
  size="$(${STAT} -c '%s' -- "${path}")"
  [[ "${size}" =~ ^[0-9]+$ ]] || fail 'profile size is malformed'
  (( size > 0 && size <= 65536 )) || fail 'profile size is outside the closed bound'
  printable_size="$(${TR} -cd '\12\40-\176' <"${path}" | ${WC} -c)"
  [[ "${printable_size}" == "${size}" ]] ||
    fail 'profile contains a control, carriage-return, NUL, or non-ASCII byte'
  last_byte="$(${TAIL} -c 1 -- "${path}" | ${OD} -An -tu1 | ${TR} -d '[:space:]')"
  [[ "${last_byte}" == 10 ]] || fail 'profile must end with one LF byte'
}

validate_profile_bytes "${profile_path}"
validate_profile_bytes "${candidate_profile}"
external_profile_digest="$(${SHA256SUM} -- "${profile_path}")"
external_profile_digest="${external_profile_digest%% *}"
snapshot_profile_digest="$(${SHA256SUM} -- "${candidate_profile}")"
snapshot_profile_digest="${snapshot_profile_digest%% *}"
readonly external_profile_digest snapshot_profile_digest
[[ "${external_profile_digest}" == "${expected_profile_sha256}" ]] ||
  fail 'external profile bytes do not match the caller-supplied expected digest'
[[ "${snapshot_profile_digest}" == "${expected_profile_sha256}" ]] ||
  fail 'candidate profile snapshot does not match the externally expected digest'
${CMP} -s -- "${profile_path}" "${candidate_profile}" ||
  fail 'candidate profile snapshot differs from the external profile bytes'

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
    ${#value} -le 4096 ]] || fail "profile line ${line_count} has invalid bounds"
  [[ ! -v "fields[${key}]" ]] || fail "profile has duplicate key: ${key}"
  fields["${key}"]="${value}"
done <"${candidate_profile}"
readonly line_count
[[ "${line_count}" -eq 76 ]] || fail 'profile does not have the expected field count'

require_field() {
  local key="$1"
  local expected="$2"
  [[ -v "fields[${key}]" && "${fields[${key}]}" == "${expected}" ]] ||
    fail "profile has an unexpected value for ${key}"
}

require_lower_sha256_field() {
  local key="$1"
  [[ -v "fields[${key}]" && "${fields[${key}]}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "profile field is not one lowercase SHA-256: ${key}"
}

require_field format a-quo-omarchy-evaluation-target-profile-v1
require_field state bootstrap-unarmed
require_field armable false
require_field release_asset_count 8
[[ "${fields[omarchy_release_key_fingerprint]:-}" =~ ^[0-9A-F]{40}$ ]] ||
  fail 'profile release-key fingerprint is malformed'
[[ "${fields[omarchy_release_key_size]:-}" =~ ^[0-9]+$ ]] ||
  fail 'profile release-key size is malformed'
(( fields[omarchy_release_key_size] > 0 && fields[omarchy_release_key_size] <= 65536 )) ||
  fail 'profile release-key size is outside the closed bound'
require_lower_sha256_field omarchy_release_key_sha256

declare -a object_roles=()
declare -a object_paths=()
declare -a object_sizes=()
declare -a object_hashes=()
object_roles[1]=release-key
object_paths[1]=objects/omarchy-release.gpg
object_sizes[1]="${fields[omarchy_release_key_size]}"
object_hashes[1]="${fields[omarchy_release_key_sha256]}"

declare -A seen_object_paths=([objects/omarchy-release.gpg]=1)
object_index=1
for asset_index in 1 2 3 4 5 6 7; do
  printf -v asset_key 'release_asset_%02d' "${asset_index}"
  [[ -v "fields[${asset_key}]" ]] || fail "profile is missing ${asset_key}"
  IFS='|' read -r \
    asset_base asset_role data_filename data_size data_hash \
    signature_filename signature_size signature_hash extra \
    <<<"${fields[${asset_key}]}"
  [[ -z "${extra:-}" ]] || fail "${asset_key} has the wrong field count"
  [[ "${asset_base}" == stable || "${asset_base}" == bundle ]] ||
    fail "${asset_key} has an unsupported release base"
  [[ "${asset_role}" =~ ^[a-z][a-z0-9-]{0,63}$ ]] ||
    fail "${asset_key} has an invalid role"
  for filename in "${data_filename}" "${signature_filename}"; do
    [[ "${filename}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
      fail "${asset_key} has an unsafe filename"
  done
  [[ "${data_size}" =~ ^[0-9]+$ && "${signature_size}" =~ ^[0-9]+$ ]] ||
    fail "${asset_key} has a malformed size"
  (( data_size > 0 && data_size <= 1048576 && signature_size > 0 && \
    signature_size <= 65536 )) || fail "${asset_key} exceeds bootstrap bounds"
  [[ "${data_hash}" =~ ^[0-9a-f]{64}$ && \
    "${signature_hash}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "${asset_key} has a malformed digest"
  data_path="objects/${asset_base}/${data_filename}"
  signature_path="objects/${asset_base}/${signature_filename}"
  [[ ! -v "seen_object_paths[${data_path}]" && \
    ! -v "seen_object_paths[${signature_path}]" ]] ||
    fail "${asset_key} duplicates an object path"
  seen_object_paths["${data_path}"]=1
  seen_object_paths["${signature_path}"]=1
  ((object_index += 1))
  object_roles[object_index]="${asset_base}-${asset_role}"
  object_paths[object_index]="${data_path}"
  object_sizes[object_index]="${data_size}"
  object_hashes[object_index]="${data_hash}"
  ((object_index += 1))
  object_roles[object_index]="${asset_base}-${asset_role}-signature"
  object_paths[object_index]="${signature_path}"
  object_sizes[object_index]="${signature_size}"
  object_hashes[object_index]="${signature_hash}"
done
readonly object_index
[[ "${object_index}" -eq 15 ]] || fail 'bootstrap object plan is not exactly 15 objects'

declare -a expected_paths=(objects objects/stable objects/bundle profile.snapshot)
declare -a expected_types=(directory directory directory file)
for index in {1..15}; do
  expected_paths+=("${object_paths[index]}")
  expected_types+=(file)
done
if [[ "${emit_observations}" == true ]]; then
  expected_paths+=(INCOMPLETE)
  expected_types+=(file)
elif [[ "${pre_completion}" == true ]]; then
  expected_paths+=(receipt.v1 INCOMPLETE)
  expected_types+=(file file)
else
  expected_paths+=(receipt.v1 COMPLETE)
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
    directory_mode="$(${STAT} -c '%a' -- "${candidate_directory}/${relative_path}")"
    directory_links="$(${STAT} -c '%h' -- "${candidate_directory}/${relative_path}")"
    [[ "${directory_mode}" == 700 && "${directory_links}" =~ ^[0-9]+$ ]] ||
      fail "candidate directory has the wrong mode or link count: ${relative_path}"
    (( directory_links >= 2 )) || fail "candidate directory link count is impossible: ${relative_path}"
  else
    [[ "${entry_type}" == f ]] || fail "candidate file has the wrong type: ${relative_path}"
    [[ "$(${STAT} -c '%a:%h' -- "${candidate_directory}/${relative_path}")" == 400:1 ]] ||
      fail "candidate file has the wrong mode or link count: ${relative_path}"
  fi
done < <(${FIND} -P "${candidate_directory}" -mindepth 1 -printf '%P\0%y\0')
readonly entry_count
[[ "${entry_count}" -eq "${#expected_paths[@]}" ]] ||
  fail 'candidate is missing one or more required entries'
for index in "${!expected_paths[@]}"; do
  [[ "${seen_expected_entries[index]:-false}" == true ]] ||
    fail "candidate is missing a required entry: ${expected_paths[index]}"
done

if [[ "${emit_observations}" == true || "${pre_completion}" == true ]]; then
  [[ "$(${STAT} -c '%s' -- "${candidate_directory}/INCOMPLETE")" == 21 && \
    "$(<"${candidate_directory}/INCOMPLETE")" == incomplete-candidate ]] ||
    fail 'INCOMPLETE marker content is invalid'
fi

declare -a observed_object_records=()
for index in {1..15}; do
  object_path="${candidate_directory}/${object_paths[index]}"
  metadata_before="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${object_path}")"
  observed_size="$(${STAT} -c '%s' -- "${object_path}")"
  observed_hash="$(${SHA256SUM} -- "${object_path}")"
  observed_hash="${observed_hash%% *}"
  metadata_after="$(${STAT} -c '%d:%i:%s:%f:%Y' -- "${object_path}")"
  [[ "${metadata_after}" == "${metadata_before}" ]] ||
    fail "object metadata changed while hashing: ${object_paths[index]}"
  [[ "${observed_size}" == "${object_sizes[index]}" ]] ||
    fail "object has the wrong size: ${object_paths[index]}"
  [[ "${observed_hash}" == "${object_hashes[index]}" ]] ||
    fail "object has the wrong SHA-256: ${object_paths[index]}"
  observed_object_records[index]="${object_roles[index]}|${object_paths[index]}|${observed_size}|${observed_hash}"
done

temporary_gpg_home="$(${MKTEMP} -d "${TMPDIR:-/tmp}/a-quo-bootstrap-gpg.XXXXXX")"
readonly temporary_gpg_home
cleanup() {
  ${RM} -rf -- "${temporary_gpg_home}"
}
trap cleanup EXIT

key_listing="$(${GPG} --batch --no-options --homedir "${temporary_gpg_home}" \
  --auto-key-locate clear --no-auto-key-retrieve --with-colons \
  --import-options show-only --import \
  "${candidate_directory}/${object_paths[1]}" 2>/dev/null)" ||
  fail 'release key could not be parsed as one public OpenPGP key'
readonly key_listing
mapfile -t primary_fingerprints < <(
  # shellcheck disable=SC2016
  printf '%s\n' "${key_listing}" | ${AWK} -F: '
    $1 == "pub" { public_keys += 1; want_fingerprint = 1; next }
    want_fingerprint && $1 == "fpr" { print $10; want_fingerprint = 0 }
    END { if (public_keys != 1) exit 73 }
  '
) || fail 'release key does not contain exactly one primary public key'
[[ "${#primary_fingerprints[@]}" -eq 1 && \
  "${primary_fingerprints[0]}" == "${fields[omarchy_release_key_fingerprint]}" ]] ||
  fail 'release key primary fingerprint does not match the profile'
# shellcheck disable=SC2016
if printf '%s\n' "${key_listing}" | ${AWK} -F: '$1 == "sec" { found = 1 } END { exit !found }'; then
  fail 'release key object unexpectedly contains secret key material'
fi
if ! ${GPG} --batch --no-options --homedir "${temporary_gpg_home}" \
  --auto-key-locate clear --no-auto-key-retrieve \
  --import "${candidate_directory}/${object_paths[1]}" >/dev/null 2>&1; then
  fail 'release key could not be imported into the isolated verifier home'
fi

declare -a observed_signature_records=()
for signature_index in {1..7}; do
  data_object_index=$((signature_index * 2))
  signature_object_index=$((data_object_index + 1))
  status_file="$(${MKTEMP} "${temporary_gpg_home}/status.XXXXXX")"
  if ! ${GPG} --batch --no-options --homedir "${temporary_gpg_home}" \
    --auto-key-locate clear --no-auto-key-retrieve --status-fd 3 --verify \
    "${candidate_directory}/${object_paths[signature_object_index]}" \
    "${candidate_directory}/${object_paths[data_object_index]}" \
    3>"${status_file}" >/dev/null 2>/dev/null; then
    fail "signature verification failed for object ${data_object_index}"
  fi
  # shellcheck disable=SC2016
  if ${AWK} '$1 == "[GNUPG:]" && $2 ~ /^(BADSIG|ERRSIG|NO_PUBKEY|EXPKEYSIG|EXPSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED|KEYREVOKED)$/ { bad = 1 } END { exit !bad }' \
    "${status_file}"; then
    fail "signature status includes an expiry, revocation, or verification failure for object ${data_object_index}"
  fi
  mapfile -t valid_signature_lines < <(
    # shellcheck disable=SC2016
    ${AWK} '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print }' "${status_file}"
  )
  # shellcheck disable=SC2016
  good_signature_count="$(${AWK} '$1 == "[GNUPG:]" && $2 == "GOODSIG" { count += 1 } END { print count + 0 }' \
    "${status_file}")"
  # shellcheck disable=SC2016
  new_signature_count="$(${AWK} '$1 == "[GNUPG:]" && $2 == "NEWSIG" { count += 1 } END { print count + 0 }' \
    "${status_file}")"
  [[ "${#valid_signature_lines[@]}" -eq 1 ]] ||
    fail "signature produced other than one VALIDSIG for object ${data_object_index}"
  [[ "${good_signature_count}" == 1 && "${new_signature_count}" == 1 ]] ||
    fail "signature produced other than one NEWSIG and GOODSIG for object ${data_object_index}"
  read -r -a signature_tokens <<<"${valid_signature_lines[0]}"
  (( ${#signature_tokens[@]} >= 12 )) ||
    fail "VALIDSIG record is incomplete for object ${data_object_index}"
  signing_fingerprint="${signature_tokens[2]}"
  primary_fingerprint="${signature_tokens[${#signature_tokens[@]} - 1]}"
  [[ "${signing_fingerprint}" =~ ^[0-9A-F]{40}$ && \
    "${primary_fingerprint}" == "${fields[omarchy_release_key_fingerprint]}" ]] ||
    fail "VALIDSIG fingerprint does not match the profile for object ${data_object_index}"
  observed_signature_records[signature_index]="${data_object_index}|${signature_object_index}|openpgp-validsig|${primary_fingerprint}|${signing_fingerprint}"
  ${RM} -f -- "${status_file}"
done

validate_closed_signed_text() {
  local label="$1"
  local path="$2"
  local expected_line_count="$3"
  local size
  local printable_size
  local last_byte
  local observed_line_count
  size="$(${STAT} -c '%s' -- "${path}")"
  [[ "${size}" =~ ^[0-9]+$ ]] || fail "${label} size is malformed"
  (( size > 0 && size <= 4096 )) || fail "${label} is outside the closed byte bound"
  printable_size="$(${TR} -cd '\12\40-\176' <"${path}" | ${WC} -c)"
  [[ "${printable_size}" == "${size}" ]] ||
    fail "${label} contains a control, carriage-return, NUL, or non-ASCII byte"
  last_byte="$(${TAIL} -c 1 -- "${path}" | ${OD} -An -tu1 | ${TR} -d '[:space:]')"
  [[ "${last_byte}" == 10 ]] || fail "${label} must end with one LF byte"
  observed_line_count="$(${AWK} 'END { print NR + 0 }' "${path}")"
  [[ "${observed_line_count}" == "${expected_line_count}" ]] ||
    fail "${label} does not have the exact line count"
}

readonly stable_release_path="${candidate_directory}/${object_paths[2]}"
readonly bundle_release_path="${candidate_directory}/${object_paths[6]}"
readonly bundle_manifest_path="${candidate_directory}/${object_paths[8]}"
validate_closed_signed_text stable-release "${stable_release_path}" 7
validate_closed_signed_text bundle-release "${bundle_release_path}" 10
validate_closed_signed_text bundle-manifest "${bundle_manifest_path}" 10

mapfile -t stable_release_lines <"${stable_release_path}"
[[ "${fields[omarchy_stable_release_sequence]:-}" =~ ^[1-9][0-9]{0,8}$ && \
  "${fields[omarchy_stable_release_tag]:-}" =~ ^v[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ && \
  "${fields[omarchy_source_commit]:-}" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'profile stable-release descriptor expectations are malformed'
[[ "${stable_release_lines[0]}" == format=1 ]] ||
  fail 'stable release has an unexpected format field'
[[ "${stable_release_lines[1]}" == track=stable-mac ]] ||
  fail 'stable release has an unexpected track field'
[[ "${stable_release_lines[2]}" == sequence="${fields[omarchy_stable_release_sequence]:-}" ]] ||
  fail 'stable release sequence does not match the profile'
stable_version="${stable_release_lines[3]#version=}"
[[ "${stable_release_lines[3]}" == version=* &&
  "${stable_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+-mac\.[1-9][0-9]*$ ]] ||
  fail 'stable release has an invalid version field'
[[ "${stable_release_lines[4]}" == source_tag="${fields[omarchy_stable_release_tag]:-}" &&
  "${fields[omarchy_stable_release_tag]:-}" == "v${stable_version}" ]] ||
  fail 'stable release tag or version does not match the profile'
[[ "${stable_release_lines[5]}" == source_commit="${fields[omarchy_source_commit]:-}" ]] ||
  fail 'stable release source commit does not match the profile'
[[ "${stable_release_lines[6]}" == minimum_updater_version=1 ]] ||
  fail 'stable release has an unexpected minimum updater version'

mapfile -t bundle_release_lines <"${bundle_release_path}"
[[ "${fields[omarchy_bundle_release_sequence]:-}" =~ ^[1-9][0-9]{0,8}$ && \
  "${fields[omarchy_bundle_release_tag]:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,95}$ && \
  "${fields[omarchy_bundle_source_commit]:-}" =~ ^[0-9a-f]{40}$ && \
  "${fields[omarchy_bundle_package_source_commit]:-}" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'profile bundle-release descriptor expectations are malformed'
[[ "${bundle_release_lines[0]}" == format=1 ]] ||
  fail 'bundle release has an unexpected format field'
[[ "${bundle_release_lines[1]}" == bundle=asahi-quattro ]] ||
  fail 'bundle release has an unexpected bundle field'
[[ "${bundle_release_lines[2]}" == sequence="${fields[omarchy_bundle_release_sequence]:-}" ]] ||
  fail 'bundle release sequence does not match the profile'
[[ "${bundle_release_lines[3]}" == release_tag="${fields[omarchy_bundle_release_tag]:-}" ]] ||
  fail 'bundle release tag does not match the profile'
[[ "${bundle_release_lines[4]}" == source_commit="${fields[omarchy_bundle_source_commit]:-}" &&
  "${fields[omarchy_bundle_source_commit]:-}" == "${fields[omarchy_source_commit]:-}" ]] ||
  fail 'bundle release source commit does not match the profile or stable release'
[[ "${fields[omarchy_bundle_release_tag]:-}" == \
  "asahi-quattro-${fields[omarchy_bundle_source_commit]:0:8}" ]] ||
  fail 'bundle release tag does not match its source commit prefix'
[[ "${bundle_release_lines[5]}" == \
  package_source_commit="${fields[omarchy_bundle_package_source_commit]:-}" ]] ||
  fail 'bundle release package source commit does not match the profile'

manifest_sha256="${bundle_release_lines[6]#manifest_sha256=}"
upgrader_sha256="${bundle_release_lines[7]#upgrader_sha256=}"
bundle_updater_sha256="${bundle_release_lines[8]#bundle_updater_sha256=}"
fresh_installer_sha256="${bundle_release_lines[9]#fresh_installer_sha256=}"
for descriptor_hash in \
  "${manifest_sha256}" \
  "${upgrader_sha256}" \
  "${bundle_updater_sha256}" \
  "${fresh_installer_sha256}"; do
  [[ "${descriptor_hash}" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'bundle release contains a malformed asset SHA-256'
done
[[ "${bundle_release_lines[6]}" == manifest_sha256="${manifest_sha256}" &&
  "${manifest_sha256}" == "${object_hashes[8]}" ]] ||
  fail 'bundle release manifest SHA-256 does not match the signed manifest object'
[[ "${bundle_release_lines[8]}" == bundle_updater_sha256="${bundle_updater_sha256}" &&
  "${bundle_updater_sha256}" == "${object_hashes[14]}" ]] ||
  fail 'bundle release updater SHA-256 does not match the signed updater object'
[[ "${bundle_release_lines[9]}" == fresh_installer_sha256="${fresh_installer_sha256}" &&
  "${fresh_installer_sha256}" == "${object_hashes[12]}" ]] ||
  fail 'bundle release fresh-installer SHA-256 does not match the signed installer object'

IFS='|' read -r \
  upgrade_base upgrade_role upgrade_filename _upgrade_size upgrade_profile_sha256 \
  upgrade_signature_filename upgrade_signature_size upgrade_signature_sha256 upgrade_extra \
  <<<"${fields[release_asset_08]:-}"
[[ -z "${upgrade_extra:-}" && "${fields[release_asset_08]:-}" == \
  "${upgrade_base}|${upgrade_role}|${upgrade_filename}|${_upgrade_size}|${upgrade_profile_sha256}|${upgrade_signature_filename}|${upgrade_signature_size}|${upgrade_signature_sha256}" && \
  "${upgrade_base}" == bundle &&
  "${upgrade_role}" == upgrade-tool &&
  "${upgrade_filename}" == omarchy-upgrade-to-quattro &&
  "${_upgrade_size}" =~ ^[1-9][0-9]{0,8}$ &&
  "${upgrade_signature_filename}" == descriptor-bound &&
  "${upgrade_signature_size}" == 0 && "${upgrade_signature_sha256}" == none &&
  "${upgrade_profile_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'profile upgrade-tool expectation is malformed'
[[ "${bundle_release_lines[7]}" == upgrader_sha256="${upgrader_sha256}" &&
  "${upgrader_sha256}" == "${upgrade_profile_sha256}" ]] ||
  fail 'bundle release upgrader SHA-256 does not match the profile expectation'

mapfile -t bundle_manifest_lines <"${bundle_manifest_path}"
[[ "${bundle_manifest_lines[0]}" == format=2 ]] ||
  fail 'bundle manifest has an unexpected format field'
[[ "${bundle_manifest_lines[1]}" == bundle=asahi-quattro ]] ||
  fail 'bundle manifest has an unexpected bundle field'
[[ "${bundle_manifest_lines[2]}" == \
  source_commit="${fields[omarchy_bundle_source_commit]:-}" ]] ||
  fail 'bundle manifest source commit does not match the signed release'
[[ "${fields[bundle_package_count]:-}" == 6 &&
  "${bundle_manifest_lines[3]}" == package_count=6 ]] ||
  fail 'bundle manifest package count does not match the profile'

declare -A signed_manifest_package_names=()
for package_index in {1..6}; do
  printf -v package_key 'bundle_package_%02d' "${package_index}"
  IFS='|' read -r \
    expected_package_name expected_package_version expected_package_architecture \
    expected_package_filename _expected_package_size expected_package_sha256 \
    _expected_signature_filename _expected_signature_size _expected_signature_sha256 \
    package_extra <<<"${fields[${package_key}]:-}"
  [[ -z "${package_extra:-}" && "${fields[${package_key}]:-}" == \
    "${expected_package_name}|${expected_package_version}|${expected_package_architecture}|${expected_package_filename}|${_expected_package_size}|${expected_package_sha256}|${_expected_signature_filename}|${_expected_signature_size}|${_expected_signature_sha256}" && \
    "${expected_package_name}" =~ ^[a-z0-9][a-z0-9._+-]{0,63}$ &&
    "${expected_package_version}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ &&
    ( "${expected_package_architecture}" == any ||
      "${expected_package_architecture}" == aarch64 ) &&
    "${expected_package_filename}" == \
      "${expected_package_name}-${expected_package_version}-${expected_package_architecture}.pkg.tar.xz" &&
    "${_expected_package_size}" =~ ^[1-9][0-9]{0,9}$ && \
    "${expected_package_sha256}" =~ ^[0-9a-f]{64}$ && \
    "${_expected_signature_filename}" == "${expected_package_filename}.sig" && \
    "${_expected_signature_size}" =~ ^[1-9][0-9]{0,8}$ && \
    "${_expected_signature_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "profile ${package_key} has malformed signed-manifest fields"
  [[ ! -v "signed_manifest_package_names[${expected_package_name}]" ]] ||
    fail "profile repeats a signed-manifest package name: ${expected_package_name}"
  signed_manifest_package_names["${expected_package_name}"]=1
  expected_manifest_line="package=${package_index}|${expected_package_name}|${expected_package_version}|${expected_package_architecture}|${expected_package_filename}|${expected_package_sha256}"
  [[ "${bundle_manifest_lines[package_index + 3]}" == "${expected_manifest_line}" ]] ||
    fail "bundle manifest package ${package_index} does not match the profile tuple"
done

emit_records() {
  local index
  for index in {1..15}; do
    printf 'object_%02d=%s\n' "${index}" "${observed_object_records[index]}"
  done
  for index in {1..7}; do
    printf 'signature_%02d=%s\n' "${index}" "${observed_signature_records[index]}"
  done
}

if [[ "${emit_observations}" == true ]]; then
  emit_records
  exit 0
fi

readonly receipt_path="${candidate_directory}/receipt.v1"
receipt_size="$(${STAT} -c '%s' -- "${receipt_path}")"
readonly receipt_size
(( receipt_size > 0 && receipt_size <= 65536 )) || fail 'receipt size is outside the closed bound'
receipt_printable_size="$(${TR} -cd '\12\40-\176' <"${receipt_path}" | ${WC} -c)"
readonly receipt_printable_size
[[ "${receipt_printable_size}" == "${receipt_size}" ]] ||
  fail 'receipt contains a control, carriage-return, NUL, or non-ASCII byte'
receipt_last_byte="$(${TAIL} -c 1 -- "${receipt_path}" | ${OD} -An -tu1 | ${TR} -d '[:space:]')"
readonly receipt_last_byte
[[ "${receipt_last_byte}" == 10 ]] || fail 'receipt must end with one LF byte'

declare -A receipt_fields=()
declare -a expected_receipt_keys=(
  format status authority scope profile_repository profile_commit profile_path
  observed_profile_sha256 profile_external_authentication object_count
)
for index in {1..15}; do
  printf -v object_key 'object_%02d' "${index}"
  expected_receipt_keys+=("${object_key}")
done
expected_receipt_keys+=(signature_count)
for index in {1..7}; do
  printf -v signature_key 'signature_%02d' "${index}"
  expected_receipt_keys+=("${signature_key}")
done
expected_receipt_keys+=(curl_path curl_sha256 gpg_path gpg_sha256)
[[ "${#expected_receipt_keys[@]}" -eq 37 ]] || fail 'internal receipt-key plan is malformed'
receipt_line_count=0
while IFS= read -r line; do
  ((receipt_line_count += 1))
  (( receipt_line_count <= ${#expected_receipt_keys[@]} )) ||
    fail 'receipt does not have the exact field count'
  [[ -n "${line}" && "${line}" == *=* ]] ||
    fail "receipt line ${receipt_line_count} is not one nonempty key/value record"
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${value}" != *'='* ]] || fail "receipt line ${receipt_line_count} has an extra separator"
  [[ "${key}" =~ ^[a-z][a-z0-9_]{0,63}$ && -n "${value}" && \
    ${#value} -le 4096 ]] || fail "receipt line ${receipt_line_count} has invalid bounds"
  [[ "${key}" == "${expected_receipt_keys[receipt_line_count - 1]}" ]] ||
    fail "receipt field order is invalid at line ${receipt_line_count}"
  [[ ! -v "receipt_fields[${key}]" ]] || fail "receipt has duplicate key: ${key}"
  case "${key}" in
    format|status|authority|scope|profile_repository|profile_commit|profile_path | \
      observed_profile_sha256|profile_external_authentication|object_count | \
      object_0[1-9]|object_1[0-5]|signature_count|signature_0[1-7] | \
      curl_path|curl_sha256|gpg_path|gpg_sha256) ;;
    expected_*|self_hash|receipt_sha256|safe|trusted)
      fail "receipt contains a forbidden authority or self-authentication field: ${key}"
      ;;
    *) fail "receipt contains an unknown field: ${key}" ;;
  esac
  receipt_fields["${key}"]="${value}"
done <"${receipt_path}"
readonly receipt_line_count
[[ "${receipt_line_count}" -eq 37 ]] || fail 'receipt does not have the exact field count'

require_receipt_field() {
  local key="$1"
  local expected="$2"
  [[ -v "receipt_fields[${key}]" && "${receipt_fields[${key}]}" == "${expected}" ]] ||
    fail "receipt has an unexpected value for ${key}"
}

require_receipt_field format a-quo-omarchy-bootstrap-candidate-v1
require_receipt_field status complete-candidate
require_receipt_field authority none
require_receipt_field scope signed-bootstrap-assets-01-through-07
require_receipt_field profile_external_authentication required-not-established-by-this-receipt
require_receipt_field observed_profile_sha256 "${expected_profile_sha256}"
require_receipt_field object_count 15
require_receipt_field signature_count 7
require_receipt_field profile_repository https://github.com/SurreptitiousFabric/a-quo.git
require_receipt_field profile_commit 3dcd52f3a0a4c678b0c2e015efd811164cc256bc
require_receipt_field profile_path \
  packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile

for tool_name in curl gpg; do
  tool_path_key="${tool_name}_path"
  tool_hash_key="${tool_name}_sha256"
  require_receipt_field "${tool_path_key}" "/usr/bin/${tool_name}"
  [[ "${receipt_fields[${tool_hash_key}]:-}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "receipt tool digest is malformed: ${tool_hash_key}"
done

for index in {1..15}; do
  printf -v object_key 'object_%02d' "${index}"
  [[ -v "receipt_fields[${object_key}]" ]] || fail "receipt is missing ${object_key}"
  receipt_object_record="${receipt_fields[${object_key}]}"
  IFS='|' read -r \
    receipt_role receipt_relative_path receipt_object_size receipt_object_hash \
    transport_class redirect_host redirect_count extra \
    <<<"${receipt_object_record}"
  [[ -z "${extra:-}" ]] || fail "receipt ${object_key} has the wrong field count"
  [[ "${receipt_object_record}" == \
    "${receipt_role}|${receipt_relative_path}|${receipt_object_size}|${receipt_object_hash}|${transport_class}|${redirect_host}|${redirect_count}" ]] ||
    fail "receipt ${object_key} is not in canonical field form"
  expected_prefix="${observed_object_records[index]}"
  [[ "${receipt_role}|${receipt_relative_path}|${receipt_object_size}|${receipt_object_hash}" == \
    "${expected_prefix}" ]] || fail "receipt ${object_key} does not match the verified object"
  if (( index == 1 )); then
    [[ "${transport_class}" == raw-direct && "${redirect_host}" == none && \
      "${redirect_count}" == 0 ]] || fail 'receipt release-key transport is invalid'
  else
    [[ "${transport_class}" == github-release ]] ||
      fail "receipt ${object_key} has the wrong transport class"
    case "${redirect_host}|${redirect_count}" in
      none\|0|release-assets.githubusercontent.com\|1|objects.githubusercontent.com\|1) ;;
      *) fail "receipt ${object_key} has an invalid redirect observation" ;;
    esac
  fi
done

for index in {1..7}; do
  printf -v signature_key 'signature_%02d' "${index}"
  require_receipt_field "${signature_key}" "${observed_signature_records[index]}"
done

if [[ "${pre_completion}" == false ]]; then
  [[ "$(${STAT} -c '%s' -- "${candidate_directory}/COMPLETE")" == 19 && \
    "$(<"${candidate_directory}/COMPLETE")" == complete-candidate ]] ||
    fail 'COMPLETE marker content is invalid'
fi

if [[ "${pre_completion}" == true ]]; then
  reported_candidate_status=verified-incomplete-non-authoritative
else
  reported_candidate_status=verified-non-authoritative
fi
readonly reported_candidate_status
printf '%s\n' \
  "candidate_status=${reported_candidate_status}" \
  'authority=none' \
  "profile_sha256=${expected_profile_sha256}" \
  'object_count=15' \
  'signature_count=7' \
  'signed_descriptor_bindings=verified-non-authoritative' \
  'external_profile_authentication_required=true' \
  'signed_does_not_mean_safe=true' \
  'network_activity=false' \
  'vm_started=false'
