#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-evaluation-target-profile.sh"
readonly PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile"
readonly EXPECTED_PROFILE_SHA256='84f23e93c4d240aef5c0b8e01769d9245cbdb1757eb5da7acd4a3130246949da'

[[ -x "${VERIFIER}" && ! -L "${VERIFIER}" ]] || {
  printf '%s\n' 'target-profile verifier is missing, non-executable, or a symlink' >&2
  exit 1
}
[[ -f "${PROFILE}" && ! -L "${PROFILE}" ]] || {
  printf '%s\n' 'canonical target profile is missing or is a symlink' >&2
  exit 1
}

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-target-profile.XXXXXX")"
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
    printf 'target-profile refusal mismatch: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

replace_field() {
  local source="$1"
  local destination="$2"
  local key="$3"
  local replacement="$4"
  awk -v key="${key}" -v replacement="${replacement}" '
    index($0, key "=") == 1 { print key "=" replacement; found += 1; next }
    { print }
    END { if (found != 1) exit 73 }
  ' "${source}" >"${destination}"
}

EXPECTED_OUTPUT="$(printf '%s\n' \
  'profile_id=a-quo-omarchy4-aarch64-dec29fa-v1' \
  "profile_sha256=${EXPECTED_PROFILE_SHA256}" \
  'state=bootstrap-unarmed' \
  'armable=false' \
  'unresolved_input_count=10' \
  'external_authentication_required=true' \
  'network_activity=false' \
  'vm_started=false')"
readonly EXPECTED_OUTPUT
OBSERVED_OUTPUT="$("${VERIFIER}")"
readonly OBSERVED_OUTPUT
if [[ "${OBSERVED_OUTPUT}" != "${EXPECTED_OUTPUT}" ]]; then
  printf 'canonical target-profile output mismatch: %q\n' "${OBSERVED_OUTPUT}" >&2
  exit 1
fi

assert_refused require-runnable \
  'profile is intentionally unarmed; reviewed frozen inputs and a new profile revision are required' \
  --require-runnable "${PROFILE}"

set +e
USAGE_OUTPUT="$("${VERIFIER}" one two three 2>&1)"
USAGE_STATUS="$?"
set -e
if [[ "${USAGE_STATUS}" -ne 2 || "${USAGE_OUTPUT}" != usage:* ]]; then
  printf 'target-profile verifier has the wrong usage refusal: status=%s output=%q\n' \
    "${USAGE_STATUS}" "${USAGE_OUTPUT}" >&2
  exit 1
fi

mkdir -- "${TEMPORARY_ROOT}/directory"
assert_refused directory 'profile must be one existing regular non-symlink file' \
  "${TEMPORARY_ROOT}/directory"
ln -s -- "${PROFILE}" "${TEMPORARY_ROOT}/profile-link"
assert_refused symlink 'profile must be one existing regular non-symlink file' \
  "${TEMPORARY_ROOT}/profile-link"
mkfifo -- "${TEMPORARY_ROOT}/profile-fifo"
assert_refused fifo 'profile must be one existing regular non-symlink file' \
  "${TEMPORARY_ROOT}/profile-fifo"

dd if=/dev/zero of="${TEMPORARY_ROOT}/oversized" bs=65537 count=1 status=none
assert_refused oversized 'profile size is outside the closed bound' \
  "${TEMPORARY_ROOT}/oversized"

head -c -1 -- "${PROFILE}" >"${TEMPORARY_ROOT}/missing-final-lf"
assert_refused missing-final-lf 'profile must end with one LF byte' \
  "${TEMPORARY_ROOT}/missing-final-lf"

awk 'NR == 1 { printf "%s\r\n", $0; next } { print }' \
  "${PROFILE}" >"${TEMPORARY_ROOT}/carriage-return"
assert_refused carriage-return 'profile contains a control, carriage-return, NUL, or non-ASCII byte' \
  "${TEMPORARY_ROOT}/carriage-return"

cp -- "${PROFILE}" "${TEMPORARY_ROOT}/nul-byte"
printf '\0' >>"${TEMPORARY_ROOT}/nul-byte"
assert_refused nul-byte 'profile contains a control, carriage-return, NUL, or non-ASCII byte' \
  "${TEMPORARY_ROOT}/nul-byte"

cp -- "${PROFILE}" "${TEMPORARY_ROOT}/blank-line"
printf '\n' >>"${TEMPORARY_ROOT}/blank-line"
assert_refused blank-line 'blank line' "${TEMPORARY_ROOT}/blank-line"

cp -- "${PROFILE}" "${TEMPORARY_ROOT}/comment"
printf '%s\n' '# not allowed' >>"${TEMPORARY_ROOT}/comment"
assert_refused comment 'missing key/value separator' "${TEMPORARY_ROOT}/comment"

awk 'NR == 1 { print $0 "=extra"; next } { print }' \
  "${PROFILE}" >"${TEMPORARY_ROOT}/extra-separator"
assert_refused extra-separator 'extra key/value separator' \
  "${TEMPORARY_ROOT}/extra-separator"

cp -- "${PROFILE}" "${TEMPORARY_ROOT}/duplicate"
head -n 1 -- "${PROFILE}" >>"${TEMPORARY_ROOT}/duplicate"
assert_refused duplicate 'duplicate key: format' "${TEMPORARY_ROOT}/duplicate"

cp -- "${PROFILE}" "${TEMPORARY_ROOT}/unknown"
printf '%s\n' 'mystery=value' >>"${TEMPORARY_ROOT}/unknown"
assert_refused unknown 'unknown key: mystery' "${TEMPORARY_ROOT}/unknown"

awk '$0 !~ /^support_claim=/' "${PROFILE}" >"${TEMPORARY_ROOT}/missing"
assert_refused missing 'profile does not have the exact field count' \
  "${TEMPORARY_ROOT}/missing"

awk 'NR == 1 { first = $0; next } NR == 2 { print; print first; next } { print }' \
  "${PROFILE}" >"${TEMPORARY_ROOT}/reordered"
assert_refused reordered 'profile bytes do not match the reviewed canonical profile' \
  "${TEMPORARY_ROOT}/reordered"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/moving-release" \
  omarchy_stable_download_base \
  https://github.com/maralcbr/omarchy-mx-mac/releases/latest/download/
assert_refused moving-release 'contains a moving selector' \
  "${TEMPORARY_ROOT}/moving-release"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/moving-key" \
  omarchy_release_key_url \
  https://raw.githubusercontent.com/maralcbr/omarchy-mx-mac/main/default/omarchy-release.gpg
assert_refused moving-key 'contains a moving selector' "${TEMPORARY_ROOT}/moving-key"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/channel" \
  omarchy_bundle_download_base \
  https://github.com/maralcbr/omarchy-pkgs/releases/download/asahi-quattro-channel/
assert_refused channel 'contains a moving selector' "${TEMPORARY_ROOT}/channel"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/plain-http" \
  asahi_keyring_url \
  http://github.com/asahi-alarm/asahi-alarm/releases/download/aarch64/keyring.pkg.tar.xz
assert_refused plain-http 'is not one exact HTTPS locator' "${TEMPORARY_ROOT}/plain-http"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/query-url" \
  asahi_keyring_url \
  'https://github.com/asahi-alarm/asahi-alarm/releases/download/aarch64/keyring.pkg.tar.xz?mutable'
assert_refused query-url 'is not one exact HTTPS locator' "${TEMPORARY_ROOT}/query-url"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/false-armable" armable true
assert_refused false-armable 'unexpected value for armable' "${TEMPORARY_ROOT}/false-armable"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/false-signature" a_quo_signature present
assert_refused false-signature 'unexpected value for a_quo_signature' \
  "${TEMPORARY_ROOT}/false-signature"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/false-release" \
  a_quo_artifact_status RELEASE-READY
assert_refused false-release 'unexpected value for a_quo_artifact_status' \
  "${TEMPORARY_ROOT}/false-release"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/uppercase-hash" a_quo_package_sha256 \
  FF906394C5FC3346DB2E46F9D340D7AD49249380797B759CAAEF152B4432631D
assert_refused uppercase-hash 'a_quo_package_sha256 is not one lowercase SHA-256' \
  "${TEMPORARY_ROOT}/uppercase-hash"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/substituted-hash" a_quo_package_sha256 \
  0000000000000000000000000000000000000000000000000000000000000000
assert_refused substituted-hash 'unexpected value for a_quo_package_sha256' \
  "${TEMPORARY_ROOT}/substituted-hash"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/asset-count" release_asset_count 7
assert_refused asset-count 'unexpected value for release_asset_count' \
  "${TEMPORARY_ROOT}/asset-count"

awk 'BEGIN { FS = OFS = "=" }
  $1 == "release_asset_05" { sub(/^bundle\|bundle-installer\|/, "bundle|release-record|", $2) }
  { print }
' "${PROFILE}" >"${TEMPORARY_ROOT}/wrong-asset-role"
assert_refused wrong-asset-role 'release_asset_05 has the wrong base or role' \
  "${TEMPORARY_ROOT}/wrong-asset-role"

awk 'BEGIN { FS = OFS = "=" }
  $1 == "bundle_package_06" { sub(/\|[^|]+\|119\|[0-9a-f]+$/, "", $2) }
  { print }
' "${PROFILE}" >"${TEMPORARY_ROOT}/missing-package-signature"
assert_refused missing-package-signature 'bundle_package_06 has the wrong field count' \
  "${TEMPORARY_ROOT}/missing-package-signature"

awk 'BEGIN { FS = OFS = "=" }
  $1 == "bundle_package_06" { sub(/^ttf-jetbrains-mono-nerd-basic\|/, "omarchy-keyring|", $2) }
  { print }
' "${PROFILE}" >"${TEMPORARY_ROOT}/duplicate-package"
assert_refused duplicate-package 'duplicate bundle package: omarchy-keyring' \
  "${TEMPORARY_ROOT}/duplicate-package"

cp -- "${PROFILE}" "${TEMPORARY_ROOT}/observation-key"
printf '%s\n' 'observed_rootfs_sha256=0000000000000000000000000000000000000000000000000000000000000000' \
  >>"${TEMPORARY_ROOT}/observation-key"
assert_refused observation-key 'observation or self-authentication key is forbidden' \
  "${TEMPORARY_ROOT}/observation-key"

cp -- "${PROFILE}" "${TEMPORARY_ROOT}/self-hash"
printf '%s\n' 'profile_sha256=0000000000000000000000000000000000000000000000000000000000000000' \
  >>"${TEMPORARY_ROOT}/self-hash"
assert_refused self-hash 'observation or self-authentication key is forbidden' \
  "${TEMPORARY_ROOT}/self-hash"

if grep -Eq '^[[:space:]]*(source|eval)[[:space:]]' "${VERIFIER}"; then
  printf '%s\n' 'target-profile verifier executes source or eval' >&2
  exit 1
fi
if grep -Eq '(^|[;&|[:space:]/])(curl|wget|gh|docker|podman|qemu-system|pacman|systemctl|mount|sudo)([;&|[:space:]]|$)' \
  "${VERIFIER}"; then
  printf '%s\n' 'target-profile verifier contains a network, VM, package, service, or mount command' >&2
  exit 1
fi

printf '%s\n' \
  'Omarchy evaluation target profile passed offline unarmed and hostile-input contract checks'
