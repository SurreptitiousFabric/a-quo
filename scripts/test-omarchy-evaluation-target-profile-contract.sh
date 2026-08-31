#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-evaluation-target-profile.sh"
readonly BOOTSTRAP_ACQUIRER="${SCRIPT_DIRECTORY}/acquire-omarchy-bootstrap-candidates.sh"
readonly BOOTSTRAP_CANDIDATE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-bootstrap-candidate.sh"
readonly V1_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile"
readonly V2_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly PROFILE="${V2_PROFILE}"
readonly V1_EXPECTED_PROFILE_SHA256='84f23e93c4d240aef5c0b8e01769d9245cbdb1757eb5da7acd4a3130246949da'
readonly V2_EXPECTED_PROFILE_SHA256='3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6'

[[ -x "${VERIFIER}" && ! -L "${VERIFIER}" ]] || {
  printf '%s\n' 'target-profile verifier is missing, non-executable, or a symlink' >&2
  exit 1
}
for profile in \
  "${V1_PROFILE}" \
  "${V2_PROFILE}" \
  "${BOOTSTRAP_ACQUIRER}" \
  "${BOOTSTRAP_CANDIDATE_VERIFIER}"; do
  [[ -f "${profile}" && ! -L "${profile}" ]] || {
    printf 'canonical target profile is missing or is a symlink: %s\n' \
      "${profile}" >&2
    exit 1
  }
done

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

V1_EXPECTED_OUTPUT="$(printf '%s\n' \
  'profile_id=a-quo-omarchy4-aarch64-dec29fa-v1' \
  "profile_sha256=${V1_EXPECTED_PROFILE_SHA256}" \
  'state=bootstrap-unarmed' \
  'armable=false' \
  'unresolved_input_count=10' \
  'external_authentication_required=true' \
  'network_activity=false' \
  'vm_started=false')"
readonly V1_EXPECTED_OUTPUT
V2_EXPECTED_OUTPUT="$(printf '%s\n' \
  'profile_id=a-quo-omarchy4-aarch64-dec29fa-v2' \
  "profile_sha256=${V2_EXPECTED_PROFILE_SHA256}" \
  'state=bootstrap-unarmed' \
  'armable=false' \
  'unresolved_input_count=10' \
  'external_authentication_required=true' \
  'network_activity=false' \
  'vm_started=false')"
readonly V2_EXPECTED_OUTPUT

DEFAULT_OUTPUT="$("${VERIFIER}")"
EXPLICIT_V1_OUTPUT="$("${VERIFIER}" "${V1_PROFILE}")"
EXPLICIT_V2_OUTPUT="$("${VERIFIER}" "${V2_PROFILE}")"
readonly DEFAULT_OUTPUT EXPLICIT_V1_OUTPUT EXPLICIT_V2_OUTPUT
if [[ "${DEFAULT_OUTPUT}" != "${V2_EXPECTED_OUTPUT}" || \
  "${EXPLICIT_V2_OUTPUT}" != "${V2_EXPECTED_OUTPUT}" ]]; then
  printf 'canonical v2 target-profile output mismatch: default=%q explicit=%q\n' \
    "${DEFAULT_OUTPUT}" "${EXPLICIT_V2_OUTPUT}" >&2
  exit 1
fi
if [[ "${EXPLICIT_V1_OUTPUT}" != "${V1_EXPECTED_OUTPUT}" ]]; then
  printf 'canonical v1 target-profile output mismatch: %q\n' \
    "${EXPLICIT_V1_OUTPUT}" >&2
  exit 1
fi

assert_refused require-runnable-v1 \
  'profile is intentionally unarmed; reviewed frozen inputs and a new profile revision are required' \
  --require-runnable "${V1_PROFILE}"
assert_refused require-runnable-v2 \
  'profile is intentionally unarmed; reviewed frozen inputs and a new profile revision are required' \
  --require-runnable "${V2_PROFILE}"

V2_ACQUISITION_OUTPUT="${TEMPORARY_ROOT}/v2-acquisition-must-not-exist"
set +e
V2_ACQUISITION_REFUSAL="$("${BOOTSTRAP_ACQUIRER}" \
  --profile "${V2_PROFILE}" \
  --output "${V2_ACQUISITION_OUTPUT}" \
  --acknowledge-networked-candidate-only 2>&1)"
V2_ACQUISITION_STATUS="$?"
set -e
readonly V2_ACQUISITION_OUTPUT V2_ACQUISITION_REFUSAL V2_ACQUISITION_STATUS
if [[ "${V2_ACQUISITION_STATUS}" -ne 1 || \
  "${V2_ACQUISITION_REFUSAL}" != \
    *'only the canonical frozen profile path is accepted'* || \
  -e "${V2_ACQUISITION_OUTPUT}" || -L "${V2_ACQUISITION_OUTPUT}" ]]; then
  printf 'v2 bootstrap acquisition refusal mismatch: status=%s output=%q path_exists=%s\n' \
    "${V2_ACQUISITION_STATUS}" "${V2_ACQUISITION_REFUSAL}" \
    "$([[ -e "${V2_ACQUISITION_OUTPUT}" || -L "${V2_ACQUISITION_OUTPUT}" ]] && \
      printf true || printf false)" >&2
  exit 1
fi

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

replace_field "${V2_PROFILE}" "${TEMPORARY_ROOT}/v1-format-v2-id" format \
  a-quo-omarchy-evaluation-target-profile-v1
assert_refused v1-format-v2-id \
  'format and profile_id do not name one supported immutable profile' \
  "${TEMPORARY_ROOT}/v1-format-v2-id"

replace_field "${V2_PROFILE}" "${TEMPORARY_ROOT}/v2-format-v1-id" profile_id \
  a-quo-omarchy4-aarch64-dec29fa-v1
assert_refused v2-format-v1-id \
  'format and profile_id do not name one supported immutable profile' \
  "${TEMPORARY_ROOT}/v2-format-v1-id"

replace_field "${V1_PROFILE}" "${TEMPORARY_ROOT}/v2-format-with-v1-fields" format \
  a-quo-omarchy-evaluation-target-profile-v2
assert_refused v2-format-with-v1-fields \
  'format and profile_id do not name one supported immutable profile' \
  "${TEMPORARY_ROOT}/v2-format-with-v1-fields"

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

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/retained-scope" \
  expectation_scope retained-inputs
assert_refused retained-scope 'unexpected value for expectation_scope' \
  "${TEMPORARY_ROOT}/retained-scope"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/retained-authority" \
  retained_input_authority trusted
assert_refused retained-authority 'unexpected value for retained_input_authority' \
  "${TEMPORARY_ROOT}/retained-authority"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/mutable-oci-tag" \
  builder_base_oci_discovery_tag latest
assert_refused mutable-oci-tag 'unexpected value for builder_base_oci_discovery_tag' \
  "${TEMPORARY_ROOT}/mutable-oci-tag"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/uppercase-oci-config-digest" \
  builder_base_oci_config_digest \
  sha256:5B8C0C14690ED170DA4E663FE0BAE0D58EFE59661E791296FFAB28ED2113B650
assert_refused uppercase-oci-config-digest \
  'builder_base_oci_config_digest is not one lowercase sha256 descriptor digest' \
  "${TEMPORARY_ROOT}/uppercase-oci-config-digest"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/oci-layer-count" \
  builder_base_oci_layer_count 2
assert_refused oci-layer-count 'unexpected value for builder_base_oci_layer_count' \
  "${TEMPORARY_ROOT}/oci-layer-count"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/retained-oci" \
  builder_base_oci_retention retained
assert_refused retained-oci 'unexpected value for builder_base_oci_retention' \
  "${TEMPORARY_ROOT}/retained-oci"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/apt-request-count" \
  builder_apt_top_level_request_count 15
assert_refused apt-request-count \
  'unexpected value for builder_apt_top_level_request_count' \
  "${TEMPORARY_ROOT}/apt-request-count"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/duplicate-apt-request" \
  builder_apt_top_level_requests \
  ca-certificates,curl,dosfstools,e2fsprogs,fdisk,gnupg,libarchive-tools,openssh-client,parted,qemu-efi-aarch64,qemu-system-arm,qemu-utils,socat,socat
assert_refused duplicate-apt-request \
  'unexpected value for builder_apt_top_level_requests' \
  "${TEMPORARY_ROOT}/duplicate-apt-request"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/retained-apt-closure" \
  builder_apt_snapshot_and_closure retained
assert_refused retained-apt-closure \
  'unexpected value for builder_apt_snapshot_and_closure' \
  "${TEMPORARY_ROOT}/retained-apt-closure"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/moving-alarm-key" \
  alarm_builder_key_url \
  https://raw.githubusercontent.com/archlinuxarm/archlinuxarm-keyring/main/packager/builder.asc
assert_refused moving-alarm-key 'contains a moving selector' \
  "${TEMPORARY_ROOT}/moving-alarm-key"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/uppercase-alarm-key-hash" \
  alarm_builder_key_sha256 \
  26196AE6D6EFBB1138BE6805245D577ADBCD94B887EAF0569F88EFE003E6B3D9
assert_refused uppercase-alarm-key-hash \
  'alarm_builder_key_sha256 is not one lowercase SHA-256' \
  "${TEMPORARY_ROOT}/uppercase-alarm-key-hash"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/signed-alarm-source" \
  alarm_builder_key_source_authentication signed-git-commit
assert_refused signed-alarm-source \
  'unexpected value for alarm_builder_key_source_authentication' \
  "${TEMPORARY_ROOT}/signed-alarm-source"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/authorized-alarm-key" \
  alarm_builder_key_current_publisher_authorization established
assert_refused authorized-alarm-key \
  'unexpected value for alarm_builder_key_current_publisher_authorization' \
  "${TEMPORARY_ROOT}/authorized-alarm-key"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/pacman-priority" \
  pacman_repository_priority core-first
assert_refused pacman-priority 'unexpected value for pacman_repository_priority' \
  "${TEMPORARY_ROOT}/pacman-priority"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/retained-pacman-lock" \
  pacman_repository_lock_status retained
assert_refused retained-pacman-lock \
  'unexpected value for pacman_repository_lock_status' \
  "${TEMPORARY_ROOT}/retained-pacman-lock"

replace_field "${PROFILE}" "${TEMPORARY_ROOT}/resolved-ubuntu-input" \
  unresolved_input_02 ubuntu-apt-snapshot-and-package-lock-resolved
assert_refused resolved-ubuntu-input 'unexpected value for unresolved_input_02' \
  "${TEMPORARY_ROOT}/resolved-ubuntu-input"

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

for frozen_v1_literal in \
  'a-quo-omarchy4-aarch64-dec29fa-v1.profile' \
  '84f23e93c4d240aef5c0b8e01769d9245cbdb1757eb5da7acd4a3130246949da' \
  '3dcd52f3a0a4c678b0c2e015efd811164cc256bc'; do
  grep -Fq -- "${frozen_v1_literal}" "${BOOTSTRAP_ACQUIRER}" || {
    printf 'bootstrap acquirer lost frozen v1 literal: %s\n' \
      "${frozen_v1_literal}" >&2
    exit 1
  }
done
# shellcheck disable=SC2016
grep -Fq -- '[[ "${line_count}" -eq 76 ]]' "${BOOTSTRAP_CANDIDATE_VERIFIER}" || {
  printf '%s\n' 'bootstrap candidate verifier lost its frozen v1 field count' >&2
  exit 1
}
grep -Fq -- 'a-quo-omarchy-evaluation-target-profile-v1' \
  "${BOOTSTRAP_CANDIDATE_VERIFIER}" || {
  printf '%s\n' 'bootstrap candidate verifier lost its frozen v1 profile format' >&2
  exit 1
}
grep -Fq -- 'packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile' \
  "${BOOTSTRAP_CANDIDATE_VERIFIER}" || {
  printf '%s\n' 'bootstrap candidate verifier lost its frozen v1 receipt path' >&2
  exit 1
}
if grep -Fq -- 'a-quo-omarchy4-aarch64-dec29fa-v2.profile' \
  "${BOOTSTRAP_ACQUIRER}" "${BOOTSTRAP_CANDIDATE_VERIFIER}"; then
  printf '%s\n' 'v1 bootstrap boundary must not accept the v2 profile' >&2
  exit 1
fi

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
