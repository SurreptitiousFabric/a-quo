#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly V2_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly DEFAULT_PROFILE="${V2_PROFILE}"
readonly V1_EXPECTED_PROFILE_SHA256='84f23e93c4d240aef5c0b8e01769d9245cbdb1757eb5da7acd4a3130246949da'
readonly V2_EXPECTED_PROFILE_SHA256='3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6'
readonly V1_EXPECTED_FIELD_COUNT=76
readonly V2_EXPECTED_FIELD_COUNT=129
readonly MAXIMUM_PROFILE_BYTES=65536

fail() {
  printf 'Omarchy evaluation target profile refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--require-runnable] [PROFILE]\n' "${0##*/}" >&2
  exit 2
}

require_runnable=false
profile_path="${DEFAULT_PROFILE}"
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
if [[ ! "${PROFILE_SIZE}" =~ ^[0-9]+$ ]] ||
  (( PROFILE_SIZE == 0 || PROFILE_SIZE > MAXIMUM_PROFILE_BYTES )); then
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
  [[ "${line}" == *=* ]] || fail "missing key/value separator at line ${line_number}"
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${value}" != *'='* ]] || fail "extra key/value separator at line ${line_number}"
  [[ "${key}" =~ ^[a-z][a-z0-9_]{0,63}$ ]] ||
    fail "invalid key at line ${line_number}"
  [[ -n "${value}" && ${#value} -le 4096 && "${value}" != ' '* && \
    "${value}" != *' ' ]] || fail "invalid value bounds at line ${line_number}"
  [[ ! -v "fields[${key}]" ]] || fail "duplicate key: ${key}"
  case "${key}" in
    format|profile_id|state|armable|purpose|architecture|vm_disk_virtual_bytes | \
      expectation_scope|retained_input_authority | \
      builder_base_oci_repository|builder_base_oci_platform | \
      builder_base_oci_index_digest|builder_base_oci_manifest_digest | \
      builder_base_oci_discovery_tag|builder_base_oci_discovery_tag_authority | \
      builder_base_oci_variant|builder_base_oci_index_media_type | \
      builder_base_oci_index_size|builder_base_oci_manifest_media_type | \
      builder_base_oci_manifest_size|builder_base_oci_config_media_type | \
      builder_base_oci_config_size|builder_base_oci_config_digest | \
      builder_base_oci_layer_count|builder_base_oci_layer_01_media_type | \
      builder_base_oci_layer_01_size|builder_base_oci_layer_01_digest | \
      builder_base_oci_diff_id_count|builder_base_oci_diff_id_01 | \
      builder_base_oci_source_repository_assertion | \
      builder_base_oci_source_revision_assertion | \
      builder_base_oci_source_serial_assertion | \
      builder_base_oci_source_version_assertion|builder_base_oci_integrity | \
      builder_base_oci_publisher_authentication | \
      builder_base_oci_source_to_image_provenance|builder_base_oci_retention | \
      builder_dockerfile_source_commit|builder_dockerfile_source_path | \
      builder_dockerfile_git_blob_sha1|builder_dockerfile_size | \
      builder_dockerfile_sha256|builder_apt_top_level_request_count | \
      builder_apt_top_level_requests|builder_apt_snapshot_and_closure | \
      profile_authentication|self_authentication|release_claim|support_claim | \
      reproducibility_claim|clean_system_claim | \
      a_quo_source_repository|a_quo_source_commit|a_quo_package_name | \
      a_quo_package_size|a_quo_package_sha256|a_quo_expected_package_query | \
      a_quo_signature|a_quo_build_environment|a_quo_artifact_status | \
      a_quo_release_provenance|omarchy_source_repository | \
      omarchy_source_commit|omarchy_source_authentication | \
      omarchy_stable_release_tag|omarchy_stable_release_sequence | \
      omarchy_expected_package_query|omarchy_release_key_url | \
      omarchy_release_key_size|omarchy_release_key_sha256 | \
      omarchy_release_key_fingerprint|omarchy_stable_download_base | \
      omarchy_bundle_repository|omarchy_bundle_release_tag | \
      omarchy_bundle_release_sequence|omarchy_bundle_source_commit | \
      omarchy_bundle_package_source_commit|omarchy_bundle_download_base | \
      release_asset_count|release_asset_0[1-8]|bundle_package_count | \
      bundle_package_0[1-6]|asahi_keyring_url|asahi_keyring_size | \
      asahi_keyring_sha256|asahi_keyring_authentication | \
      alarm_rootfs_expected_signer_fingerprint | \
      alarm_builder_key_source_repository|alarm_builder_key_source_commit | \
      alarm_builder_key_source_path|alarm_builder_key_source_git_blob_sha1 | \
      alarm_builder_key_url|alarm_builder_key_size|alarm_builder_key_sha256 | \
      alarm_builder_key_fingerprint|alarm_builder_key_source_authentication | \
      alarm_builder_key_authentication|alarm_builder_key_role | \
      alarm_builder_key_current_publisher_authorization | \
      alarm_builder_key_current_revocation | \
      pacman_required_repository_name_set|pacman_repository_priority | \
      alarm_repository_database_policy|alarm_repository_package_policy | \
      asahi_repository_trust_domain|pacman_repository_lock_status | \
      unresolved_input_count | \
      unresolved_input_0[1-9]|unresolved_input_10) ;;
    observed_*|profile_sha256|self_hash)
      fail "observation or self-authentication key is forbidden: ${key}"
      ;;
    *) fail "unknown key: ${key}" ;;
  esac
  fields["${key}"]="${value}"
done <"${profile_path}"
readonly line_number

expected_profile_sha256=''
expected_field_count=''
case "${fields[format]:-}|${fields[profile_id]:-}" in
  a-quo-omarchy-evaluation-target-profile-v1\|a-quo-omarchy4-aarch64-dec29fa-v1)
    expected_profile_sha256="${V1_EXPECTED_PROFILE_SHA256}"
    expected_field_count="${V1_EXPECTED_FIELD_COUNT}"
    ;;
  a-quo-omarchy-evaluation-target-profile-v2\|a-quo-omarchy4-aarch64-dec29fa-v2)
    expected_profile_sha256="${V2_EXPECTED_PROFILE_SHA256}"
    expected_field_count="${V2_EXPECTED_FIELD_COUNT}"
    ;;
  *) fail 'format and profile_id do not name one supported immutable profile' ;;
esac
readonly expected_profile_sha256 expected_field_count

[[ "${line_number}" -eq "${expected_field_count}" ]] ||
  fail 'profile does not have the exact field count for its version'

PROFILE_METADATA_AFTER="$(stat -c '%d:%i:%s:%f:%Y' -- "${profile_path}")" ||
  fail 'profile metadata became unavailable'
readonly PROFILE_METADATA_AFTER
[[ "${PROFILE_METADATA_AFTER}" == "${PROFILE_METADATA_BEFORE}" ]] ||
  fail 'profile metadata changed during verification'
PROFILE_SHA256="$(sha256sum -- "${profile_path}")"
PROFILE_SHA256="${PROFILE_SHA256%% *}"
readonly PROFILE_SHA256

assert_field() {
  local key="$1"
  local expected="$2"
  [[ -v "fields[${key}]" ]] || fail "required key is absent: ${key}"
  [[ "${fields[${key}]}" == "${expected}" ]] || fail "unexpected value for ${key}"
}

assert_lower_sha256() {
  local key="$1"
  [[ -v "fields[${key}]" && "${fields[${key}]}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "${key} is not one lowercase SHA-256"
}

assert_prefixed_lower_sha256() {
  local key="$1"
  [[ -v "fields[${key}]" && "${fields[${key}]}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "${key} is not one lowercase sha256 descriptor digest"
}

assert_lower_git_object() {
  local key="$1"
  [[ -v "fields[${key}]" && "${fields[${key}]}" =~ ^[0-9a-f]{40}$ ]] ||
    fail "${key} is not one lowercase Git object identifier"
}

assert_upper_fingerprint() {
  local key="$1"
  [[ -v "fields[${key}]" && "${fields[${key}]}" =~ ^[0-9A-F]{40}$ ]] ||
    fail "${key} is not one uppercase fingerprint"
}

assert_exact_https_url() {
  local key="$1"
  local value="${fields[${key}]:-}"
  [[ "${value}" == https://* && "${value}" != *'?'* && "${value}" != *'#'* && \
    "${value}" != *'/../'* && "${value}" != *'/./'* ]] ||
    fail "${key} is not one exact HTTPS locator"
  if [[ "${value,,}" == *'/latest/'* || "${value,,}" == *'/main/'* ||
    "${value,,}" == *channel* ]]; then
    fail "${key} contains a moving selector"
  fi
}

assert_field state bootstrap-unarmed
assert_field armable false
assert_field purpose evaluation-only
assert_field architecture aarch64
assert_field vm_disk_virtual_bytes 103079215104
assert_field profile_authentication external-pinned-git-object-required
assert_field self_authentication none
assert_field release_claim not-established
assert_field support_claim not-established
assert_field reproducibility_claim not-established
assert_field clean_system_claim not-established
assert_field builder_base_oci_repository docker.io/library/ubuntu
assert_field builder_base_oci_platform linux/arm64
assert_field builder_base_oci_index_digest \
  sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
assert_field builder_base_oci_manifest_digest \
  sha256:95fa486768020359141f1318720f43e7982ef926c792891d984aef9aaf05e7ea

if [[ "${fields[format]}" == a-quo-omarchy-evaluation-target-profile-v2 ]]; then
  assert_field expectation_scope reviewed-metadata-only
  assert_field retained_input_authority none
  assert_field builder_base_oci_discovery_tag noble-20260810
  assert_field builder_base_oci_discovery_tag_authority none
  assert_field builder_base_oci_variant v8
  assert_field builder_base_oci_index_media_type \
    application/vnd.oci.image.index.v1+json
  assert_field builder_base_oci_index_size 6688
  assert_field builder_base_oci_manifest_media_type \
    application/vnd.oci.image.manifest.v1+json
  assert_field builder_base_oci_manifest_size 424
  assert_field builder_base_oci_config_media_type \
    application/vnd.oci.image.config.v1+json
  assert_field builder_base_oci_config_size 2067
  assert_prefixed_lower_sha256 builder_base_oci_config_digest
  assert_field builder_base_oci_config_digest \
    sha256:5b8c0c14690ed170da4e663fe0bae0d58efe59661e791296ffab28ed2113b650
  assert_field builder_base_oci_layer_count 1
  assert_field builder_base_oci_layer_01_media_type \
    application/vnd.oci.image.layer.v1.tar+gzip
  assert_field builder_base_oci_layer_01_size 28887235
  assert_prefixed_lower_sha256 builder_base_oci_layer_01_digest
  assert_field builder_base_oci_layer_01_digest \
    sha256:0b613318ea879878918380aa3aeb220dfe824e311b83bc955cb8a1d4319650ab
  assert_field builder_base_oci_diff_id_count 1
  assert_prefixed_lower_sha256 builder_base_oci_diff_id_01
  assert_field builder_base_oci_diff_id_01 \
    sha256:646eea22414270d74b0c9e9d6d3b9550701ae62e658a099825d4d15045a3630b
  assert_exact_https_url builder_base_oci_source_repository_assertion
  assert_field builder_base_oci_source_repository_assertion \
    https://git.launchpad.net/cloud-images/+oci/ubuntu-base
  assert_lower_git_object builder_base_oci_source_revision_assertion
  assert_field builder_base_oci_source_revision_assertion \
    73ecb123318a4fa4b264fae169d4773bc4c9c9c6
  assert_field builder_base_oci_source_serial_assertion 20260810
  assert_field builder_base_oci_source_version_assertion 24.04
  assert_field builder_base_oci_integrity content-addressed-descriptor-chain
  assert_field builder_base_oci_publisher_authentication not-established
  assert_field builder_base_oci_source_to_image_provenance not-established
  assert_field builder_base_oci_retention required-not-retained
  assert_lower_git_object builder_dockerfile_source_commit
  assert_field builder_dockerfile_source_commit \
    dec29fa90afc3d16a7e0c487c1869c7e512282ca
  assert_field builder_dockerfile_source_path test/vm/asahi-fresh/Dockerfile
  assert_lower_git_object builder_dockerfile_git_blob_sha1
  assert_field builder_dockerfile_git_blob_sha1 \
    dd8d6e71e0ff14e91937c7763a176d24338d29fc
  assert_field builder_dockerfile_size 409
  assert_lower_sha256 builder_dockerfile_sha256
  assert_field builder_dockerfile_sha256 \
    e77219761f9384f56831a07c8b2dfbdf101e5274d2409f7757ae9c015bffd139
  assert_field builder_apt_top_level_request_count 14
  assert_field builder_apt_top_level_requests \
    ca-certificates,curl,dosfstools,e2fsprogs,fdisk,gnupg,libarchive-tools,openssh-client,parted,qemu-efi-aarch64,qemu-system-arm,qemu-utils,socat,udev
  assert_field builder_apt_snapshot_and_closure required-not-retained
fi

assert_field a_quo_source_repository https://github.com/SurreptitiousFabric/a-quo.git
assert_field a_quo_source_commit 81658b7f8d48b0fdadc860edd1b27e1bf4da7d2f
assert_field a_quo_package_name \
  a-quo-0.1.0.r61.g81658b7f8d48-1-aarch64.pkg.tar.zst
assert_field a_quo_package_size 12169663
assert_lower_sha256 a_quo_package_sha256
assert_field a_quo_package_sha256 \
  ff906394c5fc3346db2e46f9d340d7ad49249380797b759caaef152b4432631d
assert_field a_quo_expected_package_query 'a-quo 0.1.0.r61.g81658b7f8d48-1'
assert_field a_quo_signature absent
assert_field a_quo_build_environment native-host-nonhermetic
assert_field a_quo_artifact_status PACKAGE-SKELETON-NONPUBLISHABLE
assert_field a_quo_release_provenance not-established

assert_field omarchy_source_repository https://github.com/maralcbr/omarchy-mx-mac.git
assert_field omarchy_source_commit dec29fa90afc3d16a7e0c487c1869c7e512282ca
assert_field omarchy_source_authentication signed-release-record-only
assert_field omarchy_stable_release_tag v4.0.0-mac.11
assert_field omarchy_stable_release_sequence 11
assert_field omarchy_expected_package_query 'omarchy-dev 4.0.0.r6589.gdec29fa-1'
assert_field omarchy_release_key_size 261
assert_lower_sha256 omarchy_release_key_sha256
assert_field omarchy_release_key_sha256 \
  16700437574a69166f74c2f74d0ad3a7badcb5873386de172a9b84f70a14edb5
assert_upper_fingerprint omarchy_release_key_fingerprint
assert_field omarchy_release_key_fingerprint \
  5983B1CA32CB778F4D74D24ECFF35022CA5B5959
assert_field omarchy_bundle_release_tag asahi-quattro-dec29fa9
assert_field omarchy_bundle_release_sequence 15
assert_field omarchy_bundle_source_commit dec29fa90afc3d16a7e0c487c1869c7e512282ca
assert_field omarchy_bundle_package_source_commit \
  a0e79624e0f12ad2bcb9ce53760474e3a01484f5

for url_key in \
  a_quo_source_repository \
  omarchy_source_repository \
  omarchy_release_key_url \
  omarchy_stable_download_base \
  omarchy_bundle_repository \
  omarchy_bundle_download_base \
  asahi_keyring_url; do
  assert_exact_https_url "${url_key}"
done
assert_field omarchy_release_key_url \
  https://raw.githubusercontent.com/maralcbr/omarchy-mx-mac/dec29fa90afc3d16a7e0c487c1869c7e512282ca/default/omarchy-release.gpg
assert_field omarchy_stable_download_base \
  https://github.com/maralcbr/omarchy-mx-mac/releases/download/v4.0.0-mac.11/
assert_field omarchy_bundle_repository https://github.com/maralcbr/omarchy-pkgs.git
assert_field omarchy_bundle_download_base \
  https://github.com/maralcbr/omarchy-pkgs/releases/download/asahi-quattro-dec29fa9/

assert_field release_asset_count 8
declare -A asset_names=()
for index in {01..08}; do
  record_key="release_asset_${index}"
  IFS='|' read -r -a parts <<<"${fields[${record_key}]:-}"
  [[ "${#parts[@]}" -eq 8 ]] || fail "${record_key} has the wrong field count"
  base="${parts[0]}"
  role="${parts[1]}"
  filename="${parts[2]}"
  size="${parts[3]}"
  sha256="${parts[4]}"
  signature_filename="${parts[5]}"
  signature_size="${parts[6]}"
  signature_sha256="${parts[7]}"
  case "${index}" in
    01) expected_base=stable; expected_role=release-record ;;
    02) expected_base=stable; expected_role=bootstrap-installer ;;
    03) expected_base=bundle; expected_role=release-record ;;
    04) expected_base=bundle; expected_role=package-manifest ;;
    05) expected_base=bundle; expected_role=bundle-installer ;;
    06) expected_base=bundle; expected_role=fresh-installer ;;
    07) expected_base=bundle; expected_role=bundle-updater ;;
    08) expected_base=bundle; expected_role=upgrade-tool ;;
  esac
  [[ "${base}" == "${expected_base}" && "${role}" == "${expected_role}" ]] ||
    fail "${record_key} has the wrong base or role"
  [[ "${filename}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
    fail "${record_key} has an unsafe filename"
  [[ "${size}" =~ ^[1-9][0-9]{0,8}$ && "${sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "${record_key} has invalid size or hash"
  [[ ! -v "asset_names[${filename}]" ]] || fail "duplicate release asset: ${filename}"
  asset_names["${filename}"]=1
  if [[ "${signature_filename}" == descriptor-bound ]]; then
    [[ "${index}" == 08 && "${signature_size}" == 0 && \
      "${signature_sha256}" == none ]] ||
      fail "${record_key} has an invalid descriptor-bound signature marker"
  else
    [[ "${signature_filename}" == "${filename}.sig" && \
      "${signature_size}" == 119 && "${signature_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
      fail "${record_key} has invalid detached-signature metadata"
  fi
done

assert_field bundle_package_count 6
declare -A package_names=()
for index in {01..06}; do
  record_key="bundle_package_${index}"
  IFS='|' read -r -a parts <<<"${fields[${record_key}]:-}"
  [[ "${#parts[@]}" -eq 9 ]] || fail "${record_key} has the wrong field count"
  package_name="${parts[0]}"
  package_version="${parts[1]}"
  package_architecture="${parts[2]}"
  filename="${parts[3]}"
  size="${parts[4]}"
  sha256="${parts[5]}"
  signature_filename="${parts[6]}"
  signature_size="${parts[7]}"
  signature_sha256="${parts[8]}"
  case "${index}" in
    01)
      expected_package_name=omarchy-keyring
      expected_package_version=20251027-1
      expected_package_architecture=any
      ;;
    02)
      expected_package_name=omarchy-settings-dev
      expected_package_version=4.0.0.r6589.gdec29fa-1
      expected_package_architecture=aarch64
      ;;
    03)
      expected_package_name=omarchy-dev
      expected_package_version=4.0.0.r6589.gdec29fa-1
      expected_package_architecture=aarch64
      ;;
    04)
      expected_package_name=omarchy-nvim
      expected_package_version=2026.8.1-1
      expected_package_architecture=any
      ;;
    05)
      expected_package_name=quickshell-git
      expected_package_version=0.3.0.r20.g28771c7-1
      expected_package_architecture=aarch64
      ;;
    06)
      expected_package_name=ttf-jetbrains-mono-nerd-basic
      expected_package_version=3.4.0-1
      expected_package_architecture=any
      ;;
  esac
  [[ "${package_name}" =~ ^[a-z0-9][a-z0-9._+-]{0,63}$ && \
    "${package_version}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ && \
    ( "${package_architecture}" == any || "${package_architecture}" == aarch64 ) ]] ||
    fail "${record_key} has invalid package identity"
  [[ "${filename}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,191}$ && \
    "${size}" =~ ^[1-9][0-9]{0,9}$ && "${sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "${record_key} has invalid package filename, size, or hash"
  [[ "${signature_filename}" == "${filename}.sig" && \
    "${signature_size}" == 119 && "${signature_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "${record_key} has invalid package signature metadata"
  [[ ! -v "package_names[${package_name}]" ]] ||
    fail "duplicate bundle package: ${package_name}"
  package_names["${package_name}"]=1
  [[ "${package_name}" == "${expected_package_name}" && \
    "${package_version}" == "${expected_package_version}" && \
    "${package_architecture}" == "${expected_package_architecture}" ]] ||
    fail "${record_key} has the wrong indexed package identity"
done
IFS='|' read -r expected_omarchy_package expected_omarchy_version _ \
  <<<"${fields[bundle_package_03]}"
assert_field omarchy_expected_package_query \
  "${expected_omarchy_package} ${expected_omarchy_version}"

assert_field asahi_keyring_url \
  https://github.com/asahi-alarm/asahi-alarm/releases/download/aarch64/asahi-alarm-keyring-20241216-1-any.pkg.tar.xz
assert_field asahi_keyring_size 10120
assert_lower_sha256 asahi_keyring_sha256
assert_field asahi_keyring_sha256 \
  798f4b283ad2819aee950d042f26566ae1a68f87c12247301ce449bea3b2d81e
assert_field asahi_keyring_authentication sha256-policy-pin-only
assert_upper_fingerprint alarm_rootfs_expected_signer_fingerprint
assert_field alarm_rootfs_expected_signer_fingerprint \
  68B3537F39A313B3E574D06777193F152BDBE6A6

if [[ "${fields[format]}" == a-quo-omarchy-evaluation-target-profile-v2 ]]; then
  assert_exact_https_url alarm_builder_key_source_repository
  assert_field alarm_builder_key_source_repository \
    https://github.com/archlinuxarm/archlinuxarm-keyring.git
  assert_lower_git_object alarm_builder_key_source_commit
  assert_field alarm_builder_key_source_commit \
    91e6b11698f8df66042d56aaa56fbe9c9263847d
  assert_field alarm_builder_key_source_path packager/builder.asc
  assert_lower_git_object alarm_builder_key_source_git_blob_sha1
  assert_field alarm_builder_key_source_git_blob_sha1 \
    991d04afb7c980921d25642cc53e5c465740f60c
  assert_exact_https_url alarm_builder_key_url
  assert_field alarm_builder_key_url \
    https://raw.githubusercontent.com/archlinuxarm/archlinuxarm-keyring/91e6b11698f8df66042d56aaa56fbe9c9263847d/packager/builder.asc
  assert_field alarm_builder_key_size 5304
  assert_lower_sha256 alarm_builder_key_sha256
  assert_field alarm_builder_key_sha256 \
    26196ae6d6efbb1138be6805245d577adbcd94b887eaf0569f88efe003e6b3d9
  assert_upper_fingerprint alarm_builder_key_fingerprint
  assert_field alarm_builder_key_fingerprint \
    68B3537F39A313B3E574D06777193F152BDBE6A6
  assert_field alarm_builder_key_source_authentication unsigned-git-commit
  assert_field alarm_builder_key_authentication sha256-policy-pin-only
  assert_field alarm_builder_key_role future-rootfs-signature-policy-expectation
  assert_field alarm_builder_key_current_publisher_authorization not-established
  assert_field alarm_builder_key_current_revocation not-established
  assert_field pacman_required_repository_name_set alarm,asahi-alarm,aur,core,extra
  assert_field pacman_repository_priority not-established
  assert_field alarm_repository_database_policy \
    unsigned-database-reviewed-sha256-lock-required
  assert_field alarm_repository_package_policy exact-builder-key-signature-required
  assert_field asahi_repository_trust_domain \
    separate-key-policy-required-not-established
  assert_field pacman_repository_lock_status required-not-retained
fi

assert_field unresolved_input_count 10
declare -A unresolved_values=()
for index in {01..10}; do
  record_key="unresolved_input_${index}"
  unresolved="${fields[${record_key}]:-}"
  [[ "${unresolved}" =~ ^[a-z0-9][a-z0-9-]{0,95}$ ]] ||
    fail "${record_key} is invalid"
  [[ ! -v "unresolved_values[${unresolved}]" ]] ||
    fail "duplicate unresolved input: ${unresolved}"
  unresolved_values["${unresolved}"]=1
done

if [[ "${fields[format]}" == a-quo-omarchy-evaluation-target-profile-v2 ]]; then
  assert_field unresolved_input_01 builder-oci-retained-archive-and-final-image
  assert_field unresolved_input_02 ubuntu-apt-snapshot-and-package-lock
  assert_field unresolved_input_04 alarm-rootfs-bytes-signature-and-key-blob
  assert_field unresolved_input_05 offline-pacman-repository-lock
fi

[[ "${PROFILE_SHA256}" == "${expected_profile_sha256}" ]] ||
  fail 'profile bytes do not match the reviewed canonical profile'

if "${require_runnable}"; then
  fail 'profile is intentionally unarmed; reviewed frozen inputs and a new profile revision are required'
fi

printf '%s\n' \
  "profile_id=${fields[profile_id]}" \
  "profile_sha256=${PROFILE_SHA256}" \
  "state=${fields[state]}" \
  "armable=${fields[armable]}" \
  "unresolved_input_count=${fields[unresolved_input_count]}" \
  'external_authentication_required=true' \
  'network_activity=false' \
  'vm_started=false'
