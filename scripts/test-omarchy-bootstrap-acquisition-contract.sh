#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly ACQUIRER="${SCRIPT_DIRECTORY}/acquire-omarchy-bootstrap-candidates.sh"
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-bootstrap-candidate.sh"
readonly CANONICAL_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile"

for required_file in "${ACQUIRER}" "${VERIFIER}" "${CANONICAL_PROFILE}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] || {
    printf 'bootstrap contract input is missing or a symlink: %s\n' "${required_file}" >&2
    exit 1
  }
done
[[ -x "${ACQUIRER}" && -x "${VERIFIER}" ]] || {
  printf '%s\n' 'bootstrap acquisition scripts must be executable' >&2
  exit 1
}

for required_tool in awk chmod cp curl dd find gpg head ln mkdir mktemp mv rm sha256sum stat wc; do
  command -v "${required_tool}" >/dev/null || {
    printf 'bootstrap contract tool is unavailable: %s\n' "${required_tool}" >&2
    exit 1
  }
done

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-bootstrap-contract.XXXXXX")"
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
  output="$("$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != *"${expected}"* ]]; then
    printf 'bootstrap refusal mismatch: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

replace_field() {
  local path="$1"
  local key="$2"
  local replacement="$3"
  local temporary
  temporary="$(mktemp "${TEMPORARY_ROOT}/profile-field.XXXXXX")"
  awk -v key="${key}" -v replacement="${replacement}" '
    index($0, key "=") == 1 { print key "=" replacement; found += 1; next }
    { print }
    END { if (found != 1) exit 73 }
  ' "${path}" >"${temporary}"
  mv -- "${temporary}" "${path}"
}

profile_field() {
  local key="$1"
  awk -v key="${key}" '
    index($0, key "=") == 1 { print substr($0, length(key) + 2); found += 1 }
    END { if (found != 1) exit 73 }
  ' "${TEST_PROFILE}"
}

resign_profile_asset() {
  local asset_index="$1"
  local asset_key
  local asset_record
  local asset_base
  local asset_role
  local data_filename
  local signature_filename
  local extra
  local data_path
  local signature_path
  local data_size
  local data_hash
  local signature_size
  local signature_hash
  printf -v asset_key 'release_asset_%02d' "${asset_index}"
  asset_record="$(profile_field "${asset_key}")"
  IFS='|' read -r \
    asset_base asset_role data_filename _ _ \
    signature_filename _ _ extra \
    <<<"${asset_record}"
  [[ -z "${extra:-}" ]] || {
    printf 'test profile asset is malformed during resign: %s\n' "${asset_key}" >&2
    exit 1
  }
  data_path="${CANDIDATE}/objects/${asset_base}/${data_filename}"
  signature_path="${CANDIDATE}/objects/${asset_base}/${signature_filename}"
  rm -f -- "${signature_path}"
  gpg --batch --no-options --homedir "${GPG_HOME}" \
    --pinentry-mode loopback --passphrase '' \
    --local-user "${TEST_FINGERPRINT}" --detach-sign \
    --output "${signature_path}" "${data_path}" >/dev/null 2>&1
  data_size="$(stat -c '%s' -- "${data_path}")"
  data_hash="$(sha256sum -- "${data_path}")"
  data_hash="${data_hash%% *}"
  signature_size="$(stat -c '%s' -- "${signature_path}")"
  signature_hash="$(sha256sum -- "${signature_path}")"
  signature_hash="${signature_hash%% *}"
  replace_field "${TEST_PROFILE}" "${asset_key}" \
    "${asset_base}|${asset_role}|${data_filename}|${data_size}|${data_hash}|${signature_filename}|${signature_size}|${signature_hash}"
}

release_asset_data_hash() {
  local asset_index="$1"
  local asset_key
  local record
  printf -v asset_key 'release_asset_%02d' "${asset_index}"
  record="$(profile_field "${asset_key}")"
  awk -F'|' '{ print $5 }' <<<"${record}"
}

copy_candidate() {
  local name="$1"
  local destination="${TEMPORARY_ROOT}/${name}"
  cp -a -- "${CANDIDATE}" "${destination}"
  printf '%s\n' "${destination}"
}

prepare_semantic_mutant() {
  local name="$1"
  MUTATED="$(copy_candidate "${name}")"
  MUTATED_PROFILE="${TEMPORARY_ROOT}/${name}.profile"
  cp -- "${TEST_PROFILE}" "${MUTATED_PROFILE}"
  rm -- "${MUTATED}/receipt.v1" "${MUTATED}/COMPLETE"
  printf '%s\n' incomplete-candidate >"${MUTATED}/INCOMPLETE"
  chmod 0400 -- "${MUTATED}/INCOMPLETE" "${MUTATED_PROFILE}"
}

resign_semantic_mutant_asset() {
  local asset_index="$1"
  local asset_key
  local asset_record
  local asset_base
  local asset_role
  local data_filename
  local signature_filename
  local extra
  local data_path
  local signature_path
  local data_size
  local data_hash
  local signature_size
  local signature_hash
  printf -v asset_key 'release_asset_%02d' "${asset_index}"
  asset_record="$(awk -v key="${asset_key}" '
    index($0, key "=") == 1 { print substr($0, length(key) + 2); found += 1 }
    END { if (found != 1) exit 73 }
  ' "${MUTATED_PROFILE}")"
  IFS='|' read -r \
    asset_base asset_role data_filename _ _ signature_filename _ _ extra \
    <<<"${asset_record}"
  [[ -z "${extra:-}" ]] || {
    printf 'semantic mutant asset is malformed: %s\n' "${asset_key}" >&2
    exit 1
  }
  data_path="${MUTATED}/objects/${asset_base}/${data_filename}"
  signature_path="${MUTATED}/objects/${asset_base}/${signature_filename}"
  rm -f -- "${signature_path}"
  gpg --batch --no-options --homedir "${GPG_HOME}" \
    --pinentry-mode loopback --passphrase '' \
    --local-user "${TEST_FINGERPRINT}" --detach-sign \
    --output "${signature_path}" "${data_path}" >/dev/null 2>&1
  data_size="$(stat -c '%s' -- "${data_path}")"
  data_hash="$(sha256sum -- "${data_path}")"
  data_hash="${data_hash%% *}"
  signature_size="$(stat -c '%s' -- "${signature_path}")"
  signature_hash="$(sha256sum -- "${signature_path}")"
  signature_hash="${signature_hash%% *}"
  chmod 0600 -- "${MUTATED_PROFILE}"
  replace_field "${MUTATED_PROFILE}" "${asset_key}" \
    "${asset_base}|${asset_role}|${data_filename}|${data_size}|${data_hash}|${signature_filename}|${signature_size}|${signature_hash}"
  chmod 0600 -- "${MUTATED}/profile.snapshot"
  cp -- "${MUTATED_PROFILE}" "${MUTATED}/profile.snapshot"
  chmod 0400 -- \
    "${MUTATED_PROFILE}" "${MUTATED}/profile.snapshot" \
    "${data_path}" "${signature_path}"
}

assert_semantic_refused() {
  local label="$1"
  local expected="$2"
  local profile_digest
  profile_digest="$(sha256sum -- "${MUTATED_PROFILE}")"
  profile_digest="${profile_digest%% *}"
  assert_refused "${label}" "${expected}" \
    "${VERIFIER}" --emit-observations \
    --profile "${MUTATED_PROFILE}" \
    --externally-expected-profile-sha256 "${profile_digest}" \
    --candidate "${MUTATED}"
}

rebind_semantic_mutant_bundle_manifest() {
  local manifest_hash
  local bundle_path="${MUTATED}/objects/bundle/asahi-quattro-release"
  manifest_hash="$(awk -F= '
    $1 == "release_asset_04" { split($2, parts, "|"); print parts[5]; found += 1 }
    END { if (found != 1) exit 73 }
  ' "${MUTATED_PROFILE}")"
  chmod 0600 -- "${bundle_path}"
  awk -v manifest_hash="${manifest_hash}" '
    /^manifest_sha256=/ { print "manifest_sha256=" manifest_hash; next }
    { print }
  ' "${bundle_path}" >"${bundle_path}.changed"
  mv -- "${bundle_path}.changed" "${bundle_path}"
  resign_semantic_mutant_asset 3
}

set +e
usage_output="$("${ACQUIRER}" 2>&1)"
usage_status="$?"
set -e
if [[ "${usage_status}" -ne 2 || "${usage_output}" != usage:* ]]; then
  printf 'acquirer usage refusal mismatch: status=%s output=%q\n' \
    "${usage_status}" "${usage_output}" >&2
  exit 1
fi
assert_refused outside-output \
  'output must be one direct child of target/omarchy-evaluation-observations' \
  "${ACQUIRER}" \
  --profile "${CANONICAL_PROFILE}" \
  --output "${TEMPORARY_ROOT}/outside" \
  --acknowledge-networked-candidate-only

if grep -Eq -- '(^|[[:space:]])--(location|remote-name|remote-header-name)([=[:space:]]|$)' \
  "${ACQUIRER}"; then
  printf '%s\n' 'acquirer must not enable automatic redirect or server-selected filenames' >&2
  exit 1
fi
if grep -Eq '(^|[;&|[:space:]/])(docker|podman|qemu-system|pacman|systemctl|mount|sudo)([;&|[:space:]]|$)' \
  "${ACQUIRER}" "${VERIFIER}"; then
  printf '%s\n' 'bootstrap scripts contain a forbidden package, VM, service, mount, or privilege command' >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*(curl|wget|gh)([[:space:]]|$)|\$\{(CURL|WGET|GH)\}' \
  "${VERIFIER}"; then
  printf '%s\n' 'offline candidate verifier contains a network-capable command' >&2
  exit 1
fi
grep -Fq 'readonly CURL=/usr/bin/curl' "${ACQUIRER}" || {
  printf '%s\n' 'acquirer does not pin the curl program path' >&2
  exit 1
}
grep -Fq 'curl 8.4 or newer is required for bounded response bodies' "${ACQUIRER}" || {
  printf '%s\n' 'acquirer does not enforce the minimum bounded-body curl version' >&2
  exit 1
}
grep -Fq -- "--write-out '%{http_code}\\n%{redirect_url}'" "${ACQUIRER}" || {
  printf '%s\n' 'acquirer does not use the bounded in-memory redirect observation' >&2
  exit 1
}
grep -Fq 'private-config-fd' "${ACQUIRER}" || {
  printf '%s\n' 'acquirer does not keep the signed redirect URL out of argv' >&2
  exit 1
}
# shellcheck disable=SC2016
grep -Fq '[[ ! "${redirect_url}" =~ [[:cntrl:][:space:]]' "${ACQUIRER}" || {
  printf '%s\n' 'acquirer does not use the reviewed redirect control-character check' >&2
  exit 1
}
reviewed_redirect_example='https://release-assets.githubusercontent.com/example/object?token=opaque'
[[ ! "${reviewed_redirect_example}" =~ [[:cntrl:][:space:]] ]] || {
  printf '%s\n' 'reviewed redirect control-character check rejects an ordinary HTTPS URL' >&2
  exit 1
}
for required_hardening in \
  'set +x' \
  'ulimit -c 0' \
  '-u SSLKEYLOGFILE' \
  '--globoff'; do
  grep -Fq -- "${required_hardening}" "${ACQUIRER}" || {
    printf 'acquirer is missing redirect secrecy hardening: %s\n' \
      "${required_hardening}" >&2
    exit 1
  }
done
if grep -Eq '(^|[^A-Za-z0-9_])gpgv([^A-Za-z0-9_]|$)' \
  "${ACQUIRER}" "${VERIFIER}"; then
  printf '%s\n' 'bootstrap boundary must not use gpgv for expiry/revocation semantics' >&2
  exit 1
fi

GPG_HOME="${TEMPORARY_ROOT}/gpg-home"
readonly GPG_HOME
mkdir -m 0700 -- "${GPG_HOME}"
gpg --batch --no-options --homedir "${GPG_HOME}" \
  --pinentry-mode loopback --passphrase '' \
  --quick-generate-key \
  'A Quo Bootstrap Contract <bootstrap-contract@example.invalid>' \
  ed25519 sign 0 >/dev/null 2>&1
TEST_FINGERPRINT="$(gpg --batch --no-options --homedir "${GPG_HOME}" \
  --with-colons --list-keys 2>/dev/null | awk -F: '
    $1 == "pub" { want = 1; next }
    want && $1 == "fpr" { print $10; exit }
  ')"
readonly TEST_FINGERPRINT
[[ "${TEST_FINGERPRINT}" =~ ^[0-9A-F]{40}$ ]] || {
  printf '%s\n' 'test key did not produce one uppercase fingerprint' >&2
  exit 1
}

TEST_PROFILE="${TEMPORARY_ROOT}/profile"
CANDIDATE="${TEMPORARY_ROOT}/candidate"
readonly TEST_PROFILE CANDIDATE
cp -- "${CANONICAL_PROFILE}" "${TEST_PROFILE}"
mkdir -m 0700 -- "${CANDIDATE}"
mkdir -m 0700 -- \
  "${CANDIDATE}/objects" \
  "${CANDIDATE}/objects/stable" \
  "${CANDIDATE}/objects/bundle"
printf '%s\n' incomplete-candidate >"${CANDIDATE}/INCOMPLETE"

TEST_KEY="${CANDIDATE}/objects/omarchy-release.gpg"
readonly TEST_KEY
gpg --batch --no-options --homedir "${GPG_HOME}" \
  --export "${TEST_FINGERPRINT}" >"${TEST_KEY}"
key_size="$(stat -c '%s' -- "${TEST_KEY}")"
key_hash="$(sha256sum -- "${TEST_KEY}")"
key_hash="${key_hash%% *}"
replace_field "${TEST_PROFILE}" omarchy_release_key_size "${key_size}"
replace_field "${TEST_PROFILE}" omarchy_release_key_sha256 "${key_hash}"
replace_field "${TEST_PROFILE}" omarchy_release_key_fingerprint "${TEST_FINGERPRINT}"

for asset_index in 1 2 3 4 5 6 7; do
  printf -v asset_key 'release_asset_%02d' "${asset_index}"
  asset_record="$(awk -v key="${asset_key}" '
    index($0, key "=") == 1 { print substr($0, length(key) + 2); found += 1 }
    END { if (found != 1) exit 73 }
  ' "${TEST_PROFILE}")"
  IFS='|' read -r \
    asset_base asset_role data_filename _data_size _data_hash \
    signature_filename _signature_size _signature_hash extra \
    <<<"${asset_record}"
  [[ -z "${extra:-}" ]] || {
    printf 'test profile asset is malformed: %s\n' "${asset_key}" >&2
    exit 1
  }
  data_path="${CANDIDATE}/objects/${asset_base}/${data_filename}"
  signature_path="${CANDIDATE}/objects/${asset_base}/${signature_filename}"
  printf 'a-quo-bootstrap-contract-object-%02d\n' "${asset_index}" >"${data_path}"
  gpg --batch --no-options --homedir "${GPG_HOME}" \
    --pinentry-mode loopback --passphrase '' \
    --local-user "${TEST_FINGERPRINT}" --detach-sign \
    --output "${signature_path}" "${data_path}" >/dev/null 2>&1
  data_size="$(stat -c '%s' -- "${data_path}")"
  data_hash="$(sha256sum -- "${data_path}")"
  data_hash="${data_hash%% *}"
  signature_size="$(stat -c '%s' -- "${signature_path}")"
  signature_hash="$(sha256sum -- "${signature_path}")"
  signature_hash="${signature_hash%% *}"
  replace_field "${TEST_PROFILE}" "${asset_key}" \
    "${asset_base}|${asset_role}|${data_filename}|${data_size}|${data_hash}|${signature_filename}|${signature_size}|${signature_hash}"
done

MANIFEST_PATH="${CANDIDATE}/objects/bundle/asahi-quattro-bundle.manifest"
STABLE_RELEASE_PATH="${CANDIDATE}/objects/stable/omarchy-mx-mac-release"
BUNDLE_RELEASE_PATH="${CANDIDATE}/objects/bundle/asahi-quattro-release"
readonly MANIFEST_PATH STABLE_RELEASE_PATH BUNDLE_RELEASE_PATH
{
  printf '%s\n' \
    'format=2' \
    'bundle=asahi-quattro' \
    "source_commit=$(profile_field omarchy_bundle_source_commit)" \
    'package_count=6'
  for package_index in 1 2 3 4 5 6; do
    printf -v package_key 'bundle_package_%02d' "${package_index}"
    IFS='|' read -r \
      package_name package_version package_architecture package_filename \
      _package_size package_hash _signature_filename _signature_size \
      _signature_hash package_extra <<<"$(profile_field "${package_key}")"
    [[ -z "${package_extra:-}" ]] || {
      printf 'test package profile is malformed: %s\n' "${package_key}" >&2
      exit 1
    }
    printf 'package=%s|%s|%s|%s|%s|%s\n' \
      "${package_index}" "${package_name}" "${package_version}" \
      "${package_architecture}" "${package_filename}" "${package_hash}"
  done
} >"${MANIFEST_PATH}"
resign_profile_asset 4

stable_tag="$(profile_field omarchy_stable_release_tag)"
printf '%s\n' \
  'format=1' \
  'track=stable-mac' \
  "sequence=$(profile_field omarchy_stable_release_sequence)" \
  "version=${stable_tag#v}" \
  "source_tag=${stable_tag}" \
  "source_commit=$(profile_field omarchy_source_commit)" \
  'minimum_updater_version=1' >"${STABLE_RELEASE_PATH}"
resign_profile_asset 1

printf '%s\n' \
  'format=1' \
  'bundle=asahi-quattro' \
  "sequence=$(profile_field omarchy_bundle_release_sequence)" \
  "release_tag=$(profile_field omarchy_bundle_release_tag)" \
  "source_commit=$(profile_field omarchy_bundle_source_commit)" \
  "package_source_commit=$(profile_field omarchy_bundle_package_source_commit)" \
  "manifest_sha256=$(release_asset_data_hash 4)" \
  "upgrader_sha256=$(release_asset_data_hash 8)" \
  "bundle_updater_sha256=$(release_asset_data_hash 7)" \
  "fresh_installer_sha256=$(release_asset_data_hash 6)" \
  >"${BUNDLE_RELEASE_PATH}"
resign_profile_asset 3

chmod 0400 -- "${TEST_PROFILE}"
cp -- "${TEST_PROFILE}" "${CANDIDATE}/profile.snapshot"
chmod 0400 -- "${CANDIDATE}/profile.snapshot" "${CANDIDATE}/INCOMPLETE"
find "${CANDIDATE}/objects" -type f -exec chmod 0400 -- {} +

TEST_PROFILE_SHA256="$(sha256sum -- "${TEST_PROFILE}")"
TEST_PROFILE_SHA256="${TEST_PROFILE_SHA256%% *}"
readonly TEST_PROFILE_SHA256
OBSERVATIONS="$("${VERIFIER}" --emit-observations \
  --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --candidate "${CANDIDATE}")"
readonly OBSERVATIONS
[[ "$(printf '%s\n' "${OBSERVATIONS}" | wc -l)" -eq 22 ]] || {
  printf '%s\n' 'test verifier emitted the wrong observation count' >&2
  exit 1
}
declare -A observations=()
while IFS= read -r line; do
  observations["${line%%=*}"]="${line#*=}"
done <<<"${OBSERVATIONS}"

{
  printf '%s\n' \
    'format=a-quo-omarchy-bootstrap-candidate-v1' \
    'status=complete-candidate' \
    'authority=none' \
    'scope=signed-bootstrap-assets-01-through-07' \
    'profile_repository=https://github.com/SurreptitiousFabric/a-quo.git' \
    'profile_commit=3dcd52f3a0a4c678b0c2e015efd811164cc256bc' \
    'profile_path=packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v1.profile' \
    "observed_profile_sha256=${TEST_PROFILE_SHA256}" \
    'profile_external_authentication=required-not-established-by-this-receipt' \
    'object_count=15'
  for index in {1..15}; do
    printf -v object_key 'object_%02d' "${index}"
    if (( index == 1 )); then
      transport='raw-direct|none|0'
    else
      transport='github-release|none|0'
    fi
    printf '%s=%s|%s\n' "${object_key}" "${observations[${object_key}]}" "${transport}"
  done
  printf '%s\n' 'signature_count=7'
  for index in {1..7}; do
    printf -v signature_key 'signature_%02d' "${index}"
    printf '%s=%s\n' "${signature_key}" "${observations[${signature_key}]}"
  done
  for tool_name in curl gpg; do
    tool_path="/usr/bin/${tool_name}"
    tool_hash="$(sha256sum -- "${tool_path}")"
    tool_hash="${tool_hash%% *}"
    printf '%s_path=%s\n%s_sha256=%s\n' \
      "${tool_name}" "${tool_path}" "${tool_name}" "${tool_hash}"
  done
} >"${CANDIDATE}/receipt.v1"
chmod 0400 -- "${CANDIDATE}/receipt.v1"

pre_completion_output="$("${VERIFIER}" --pre-completion \
  --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --candidate "${CANDIDATE}")"
[[ "${pre_completion_output}" == candidate_status=verified-incomplete-non-authoritative$'\n'* ]] || {
  printf 'pre-completion output mismatch: %q\n' "${pre_completion_output}" >&2
  exit 1
}
rm -- "${CANDIDATE}/INCOMPLETE"
printf '%s\n' complete-candidate >"${CANDIDATE}/COMPLETE"
chmod 0400 -- "${CANDIDATE}/COMPLETE"

EXPECTED_OUTPUT="$(printf '%s\n' \
  'candidate_status=verified-non-authoritative' \
  'authority=none' \
  "profile_sha256=${TEST_PROFILE_SHA256}" \
  'object_count=15' \
  'signature_count=7' \
  'signed_descriptor_bindings=verified-non-authoritative' \
  'external_profile_authentication_required=true' \
  'signed_does_not_mean_safe=true' \
  'network_activity=false' \
  'vm_started=false')"
readonly EXPECTED_OUTPUT
OBSERVED_OUTPUT="$("${VERIFIER}" \
  --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --candidate "${CANDIDATE}")"
readonly OBSERVED_OUTPUT
[[ "${OBSERVED_OUTPUT}" == "${EXPECTED_OUTPUT}" ]] || {
  printf 'completed candidate output mismatch: %q\n' "${OBSERVED_OUTPUT}" >&2
  exit 1
}

prepare_semantic_mutant signed-stable-extra-field
chmod 0600 -- "${MUTATED}/objects/stable/omarchy-mx-mac-release"
printf '%s\n' unexpected=value >>"${MUTATED}/objects/stable/omarchy-mx-mac-release"
resign_semantic_mutant_asset 1
assert_semantic_refused signed-stable-extra-field \
  'stable-release does not have the exact line count'

prepare_semantic_mutant signed-stable-crlf
chmod 0600 -- "${MUTATED}/objects/stable/omarchy-mx-mac-release"
awk 'NR == 2 { printf "%s\r\n", $0; next } { print }' \
  "${MUTATED}/objects/stable/omarchy-mx-mac-release" \
  >"${MUTATED}/objects/stable/omarchy-mx-mac-release.changed"
mv -- "${MUTATED}/objects/stable/omarchy-mx-mac-release.changed" \
  "${MUTATED}/objects/stable/omarchy-mx-mac-release"
resign_semantic_mutant_asset 1
assert_semantic_refused signed-stable-crlf 'stable-release contains a control'

prepare_semantic_mutant signed-stable-missing-lf
chmod 0600 -- "${MUTATED}/objects/stable/omarchy-mx-mac-release"
head -c -1 -- "${MUTATED}/objects/stable/omarchy-mx-mac-release" \
  >"${MUTATED}/objects/stable/omarchy-mx-mac-release.changed"
mv -- "${MUTATED}/objects/stable/omarchy-mx-mac-release.changed" \
  "${MUTATED}/objects/stable/omarchy-mx-mac-release"
resign_semantic_mutant_asset 1
assert_semantic_refused signed-stable-missing-lf 'stable-release must end with one LF byte'

prepare_semantic_mutant signed-stable-oversized
chmod 0600 -- "${MUTATED}/objects/stable/omarchy-mx-mac-release"
awk 'BEGIN { for (i = 0; i < 5000; i += 1) printf "A" }' \
  >"${MUTATED}/objects/stable/omarchy-mx-mac-release"
resign_semantic_mutant_asset 1
assert_semantic_refused signed-stable-oversized \
  'stable-release is outside the closed byte bound'

prepare_semantic_mutant signed-stable-reordered
chmod 0600 -- "${MUTATED}/objects/stable/omarchy-mx-mac-release"
awk 'NR == 1 { first = $0; next } NR == 2 { print; print first; next } { print }' \
  "${MUTATED}/objects/stable/omarchy-mx-mac-release" \
  >"${MUTATED}/objects/stable/omarchy-mx-mac-release.changed"
mv -- "${MUTATED}/objects/stable/omarchy-mx-mac-release.changed" \
  "${MUTATED}/objects/stable/omarchy-mx-mac-release"
resign_semantic_mutant_asset 1
assert_semantic_refused signed-stable-reordered \
  'stable release has an unexpected format field'

prepare_semantic_mutant signed-bundle-sequence-mismatch
chmod 0600 -- "${MUTATED}/objects/bundle/asahi-quattro-release"
awk '/^sequence=/ { print "sequence=999"; next } { print }' \
  "${MUTATED}/objects/bundle/asahi-quattro-release" \
  >"${MUTATED}/objects/bundle/asahi-quattro-release.changed"
mv -- "${MUTATED}/objects/bundle/asahi-quattro-release.changed" \
  "${MUTATED}/objects/bundle/asahi-quattro-release"
resign_semantic_mutant_asset 3
assert_semantic_refused signed-bundle-sequence-mismatch \
  'bundle release sequence does not match the profile'

prepare_semantic_mutant signed-bundle-manifest-mismatch
chmod 0600 -- "${MUTATED}/objects/bundle/asahi-quattro-release"
awk '/^manifest_sha256=/ {
  print "manifest_sha256=0000000000000000000000000000000000000000000000000000000000000000"; next
} { print }' "${MUTATED}/objects/bundle/asahi-quattro-release" \
  >"${MUTATED}/objects/bundle/asahi-quattro-release.changed"
mv -- "${MUTATED}/objects/bundle/asahi-quattro-release.changed" \
  "${MUTATED}/objects/bundle/asahi-quattro-release"
resign_semantic_mutant_asset 3
assert_semantic_refused signed-bundle-manifest-mismatch \
  'bundle release manifest SHA-256 does not match the signed manifest object'

prepare_semantic_mutant signed-bundle-upgrader-mismatch
chmod 0600 -- "${MUTATED}/objects/bundle/asahi-quattro-release"
awk '/^upgrader_sha256=/ {
  print "upgrader_sha256=0000000000000000000000000000000000000000000000000000000000000000"; next
} { print }' "${MUTATED}/objects/bundle/asahi-quattro-release" \
  >"${MUTATED}/objects/bundle/asahi-quattro-release.changed"
mv -- "${MUTATED}/objects/bundle/asahi-quattro-release.changed" \
  "${MUTATED}/objects/bundle/asahi-quattro-release"
resign_semantic_mutant_asset 3
assert_semantic_refused signed-bundle-upgrader-mismatch \
  'bundle release upgrader SHA-256 does not match the profile expectation'

prepare_semantic_mutant signed-manifest-package-substitution
chmod 0600 -- "${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest"
awk '/^package=2\|/ {
  sub(/\|omarchy-settings-dev\|/, "|omarchy-settings-evil|"); print; next
} { print }' "${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest" \
  >"${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest.changed"
mv -- "${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest.changed" \
  "${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest"
resign_semantic_mutant_asset 4
rebind_semantic_mutant_bundle_manifest
assert_semantic_refused signed-manifest-package-substitution \
  'bundle manifest package 2 does not match the profile tuple'

prepare_semantic_mutant signed-manifest-package-reorder
chmod 0600 -- "${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest"
awk 'NR == 5 { first = $0; next } NR == 6 { print; print first; next } { print }' \
  "${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest" \
  >"${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest.changed"
mv -- "${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest.changed" \
  "${MUTATED}/objects/bundle/asahi-quattro-bundle.manifest"
resign_semantic_mutant_asset 4
rebind_semantic_mutant_bundle_manifest
assert_semantic_refused signed-manifest-package-reorder \
  'bundle manifest package 1 does not match the profile tuple'

wrong_digest=0000000000000000000000000000000000000000000000000000000000000000
assert_refused wrong-external-digest \
  'external profile bytes do not match the caller-supplied expected digest' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${wrong_digest}" --candidate "${CANDIDATE}"

MUTATED="$(copy_candidate mutated-object)"
chmod 0600 -- "${MUTATED}/objects/stable/omarchy-mx-mac-release"
printf 'X' | dd of="${MUTATED}/objects/stable/omarchy-mx-mac-release" \
  bs=1 count=1 conv=notrunc status=none
chmod 0400 -- "${MUTATED}/objects/stable/omarchy-mx-mac-release"
assert_refused post-completion-mutation 'object has the wrong SHA-256' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate reordered-receipt)"
chmod 0600 -- "${MUTATED}/receipt.v1"
awk 'NR == 1 { first = $0; next } NR == 2 { print; print first; next } { print }' \
  "${MUTATED}/receipt.v1" >"${MUTATED}/receipt.reordered"
mv -- "${MUTATED}/receipt.reordered" "${MUTATED}/receipt.v1"
chmod 0400 -- "${MUTATED}/receipt.v1"
assert_refused reordered-receipt 'receipt field order is invalid' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate trailing-object-field)"
chmod 0600 -- "${MUTATED}/receipt.v1"
awk '/^object_01=/ { print $0 "|"; next } { print }' \
  "${MUTATED}/receipt.v1" >"${MUTATED}/receipt.changed"
mv -- "${MUTATED}/receipt.changed" "${MUTATED}/receipt.v1"
chmod 0400 -- "${MUTATED}/receipt.v1"
assert_refused trailing-object-field 'object_01 is not in canonical field form' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate authority-escalation)"
chmod 0600 -- "${MUTATED}/receipt.v1"
awk '$0 == "authority=none" { print "authority=trusted"; next } { print }' \
  "${MUTATED}/receipt.v1" >"${MUTATED}/receipt.changed"
mv -- "${MUTATED}/receipt.changed" "${MUTATED}/receipt.v1"
chmod 0400 -- "${MUTATED}/receipt.v1"
assert_refused authority-escalation 'unexpected value for authority' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate profile-reference-change)"
chmod 0600 -- "${MUTATED}/receipt.v1"
awk '$0 ~ /^profile_commit=/ {
  print "profile_commit=0000000000000000000000000000000000000000"; next
} { print }' "${MUTATED}/receipt.v1" >"${MUTATED}/receipt.changed"
mv -- "${MUTATED}/receipt.changed" "${MUTATED}/receipt.v1"
chmod 0400 -- "${MUTATED}/receipt.v1"
assert_refused profile-reference-change 'unexpected value for profile_commit' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate expected-field)"
chmod 0600 -- "${MUTATED}/receipt.v1"
printf '%s\n' 'expected_safe=true' >>"${MUTATED}/receipt.v1"
chmod 0400 -- "${MUTATED}/receipt.v1"
assert_refused expected-field 'receipt does not have the exact field count' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate receipt-nul)"
chmod 0600 -- "${MUTATED}/receipt.v1"
printf '\0' >>"${MUTATED}/receipt.v1"
chmod 0400 -- "${MUTATED}/receipt.v1"
assert_refused receipt-nul 'receipt contains a control' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate receipt-crlf)"
chmod 0600 -- "${MUTATED}/receipt.v1"
awk 'NR == 1 { printf "%s\r\n", $0; next } { print }' \
  "${MUTATED}/receipt.v1" >"${MUTATED}/receipt.changed"
mv -- "${MUTATED}/receipt.changed" "${MUTATED}/receipt.v1"
chmod 0400 -- "${MUTATED}/receipt.v1"
assert_refused receipt-crlf 'receipt contains a control' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate missing-final-lf)"
chmod 0600 -- "${MUTATED}/receipt.v1"
head -c -1 -- "${MUTATED}/receipt.v1" >"${MUTATED}/receipt.changed"
mv -- "${MUTATED}/receipt.changed" "${MUTATED}/receipt.v1"
chmod 0400 -- "${MUTATED}/receipt.v1"
assert_refused missing-final-lf 'receipt must end with one LF byte' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate missing-object)"
rm -- "${MUTATED}/objects/bundle/asahi-quattro-release"
assert_refused missing-object 'candidate is missing one or more required entries' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate symlink-object)"
cp -- "${MUTATED}/objects/bundle/asahi-quattro-release" \
  "${TEMPORARY_ROOT}/identical-object"
rm -- "${MUTATED}/objects/bundle/asahi-quattro-release"
ln -s -- "${TEMPORARY_ROOT}/identical-object" \
  "${MUTATED}/objects/bundle/asahi-quattro-release"
assert_refused symlink-object 'candidate file has the wrong type' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate unexpected-entry)"
printf '%s\n' hostile >"${MUTATED}/objects/unexpected"
chmod 0400 -- "${MUTATED}/objects/unexpected"
assert_refused unexpected-entry 'candidate contains an unexpected entry' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

MUTATED="$(copy_candidate both-markers)"
printf '%s\n' incomplete-candidate >"${MUTATED}/INCOMPLETE"
chmod 0400 -- "${MUTATED}/INCOMPLETE"
assert_refused both-markers 'candidate contains an unexpected entry' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" --candidate "${MUTATED}"

printf '%s\n' 'offline Omarchy bootstrap acquisition contract passed'
