#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly ACQUIRER="${SCRIPT_DIRECTORY}/acquire-omarchy-ubuntu-apt-candidate.sh"
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-ubuntu-apt-candidate.sh"
readonly PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly OCI_LOCK="${REPOSITORY_ROOT}/packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock"
readonly BUILDER_LOCK="${REPOSITORY_ROOT}/packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-builder-context-v1.lock"
readonly PROFILE_SHA256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6
readonly OCI_LOCK_SHA256=667545062b9c34b990f1d6441b749a11f01f13bdf3f4aeb87ad9f0fb4a03c878
readonly BUILDER_LOCK_SHA256=4865e1c9bf4159541afff7d138dee41edc215d988862a0b2d30ed81b09b53f8d

for required_file in "${ACQUIRER}" "${VERIFIER}" "${PROFILE}" "${OCI_LOCK}" "${BUILDER_LOCK}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] || {
    printf 'Ubuntu APT contract input is missing or a symlink: %s\n' "${required_file}" >&2
    exit 1
  }
done
[[ -x "${ACQUIRER}" && -x "${VERIFIER}" ]] || {
  printf '%s\n' 'Ubuntu APT candidate scripts must be executable' >&2
  exit 1
}

for required_tool in \
  awk chmod cp find grep id ln mkdir mkfifo mktemp mv sed sha256sum sort stat timeout; do
  command -v "${required_tool}" >/dev/null || {
    printf 'Ubuntu APT contract tool is unavailable: %s\n' "${required_tool}" >&2
    exit 1
  }
done

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-ubuntu-apt-contract.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  if [[ "${TEMPORARY_ROOT}" == "${TMPDIR:-/tmp}/a-quo-ubuntu-apt-contract."* && \
    -d "${TEMPORARY_ROOT}" ]]; then
    find "${TEMPORARY_ROOT}" -depth -delete
  fi
}
trap cleanup EXIT

fail_contract() {
  printf 'Ubuntu APT contract failed: %s\n' "$1" >&2
  exit 1
}

file_sha256() {
  local digest
  digest="$(sha256sum -- "$1")"
  printf '%s\n' "${digest%% *}"
}

assert_refused() {
  local label="$1"
  local expected="$2"
  shift 2
  local output
  local status
  set +e
  output="$(timeout 10 "$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != *"${expected}"* ]]; then
    printf 'Ubuntu APT refusal mismatch: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

assert_usage_refused() {
  local label="$1"
  shift
  local output
  local status
  set +e
  output="$(timeout 10 "$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 2 || "${output}" != usage:* ]]; then
    printf 'Ubuntu APT usage mismatch: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

readonly -a VERIFIER_ARGS=(
  --profile "${PROFILE}"
  --externally-expected-profile-sha256 "${PROFILE_SHA256}"
  --oci-lock "${OCI_LOCK}"
  --externally-expected-oci-lock-sha256 "${OCI_LOCK_SHA256}"
  --builder-lock "${BUILDER_LOCK}"
  --externally-expected-builder-lock-sha256 "${BUILDER_LOCK_SHA256}"
)

write_private() {
  local path="$1"
  shift
  printf '%s\n' "$@" >"${path}"
  chmod 0400 -- "${path}"
}

build_sources_state() {
  local candidate="$1"
  local source_list="${TEMPORARY_ROOT}/fixture-sources.list"
  local original_sources="${TEMPORARY_ROOT}/fixture-original.sources"
  local effective_sources="${TEMPORARY_ROOT}/fixture-effective.sources"
  printf '%s\n' '# synthetic unchanged sources.list' >"${source_list}"
  printf '%s\n' \
    'Types: deb' \
    'URIs: http://ports.ubuntu.com/ubuntu-ports/' \
    'Suites: noble noble-updates noble-backports' \
    'Components: main universe restricted multiverse' \
    'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
    '' \
    'Types: deb' \
    'URIs: http://ports.ubuntu.com/ubuntu-ports/' \
    'Suites: noble-security' \
    'Components: main universe restricted multiverse' \
    'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
    >"${original_sources}"
  printf '%s\n' \
    'Types: deb' \
    'URIs: https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/' \
    'Suites: noble noble-updates noble-backports' \
    'Components: main universe restricted multiverse' \
    'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
    '' \
    'Types: deb' \
    'URIs: https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/' \
    'Suites: noble-security' \
    'Components: main universe restricted multiverse' \
    'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
    >"${effective_sources}"
  {
    local source_set
    local source_path
    local source_fixture
    for source_set in original-locked-oci effective-timestamped-main-archive; do
      for source_path in \
        /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do
        if [[ "${source_path}" == /etc/apt/sources.list ]]; then
          source_fixture="${source_list}"
        elif [[ "${source_set}" == original-locked-oci ]]; then
          source_fixture="${original_sources}"
        else
          source_fixture="${effective_sources}"
        fi
        if [[ "${source_path}" == /etc/apt/sources.list ]]; then
          printf 'source_set=%s\n' "${source_set}"
        fi
        printf 'path=%s\nsize=%s\nsha256=%s\ncontent-begin\n' \
          "${source_path}" "$(stat -c '%s' -- "${source_fixture}")" \
          "$(file_sha256 "${source_fixture}")"
        while IFS= read -r source_line; do
          printf '%s\n' "${source_line}"
        done <"${source_fixture}"
        printf '%s\n' content-end
      done
    done
  } >"${candidate}/state/sources.txt"
  chmod 0400 -- "${candidate}/state/sources.txt"
}

build_manifest() {
  local candidate="$1"
  local manifest="${candidate}/objects.manifest"
  chmod 0600 -- "${manifest}" 2>/dev/null || true
  {
    printf '%s\n' format=a-quo-omarchy-ubuntu-apt-object-manifest-v1
    local record
    for record in \
      'apt-version|state/apt-version.txt' \
      'snapshot-id|state/snapshot-id.txt' \
      'sources|state/sources.txt' \
      'apt-configuration|state/apt-configuration.txt' \
      'base-package-state|state/base-packages.txt' \
      'requested-packages|state/requested-packages.txt' \
      'index-targets|state/index-targets.txt' \
      'solver-plan|state/solver-plan.txt' \
      'final-package-state|state/final-packages.txt' \
      'transport-ca-bundle|transport/ca-certificates.crt' \
      'index|indexes/index-0001.bin' \
      'package|packages/curl_8.5.0-2ubuntu10_arm64.deb'; do
      local role="${record%%|*}"
      local relative_path="${record#*|}"
      printf '%s|%s|%s|%s\n' \
        "${role}" "${relative_path}" \
        "$(stat -c '%s' -- "${candidate}/${relative_path}")" \
        "$(file_sha256 "${candidate}/${relative_path}")"
    done
  } >"${manifest}"
  chmod 0400 -- "${manifest}"
}

build_receipt() {
  local candidate="$1"
  write_private "${candidate}/receipt.apt.v1" \
    'format=a-quo-omarchy-ubuntu-apt-candidate-v1' \
    'status=complete-candidate' \
    'authority=none' \
    'profile_id=a-quo-omarchy4-aarch64-dec29fa-v2' \
    "profile_sha256=${PROFILE_SHA256}" \
    "ubuntu_oci_lock_sha256=${OCI_LOCK_SHA256}" \
    "builder_context_lock_sha256=${BUILDER_LOCK_SHA256}" \
    'snapshot_id=20260831T000000Z' \
    'snapshot_selection_authority=caller-supplied-none' \
    'original_archive=http://ports.ubuntu.com/ubuntu-ports/' \
    'effective_snapshot_archive=https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/' \
    'archive_equivalence_to_original_ports=not-established' \
    'apt_version=2.8.3' \
    'apt_sandbox_user=root-in-private-single-uid-user-namespace' \
    "transport_ca_bundle_sha256=$(file_sha256 "${candidate}/transport/ca-certificates.crt")" \
    'transport_ca_bundle_source=caller-host-not-authenticated' \
    'ubuntu_archive_signature_verification=performed-by-apt-not-independently-replayed' \
    'top_level_request_count=14' \
    'object_count=12' \
    'index_count=1' \
    'package_count=1' \
    "object_manifest_sha256=$(file_sha256 "${candidate}/objects.manifest")" \
    'captured_byte_identity=verified-non-authoritative' \
    'apt_solver_execution=reported-by-acquirer-not-replayed' \
    'apt_solver_reexecution=false' \
    'transitive_closure_independently_recomputed=false' \
    'package_installation=false' \
    'dpkg_transaction=false' \
    'maintainer_scripts_executed=false' \
    'publisher_authentication=not-established' \
    'trusted_time=not-established' \
    'freshness=not-established' \
    'safety=not-established' \
    'build_authorization=not-established' \
    'final_builder_image=not-established' \
    'acquisition_network_activity=true' \
    'network_destination_allowlist=not-established' \
    'vm_started=false'
}

make_candidate() {
  local candidate="$1"
  mkdir -m 0700 -- "${candidate}"
  mkdir -m 0700 -- \
    "${candidate}/prerequisites" "${candidate}/indexes" \
    "${candidate}/packages" "${candidate}/state" "${candidate}/transport"
  cp -- "${PROFILE}" "${candidate}/prerequisites/profile.snapshot"
  cp -- "${OCI_LOCK}" "${candidate}/prerequisites/ubuntu-oci.lock.snapshot"
  cp -- "${BUILDER_LOCK}" "${candidate}/prerequisites/builder-context.lock.snapshot"
  chmod 0400 -- "${candidate}/prerequisites/"*
  write_private "${candidate}/state/apt-version.txt" 'apt_version=2.8.3'
  write_private "${candidate}/state/snapshot-id.txt" 'snapshot_id=20260831T000000Z'
  build_sources_state "${candidate}"
  write_private "${candidate}/state/apt-configuration.txt" \
    'APT::Architecture "arm64";' \
    'APT::Architectures:: "arm64";' \
    'APT::Sandbox::User "_apt";' \
    'Acquire::AllowInsecureRepositories "0";' \
    'Acquire::AllowWeakRepositories "0";' \
    'Acquire::AllowDowngradeToInsecureRepositories "0";' \
    'Dir::State::lists "lists/";' \
    'Dir::Cache::archives "archives/";' \
    'Dir::Etc "etc/apt";'
  write_private "${candidate}/state/base-packages.txt" \
    'base-files|13ubuntu10|arm64' \
    'libc6|2.39-0ubuntu8|arm64'
  write_private "${candidate}/state/requested-packages.txt" \
    ca-certificates curl dosfstools e2fsprogs fdisk gnupg libarchive-tools \
    openssh-client parted qemu-efi-aarch64 qemu-system-arm qemu-utils socat udev
  write_private "${candidate}/state/index-targets.txt" \
    'Packages|https://snapshot.ubuntu.com/ubuntu/20260831T000000Z noble/main arm64 Packages|https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/dists/noble/main/binary-arm64/Packages|/var/lib/apt/lists/snapshot.ubuntu.com_ubuntu_20260831T000000Z_dists_noble_main_binary-arm64_Packages.lz4' \
    'Packages|https://snapshot.ubuntu.com/ubuntu/20260831T000000Z noble-updates/main arm64 Packages|https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/dists/noble-updates/main/binary-arm64/Packages|/var/lib/apt/lists/snapshot.ubuntu.com_ubuntu_20260831T000000Z_dists_noble-updates_main_binary-arm64_Packages.lz4' \
    'Packages|https://snapshot.ubuntu.com/ubuntu/20260831T000000Z noble-security/main arm64 Packages|https://snapshot.ubuntu.com/ubuntu/20260831T000000Z/dists/noble-security/main/binary-arm64/Packages|/var/lib/apt/lists/snapshot.ubuntu.com_ubuntu_20260831T000000Z_dists_noble-security_main_binary-arm64_Packages.lz4'
  write_private "${candidate}/state/solver-plan.txt" \
    'Inst curl (8.5.0-2ubuntu10 Ubuntu:24.04/noble [arm64])'
  write_private "${candidate}/state/final-packages.txt" \
    'base-files|13ubuntu10|arm64' \
    'curl|8.5.0-2ubuntu10|arm64' \
    'libc6|2.39-0ubuntu8|arm64'
  write_private "${candidate}/indexes/index-0001.bin" 'synthetic signed-index candidate bytes'
  write_private "${candidate}/packages/curl_8.5.0-2ubuntu10_arm64.deb" \
    'synthetic deb candidate bytes; never executed'
  write_private "${candidate}/transport/ca-certificates.crt" \
    '-----BEGIN CERTIFICATE-----' \
    'c3ludGhldGljIGNhbmRpZGF0ZSBvbmx5' \
    '-----END CERTIFICATE-----'
  build_manifest "${candidate}"
  build_receipt "${candidate}"
  write_private "${candidate}/COMPLETE" complete-candidate
}

replace_line() {
  local path="$1"
  local pattern="$2"
  local replacement="$3"
  chmod 0600 -- "${path}"
  sed -i -- "\\|${pattern}|c\\${replacement}" "${path}"
  chmod 0400 -- "${path}"
}

refresh_object_record() {
  local candidate="$1"
  local relative_path="$2"
  local manifest="${candidate}/objects.manifest"
  local temporary="${candidate}/.manifest-refresh"
  chmod 0600 -- "${manifest}"
  awk -F'|' -v path="${relative_path}" \
    -v size="$(stat -c '%s' -- "${candidate}/${relative_path}")" \
    -v digest="$(file_sha256 "${candidate}/${relative_path}")" '
      $2 == path { print $1 "|" $2 "|" size "|" digest; found += 1; next }
      { print }
      END { if (found != 1) exit 73 }
    ' "${manifest}" >"${temporary}"
  mv -- "${temporary}" "${manifest}"
  chmod 0400 -- "${manifest}"
  replace_line "${candidate}/receipt.apt.v1" '^object_manifest_sha256=' \
    "object_manifest_sha256=$(file_sha256 "${manifest}")"
}

refresh_source_record_digest() {
  local candidate="$1"
  local wanted_record="$2"
  local sources_path="${candidate}/state/sources.txt"
  local content_digest
  local temporary="${candidate}/state/.sources-refresh"
  content_digest="$(awk -v wanted_record="${wanted_record}" '
    $0 == "content-begin" { record += 1; next }
    $0 == "content-end" { if (record == wanted_record) exit; next }
    record == wanted_record { print }
  ' "${sources_path}" | sha256sum)"
  content_digest="${content_digest%% *}"
  chmod 0600 -- "${sources_path}"
  awk -v wanted_record="${wanted_record}" -v digest="${content_digest}" '
    /^path=/ { record += 1 }
    record == wanted_record && /^sha256=/ { print "sha256=" digest; next }
    { print }
  ' "${sources_path}" >"${temporary}"
  mv -- "${temporary}" "${sources_path}"
  chmod 0400 -- "${sources_path}"
}

BASE_CANDIDATE="${TEMPORARY_ROOT}/candidate-base"
readonly BASE_CANDIDATE
make_candidate "${BASE_CANDIDATE}"

baseline_output="$("${VERIFIER}" "${VERIFIER_ARGS[@]}" \
  --candidate "${BASE_CANDIDATE}")" || fail_contract 'exact synthetic candidate was refused'
for expected_line in \
  'candidate_status=verified-non-authoritative' \
  'authority=none' \
  'snapshot_id=20260831T000000Z' \
  'object_count=12' \
  'index_count=1' \
  'package_count=1' \
  'solver_install_record_count=1' \
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
  'vm_started=false'; do
  [[ "${baseline_output}" == *"${expected_line}"* ]] ||
    fail_contract "baseline output omitted ${expected_line}"
done
grep -Fq \
  '^[A-Za-z0-9][A-Za-z0-9._+/%:~-]{0,255}$' "${VERIFIER}" ||
  fail_contract 'general candidate path grammar lost Debian tilde support'

INCOMPLETE_CANDIDATE="${TEMPORARY_ROOT}/candidate-incomplete"
cp -a -- "${BASE_CANDIDATE}" "${INCOMPLETE_CANDIDATE}"
find "${INCOMPLETE_CANDIDATE}/COMPLETE" -delete
find "${INCOMPLETE_CANDIDATE}/receipt.apt.v1" -delete
write_private "${INCOMPLETE_CANDIDATE}/INCOMPLETE" incomplete-candidate
incomplete_output="$("${VERIFIER}" --emit-observations "${VERIFIER_ARGS[@]}" \
  --candidate "${INCOMPLETE_CANDIDATE}")" ||
  fail_contract 'exact incomplete candidate observation was refused'
[[ "${incomplete_output}" == *'candidate_status=verified-incomplete-non-authoritative'* ]] ||
  fail_contract 'incomplete candidate emitted the wrong status'

assert_usage_refused missing-acknowledgement "${ACQUIRER}" \
  --profile "${PROFILE}" \
  --oci-lock "${OCI_LOCK}" \
  --builder-lock "${BUILDER_LOCK}" \
  --base-oci-candidate "${TEMPORARY_ROOT}/not-opened" \
  --snapshot 20260831T000000Z \
  --output "${TEMPORARY_ROOT}/not-created"
[[ ! -e "${TEMPORARY_ROOT}/not-created" ]] ||
  fail_contract 'missing acknowledgement reached output creation'

assert_refused wrong-profile-pin 'caller-supplied expected digest' \
  "${VERIFIER}" --profile "${PROFILE}" \
  --externally-expected-profile-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --oci-lock "${OCI_LOCK}" \
  --externally-expected-oci-lock-sha256 "${OCI_LOCK_SHA256}" \
  --builder-lock "${BUILDER_LOCK}" \
  --externally-expected-builder-lock-sha256 "${BUILDER_LOCK_SHA256}" \
  --candidate "${BASE_CANDIDATE}"

mutant_number=0
new_mutant() {
  ((mutant_number += 1))
  MUTANT="${TEMPORARY_ROOT}/mutant-${mutant_number}"
  cp -a -- "${BASE_CANDIDATE}" "${MUTANT}"
}

new_mutant
chmod 0600 -- "${MUTANT}/packages/curl_8.5.0-2ubuntu10_arm64.deb"
printf '%s\n' tampered >>"${MUTANT}/packages/curl_8.5.0-2ubuntu10_arm64.deb"
chmod 0400 -- "${MUTANT}/packages/curl_8.5.0-2ubuntu10_arm64.deb"
assert_refused package-substitution 'does not match its manifest record' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/requested-packages.txt"
sed -i 's/^curl$/wget/' "${MUTANT}/state/requested-packages.txt"
chmod 0400 -- "${MUTANT}/state/requested-packages.txt"
refresh_object_record "${MUTANT}" state/requested-packages.txt
assert_refused request-substitution 'requests differ from the frozen profile' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/snapshot-id.txt"
printf '%s\n' snapshot_id=20260230T000000Z >"${MUTANT}/state/snapshot-id.txt"
chmod 0400 -- "${MUTANT}/state/snapshot-id.txt"
refresh_object_record "${MUTANT}" state/snapshot-id.txt
assert_refused malformed-snapshot 'not one real UTC calendar timestamp' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/apt-version.txt"
printf '%s\n' apt_version=2.9.0 >"${MUTANT}/state/apt-version.txt"
chmod 0400 -- "${MUTANT}/state/apt-version.txt"
refresh_object_record "${MUTANT}" state/apt-version.txt
assert_refused apt-version 'not the locked base version' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/sources.txt"
sed -i 's|http://ports.ubuntu.com/ubuntu-ports/|http://ports.ubunxu.com/ubuntu-ports/|g' \
  "${MUTANT}/state/sources.txt"
chmod 0400 -- "${MUTANT}/state/sources.txt"
refresh_source_record_digest "${MUTANT}" 2
refresh_object_record "${MUTANT}" state/sources.txt
assert_refused source-substitution \
  'original APT source is not the exact ports archive stanza shape' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/index-targets.txt"
sed -i 's|/dists/noble/main/|/dists/noble/other/|' \
  "${MUTANT}/state/index-targets.txt"
chmod 0400 -- "${MUTANT}/state/index-targets.txt"
refresh_object_record "${MUTANT}" state/index-targets.txt
assert_refused index-target-substitution \
  'captured APT index target is duplicated or not snapshot-bound' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/apt-configuration.txt"
printf '%s\n' 'Acquire::https::Proxy "http://proxy.invalid/";' \
  >>"${MUTANT}/state/apt-configuration.txt"
chmod 0400 -- "${MUTANT}/state/apt-configuration.txt"
refresh_object_record "${MUTANT}" state/apt-configuration.txt
assert_refused apt-proxy 'captured APT configuration contains a proxy route' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/base-packages.txt"
printf '%s\n' \
  'libc6|2.39-0ubuntu8|arm64' \
  'base-files|13ubuntu10|arm64' >"${MUTANT}/state/base-packages.txt"
chmod 0400 -- "${MUTANT}/state/base-packages.txt"
refresh_object_record "${MUTANT}" state/base-packages.txt
assert_refused unsorted-base 'unsorted record' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/solver-plan.txt"
printf '%s\n' \
  'Inst curl (8.5.0-2ubuntu10 Ubuntu:24.04/noble [arm64])' \
  'Inst libc6 (2.39-0ubuntu8 Ubuntu:24.04/noble [arm64])' \
  >"${MUTANT}/state/solver-plan.txt"
chmod 0400 -- "${MUTANT}/state/solver-plan.txt"
refresh_object_record "${MUTANT}" state/solver-plan.txt
assert_refused solver-package-count \
  'solver install record count differs from retained package count' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/state/solver-plan.txt"
printf '%s\n' \
  'Inst curl (8.5.0-2ubuntu10 Ubuntu:24.04/noble [arm64])' \
  'Remv libc6 [2.39-0ubuntu8]' \
  >"${MUTANT}/state/solver-plan.txt"
chmod 0400 -- "${MUTANT}/state/solver-plan.txt"
refresh_object_record "${MUTANT}" state/solver-plan.txt
assert_refused solver-removal 'solver plan contains a removal or purge record' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
write_private "${MUTANT}/unexpected" unexpected
assert_refused extra-path 'unexpected path count' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
ln "${MUTANT}/packages/curl_8.5.0-2ubuntu10_arm64.deb" \
  "${MUTANT}/packages/second-link.deb"
assert_refused hardlink 'candidate object has unsafe identity' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
mv "${MUTANT}/prerequisites/profile.snapshot" \
  "${MUTANT}/prerequisites/profile.real"
ln -s profile.real "${MUTANT}/prerequisites/profile.snapshot"
assert_refused symlink 'prerequisite snapshot has unsafe identity' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/indexes/index-0001.bin"
assert_refused unsafe-mode 'candidate object has unsafe identity' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/objects.manifest"
printf '%s\n' \
  'index|indexes/index-0001.bin|38|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  >>"${MUTANT}/objects.manifest"
chmod 0400 -- "${MUTANT}/objects.manifest"
assert_refused duplicate-manifest-path 'repeats a path' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
replace_line "${MUTANT}/receipt.apt.v1" '^authority=' 'authority=trusted'
assert_refused false-authority 'receipt field order or value is invalid' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
replace_line "${MUTANT}/receipt.apt.v1" '^safety=' 'safety=established'
assert_refused false-safety 'receipt field order or value is invalid' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
replace_line "${MUTANT}/receipt.apt.v1" '^package_installation=' \
  'package_installation=true'
assert_refused false-installation 'receipt field order or value is invalid' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
chmod 0600 -- "${MUTANT}/prerequisites/builder-context.lock.snapshot"
cp -- "${OCI_LOCK}" "${MUTANT}/prerequisites/builder-context.lock.snapshot"
chmod 0400 -- "${MUTANT}/prerequisites/builder-context.lock.snapshot"
assert_refused cross-lock-substitution 'snapshot digest differs' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

new_mutant
mkfifo "${MUTANT}/indexes/unexpected-fifo"
assert_refused fifo 'unexpected path count' \
  "${VERIFIER}" "${VERIFIER_ARGS[@]}" --candidate "${MUTANT}"

if grep -Eq \
  '(/usr/bin/(apt|apt-get|dpkg|dpkg-deb|bwrap|curl|wget)|[[:space:]](sudo|pacman|systemctl|omarchy)[[:space:]])' \
  "${VERIFIER}"; then
  fail_contract 'offline verifier contains a package, network, sandbox, or service command'
fi
# These are literal source-code boundaries, not shell expansions.
# shellcheck disable=SC2016
for required_source in \
  '--acknowledge-networked-candidate-only' \
  'extract_exact_layer' \
  '--ro-bind "${layer_path}" /input/layer.tar.gz' \
  'initial APT list directory is not empty' \
  'initial APT archive cache shape is not exact' \
  '--unshare-all --share-net --unshare-user' \
  '--disable-userns --cap-drop ALL' \
  '--simulate' \
  '--download-only' \
  'APT::Sandbox::User=root' \
  '--no-install-recommends --no-remove install' \
  "$(printf '%q' 'dpkg status changed despite the download-only boundary')" \
  "$(printf '%q' 'package_installation=false')" \
  "$(printf '%q' 'network_destination_allowlist=not-established')"; do
  plain_required="${required_source//\\ / }"
  grep -Fq -- "${plain_required}" "${ACQUIRER}" ||
    fail_contract "acquirer omitted required boundary: ${plain_required}"
done
extractor_block="$(sed -n '/^extract_exact_layer()/,/^}/p' "${ACQUIRER}")"
[[ "${extractor_block}" == *'--unshare-all --unshare-user'* && \
  "${extractor_block}" != *'--share-net'* ]] ||
  fail_contract 'exact layer extraction is not one networkless private namespace'
if grep -Eq '(/usr/bin/(sudo|pacman|systemctl)|dpkg[[:space:]]+(-i|--install))' "${ACQUIRER}"; then
  fail_contract 'acquirer gained a host-admin or dpkg-install path'
fi

printf '%s\n' \
  'Omarchy Ubuntu APT candidate contract passed offline' \
  'candidate_authority=none' \
  'network_activity=false' \
  'package_installation=false' \
  'vm_started=false'
