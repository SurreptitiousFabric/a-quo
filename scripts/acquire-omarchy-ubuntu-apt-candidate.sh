#!/usr/bin/env bash

set +x
set -euo pipefail
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin
umask 077
ulimit -c 0

fail() {
  printf 'Omarchy Ubuntu APT acquisition refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s --profile CANONICAL_V2 --oci-lock CANONICAL_OCI_LOCK --builder-lock CANONICAL_BUILDER_LOCK --base-oci-candidate COMPLETE_OCI_CANDIDATE --snapshot YYYYMMDDTHHMMSSZ --output NEW_RUN_DIRECTORY --acknowledge-networked-candidate-only\n' \
    "${0##*/}" >&2
  exit 2
}

profile_path=''
oci_lock_path=''
builder_lock_path=''
base_oci_candidate=''
snapshot_id=''
output_directory=''
acknowledged=false
while (( $# > 0 )); do
  case "$1" in
    --profile)
      [[ -z "${profile_path}" && $# -ge 2 ]] || usage
      profile_path="$2"
      shift 2
      ;;
    --oci-lock)
      [[ -z "${oci_lock_path}" && $# -ge 2 ]] || usage
      oci_lock_path="$2"
      shift 2
      ;;
    --builder-lock)
      [[ -z "${builder_lock_path}" && $# -ge 2 ]] || usage
      builder_lock_path="$2"
      shift 2
      ;;
    --base-oci-candidate)
      [[ -z "${base_oci_candidate}" && $# -ge 2 ]] || usage
      base_oci_candidate="$2"
      shift 2
      ;;
    --snapshot)
      [[ -z "${snapshot_id}" && $# -ge 2 ]] || usage
      snapshot_id="$2"
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
readonly profile_path oci_lock_path builder_lock_path base_oci_candidate
readonly snapshot_id output_directory acknowledged
[[ -n "${profile_path}" && -n "${oci_lock_path}" && \
  -n "${builder_lock_path}" && -n "${base_oci_candidate}" && \
  -n "${snapshot_id}" && -n "${output_directory}" && \
  "${acknowledged}" == true ]] || usage
(( EUID != 0 )) || fail 'networked candidate acquisition must not run as root'
[[ "${snapshot_id}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] ||
  fail 'snapshot must use the exact YYYYMMDDTHHMMSSZ grammar'
snapshot_date="${snapshot_id%%T*}"
(( 10#${snapshot_date} >= 20230301 )) ||
  fail 'snapshot predates the documented Ubuntu Snapshot Service boundary'

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly CANONICAL_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly CANONICAL_OCI_LOCK="${REPOSITORY_ROOT}/packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-ubuntu-oci-v1.lock"
readonly CANONICAL_BUILDER_LOCK="${REPOSITORY_ROOT}/packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-builder-context-v1.lock"
readonly PROFILE_SHA256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6
readonly OCI_LOCK_SHA256=667545062b9c34b990f1d6441b749a11f01f13bdf3f4aeb87ad9f0fb4a03c878
readonly BUILDER_LOCK_SHA256=4865e1c9bf4159541afff7d138dee41edc215d988862a0b2d30ed81b09b53f8d
readonly PROFILE_REPOSITORY=https://github.com/SurreptitiousFabric/a-quo.git
readonly PROFILE_COMMIT=e13e74dca3472e54501b35c9b57ee89f57c6aed3
readonly PROFILE_REPOSITORY_PATH=packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile
readonly OBSERVATION_ROOT="${REPOSITORY_ROOT}/target/omarchy-evaluation-input-observations"
readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-evaluation-target-profile.sh"
readonly OCI_CANDIDATE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-ubuntu-oci-candidate.sh"
readonly APT_CANDIDATE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-ubuntu-apt-candidate.sh"
readonly TOP_LEVEL_REQUESTS='ca-certificates,curl,dosfstools,e2fsprogs,fdisk,gnupg,libarchive-tools,openssh-client,parted,qemu-efi-aarch64,qemu-system-arm,qemu-utils,socat,udev'
readonly HOST_CA_BUNDLE=/etc/ca-certificates/extracted/tls-ca-bundle.pem

[[ "${profile_path}" == "${CANONICAL_PROFILE}" && \
  "${oci_lock_path}" == "${CANONICAL_OCI_LOCK}" && \
  "${builder_lock_path}" == "${CANONICAL_BUILDER_LOCK}" ]] ||
  fail 'profile and prerequisite locks must be the canonical committed paths'
for required_file in \
  "${profile_path}" "${oci_lock_path}" "${builder_lock_path}" \
  "${PROFILE_VERIFIER}" "${OCI_CANDIDATE_VERIFIER}" "${APT_CANDIDATE_VERIFIER}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] ||
    fail "required repository input is missing or a symlink: ${required_file}"
done
for verifier in \
  "${PROFILE_VERIFIER}" "${OCI_CANDIDATE_VERIFIER}" "${APT_CANDIDATE_VERIFIER}"; do
  [[ -x "${verifier}" ]] || fail "required verifier is not executable: ${verifier}"
done

readonly AWK=/usr/bin/awk
readonly BSDTAR=/usr/bin/bsdtar
readonly BWRAP=/usr/bin/bwrap
readonly CHMOD=/usr/bin/chmod
readonly CMP=/usr/bin/cmp
readonly DATE=/usr/bin/date
readonly DD=/usr/bin/dd
readonly FIND=/usr/bin/find
readonly HEAD=/usr/bin/head
readonly INSTALL=/usr/bin/install
readonly MKDIR=/usr/bin/mkdir
readonly MKTEMP=/usr/bin/mktemp
readonly MV=/usr/bin/mv
readonly OD=/usr/bin/od
readonly SHA256SUM=/usr/bin/sha256sum
readonly SORT=/usr/bin/sort
readonly STAT=/usr/bin/stat
readonly SYNC=/usr/bin/sync
readonly TAIL=/usr/bin/tail
readonly TIMEOUT=/usr/bin/timeout
readonly TR=/usr/bin/tr
readonly WC=/usr/bin/wc
for required_tool in \
  "${AWK}" "${BSDTAR}" "${BWRAP}" "${CHMOD}" "${CMP}" "${DATE}" \
  "${DD}" "${FIND}" \
  "${HEAD}" "${INSTALL}" "${MKDIR}" "${MKTEMP}" "${MV}" \
  "${OD}" "${SHA256SUM}" "${SORT}" "${STAT}" "${SYNC}" \
  "${TAIL}" "${TIMEOUT}" "${TR}" "${WC}"; do
  [[ -x "${required_tool}" && -f "${required_tool}" ]] ||
    fail "required acquisition tool is unavailable or not a regular file: ${required_tool}"
done
[[ "$(${BWRAP} --version)" =~ ^bubblewrap\ ([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] ||
  fail 'Bubblewrap did not report one parseable version'
(( BASH_REMATCH[1] > 0 || BASH_REMATCH[2] >= 12 )) ||
  fail 'Bubblewrap 0.12.0 or newer is required'
snapshot_canonical="$(${DATE} -u -d \
  "${snapshot_id:0:4}-${snapshot_id:4:2}-${snapshot_id:6:2} ${snapshot_id:9:2}:${snapshot_id:11:2}:${snapshot_id:13:2} UTC" \
  '+%Y%m%dT%H%M%SZ' 2>/dev/null)" ||
  fail 'snapshot is not one real UTC calendar timestamp'
[[ "${snapshot_canonical}" == "${snapshot_id}" ]] ||
  fail 'snapshot is not one canonical UTC calendar timestamp'

file_digest() {
  local digest
  digest="$(${SHA256SUM} -- "$1")"
  printf '%s\n' "${digest%% *}"
}

[[ "$(file_digest "${profile_path}")" == "${PROFILE_SHA256}" && \
  "$(file_digest "${oci_lock_path}")" == "${OCI_LOCK_SHA256}" && \
  "$(file_digest "${builder_lock_path}")" == "${BUILDER_LOCK_SHA256}" ]] ||
  fail 'one canonical prerequisite differs from its externally pinned digest'
"${PROFILE_VERIFIER}" "${profile_path}" >/dev/null ||
  fail 'canonical profile failed its offline verifier'

[[ -d "${base_oci_candidate}" && ! -L "${base_oci_candidate}" && \
  "${base_oci_candidate}" == "${OBSERVATION_ROOT}/"* && \
  "${base_oci_candidate%/*}" == "${OBSERVATION_ROOT}" ]] ||
  fail 'base OCI candidate must be one direct retained observation child'
"${OCI_CANDIDATE_VERIFIER}" \
  --profile "${profile_path}" \
  --externally-expected-profile-sha256 "${PROFILE_SHA256}" \
  --externally-expected-profile-repository "${PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${PROFILE_COMMIT}" \
  --externally-expected-profile-path "${PROFILE_REPOSITORY_PATH}" \
  --candidate "${base_oci_candidate}" >/dev/null ||
  fail 'base OCI candidate failed exact offline verification'

[[ "${output_directory}" == /* && "${output_directory}" != */ ]] ||
  fail 'output must be one absolute path without a trailing slash'
output_name="${output_directory##*/}"
[[ "${output_name}" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ && \
  "${output_name}" != . && "${output_name}" != .. && \
  "${output_directory}" == "${OBSERVATION_ROOT}/${output_name}" ]] ||
  fail 'output must be one safely named direct observation child'
[[ "${output_directory}" != "${base_oci_candidate}" ]] ||
  fail 'APT output must differ from the retained OCI candidate'
[[ -d "${OBSERVATION_ROOT}" && ! -L "${OBSERVATION_ROOT}" && \
  "$(${STAT} -c '%a' -- "${OBSERVATION_ROOT}")" == 700 ]] ||
  fail 'observation root must be one mode-0700 non-symlink directory'
[[ ! -e "${output_directory}" && ! -L "${output_directory}" ]] ||
  fail 'output already exists'
${MKDIR} -m 0700 -- "${output_directory}"
${SYNC} -- "${OBSERVATION_ROOT}"

work_directory=''
cleanup_work() {
  if [[ -n "${work_directory}" && \
    "${work_directory}" == "${output_directory}/.work."* && \
    -d "${work_directory}" ]]; then
    ${FIND} "${work_directory}" -xdev -depth -delete
    ${SYNC} -- "${output_directory}"
  fi
}
interrupted() {
  exit 130
}
trap cleanup_work EXIT
trap interrupted HUP INT TERM

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
  local parent="${final_path%/*}"
  [[ -f "${temporary_path}" && ! -L "${temporary_path}" && \
    "$(${STAT} -c '%h' -- "${temporary_path}")" == 1 && \
    ! -e "${final_path}" && ! -L "${final_path}" ]] ||
    fail "private publication precondition failed: ${final_path##*/}"
  ${CHMOD} 0400 -- "${temporary_path}"
  ${SYNC} -- "${temporary_path}"
  ${MV} -T --no-clobber -- "${temporary_path}" "${final_path}" ||
    fail "no-clobber publication failed: ${final_path##*/}"
  [[ -f "${final_path}" && ! -L "${final_path}" && \
    "$(${STAT} -c '%a:%h' -- "${final_path}")" == 400:1 ]] ||
    fail "published file has unsafe identity: ${final_path##*/}"
  ${SYNC} -- "${final_path}"
  ${SYNC} -- "${parent}"
}

copy_private_file() {
  local source_path="$1"
  local final_path="$2"
  local maximum_bytes="$3"
  local source_size
  local temporary_path
  [[ -f "${source_path}" && ! -L "${source_path}" ]] ||
    fail "copy source is not one regular file: ${source_path}"
  source_size="$(${STAT} -c '%s' -- "${source_path}")"
  [[ "${source_size}" =~ ^[1-9][0-9]*$ && \
    source_size -le maximum_bytes ]] ||
    fail "copy source is outside the byte bound: ${source_path}"
  temporary_path="$(${MKTEMP} "${final_path%/*}/.copy.XXXXXX")"
  ${DD} if="${source_path}" of="${temporary_path}" bs=1048576 status=none
  [[ "$(${STAT} -c '%s' -- "${temporary_path}")" == "${source_size}" && \
    "$(file_digest "${temporary_path}")" == "$(file_digest "${source_path}")" ]] ||
    fail "private copy differs from its source: ${source_path}"
  publish_private_file "${temporary_path}" "${final_path}"
}

retain_failure_log() {
  local stage="$1"
  local log_path="$2"
  local log_size
  if [[ -f "${log_path}" && ! -L "${log_path}" ]]; then
    log_size="$(${STAT} -c '%s' -- "${log_path}")"
    if [[ "${log_size}" =~ ^[1-9][0-9]*$ && log_size -le 16777216 ]]; then
      if [[ ! -e "${output_directory}/diagnostics" && \
        ! -L "${output_directory}/diagnostics" ]]; then
        ${MKDIR} -m 0700 -- "${output_directory}/diagnostics"
      fi
      copy_private_file "${log_path}" \
        "${output_directory}/diagnostics/${stage}.log" 16777216
    fi
  fi
}

create_exclusive_text_file "${output_directory}/INCOMPLETE" incomplete-candidate
for directory in prerequisites indexes packages state transport; do
  ${MKDIR} -m 0700 -- "${output_directory}/${directory}"
done
${SYNC} -- "${output_directory}"
copy_private_file "${profile_path}" \
  "${output_directory}/prerequisites/profile.snapshot" 65536
copy_private_file "${oci_lock_path}" \
  "${output_directory}/prerequisites/ubuntu-oci.lock.snapshot" 65536
copy_private_file "${builder_lock_path}" \
  "${output_directory}/prerequisites/builder-context.lock.snapshot" 65536
[[ -f "${HOST_CA_BUNDLE}" && ! -L "${HOST_CA_BUNDLE}" && \
  "$(${STAT} -c '%u:%a:%h' -- "${HOST_CA_BUNDLE}")" == 0:444:1 ]] ||
  fail 'host transport CA bundle must be root-owned, mode 0444, and singly linked'
copy_private_file "${HOST_CA_BUNDLE}" \
  "${output_directory}/transport/ca-certificates.crt" 1048576

work_directory="$(${MKTEMP} -d "${output_directory}/.work.XXXXXX")"
${INSTALL} -d -m 0700 -- "${work_directory}/rootfs" "${work_directory}/generated"
readonly rootfs="${work_directory}/rootfs"
readonly generated="${work_directory}/generated"
readonly layer_path="${base_oci_candidate}/objects/layer-01.tar.gz"
[[ -f "${layer_path}" && ! -L "${layer_path}" && \
  "$(file_digest "${layer_path}")" == 0b613318ea879878918380aa3aeb220dfe824e311b83bc955cb8a1d4319650ab ]] ||
  fail 'verified base OCI candidate no longer has the exact layer bytes'

archive_names="${generated}/archive-names.txt"
${BSDTAR} -tf "${layer_path}" >"${archive_names}" ||
  fail 'exact OCI layer inventory could not be parsed'
archive_line_count=0
while IFS= read -r archive_path; do
  ((archive_line_count += 1))
  [[ -n "${archive_path}" && ${#archive_path} -le 4096 && \
    "${archive_path}" != /* && "${archive_path}" != ../* && \
    "${archive_path}" != *'/../'* && "${archive_path}" != *'/..' && \
    "${archive_path}" != *$'\r'* ]] ||
    fail 'exact OCI layer contains an unsafe archive path'
  (( archive_line_count <= 200000 )) || fail 'OCI layer entry count exceeds the bound'
done <"${archive_names}"
(( archive_line_count > 0 )) || fail 'OCI layer inventory is empty'

extract_exact_layer() {
  ${TIMEOUT} --signal=TERM --kill-after=10 300 \
    ${BWRAP} \
    --unshare-all --unshare-user \
    --uid 0 --gid 0 --disable-userns --cap-drop ALL \
    --die-with-parent --new-session --clearenv \
    --setenv PATH /usr/bin:/bin --setenv LC_ALL C \
    --ro-bind /usr /usr \
    --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib /lib64 \
    --dir /input --ro-bind "${layer_path}" /input/layer.tar.gz \
    --bind "${rootfs}" /output \
    --proc /proc --dev /dev --tmpfs /tmp \
    -- /usr/bin/bsdtar -x --no-same-owner --no-same-permissions \
    -f /input/layer.tar.gz -C /output
}
extract_exact_layer ||
  fail 'exact OCI layer could not be extracted into the private root'

require_rootfs_directory() {
  local relative_path="$1"
  [[ -d "${rootfs}/${relative_path}" && ! -L "${rootfs}/${relative_path}" ]] ||
    fail "private root directory is missing or unsafe: ${relative_path}"
}
for rootfs_directory in \
  etc etc/apt etc/apt/sources.list.d \
  usr usr/bin usr/share usr/share/keyrings \
  var var/cache var/cache/apt var/cache/apt/archives \
  var/lib var/lib/apt var/lib/apt/lists var/lib/dpkg; do
  require_rootfs_directory "${rootfs_directory}"
done
for tls_directory in etc/ssl etc/ssl/certs; do
  if [[ ! -e "${rootfs}/${tls_directory}" && \
    ! -L "${rootfs}/${tls_directory}" ]]; then
    ${INSTALL} -d -m 0755 -- "${rootfs}/${tls_directory}"
  fi
  require_rootfs_directory "${tls_directory}"
done

mapfile -t initial_list_entries < <(
  ${FIND} "${rootfs}/var/lib/apt/lists" -xdev -mindepth 1 \
    -printf '%P|%y\n' | ${SORT}
)
(( ${#initial_list_entries[@]} == 0 )) ||
  fail 'initial APT list directory is not empty'
mapfile -t initial_archive_entries < <(
  ${FIND} "${rootfs}/var/cache/apt/archives" -xdev -mindepth 1 -maxdepth 1 \
    -printf '%P|%y\n' | ${SORT}
)
[[ "${#initial_archive_entries[@]}" -eq 2 && \
  "${initial_archive_entries[0]}" == 'lock|f' && \
  "${initial_archive_entries[1]}" == 'partial|d' && \
  -f "${rootfs}/var/cache/apt/archives/lock" && \
  ! -L "${rootfs}/var/cache/apt/archives/lock" && \
  -d "${rootfs}/var/cache/apt/archives/partial" && \
  ! -L "${rootfs}/var/cache/apt/archives/partial" ]] ||
  fail 'initial APT archive cache shape is not exact'

${INSTALL} -m 0644 -- "${output_directory}/transport/ca-certificates.crt" \
  "${rootfs}/etc/ssl/certs/ca-certificates.crt"

[[ -x "${rootfs}/usr/bin/apt-get" && -f "${rootfs}/usr/bin/apt-get" && \
  ! -L "${rootfs}/usr/bin/apt-get" && -x "${rootfs}/usr/bin/dpkg-query" && \
  -f "${rootfs}/usr/bin/dpkg-query" && ! -L "${rootfs}/usr/bin/dpkg-query" && \
  -x "${rootfs}/usr/bin/dpkg-deb" && -f "${rootfs}/usr/bin/dpkg-deb" && \
  ! -L "${rootfs}/usr/bin/dpkg-deb" ]] ||
  fail 'private root does not contain the exact required APT/dpkg readers'
[[ -f "${rootfs}/etc/resolv.conf" && ! -L "${rootfs}/etc/resolv.conf" ]] ||
  fail 'private root has an unsafe resolver configuration path'
${INSTALL} -m 0644 -- /etc/resolv.conf "${rootfs}/etc/resolv.conf"

run_in_rootfs() {
  ${TIMEOUT} --signal=TERM --kill-after=30 1800 \
    ${BWRAP} \
    --unshare-all --share-net --unshare-user \
    --uid 0 --gid 0 --disable-userns --cap-drop ALL \
    --die-with-parent --new-session --hostname a-quo-apt-candidate \
    --clearenv \
    --setenv HOME /root --setenv PATH /usr/sbin:/usr/bin:/sbin:/bin \
    --setenv LC_ALL C --setenv LANG C --setenv TZ UTC --setenv TERM dumb \
    --bind "${rootfs}" / \
    --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run \
    -- "$@"
}

apt_version_output="$(run_in_rootfs /usr/bin/apt-get --version)" ||
  fail 'exact private-root APT did not report its version'
apt_version_first_line="${apt_version_output%%$'\n'*}"
[[ "${apt_version_first_line}" == 'apt 2.8.3 (arm64)' ]] ||
  fail 'private-root APT is not exact ARM64 version 2.8.3'
printf '%s\n' apt_version=2.8.3 >"${generated}/apt-version.txt"
printf 'snapshot_id=%s\n' "${snapshot_id}" >"${generated}/snapshot-id.txt"
printf '%s\n' "${TOP_LEVEL_REQUESTS}" | ${TR} ',' '\n' >"${generated}/requested-packages.txt"

# This is a dpkg-query format string, not a shell expansion.
# shellcheck disable=SC2016
run_in_rootfs /usr/bin/dpkg-query -W \
  '-f=${Package}|${Version}|${Architecture}\n' | ${SORT} -u >"${generated}/base-packages.txt" ||
  fail 'base package state could not be read from the exact private root'
base_status_digest="$(file_digest "${rootfs}/var/lib/dpkg/status")"

capture_sources() {
  local label="$1"
  printf 'source_set=%s\n' "${label}"
  {
    if [[ -f "${rootfs}/etc/apt/sources.list" && \
      ! -L "${rootfs}/etc/apt/sources.list" ]]; then
      printf '%s\0' "${rootfs}/etc/apt/sources.list"
    fi
    ${FIND} "${rootfs}/etc/apt/sources.list.d" -xdev -maxdepth 1 \
      -type f -print0
  } | ${SORT} -z |
    while IFS= read -r -d '' source_file; do
      relative_source="${source_file#"${rootfs}"}"
      printf 'path=%s\nsize=%s\nsha256=%s\n' \
        "${relative_source}" \
        "$(${STAT} -c '%s' -- "${source_file}")" \
        "$(file_digest "${source_file}")"
      printf '%s\n' content-begin
      ${DD} if="${source_file}" bs=65537 count=1 status=none
      printf '%s\n' content-end
    done
}
capture_sources original-locked-oci >"${generated}/sources-original.txt"

effective_sources="${rootfs}/etc/apt/sources.list.d/ubuntu.sources"
[[ -f "${effective_sources}" && ! -L "${effective_sources}" ]] ||
  fail 'locked OCI Deb822 source is missing or unsafe'
${CHMOD} 0600 -- "${effective_sources}"
{
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
} >"${effective_sources}"
${CHMOD} 0644 -- "${effective_sources}"
capture_sources effective-timestamped-main-archive \
  >"${generated}/sources-effective.txt"
{
  ${DD} if="${generated}/sources-original.txt" bs=65537 count=256 status=none
  ${DD} if="${generated}/sources-effective.txt" bs=65537 count=256 status=none
} >"${generated}/sources.txt"
run_in_rootfs /usr/bin/apt-config dump >"${generated}/apt-configuration.txt" ||
  fail 'exact private-root APT configuration could not be captured'

IFS=',' read -r -a requested_packages <<<"${TOP_LEVEL_REQUESTS}"
readonly apt_common=(
  -o APT::Sandbox::User=root
  -o Acquire::Languages=none
  -o Acquire::Retries=0
  -o Acquire::AllowInsecureRepositories=false
  -o Acquire::AllowDowngradeToInsecureRepositories=false
  -o APT::Get::AllowUnauthenticated=false
  -o APT::Get::Assume-Yes=true
  -o APT::Color=false
  -o Dpkg::Use-Pty=0
)
if ! run_in_rootfs /usr/bin/apt-get "${apt_common[@]}" update \
  >"${generated}/apt-update.log" 2>&1; then
  retain_failure_log apt-update "${generated}/apt-update.log"
  fail 'snapshot-bound APT index update failed in the private root'
fi
# These are APT indextarget placeholders, not shell expansions.
# shellcheck disable=SC2016
run_in_rootfs /usr/bin/apt-get "${apt_common[@]}" indextargets \
  --format '$(IDENTIFIER)|$(DESCRIPTION)|$(URI)|$(FILENAME)' \
  >"${generated}/index-targets.txt" ||
  fail 'APT index-target observations could not be captured'
index_target_count=0
while IFS= read -r index_target; do
  ((index_target_count += 1))
  IFS='|' read -r identifier description uri filename extra <<<"${index_target}"
  [[ -z "${extra}" && -n "${identifier}" && -n "${description}" && \
    "${uri}" == "https://snapshot.ubuntu.com/ubuntu/${snapshot_id}/"* && \
    "${filename}" == /var/lib/apt/lists/* ]] || {
    retain_failure_log apt-update "${generated}/apt-update.log"
    fail 'APT index target is not bound to the exact requested snapshot'
  }
  (( index_target_count <= 1024 )) || fail 'APT index-target count exceeds the bound'
done <"${generated}/index-targets.txt"
if (( index_target_count == 0 )); then
  retain_failure_log apt-update "${generated}/apt-update.log"
  fail 'APT reported no snapshot-bound index targets'
fi
if ! run_in_rootfs /usr/bin/apt-get "${apt_common[@]}" --simulate \
  --no-install-recommends --no-remove install "${requested_packages[@]}" \
  >"${generated}/solver-plan.txt" 2>&1; then
  retain_failure_log apt-simulate "${generated}/solver-plan.txt"
  fail 'snapshot-bound APT simulation failed in the private root'
fi
if ! run_in_rootfs /usr/bin/apt-get "${apt_common[@]}" --download-only \
  --no-install-recommends --no-remove install "${requested_packages[@]}" \
  >"${generated}/apt-download.log" 2>&1; then
  retain_failure_log apt-download "${generated}/apt-download.log"
  fail 'snapshot-bound APT download-only pass failed in the private root'
fi

for rootfs_directory in \
  etc etc/apt etc/apt/sources.list.d etc/ssl etc/ssl/certs \
  usr usr/bin usr/share usr/share/keyrings \
  var var/cache var/cache/apt var/cache/apt/archives \
  var/lib var/lib/apt var/lib/apt/lists var/lib/dpkg; do
  require_rootfs_directory "${rootfs_directory}"
done
[[ -f "${rootfs}/var/lib/dpkg/status" && \
  ! -L "${rootfs}/var/lib/dpkg/status" ]] ||
  fail 'dpkg status became unsafe despite the download-only boundary'
[[ "$(file_digest "${rootfs}/var/lib/dpkg/status")" == "${base_status_digest}" ]] ||
  fail 'dpkg status changed despite the download-only boundary'
# This is a dpkg-query format string, not a shell expansion.
# shellcheck disable=SC2016
run_in_rootfs /usr/bin/dpkg-query -W \
  '-f=${Package}|${Version}|${Architecture}\n' | ${SORT} -u >"${generated}/base-packages-after.txt" ||
  fail 'post-download base package state could not be read'
${CMP} -s -- "${generated}/base-packages.txt" "${generated}/base-packages-after.txt" ||
  fail 'installed package state changed despite the download-only boundary'

index_number=0
while IFS= read -r index_source; do
  [[ "${index_source}" == "${rootfs}/var/lib/apt/lists/"* && \
    -f "${index_source}" && ! -L "${index_source}" ]] ||
    fail 'APT lists inventory escaped the exact private root or contains a non-file'
  [[ "${index_source##*/}" != lock ]] || continue
  index_size="$(${STAT} -c '%s' -- "${index_source}")"
  (( index_size > 0 )) || continue
  ((index_number += 1))
  printf -v retained_index_name 'index-%04d.bin' "${index_number}"
  copy_private_file "${index_source}" \
    "${output_directory}/indexes/${retained_index_name}" 536870912
done < <(${FIND} "${rootfs}/var/lib/apt/lists" -xdev -type f -print | ${SORT})
(( index_number > 0 )) || fail 'APT retained no nonempty index files'

package_number=0
package_metadata="${generated}/downloaded-packages.txt"
: >"${package_metadata}"
while IFS= read -r package_source; do
  [[ "${package_source}" == "${rootfs}/var/cache/apt/archives/"*.deb && \
    -f "${package_source}" && ! -L "${package_source}" ]] ||
    fail 'APT archive inventory contains an unsafe package path'
  package_basename="${package_source##*/}"
  [[ "${package_basename}" =~ ^[A-Za-z0-9][A-Za-z0-9._+:%~-]{0,200}\.deb$ ]] ||
    fail 'APT produced a package basename outside the closed grammar'
  ((package_number += 1))
  copy_private_file "${package_source}" \
    "${output_directory}/packages/${package_basename}" 536870912
  package_name="$(run_in_rootfs /usr/bin/dpkg-deb -f \
    "/var/cache/apt/archives/${package_basename}" Package)" ||
    fail 'downloaded package name could not be read in the sandbox'
  package_version="$(run_in_rootfs /usr/bin/dpkg-deb -f \
    "/var/cache/apt/archives/${package_basename}" Version)" ||
    fail 'downloaded package version could not be read in the sandbox'
  package_arch="$(run_in_rootfs /usr/bin/dpkg-deb -f \
    "/var/cache/apt/archives/${package_basename}" Architecture)" ||
    fail 'downloaded package architecture could not be read in the sandbox'
  [[ "${package_name}" =~ ^[a-z0-9][a-z0-9+.-]{0,127}$ && \
    "${package_version}" =~ ^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,191}$ && \
    "${package_arch}" =~ ^(arm64|all)$ ]] ||
    fail 'downloaded package metadata is outside the closed grammar'
  printf '%s|%s|%s\n' \
    "${package_name}" "${package_version}" "${package_arch}" \
    >>"${package_metadata}"
done < <(${FIND} "${rootfs}/var/cache/apt/archives" -xdev -maxdepth 1 \
  -type f -name '*.deb' -print | ${SORT})
(( package_number > 0 )) || fail 'APT download-only pass retained no package archives'
${SORT} -u -o "${package_metadata}" "${package_metadata}"

# This is an awk program, not a shell expression.
# shellcheck disable=SC2016
${AWK} -F'|' '
  FNR == NR { records[$1 SUBSEP $3] = $0; next }
  { records[$1 SUBSEP $3] = $0 }
  END { for (key in records) print records[key] }
' "${generated}/base-packages.txt" "${package_metadata}" | ${SORT} \
  >"${generated}/final-packages.txt"

for state_name in \
  apt-version snapshot-id sources apt-configuration base-packages \
  requested-packages index-targets solver-plan final-packages; do
  copy_private_file "${generated}/${state_name}.txt" \
    "${output_directory}/state/${state_name}.txt" 16777216
done

manifest_temporary="$(${MKTEMP} "${output_directory}/.objects.manifest.XXXXXX")"
{
  printf '%s\n' format=a-quo-omarchy-ubuntu-apt-object-manifest-v1
  for state_record in \
    'apt-version|state/apt-version.txt' \
    'snapshot-id|state/snapshot-id.txt' \
    'sources|state/sources.txt' \
    'apt-configuration|state/apt-configuration.txt' \
    'base-package-state|state/base-packages.txt' \
    'requested-packages|state/requested-packages.txt' \
    'index-targets|state/index-targets.txt' \
    'solver-plan|state/solver-plan.txt' \
    'final-package-state|state/final-packages.txt'; do
    role="${state_record%%|*}"
    relative_path="${state_record#*|}"
    printf '%s|%s|%s|%s\n' \
      "${role}" "${relative_path}" \
      "$(${STAT} -c '%s' -- "${output_directory}/${relative_path}")" \
      "$(file_digest "${output_directory}/${relative_path}")"
  done
  printf 'transport-ca-bundle|transport/ca-certificates.crt|%s|%s\n' \
    "$(${STAT} -c '%s' -- "${output_directory}/transport/ca-certificates.crt")" \
    "$(file_digest "${output_directory}/transport/ca-certificates.crt")"
  while IFS= read -r retained_index; do
    relative_path="indexes/${retained_index##*/}"
    printf 'index|%s|%s|%s\n' \
      "${relative_path}" \
      "$(${STAT} -c '%s' -- "${retained_index}")" \
      "$(file_digest "${retained_index}")"
  done < <(${FIND} "${output_directory}/indexes" -xdev -maxdepth 1 -type f -print | ${SORT})
  while IFS= read -r retained_package; do
    relative_path="packages/${retained_package##*/}"
    printf 'package|%s|%s|%s\n' \
      "${relative_path}" \
      "$(${STAT} -c '%s' -- "${retained_package}")" \
      "$(file_digest "${retained_package}")"
  done < <(${FIND} "${output_directory}/packages" -xdev -maxdepth 1 -type f -print | ${SORT})
} >"${manifest_temporary}"
publish_private_file "${manifest_temporary}" "${output_directory}/objects.manifest"

cleanup_work
work_directory=''

observation_output="$("${APT_CANDIDATE_VERIFIER}" --emit-observations \
  --profile "${profile_path}" \
  --externally-expected-profile-sha256 "${PROFILE_SHA256}" \
  --oci-lock "${oci_lock_path}" \
  --externally-expected-oci-lock-sha256 "${OCI_LOCK_SHA256}" \
  --builder-lock "${builder_lock_path}" \
  --externally-expected-builder-lock-sha256 "${BUILDER_LOCK_SHA256}" \
  --candidate "${output_directory}")" ||
  fail 'captured APT candidate failed offline byte verification'
declare -A observations=()
observation_count=0
while IFS= read -r line; do
  ((observation_count += 1))
  key="${line%%=*}"
  value="${line#*=}"
  [[ "${line}" == *=* && "${value}" != *'='* && \
    "${key}" =~ ^[a-z][a-z0-9_]{0,63}$ && ! -v "observations[${key}]" ]] ||
    fail 'offline APT verifier emitted a malformed observation record'
  observations["${key}"]="${value}"
done <<<"${observation_output}"
[[ "${observation_count}" -eq 24 && \
  "${observations[candidate_status]:-}" == verified-incomplete-non-authoritative && \
  "${observations[authority]:-}" == none && \
  "${observations[snapshot_id]:-}" == "${snapshot_id}" && \
  "${observations[index_count]:-}" == "${index_number}" && \
  "${observations[package_count]:-}" == "${package_number}" && \
  "${observations[solver_install_record_count]:-}" == "${package_number}" && \
  "${observations[package_installation]:-}" == false && \
  "${observations[dpkg_transaction]:-}" == false && \
  "${observations[network_activity]:-}" == false && \
  "${observations[vm_started]:-}" == false ]] ||
  fail 'offline APT observations were not the exact candidate-only result'

receipt_temporary="$(${MKTEMP} "${output_directory}/.receipt.apt.v1.XXXXXX")"
{
  printf '%s\n' \
    'format=a-quo-omarchy-ubuntu-apt-candidate-v1' \
    'status=complete-candidate' \
    'authority=none' \
    "profile_id=${observations[profile_id]}" \
    "profile_sha256=${PROFILE_SHA256}" \
    "ubuntu_oci_lock_sha256=${OCI_LOCK_SHA256}" \
    "builder_context_lock_sha256=${BUILDER_LOCK_SHA256}" \
    "snapshot_id=${snapshot_id}" \
    'snapshot_selection_authority=caller-supplied-none' \
    'original_archive=http://ports.ubuntu.com/ubuntu-ports/' \
    "effective_snapshot_archive=https://snapshot.ubuntu.com/ubuntu/${snapshot_id}/" \
    'archive_equivalence_to_original_ports=not-established' \
    'apt_version=2.8.3' \
    'apt_sandbox_user=root-in-private-single-uid-user-namespace' \
    "transport_ca_bundle_sha256=${observations[transport_ca_bundle_sha256]}" \
    'transport_ca_bundle_source=caller-host-not-authenticated' \
    'ubuntu_archive_signature_verification=performed-by-apt-not-independently-replayed' \
    'top_level_request_count=14' \
    "object_count=${observations[object_count]}" \
    "index_count=${observations[index_count]}" \
    "package_count=${observations[package_count]}" \
    "object_manifest_sha256=${observations[object_manifest_sha256]}" \
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
} >"${receipt_temporary}"
publish_private_file "${receipt_temporary}" "${output_directory}/receipt.apt.v1"

"${APT_CANDIDATE_VERIFIER}" --pre-completion \
  --profile "${profile_path}" \
  --externally-expected-profile-sha256 "${PROFILE_SHA256}" \
  --oci-lock "${oci_lock_path}" \
  --externally-expected-oci-lock-sha256 "${OCI_LOCK_SHA256}" \
  --builder-lock "${builder_lock_path}" \
  --externally-expected-builder-lock-sha256 "${BUILDER_LOCK_SHA256}" \
  --candidate "${output_directory}" >/dev/null ||
  fail 'full APT receipt failed verification before completion publication'

complete_temporary="$(${MKTEMP} "${output_directory}/.complete.XXXXXX")"
printf '%s\n' complete-candidate >"${complete_temporary}"
publish_private_file "${complete_temporary}" "${output_directory}/COMPLETE"
${FIND} "${output_directory}/INCOMPLETE" -xdev -delete
${SYNC} -- "${output_directory}"

set +e
final_output="$("${APT_CANDIDATE_VERIFIER}" \
  --profile "${profile_path}" \
  --externally-expected-profile-sha256 "${PROFILE_SHA256}" \
  --oci-lock "${oci_lock_path}" \
  --externally-expected-oci-lock-sha256 "${OCI_LOCK_SHA256}" \
  --builder-lock "${builder_lock_path}" \
  --externally-expected-builder-lock-sha256 "${BUILDER_LOCK_SHA256}" \
  --candidate "${output_directory}" 2>&1)"
final_status="$?"
set -e
if (( final_status != 0 )); then
  create_exclusive_text_file "${output_directory}/INCOMPLETE" incomplete-candidate
  ${FIND} "${output_directory}/COMPLETE" -xdev -delete
  ${SYNC} -- "${output_directory}"
  fail 'completed APT candidate failed final verification and returned to incomplete state'
fi

printf '%s\n' \
  "candidate_directory=${output_directory}" \
  'candidate_authority=none' \
  'acquisition_network_activity=true' \
  'package_installation=false' \
  'signed_does_not_mean_safe=true' \
  "${final_output}"
