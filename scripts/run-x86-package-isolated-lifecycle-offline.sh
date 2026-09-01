#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

fail_lifecycle() {
  printf 'x86_64 isolated package lifecycle refused: %s\n' "$1" >&2
  exit 1
}

[[ "$#" -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || {
  printf 'usage: %s F2_SOURCE_COMMIT\n' "${0##*/}" >&2
  exit 2
}

readonly EXPECTED_F2_COMMIT="$1"
readonly EXPECTED_WORKSPACE=/workspace
readonly EXPECTED_UID=1001
readonly EXPECTED_GID=1001
readonly EXPECTED_HOME=/home/a-quo-observer
readonly EXPECTED_MISE_SHA256=cff4832ded79af2951e800bddcb5a22acac58630d765a2d062c1180680a0bb35
readonly EXPECTED_PROFILE='packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile'
readonly EXPECTED_PROFILE_ID='a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1'
readonly EXPECTED_PROFILE_SHA256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d
readonly EXPECTED_ARCHITECTURE=x86_64
readonly EXPECTED_NAMESPACE=physical-x86_64-official-omarchy-4.0.2
readonly F1_SOURCE_COMMIT=ee47d7f1e4432ea3b3edab25dc0875b7133d5733
readonly F1_WORKFLOW_RUN_ID=33456949816
readonly F1_ARTIFACT_ID=9781997778
readonly F1_DOWNLOAD_ACTION_COMMIT=3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c
readonly F1_ARTIFACT_ZIP_SHA256=15e24d068cd31b2de8cd23730303b5ad95a5d534d96c76076ddc015558d34f75
readonly F1_ARTIFACT_ZIP_BYTES=19036458
readonly F1_MEMBER_COUNT=15
readonly F1_MEMBER_INVENTORY_SHA256=88d5a8aa66cd3d1c1e50f6181eb47e7914f657f8b639eaa69a1944fe46aee32a
readonly F1_PACKAGE_FILENAME='a-quo-0.1.0.r101.gee47d7f1e443-1-x86_64.pkg.tar.zst'
readonly F1_PACKAGE_SHA256=75db0ad706aac8c69fefa29c0d27029b80796d665f452e296d0baae09ac25e11
readonly F1_STATIC_ACCEPTANCE_SHA256=4e5c4956115a590d441040addc08411363829aeb8d32932ff064a3017836b56b
readonly F1_VERIFIER_RECEIPT_SHA256=575a4c2e2f3347de9f8781a8608c86bb83eeda7a9988273416688bfbe6fbcdfd
readonly F1_HOSTED_ACCEPTANCE_SHA256=98f20b98821cf35a644df3cc0ee58cdd00781a70524a103f4212257fc803d928
readonly F1_OUTER_MANIFEST_SHA256=a8cccc971941dde6ee270cd76603c6b457e1c71e99953f9b8b0cfe63220960be
readonly F1_LOCK_SHA256=333c9ae548e0f9c269a62859d11a4ccaf0ea4a88c7b0ed0c9a4f19ed785d5d48
readonly EXPECTED_F1_ROOT=/stage4-f1
readonly F1_ARCHIVE="${EXPECTED_F1_ROOT}/artifact.zip"
readonly F1_CUSTODY_RECEIPT="${EXPECTED_F1_ROOT}/F1-CUSTODY.txt"
readonly F1_CUSTODY_MANIFEST="${EXPECTED_F1_ROOT}/SHA256SUMS"
readonly MAXIMUM_RECEIPT_BYTES=131072
readonly MAXIMUM_ARCHIVE_INVENTORY_BYTES=131072
readonly MAXIMUM_CUSTODY_RECEIPT_BYTES=2048
readonly MAXIMUM_CUSTODY_MANIFEST_BYTES=512

for git_override in \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CEILING_DIRECTORIES GIT_COMMON_DIR GIT_CONFIG \
  GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM \
  GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_DIR GIT_GRAFT_FILE \
  GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_EXEC_PATH GIT_INDEX_FILE GIT_NAMESPACE \
  GIT_OBJECT_DIRECTORY GIT_OPTIONAL_LOCKS \
  GIT_QUARANTINE_PATH GIT_REPLACE_REF_BASE GIT_SHALLOW_FILE \
  GIT_WORK_TREE; do
  [[ ! -v "${git_override}" ]] ||
    fail_lifecycle "inherited Git repository override: ${git_override}"
done
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_NO_LAZY_FETCH=1
export GIT_NO_REPLACE_OBJECTS=1
export GIT_OPTIONAL_LOCKS=0

for required_tool in \
  awk basename bash bsdtar cat chmod cmp cut dd env find git grep head id \
  install mkdir mktemp od readlink realpath rm sed sha256sum sort stat \
  tail tr uname uniq wc; do
  command -v "${required_tool}" >/dev/null ||
    fail_lifecycle "required offline lifecycle tool is unavailable: ${required_tool}"
done

require_safe_user_directory() {
  local directory="$1" expected_mode="$2"
  [[ -d "${directory}" && ! -L "${directory}" &&
    "$(realpath -e -- "${directory}")" == "${directory}" &&
    "$(stat -c '%u:%g:%a:%F' -- "${directory}")" == \
      "${EXPECTED_UID}:${EXPECTED_GID}:${expected_mode}:directory" ]] ||
    fail_lifecycle "offline writable directory is unsafe: ${directory}"
}

[[ "$(id -u)" == "${EXPECTED_UID}" && "$(id -g)" == "${EXPECTED_GID}" ]] ||
  fail_lifecycle 'offline lifecycle must run as the reviewed unprivileged UID/GID'
(( EUID != 0 )) || fail_lifecycle 'offline lifecycle must never run as real root'
[[ "$(uname -m)" == "${EXPECTED_ARCHITECTURE}" && -f /etc/arch-release ]] ||
  fail_lifecycle 'offline lifecycle requires an architecture-matched Arch environment'
[[ "${HOME:-}" == "${EXPECTED_HOME}" &&
  "$(pwd -P)" == "${EXPECTED_WORKSPACE}" ]] ||
  fail_lifecycle 'offline lifecycle HOME or working directory differs from policy'
[[ "${MISE_CACHE_DIR:-}" == "${EXPECTED_HOME}/.cache/mise" &&
  "${MISE_DATA_DIR:-}" == "${EXPECTED_HOME}/.local/share/mise" &&
  "${MISE_TRUSTED_CONFIG_PATHS:-}" == "${EXPECTED_WORKSPACE}" &&
  "${MISE_OFFLINE:-}" == 1 && "${CARGO_NET_OFFLINE:-}" == true ]] ||
  fail_lifecycle 'offline toolchain environment is missing or malformed'
[[ "${EXPECTED_WORKSPACE}" == "$(realpath -e -- "${EXPECTED_WORKSPACE}")" &&
  ! -L "${EXPECTED_WORKSPACE}" ]] ||
  fail_lifecycle 'canonical workspace path is unavailable or unsafe'
require_safe_user_directory "${EXPECTED_WORKSPACE}/target" 755
require_safe_user_directory "${EXPECTED_HOME}" 700
[[ -f /usr/local/bin/mise && ! -L /usr/local/bin/mise &&
  "$(readlink -f -- /usr/local/bin/mise)" == /usr/local/bin/mise &&
  "$(stat -c '%u:%g:%a:%h:%F' -- /usr/local/bin/mise)" == \
    "${EXPECTED_UID}:${EXPECTED_GID}:555:1:regular file" ]] ||
  fail_lifecycle 'read-only Mise mount metadata differs from policy'
[[ -d "${EXPECTED_F1_ROOT}" && ! -L "${EXPECTED_F1_ROOT}" &&
  "$(realpath -e -- "${EXPECTED_F1_ROOT}")" == "${EXPECTED_F1_ROOT}" &&
  "$(stat -c '%u:%g:%a:%F' -- "${EXPECTED_F1_ROOT}")" == \
    '0:0:555:directory' ]] || fail_lifecycle 'root-custodied F1 mount is unsafe'
[[ "$(find "${EXPECTED_F1_ROOT}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == \
  "$(printf '%s\n' F1-CUSTODY.txt SHA256SUMS artifact.zip | sort)" ]] ||
  fail_lifecycle 'root-custodied F1 mount has an unexpected inventory'
for f1_file in "${F1_ARCHIVE}" "${F1_CUSTODY_RECEIPT}" "${F1_CUSTODY_MANIFEST}"; do
  [[ -f "${f1_file}" && ! -L "${f1_file}" &&
    "$(stat -c '%u:%g:%a:%h:%F' -- "${f1_file}")" == \
      '0:0:444:1:regular file' ]] ||
    fail_lifecycle "root-custodied F1 file is unsafe: ${f1_file}"
done
[[ "$(stat -c '%s' -- "${F1_CUSTODY_RECEIPT}")" -ge 1 &&
  "$(stat -c '%s' -- "${F1_CUSTODY_RECEIPT}")" -le \
    "${MAXIMUM_CUSTODY_RECEIPT_BYTES}" &&
  "$(stat -c '%s' -- "${F1_CUSTODY_MANIFEST}")" -ge 1 &&
  "$(stat -c '%s' -- "${F1_CUSTODY_MANIFEST}")" -le \
    "${MAXIMUM_CUSTODY_MANIFEST_BYTES}" ]] ||
  fail_lifecycle 'root-custodied F1 receipt or manifest exceeds its closed byte bound'
[[ -d /sys/class/net/lo ]] ||
  fail_lifecycle 'offline container has no loopback interface'
mapfile -t network_interfaces < <(
  find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort
)
[[ "${#network_interfaces[@]}" -eq 1 && "${network_interfaces[0]}" == lo ]] ||
  fail_lifecycle 'offline container has a non-loopback network interface'

if ( : >/.a-quo-x86-stage5-rootfs-probe ) 2>/dev/null; then
  rm -f -- /.a-quo-x86-stage5-rootfs-probe
  fail_lifecycle 'container root filesystem is writable'
fi
if ( : >"${EXPECTED_WORKSPACE}/.a-quo-x86-stage5-workspace-probe" ) 2>/dev/null; then
  rm -f -- "${EXPECTED_WORKSPACE}/.a-quo-x86-stage5-workspace-probe"
  fail_lifecycle 'repository root is writable outside the target submount'
fi
target_probe="$(mktemp \
  "${EXPECTED_WORKSPACE}/target/.a-quo-x86-stage5-target-probe.XXXXXX")" ||
  fail_lifecycle 'target output mount is not writable'
rm -f -- "${target_probe}"
home_probe="$(mktemp "${EXPECTED_HOME}/.a-quo-x86-stage5-home-probe.XXXXXX")" ||
  fail_lifecycle 'observer home mount is not writable'
rm -f -- "${home_probe}"
mise_digest="$(sha256sum -- /usr/local/bin/mise | cut -d ' ' -f 1)" ||
  fail_lifecycle 'Mise bind mount cannot be hashed'
[[ "${mise_digest}" == "${EXPECTED_MISE_SHA256}" ]] ||
  fail_lifecycle 'Mise bind mount bytes differ from the reviewed input'
if ( chmod u+w /usr/local/bin/mise ) 2>/dev/null; then
  fail_lifecycle 'Mise bind mount is writable'
fi
if ( chmod u+w "${F1_ARCHIVE}" ) 2>/dev/null; then
  fail_lifecycle 'root-custodied F1 bind mount is writable'
fi

readonly SCRIPT_DIRECTORY="${EXPECTED_WORKSPACE}/scripts"
readonly PROFILE="${EXPECTED_WORKSPACE}/${EXPECTED_PROFILE}"
readonly F1_LOCK="${EXPECTED_WORKSPACE}/packaging/evaluation-input-locks/a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock"
readonly F1_LOCK_VERIFIER="${SCRIPT_DIRECTORY}/verify-x86-package-stage4-f1-lock.sh"
readonly BUILDER="${SCRIPT_DIRECTORY}/build-arch-package-skeleton.sh"
readonly TARGET_RESOLVER="${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh"
readonly PACKAGE_VERIFIER="${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh"
readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh"
readonly UPGRADE_SMOKE="${SCRIPT_DIRECTORY}/test-arch-package-upgrade-smoke.sh"

while IFS='|' read -r path expected executable; do
  [[ -f "${path}" && ! -L "${path}" ]] ||
    fail_lifecycle "reviewed input is unavailable or unsafe: ${path}"
  [[ "$(sha256sum -- "${path}" | cut -d ' ' -f 1)" == "${expected}" ]] ||
    fail_lifecycle "reviewed input bytes changed: ${path}"
  [[ "${executable}" == false || -x "${path}" ]] ||
    fail_lifecycle "reviewed input is not executable: ${path}"
done <<EOF
${F1_LOCK}|${F1_LOCK_SHA256}|false
${F1_LOCK_VERIFIER}|56511a76b8f1dccf1c80489f3b4ecf7434a5122f5c30479cc0909903d87c7ea0|true
${BUILDER}|63c54347df158778bcafaa307acae49cec38e1eddf6727a1e5bf6316769d9fee|true
${TARGET_RESOLVER}|e1cbb386db5f890ae61509a2ca33acd6180c459c4a9778c203f9cefbe9b88831|true
${PACKAGE_VERIFIER}|f0427319b1d6903261903c3756d1c2bf77b261be9a298b413fe317c41d495c92|true
${PROFILE_VERIFIER}|af95814e6844362afce6e5cc1a4275abc18b3202f62776e19f17c87a699dc2fc|true
${UPGRADE_SMOKE}|48414a001bee094422790417e86eb950ae044db4258ef9d150b86f8a98e77f71|true
EOF

LOCK_RECEIPT="$("${F1_LOCK_VERIFIER}")" ||
  fail_lifecycle 'immutable F1 lock verification failed'
readonly LOCK_RECEIPT
[[ "${#LOCK_RECEIPT}" -le "${MAXIMUM_RECEIPT_BYTES}" ]] ||
  fail_lifecycle 'F1 lock receipt exceeds its closed byte bound'
grep -Fqx "f1_lock_sha256=${F1_LOCK_SHA256}" <<<"${LOCK_RECEIPT}" ||
  fail_lifecycle 'F1 lock receipt does not bind the reviewed lock'

for forbidden_config in \
  /etc/gitconfig "${HOME}/.gitconfig" "${HOME}/.config/git/config"; do
  [[ ! -e "${forbidden_config}" && ! -L "${forbidden_config}" ]] ||
    fail_lifecycle "system or global Git configuration exists: ${forbidden_config}"
done
for config_scope in system global; do
  set +e
  CONFIG_OUTPUT="$(git config --"${config_scope}" --null --list 2>/dev/null)"
  config_status="$?"
  set -e
  [[ -z "${CONFIG_OUTPUT}" &&
    ( "${config_status}" -eq 0 || "${config_status}" -eq 1 ) ]] ||
    fail_lifecycle "${config_scope} Git configuration is not empty"
done

GIT_COMMON_DIRECTORY="$({
  git -C "${EXPECTED_WORKSPACE}" rev-parse --path-format=absolute --git-common-dir
} 2>/dev/null)" || fail_lifecycle 'Git common directory is unavailable'
readonly GIT_COMMON_DIRECTORY
[[ "${GIT_COMMON_DIRECTORY}" == "${EXPECTED_WORKSPACE}/.git" &&
  -d "${GIT_COMMON_DIRECTORY}" && ! -L "${GIT_COMMON_DIRECTORY}" &&
  "$(realpath -e -- "${GIT_COMMON_DIRECTORY}")" == \
    "${EXPECTED_WORKSPACE}/.git" ]] ||
  fail_lifecycle 'Git common directory is unsafe'
GIT_OBJECTS_DIRECTORY="${GIT_COMMON_DIRECTORY}/objects"
readonly GIT_OBJECTS_DIRECTORY
[[ -d "${GIT_OBJECTS_DIRECTORY}" && ! -L "${GIT_OBJECTS_DIRECTORY}" &&
  "$(realpath -e -- "${GIT_OBJECTS_DIRECTORY}")" == \
    "${GIT_OBJECTS_DIRECTORY}" ]] ||
  fail_lifecycle 'Git object directory is unsafe'
for git_info_directory in \
  "${GIT_COMMON_DIRECTORY}/info" "${GIT_OBJECTS_DIRECTORY}/info"; do
  [[ -d "${git_info_directory}" && ! -L "${git_info_directory}" &&
    "$(realpath -e -- "${git_info_directory}")" == \
      "${git_info_directory}" ]] ||
    fail_lifecycle "Git metadata directory is unsafe: ${git_info_directory}"
done
for alternate_file in \
  "${GIT_COMMON_DIRECTORY}/objects/info/alternates" \
  "${GIT_COMMON_DIRECTORY}/objects/info/http-alternates" \
  "${GIT_COMMON_DIRECTORY}/info/grafts"; do
  [[ ! -e "${alternate_file}" && ! -L "${alternate_file}" ]] ||
    fail_lifecycle "Git repository contains forbidden object substitution state: ${alternate_file}"
done
set +e
git -C "${EXPECTED_WORKSPACE}" config --local --get-regexp \
  '^(include\.path|includeif\..*\.path|core\.(alternaterefscommand|alternaterefsprefixes)|extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$' \
  >/dev/null 2>&1
dangerous_local_config_status="$?"
set -e
[[ "${dangerous_local_config_status}" -eq 1 ]] ||
  fail_lifecycle 'Git repository contains an include or object-substitution configuration'
[[ "$(git -C "${EXPECTED_WORKSPACE}" rev-parse --is-shallow-repository)" == false ]] ||
  fail_lifecycle 'Git repository is shallow'
[[ -z "$(git -C "${EXPECTED_WORKSPACE}" for-each-ref --count=1 \
  --format='%(refname)' refs/replace)" ]] ||
  fail_lifecycle 'Git repository contains replacement refs'
set +e
PROMISOR_CONFIG="$(git -C "${EXPECTED_WORKSPACE}" config --local --get-regexp \
  '^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$' 2>/dev/null)"
promisor_status="$?"
set -e
[[ "${promisor_status}" -eq 1 && -z "${PROMISOR_CONFIG}" ]] ||
  fail_lifecycle 'Git repository contains promisor or partial-clone configuration'

SOURCE_HEAD="$(git -C "${EXPECTED_WORKSPACE}" rev-parse --verify HEAD)"
readonly SOURCE_HEAD
[[ "${SOURCE_HEAD}" == "${EXPECTED_F2_COMMIT}" &&
  "${SOURCE_HEAD}" != "${F1_SOURCE_COMMIT}" ]] ||
  fail_lifecycle 'F2 must be the distinct exact workflow source commit'
[[ -z "$(git -C "${EXPECTED_WORKSPACE}" -c core.fsmonitor=false \
  status --porcelain=v1 --untracked-files=normal)" ]] ||
  fail_lifecycle 'F2 repository must be clean'
git -C "${EXPECTED_WORKSPACE}" cat-file -e "${F1_SOURCE_COMMIT}^{commit}" 2>/dev/null ||
  fail_lifecycle 'F1 source commit is unavailable in complete history'
git -C "${EXPECTED_WORKSPACE}" merge-base --is-ancestor \
  "${F1_SOURCE_COMMIT}" "${SOURCE_HEAD}" ||
  fail_lifecycle 'F2 source commit is not a descendant of F1'

require_safe_user_directory "${EXPECTED_WORKSPACE}/target" 755
[[ -z "$(find "${EXPECTED_WORKSPACE}/target" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
  fail_lifecycle 'offline target mount must start empty'
TEMPORARY_PREFIX="${EXPECTED_WORKSPACE}/target/.a-quo-x86-stage5-wrapper."
readonly TEMPORARY_PREFIX
TEMPORARY_ROOT="$(mktemp -d "${TEMPORARY_PREFIX}XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")"
readonly TEMPORARY_IDENTITY
cleanup() {
  local status="$?" current_identity
  trap - EXIT
  case "${TEMPORARY_ROOT}" in "${TEMPORARY_PREFIX}"??????) ;; *) exit 1 ;; esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] || exit 1
  current_identity="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" || exit 1
  [[ "${current_identity}" == "${TEMPORARY_IDENTITY}" ]] || exit 1
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${status}"
}
trap cleanup EXIT

EXPECTED_CUSTODY_RECEIPT="${TEMPORARY_ROOT}/F1-CUSTODY.expected"
EXPECTED_CUSTODY_MANIFEST="${TEMPORARY_ROOT}/SHA256SUMS.expected"
readonly EXPECTED_CUSTODY_RECEIPT EXPECTED_CUSTODY_MANIFEST
cat >"${EXPECTED_CUSTODY_RECEIPT}" <<EOF
format=a-quo-x86_64-stage4-f1-root-custody-v1
repository=SurreptitiousFabric/a-quo
stage4_source_commit=${F1_SOURCE_COMMIT}
workflow_run_id=${F1_WORKFLOW_RUN_ID}
artifact_id=${F1_ARTIFACT_ID}
artifact_zip_sha256=${F1_ARTIFACT_ZIP_SHA256}
artifact_zip_bytes=${F1_ARTIFACT_ZIP_BYTES}
artifact_member_inventory_sha256=${F1_MEMBER_INVENTORY_SHA256}
package_sha256=${F1_PACKAGE_SHA256}
f1_lock_sha256=${F1_LOCK_SHA256}
download_action_commit=${F1_DOWNLOAD_ACTION_COMMIT}
root_custody=true
raw_zip_verified_before_mount=true
raw_zip_extracted_before_mount=false
mutable_by_offline_container=false
stage_5_executed=false
stage_6_authorized=false
physical_target_evidence=false
aarch64_gate_satisfied_by_x86_64=false
EOF
cmp -- "${EXPECTED_CUSTODY_RECEIPT}" "${F1_CUSTODY_RECEIPT}" ||
  fail_lifecycle 'root-custodied F1 receipt differs from its exact canonical bytes'
printf '%s  %s\n%s  %s\n' \
  "$(sha256sum -- "${F1_CUSTODY_RECEIPT}" | cut -d ' ' -f 1)" \
  F1-CUSTODY.txt "${F1_ARTIFACT_ZIP_SHA256}" artifact.zip \
  >"${EXPECTED_CUSTODY_MANIFEST}"
cmp -- "${EXPECTED_CUSTODY_MANIFEST}" "${F1_CUSTODY_MANIFEST}" ||
  fail_lifecycle 'root-custodied F1 checksum manifest is not the exact two-line relative manifest'
(cd -- "${EXPECTED_F1_ROOT}" && sha256sum --check --strict SHA256SUMS) ||
  fail_lifecycle 'root-custodied F1 relative checksum replay failed'
[[ "$(stat -c '%s' -- "${F1_ARCHIVE}")" == "${F1_ARTIFACT_ZIP_BYTES}" &&
  "$(sha256sum -- "${F1_ARCHIVE}" | cut -d ' ' -f 1)" == \
    "${F1_ARTIFACT_ZIP_SHA256}" ]] ||
  fail_lifecycle 'root-custodied F1 artifact identity changed'
F1_ARCHIVE_SNAPSHOT="${TEMPORARY_ROOT}/f1.zip"
readonly F1_ARCHIVE_SNAPSHOT
F1_METADATA_BEFORE="$(stat -c '%d:%i:%s:%f:%Y:%Z' -- "${F1_ARCHIVE}")"
dd if="${F1_ARCHIVE}" of="${F1_ARCHIVE_SNAPSHOT}" \
  bs=1048576 count=257 iflag=fullblock,nofollow status=none ||
  fail_lifecycle 'F1 artifact could not be privately snapshotted'
F1_METADATA_AFTER="$(stat -c '%d:%i:%s:%f:%Y:%Z' -- "${F1_ARCHIVE}")"
[[ "${F1_METADATA_BEFORE}" == "${F1_METADATA_AFTER}" &&
  "$(stat -c '%s:%h:%F' -- "${F1_ARCHIVE_SNAPSHOT}")" == \
    "${F1_ARTIFACT_ZIP_BYTES}:1:regular file" &&
  "$(sha256sum -- "${F1_ARCHIVE_SNAPSHOT}" | cut -d ' ' -f 1)" == \
    "${F1_ARTIFACT_ZIP_SHA256}" ]] ||
  fail_lifecycle 'private F1 artifact snapshot does not match the immutable lock'
chmod 0400 -- "${F1_ARCHIVE_SNAPSHOT}"

F1_INVENTORY="${TEMPORARY_ROOT}/f1-inventory"
F1_INVENTORY_SORTED="${TEMPORARY_ROOT}/f1-inventory.sorted"
F1_EXPECTED_INVENTORY="${TEMPORARY_ROOT}/f1-inventory.expected"
readonly F1_INVENTORY F1_INVENTORY_SORTED F1_EXPECTED_INVENTORY
bsdtar -tf "${F1_ARCHIVE_SNAPSHOT}" >"${F1_INVENTORY}" ||
  fail_lifecycle 'F1 artifact inventory is unreadable'
[[ "$(stat -c '%s' -- "${F1_INVENTORY}")" -le \
  "${MAXIMUM_ARCHIVE_INVENTORY_BYTES}" ]] ||
  fail_lifecycle 'F1 artifact inventory exceeds its closed byte bound'
[[ "$(tr -cd '\11\12\40-\176' <"${F1_INVENTORY}" | wc -c)" == \
  "$(stat -c '%s' -- "${F1_INVENTORY}")" ]] ||
  fail_lifecycle 'F1 artifact inventory contains a forbidden byte'
if grep -Eq '(^/|(^|/)\.\.(/|$)|\\)' "${F1_INVENTORY}"; then
  fail_lifecycle 'F1 artifact inventory contains an unsafe path'
fi
LC_ALL=C sort "${F1_INVENTORY}" >"${F1_INVENTORY_SORTED}"
[[ "$(wc -l <"${F1_INVENTORY_SORTED}")" == "${F1_MEMBER_COUNT}" &&
  "$(uniq "${F1_INVENTORY_SORTED}" | wc -l)" == "${F1_MEMBER_COUNT}" &&
  "$(sha256sum -- "${F1_INVENTORY_SORTED}" | cut -d ' ' -f 1)" == \
    "${F1_MEMBER_INVENTORY_SHA256}" ]] ||
  fail_lifecycle 'F1 artifact member count, uniqueness, or inventory digest changed'
printf '%s\n' \
  "a-quo/a-quo/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/.SRCINFO" \
  "a-quo/a-quo/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/PACKAGE-SKELETON-METADATA.txt" \
  "a-quo/a-quo/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/PKGBUILD" \
  "a-quo/a-quo/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/SHA256SUMS" \
  "a-quo/a-quo/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/${F1_PACKAGE_FILENAME}" \
  "a-quo/a-quo/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/a-quo-${F1_SOURCE_COMMIT}.tar" \
  "a-quo/a-quo/target/arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/SHA256SUMS" \
  "a-quo/a-quo/target/arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/STATIC-ACCEPTANCE.txt" \
  "a-quo/a-quo/target/arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}/VERIFIER-RECEIPT.txt" \
  "_temp/a-quo-arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}.hosted-acceptance/ACCEPTANCE-SHA256SUMS" \
  "_temp/a-quo-arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}.hosted-acceptance/HOSTED-ACCEPTANCE.txt" \
  "_temp/a-quo-arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}.hosted-preflight/HOSTED-PREFLIGHT.txt" \
  "_temp/a-quo-arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}.hosted-preflight/OFFLINE-CONTAINER-CONFIG.json" \
  "_temp/a-quo-arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}.hosted-preflight/OFFLINE-CONTAINER-INSPECT.json" \
  "_temp/a-quo-arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}.hosted-preflight/PREFLIGHT-SHA256SUMS" |
  LC_ALL=C sort >"${F1_EXPECTED_INVENTORY}"
cmp -- "${F1_EXPECTED_INVENTORY}" "${F1_INVENTORY_SORTED}" ||
  fail_lifecycle 'F1 artifact inventory differs from the reviewed exact 15 members'
[[ "$(bsdtar -tvf "${F1_ARCHIVE_SNAPSHOT}" | awk 'substr($1,1,1) != "-" {bad += 1} END {print bad + 0}')" == 0 ]] ||
  fail_lifecycle 'F1 artifact contains a symlink or special member'

F1_EXTRACTED="${TEMPORARY_ROOT}/f1-extracted"
readonly F1_EXTRACTED
mkdir -m 0700 -- "${F1_EXTRACTED}"
bsdtar --no-same-owner --no-same-permissions -xf \
  "${F1_ARCHIVE_SNAPSHOT}" -C "${F1_EXTRACTED}" ||
  fail_lifecycle 'F1 artifact extraction failed'
[[ "$(find "${F1_EXTRACTED}" -type f | wc -l)" == "${F1_MEMBER_COUNT}" &&
  "$(find "${F1_EXTRACTED}" ! -type f ! -type d | wc -l)" == 0 ]] ||
  fail_lifecycle 'F1 extraction created an unexpected file type or count'
while IFS= read -r extracted_file; do
  [[ ! -L "${extracted_file}" &&
    "$(stat -c '%h:%F' -- "${extracted_file}")" == '1:regular file' ]] ||
    fail_lifecycle "F1 extraction contains a link or unsafe file: ${extracted_file}"
done < <(find "${F1_EXTRACTED}" -type f -print)

F1_PACKAGE_ROOT="${F1_EXTRACTED}/a-quo/a-quo/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}"
F1_ACCEPTANCE_ROOT="${F1_EXTRACTED}/a-quo/a-quo/target/arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}"
F1_PREFLIGHT_ROOT="${F1_EXTRACTED}/_temp/a-quo-arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}.hosted-preflight"
F1_HOSTED_ROOT="${F1_EXTRACTED}/_temp/a-quo-arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${F1_SOURCE_COMMIT}.hosted-acceptance"
F1_PACKAGE="${F1_PACKAGE_ROOT}/${F1_PACKAGE_FILENAME}"
readonly F1_PACKAGE_ROOT F1_ACCEPTANCE_ROOT F1_PREFLIGHT_ROOT F1_HOSTED_ROOT F1_PACKAGE
(cd -- "${F1_PACKAGE_ROOT}" && sha256sum --check --strict SHA256SUMS) ||
  fail_lifecycle 'F1 package ledger failed after private extraction'
(cd -- "${F1_ACCEPTANCE_ROOT}" && sha256sum --check --strict SHA256SUMS) ||
  fail_lifecycle 'F1 static-acceptance ledger failed after private extraction'
(cd -- "${F1_PREFLIGHT_ROOT}" && sha256sum --check --strict PREFLIGHT-SHA256SUMS) ||
  fail_lifecycle 'F1 preflight ledger failed after private extraction'
(cd -- "${F1_HOSTED_ROOT}" && sha256sum --check --strict ACCEPTANCE-SHA256SUMS) ||
  fail_lifecycle 'F1 hosted-acceptance ledger failed after private extraction'
[[ "$(sha256sum -- "${F1_PACKAGE}" | cut -d ' ' -f 1)" == "${F1_PACKAGE_SHA256}" &&
  "$(sha256sum -- "${F1_ACCEPTANCE_ROOT}/STATIC-ACCEPTANCE.txt" | cut -d ' ' -f 1)" == "${F1_STATIC_ACCEPTANCE_SHA256}" &&
  "$(sha256sum -- "${F1_ACCEPTANCE_ROOT}/VERIFIER-RECEIPT.txt" | cut -d ' ' -f 1)" == "${F1_VERIFIER_RECEIPT_SHA256}" &&
  "$(sha256sum -- "${F1_HOSTED_ROOT}/HOSTED-ACCEPTANCE.txt" | cut -d ' ' -f 1)" == "${F1_HOSTED_ACCEPTANCE_SHA256}" &&
  "$(sha256sum -- "${F1_HOSTED_ROOT}/ACCEPTANCE-SHA256SUMS" | cut -d ' ' -f 1)" == "${F1_OUTER_MANIFEST_SHA256}" ]] ||
  fail_lifecycle 'F1 package or reviewed receipt bytes changed after extraction'

for accepted_receipt in \
  "${F1_ACCEPTANCE_ROOT}/STATIC-ACCEPTANCE.txt" \
  "${F1_HOSTED_ROOT}/HOSTED-ACCEPTANCE.txt"; do
  for claim in \
    "policy_commit=${F1_SOURCE_COMMIT}" \
    "profile_id=${EXPECTED_PROFILE_ID}" \
    "profile_sha256=${EXPECTED_PROFILE_SHA256}" \
    "architecture=${EXPECTED_ARCHITECTURE}" \
    "evidence_namespace=${EXPECTED_NAMESPACE}" \
    "package_sha256=${F1_PACKAGE_SHA256}" \
    'package_static_acceptance=true' 'stage_4_completed=true' \
    'stage_5_executed=false' 'stage_6_authorized=false' \
    'physical_target_evidence=false' \
    'aarch64_gate_satisfied_by_x86_64=false'; do
    [[ "$(grep -Fxc -- "${claim}" "${accepted_receipt}")" -eq 1 ]] ||
      fail_lifecycle "F1 accepted receipt lost exact claim: ${claim}"
  done
done

F2_PACKAGE_ROOT="${EXPECTED_WORKSPACE}/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${SOURCE_HEAD}"
LIFECYCLE_ROOT="${EXPECTED_WORKSPACE}/target/arch-package-isolated-lifecycle/${EXPECTED_NAMESPACE}/${SOURCE_HEAD}"
readonly F2_PACKAGE_ROOT LIFECYCLE_ROOT
[[ ! -e "${F2_PACKAGE_ROOT}" && ! -L "${F2_PACKAGE_ROOT}" &&
  ! -e "${LIFECYCLE_ROOT}" && ! -L "${LIFECYCLE_ROOT}" ]] ||
  fail_lifecycle 'F2 package or lifecycle evidence root already exists'
[[ ! -e "${EXPECTED_WORKSPACE}/target/arch-package-isolated-lifecycle" &&
  ! -L "${EXPECTED_WORKSPACE}/target/arch-package-isolated-lifecycle" ]] ||
  fail_lifecycle 'isolated lifecycle output parent unexpectedly exists'

"${BUILDER}" "${PROFILE}" >"${TEMPORARY_ROOT}/builder-receipt.txt" ||
  fail_lifecycle 'F2 package build/static verification failed'
[[ "$(stat -c '%s' -- "${TEMPORARY_ROOT}/builder-receipt.txt")" -ge 1 &&
  "$(stat -c '%s' -- "${TEMPORARY_ROOT}/builder-receipt.txt")" -le \
    "${MAXIMUM_RECEIPT_BYTES}" ]] ||
  fail_lifecycle 'F2 builder/verifier receipt exceeds its closed byte bound'
for builder_claim in \
  "profile_id=${EXPECTED_PROFILE_ID}" \
  "profile_sha256=${EXPECTED_PROFILE_SHA256}" \
  'profile_binding_role=package-target-policy' \
  'package_target_kind=physical-bare-metal' \
  "architecture=${EXPECTED_ARCHITECTURE}" \
  'verification_host_architecture=x86_64' \
  'verification_host_profile_match=not-established' \
  'native_hardware_claim=not-established' \
  'physical_target_evidence=false' \
  "evidence_namespace=${EXPECTED_NAMESPACE}" \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  [[ "$(grep -Fxc -- "${builder_claim}" \
    "${TEMPORARY_ROOT}/builder-receipt.txt")" -eq 1 ]] ||
    fail_lifecycle "F2 builder/verifier receipt lost exact claim: ${builder_claim}"
done
[[ -d "${F2_PACKAGE_ROOT}" && ! -L "${F2_PACKAGE_ROOT}" ]] ||
  fail_lifecycle 'F2 package output root is unavailable or unsafe'
for package_directory in \
  "${EXPECTED_WORKSPACE}/target/arch-package-skeleton" \
  "${EXPECTED_WORKSPACE}/target/arch-package-skeleton/${EXPECTED_NAMESPACE}" \
  "${F2_PACKAGE_ROOT}"; do
  require_safe_user_directory "${package_directory}" 700
done
mapfile -t f2_packages < <(find "${F2_PACKAGE_ROOT}" -mindepth 1 -maxdepth 1 \
  -type f -name 'a-quo-*-x86_64.pkg.tar.zst' -print)
(( ${#f2_packages[@]} == 1 )) ||
  fail_lifecycle 'F2 build did not produce exactly one x86_64 package'
F2_PACKAGE="${f2_packages[0]}"
F2_PACKAGE_SHA256="$(sha256sum -- "${F2_PACKAGE}" | cut -d ' ' -f 1)"
readonly F2_PACKAGE F2_PACKAGE_SHA256
[[ "${F2_PACKAGE_SHA256}" =~ ^[0-9a-f]{64}$ &&
  "${F2_PACKAGE_SHA256}" != "${F1_PACKAGE_SHA256}" &&
  "$(stat -c '%h:%F' -- "${F2_PACKAGE}")" == '1:regular file' ]] ||
  fail_lifecycle 'F2 package identity is unsafe or not distinct from F1'
[[ "$(grep -Fxc -- \
  "non-publishable package skeleton written to: ${F2_PACKAGE_ROOT}" \
  "${TEMPORARY_ROOT}/builder-receipt.txt")" -eq 1 ]] ||
  fail_lifecycle 'F2 builder/verifier receipt does not name the exact output root'

SMOKE_RECEIPT="${TEMPORARY_ROOT}/UPGRADE-SMOKE-RECEIPT.txt"
SMOKE_STDERR="${TEMPORARY_ROOT}/UPGRADE-SMOKE-STDERR.txt"
readonly SMOKE_RECEIPT SMOKE_STDERR
set +e
env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_SYSTEM -u GIT_CONFIG_NOSYSTEM \
  -u GIT_OPTIONAL_LOCKS "${UPGRADE_SMOKE}" \
  "${F1_PACKAGE}" "${F1_PACKAGE_SHA256}" "${F1_SOURCE_COMMIT}" \
  "${F2_PACKAGE}" "${F2_PACKAGE_SHA256}" "${SOURCE_HEAD}" "${PROFILE}" \
  >"${SMOKE_RECEIPT}" 2>"${SMOKE_STDERR}"
smoke_status="$?"
set -e
[[ "${smoke_status}" -eq 0 && ! -s "${SMOKE_STDERR}" &&
  "$(stat -c '%s' -- "${SMOKE_RECEIPT}")" -le "${MAXIMUM_RECEIPT_BYTES}" ]] ||
  fail_lifecycle 'unchanged package-transition smoke failed or emitted unsafe output'
[[ "$(grep -Fxc -- \
  'passed isolated fakeroot/libalpm old-to-new transition, removal, and reinstall' \
  "${SMOKE_RECEIPT}")" -eq 1 ]] ||
  fail_lifecycle 'package-transition smoke success marker is missing or duplicated'
SMOKE_FINAL="${TEMPORARY_ROOT}/UPGRADE-SMOKE-FINAL.txt"
readonly SMOKE_FINAL
sed -n '/^passed isolated fakeroot\/libalpm old-to-new transition, removal, and reinstall$/,$p' \
  "${SMOKE_RECEIPT}" >"${SMOKE_FINAL}"
for smoke_claim in \
  "profile_id=${EXPECTED_PROFILE_ID}" \
  "profile_sha256=${EXPECTED_PROFILE_SHA256}" \
  "architecture=${EXPECTED_ARCHITECTURE}" \
  "evidence_namespace=${EXPECTED_NAMESPACE}" \
  "policy_commit=${SOURCE_HEAD}" \
  "old_source_commit=${F1_SOURCE_COMMIT}" \
  "old_package_sha256=${F1_PACKAGE_SHA256}" \
  "new_source_commit=${SOURCE_HEAD}" \
  "new_package_sha256=${F2_PACKAGE_SHA256}" \
  'lifecycle_root=private-alternate-fakeroot-libalpm' \
  'package_transition_tested=isolated-fakeroot-libalpm' \
  'caller_pinned_package_sha256_matched=true' \
  'user_state_preserved=true' \
  'network_or_repository_sync_performed=false' \
  'real_root_ownership_tested=false' \
  'live_package_upgrade_tested=false' \
  'physical_omarchy_state_changed=false' \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  [[ "$(grep -Fxc -- "${smoke_claim}" "${SMOKE_FINAL}")" -eq 1 ]] ||
    fail_lifecycle "package-transition receipt lost exact claim: ${smoke_claim}"
done

install -d -m 0755 -- \
  "${EXPECTED_WORKSPACE}/target/arch-package-isolated-lifecycle"
require_safe_user_directory \
  "${EXPECTED_WORKSPACE}/target/arch-package-isolated-lifecycle" 755
install -d -m 0755 -- \
  "${EXPECTED_WORKSPACE}/target/arch-package-isolated-lifecycle/${EXPECTED_NAMESPACE}"
require_safe_user_directory \
  "${EXPECTED_WORKSPACE}/target/arch-package-isolated-lifecycle/${EXPECTED_NAMESPACE}" 755
install -d -m 0755 -- "${LIFECYCLE_ROOT}"
require_safe_user_directory "${LIFECYCLE_ROOT}" 755
install -m 0644 -- "${SMOKE_RECEIPT}" \
  "${LIFECYCLE_ROOT}/UPGRADE-SMOKE-RECEIPT.txt"
install -m 0644 -- "${TEMPORARY_ROOT}/builder-receipt.txt" \
  "${LIFECYCLE_ROOT}/F2-BUILDER-VERIFIER-RECEIPT.txt"
SMOKE_RECEIPT_SHA256="$(sha256sum -- "${LIFECYCLE_ROOT}/UPGRADE-SMOKE-RECEIPT.txt" | cut -d ' ' -f 1)"
readonly SMOKE_RECEIPT_SHA256
F2_BUILDER_VERIFIER_RECEIPT_SHA256="$(sha256sum -- \
  "${LIFECYCLE_ROOT}/F2-BUILDER-VERIFIER-RECEIPT.txt" | cut -d ' ' -f 1)"
readonly F2_BUILDER_VERIFIER_RECEIPT_SHA256
F2_PACKAGE_FILENAME="$(basename -- "${F2_PACKAGE}")"
readonly F2_PACKAGE_FILENAME
cat >"${LIFECYCLE_ROOT}/LIFECYCLE-RECEIPT.txt" <<EOF
format=a-quo-x86_64-isolated-package-lifecycle-v1
policy_commit=${SOURCE_HEAD}
profile_id=${EXPECTED_PROFILE_ID}
profile_sha256=${EXPECTED_PROFILE_SHA256}
profile_binding_role=package-target-policy
package_target_kind=physical-bare-metal
architecture=${EXPECTED_ARCHITECTURE}
evidence_namespace=${EXPECTED_NAMESPACE}
execution_environment=architecture-matched-hosted-container
execution_host_profile_match=not-established
native_hardware_claim=not-established
observation_authority=none
package_source_to_binary_provenance_established=false
dependency_closure_established=false
package_signature_verified=false
package_scriptlets_executed=false
package_hooks_executed=false
network_or_repository_sync_performed=false
f1_lock_sha256=${F1_LOCK_SHA256}
f1_source_commit=${F1_SOURCE_COMMIT}
f1_artifact_id=${F1_ARTIFACT_ID}
f1_artifact_zip_sha256=${F1_ARTIFACT_ZIP_SHA256}
f1_package_filename=${F1_PACKAGE_FILENAME}
f1_package_sha256=${F1_PACKAGE_SHA256}
f2_source_commit=${SOURCE_HEAD}
f2_package_filename=${F2_PACKAGE_FILENAME}
f2_package_sha256=${F2_PACKAGE_SHA256}
f2_builder_verifier_receipt_sha256=${F2_BUILDER_VERIFIER_RECEIPT_SHA256}
upgrade_smoke_sha256=48414a001bee094422790417e86eb950ae044db4258ef9d150b86f8a98e77f71
upgrade_smoke_receipt_sha256=${SMOKE_RECEIPT_SHA256}
lifecycle_root=private-alternate-fakeroot-libalpm
transaction_sequence=install-upgrade-remove-reinstall
four_private_transactions_succeeded=true
package_transition_tested=isolated-fakeroot-libalpm
real_pacman_bridge_executed=false
real_root_execution=false
real_system_state_mutated=false
physical_omarchy_state_changed=false
physical_target_evidence=false
stage_4_f1_accepted=true
stage_5_executed=true
stage_6_authorized=false
installed_core_evaluator_executed=false
consent_evaluator_executed=false
plugin_lifecycle_executed=false
enablement_executed=false
interruption_tested=false
rollback_failure_tested=false
power_loss_tested=false
cross_profile_evidence_accepted=false
aarch64_gate_satisfied_by_x86_64=false
publication_performed=false
EOF
chmod 0644 -- "${LIFECYCLE_ROOT}/LIFECYCLE-RECEIPT.txt"
(
  cd -- "${LIFECYCLE_ROOT}"
  sha256sum F2-BUILDER-VERIFIER-RECEIPT.txt LIFECYCLE-RECEIPT.txt \
    UPGRADE-SMOKE-RECEIPT.txt >SHA256SUMS
  chmod 0644 SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)

[[ "$(git -C "${EXPECTED_WORKSPACE}" rev-parse --verify HEAD)" == "${SOURCE_HEAD}" &&
  -z "$(git -C "${EXPECTED_WORKSPACE}" -c core.fsmonitor=false \
    status --porcelain=v1 --untracked-files=normal)" ]] ||
  fail_lifecycle 'source repository changed during isolated lifecycle'
[[ "$(sha256sum -- "${F1_ARCHIVE}" | cut -d ' ' -f 1)" == \
  "${F1_ARTIFACT_ZIP_SHA256}" ]] ||
  fail_lifecycle 'root-custodied F1 artifact changed during isolated lifecycle'

cat -- "${LIFECYCLE_ROOT}/LIFECYCLE-RECEIPT.txt"
cd -- "${LIFECYCLE_ROOT}"
exec sha256sum --check --strict SHA256SUMS
