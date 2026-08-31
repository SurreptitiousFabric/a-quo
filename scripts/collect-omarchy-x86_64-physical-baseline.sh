#!/usr/bin/env bash
# shellcheck disable=SC2016

set -euo pipefail
export LC_ALL=C
umask 077

# This collector is intentionally standalone and stdout-only. Keep every tool
# path absolute so the physical-target run does not consult Mise, a login
# shell, aliases, functions, or caller-selected executables.
readonly TOOL_ROOT=/usr/bin
readonly ETC_ROOT=/etc
readonly PROC_ROOT=/proc
readonly SYS_ROOT=/sys
readonly RUN_ROOT=/run
readonly USR_ROOT=/usr

readonly AWK="${TOOL_ROOT}/awk"
readonly FIND="${TOOL_ROOT}/find"
readonly GREP="${TOOL_ROOT}/grep"
readonly HYPRCTL="${TOOL_ROOT}/hyprctl"
readonly LOGINCTL="${TOOL_ROOT}/loginctl"
readonly PACMAN="${TOOL_ROOT}/pacman"
readonly PACMAN_CONF="${TOOL_ROOT}/pacman-conf"
readonly READLINK="${TOOL_ROOT}/readlink"
readonly SHA256SUM="${TOOL_ROOT}/sha256sum"
readonly SORT="${TOOL_ROOT}/sort"
readonly STAT="${TOOL_ROOT}/stat"
readonly SYSTEMCTL="${TOOL_ROOT}/systemctl"
readonly UNAME="${TOOL_ROOT}/uname"

readonly PROFILE_ID=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1
readonly PROFILE_SHA256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d
readonly EVIDENCE_NAMESPACE=physical-x86_64-official-omarchy-4.0.2
readonly COLLECTOR_REPOSITORY_PATH=scripts/collect-omarchy-x86_64-physical-baseline.sh
readonly MAXIMUM_COMMAND_OUTPUT_BYTES=1048576
readonly EXPECTED_DESKTOP_UID=1000
readonly PROFILE_RUNTIME_DIRECTORY=/run/user/1000

fail() {
  printf 'Omarchy x86_64 read-only baseline collection refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s\n' "${0##*/}" >&2
  exit 2
}

[[ "$#" -eq 0 ]] || usage
(( EUID != 0 )) || fail 'collector must run as the ordinary desktop user'
(( EUID == EXPECTED_DESKTOP_UID )) ||
  fail 'collector user differs from the frozen desktop UID'
for inherited_override in BASH_ENV ENV CDPATH GLOBIGNORE; do
  [[ ! -v "${inherited_override}" ]] ||
    fail "refusing inherited shell override: ${inherited_override}"
done

for required_tool in \
  "${AWK}" "${FIND}" "${GREP}" "${HYPRCTL}" "${LOGINCTL}" \
  "${PACMAN}" "${PACMAN_CONF}" "${READLINK}" "${SHA256SUM}" "${SORT}" "${STAT}" \
  "${SYSTEMCTL}" "${UNAME}"; do
  [[ -x "${required_tool}" ]] ||
    fail "required direct read-only tool is unavailable: ${required_tool}"
done

readonly COLLECTOR_PATH="${BASH_SOURCE[0]}"
[[ -f "${COLLECTOR_PATH}" && ! -L "${COLLECTOR_PATH}" ]] ||
  fail 'collector must be one regular non-symlink file'
COLLECTOR_METADATA_BEFORE="$("${STAT}" -c '%d:%i:%s:%f:%Y:%h' -- "${COLLECTOR_PATH}")" ||
  fail 'collector metadata is unavailable'
readonly COLLECTOR_METADATA_BEFORE
[[ "${COLLECTOR_METADATA_BEFORE##*:}" == 1 ]] ||
  fail 'collector must have exactly one hard link'
COLLECTOR_SHA256="$("${SHA256SUM}" -- "${COLLECTOR_PATH}")" ||
  fail 'collector hash is unavailable'
COLLECTOR_SHA256="${COLLECTOR_SHA256%% *}"
readonly COLLECTOR_SHA256
[[ "${COLLECTOR_SHA256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'collector hash is malformed'

readonly OS_RELEASE="${ETC_ROOT}/os-release"
readonly CPU_INFO="${PROC_ROOT}/cpuinfo"
readonly HARDWARE_VENDOR_PATH="${SYS_ROOT}/devices/virtual/dmi/id/sys_vendor"
readonly HARDWARE_MODEL_PATH="${SYS_ROOT}/devices/virtual/dmi/id/product_name"
readonly PACMAN_LOCK="${RUN_ROOT}/../var/lib/pacman/db.lck"
readonly DISPOSABLE_MARKER="${ETC_ROOT}/a-quo/disposable-omarchy-evaluator-v1"
readonly EVALUATOR_PASSWD="${ETC_ROOT}/passwd"
readonly BRIDGE_LOCK_DIRECTORY="${RUN_ROOT}/a-quo-package-evaluator"

for required_file in \
  "${CPU_INFO}" "${HARDWARE_VENDOR_PATH}" \
  "${HARDWARE_MODEL_PATH}" "${EVALUATOR_PASSWD}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] ||
    fail "required observation input is unavailable or unsafe: ${required_file}"
done
if [[ -L "${OS_RELEASE}" ]]; then
  [[ "$("${READLINK}" -f -- "${OS_RELEASE}")" == "${USR_ROOT}/lib/os-release" ]] ||
    fail 'OS release symlink does not resolve to the fixed vendor path'
elif [[ ! -f "${OS_RELEASE}" ]]; then
  fail 'OS release input is unavailable'
fi
[[ "$("${STAT}" -L -c '%u:%g:%F:%h' -- "${OS_RELEASE}")" == \
  '0:0:regular file:1' ]] || fail 'OS release target metadata is unsafe'

bounded_output() {
  local label="$1"
  local value="$2"
  (( ${#value} <= MAXIMUM_COMMAND_OUTPUT_BYTES )) ||
    fail "${label} output exceeds the closed bound"
  [[ "${value}" != *$'\r'* ]] || fail "${label} output contains CR bytes"
}

sha256_file() {
  local path="$1"
  local result
  result="$("${SHA256SUM}" -- "${path}")" || return 1
  result="${result%% *}"
  [[ "${result}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${result}"
}

package_query() {
  local package="$1"
  local result
  result="$("${PACMAN}" -Q -- "${package}")" ||
    fail "installed package query failed: ${package}"
  bounded_output "package ${package}" "${result}"
  [[ "${result}" == "${package} "* && "${result}" != *$'\n'* ]] ||
    fail "installed package query is malformed: ${package}"
  printf '%s\n' "${result}"
}

package_architecture() {
  local package="$1"
  local result
  result="$("${PACMAN}" -Qi -- "${package}")" ||
    fail "installed package metadata query failed: ${package}"
  bounded_output "package metadata ${package}" "${result}"
  result="$("${AWK}" -F ':[[:space:]]*' \
    '$1 ~ /^Architecture[[:space:]]*$/ { print $2 }' <<<"${result}")"
  [[ -n "${result}" && "${result}" != *$'\n'* && "${result}" != *' '* ]] ||
    fail "installed package architecture is malformed: ${package}"
  printf '%s\n' "${result}"
}

package_upstream_version() {
  local query="$1"
  local version="${query#* }"
  version="${version%%-*}"
  version="${version%%+*}"
  [[ "${version}" =~ ^[0-9]+\.[0-9]+([.][0-9]+)?$ ]] ||
    fail "package upstream version is malformed: ${query%% *}"
  printf '%s\n' "${version}"
}

read_single_line() {
  local path="$1"
  local value
  IFS= read -r value <"${path}" || fail "could not read: ${path}"
  [[ -n "${value}" && ${#value} -le 256 && "${value}" != *'='* &&
    "${value}" != *$'\r'* ]] || fail "single-line input is malformed: ${path}"
  printf '%s\n' "${value}"
}

environment_value() {
  local environment_record="$1"
  local name="$2"
  local value
  value="$("${AWK}" -v name="${name}" \
    'index($0, name "=") == 1 { if (seen++) exit 2; print substr($0, length(name) + 2) } END { if (!seen) exit 1 }' \
    <<<"${environment_record}")" || fail "user-manager environment lacks ${name}"
  [[ -n "${value}" && ${#value} -le 4096 && "${value}" != *$'\n'* &&
    "${value}" != *$'\r'* ]] || fail "user-manager environment value is malformed: ${name}"
  printf '%s\n' "${value}"
}

HARDWARE_VENDOR_RAW="$(read_single_line "${HARDWARE_VENDOR_PATH}")"
readonly HARDWARE_VENDOR_RAW
[[ "${HARDWARE_VENDOR_RAW}" == Apple* ]] || fail 'hardware vendor is not Apple'
readonly HARDWARE_VENDOR=Apple
HARDWARE_MODEL="$(read_single_line "${HARDWARE_MODEL_PATH}")"
readonly HARDWARE_MODEL

CPU_SUMMARY="$("${AWK}" -F: '
  function trim(value) { sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); return value }
  /^processor[[:space:]]*:/ { threads += 1 }
  /^cpu cores[[:space:]]*:/ { value = trim($2); if (cores == "") cores = value; else if (cores != value) exit 2 }
  /^model name[[:space:]]*:/ { value = trim($2); if (index(value, "i5-5250U") == 0) exit 3; models += 1 }
  END { if (threads < 1 || cores !~ /^[1-9][0-9]*$/ || models != threads) exit 4; printf "%s:%s\n", cores, threads }
' "${CPU_INFO}")" || fail 'CPU topology/model observation failed'
readonly CPU_SUMMARY
readonly CPU_CORE_COUNT="${CPU_SUMMARY%%:*}"
readonly CPU_THREAD_COUNT="${CPU_SUMMARY#*:}"
readonly CPU_MODEL=Intel-Core-i5-5250U

OS_NAME="$("${AWK}" -F= '$1 == "NAME" { value=$2; gsub(/^"|"$/, "", value); print value }' "${OS_RELEASE}")"
OS_VERSION="$("${AWK}" -F= '$1 == "VERSION" { value=$2; gsub(/^"|"$/, "", value); print value }' "${OS_RELEASE}")"
readonly OS_NAME OS_VERSION
[[ "${OS_NAME}" == Omarchy && "${OS_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail 'OS release identity is malformed'
OS_RELEASE_SHA256="$(sha256_file "${OS_RELEASE}")"
readonly OS_RELEASE_SHA256
ARCHITECTURE="$("${UNAME}" -m)"
readonly ARCHITECTURE
KERNEL_RELEASE="$("${UNAME}" -r)"
readonly KERNEL_RELEASE
[[ "${ARCHITECTURE}" =~ ^[A-Za-z0-9_.-]+$ &&
  "${KERNEL_RELEASE}" =~ ^[A-Za-z0-9_.+-]+$ ]] ||
  fail 'kernel observation is malformed'

PACKAGE_QUERY_BEFORE="$("${PACMAN}" -Q)" || fail 'complete package query failed'
bounded_output 'complete package query' "${PACKAGE_QUERY_BEFORE}"
PACKAGE_COUNT="$("${AWK}" 'NF == 2 { count += 1; next } { exit 2 } END { print count }' \
  <<<"${PACKAGE_QUERY_BEFORE}")" || fail 'complete package query is malformed'
readonly PACKAGE_COUNT
PACKAGE_QUERY_SHA256_BEFORE="$(printf '%s\n' "${PACKAGE_QUERY_BEFORE}" |
  "${SORT}" | "${SHA256SUM}")" || fail 'complete package-query hash failed'
PACKAGE_QUERY_SHA256_BEFORE="${PACKAGE_QUERY_SHA256_BEFORE%% *}"
readonly PACKAGE_QUERY_SHA256_BEFORE

OMARCHY_QUERY="$(package_query omarchy)"
readonly OMARCHY_QUERY
OMARCHY_SETTINGS_QUERY="$(package_query omarchy-settings)"
readonly OMARCHY_SETTINGS_QUERY
GLIBC_QUERY="$(package_query glibc)"
readonly GLIBC_QUERY
PACMAN_QUERY="$(package_query pacman)"
readonly PACMAN_QUERY
HYPRLAND_QUERY="$(package_query hyprland)"
readonly HYPRLAND_QUERY
QUICKSHELL_QUERY="$(package_query quickshell)"
readonly QUICKSHELL_QUERY
UWSM_QUERY="$(package_query uwsm)"
readonly UWSM_QUERY
SYSTEMD_QUERY="$(package_query systemd)"
readonly SYSTEMD_QUERY
GLIBC_VERSION="$(package_upstream_version "${GLIBC_QUERY}")"
readonly GLIBC_VERSION
readonly PACMAN_VERSION="${PACMAN_QUERY#* }"
HYPRLAND_VERSION="$(package_upstream_version "${HYPRLAND_QUERY}")"
readonly HYPRLAND_VERSION
QUICKSHELL_VERSION="$(package_upstream_version "${QUICKSHELL_QUERY}")"
readonly QUICKSHELL_VERSION
UWSM_VERSION="$(package_upstream_version "${UWSM_QUERY}")"
readonly UWSM_VERSION
readonly SYSTEMD_VERSION="${SYSTEMD_QUERY#* }"
OMARCHY_ARCHITECTURE="$(package_architecture omarchy)"
readonly OMARCHY_ARCHITECTURE
OMARCHY_SETTINGS_ARCHITECTURE="$(package_architecture omarchy-settings)"
readonly OMARCHY_SETTINGS_ARCHITECTURE

PACMAN_ARCHITECTURE="$("${PACMAN_CONF}" Architecture)" ||
  fail 'pacman architecture query failed'
readonly PACMAN_ARCHITECTURE
[[ "${PACMAN_ARCHITECTURE}" =~ ^[A-Za-z0-9_]+$ ]] ||
  fail 'pacman architecture is malformed'
PACMAN_REPOSITORIES="$("${PACMAN_CONF}" --repo-list)" ||
  fail 'pacman repository query failed'
bounded_output 'pacman repository' "${PACMAN_REPOSITORIES}"
PACMAN_REPOSITORY_NAME_SET="$("${AWK}" 'NF == 1 { if (seen++) printf ","; printf "%s", $1; next } { exit 2 } END { print "" }' \
  <<<"${PACMAN_REPOSITORIES}")" || fail 'pacman repository set is malformed'
readonly PACMAN_REPOSITORY_NAME_SET

set +e
PACMAN_DATABASE_OUTPUT="$("${PACMAN}" -Dk 2>&1)"
PACMAN_DATABASE_STATUS="$?"
set -e
bounded_output 'pacman database consistency' "${PACMAN_DATABASE_OUTPUT}"
[[ "${PACMAN_DATABASE_STATUS}" -eq 0 ]] || fail 'pacman database consistency check failed'
readonly PACMAN_DATABASE_CONSISTENCY=consistent
[[ ! -e "${PACMAN_LOCK}" && ! -L "${PACMAN_LOCK}" ]] ||
  fail 'pacman database lock is present before collection'
readonly PACMAN_LOCK_STATE=absent

CACHE_DIRECTORIES="$("${PACMAN_CONF}" CacheDir)" || fail 'pacman cache query failed'
bounded_output 'pacman cache' "${CACHE_DIRECTORIES}"
declare -a omarchy_archives=()
declare -a settings_archives=()
while IFS= read -r cache_directory; do
  [[ "${cache_directory}" == /* && "${cache_directory}" != *$'\r'* ]] ||
    fail 'pacman cache path is malformed'
  omarchy_archive="${cache_directory%/}/${OMARCHY_QUERY/ /-}-${OMARCHY_ARCHITECTURE}.pkg.tar.zst"
  settings_archive="${cache_directory%/}/${OMARCHY_SETTINGS_QUERY/ /-}-${OMARCHY_SETTINGS_ARCHITECTURE}.pkg.tar.zst"
  [[ ! -L "${omarchy_archive}" ]] || fail 'Omarchy package archive is a symlink'
  [[ ! -L "${settings_archive}" ]] || fail 'Omarchy settings archive is a symlink'
  [[ ! -f "${omarchy_archive}" ]] || omarchy_archives+=("${omarchy_archive}")
  [[ ! -f "${settings_archive}" ]] || settings_archives+=("${settings_archive}")
done <<<"${CACHE_DIRECTORIES}"
[[ "${#omarchy_archives[@]}" -eq 1 && "${#settings_archives[@]}" -eq 1 ]] ||
  fail 'expected exactly one cached archive for each Omarchy package'
OMARCHY_ARCHIVE_SHA256="$(sha256_file "${omarchy_archives[0]}")"
readonly OMARCHY_ARCHIVE_SHA256
OMARCHY_SETTINGS_ARCHIVE_SHA256="$(sha256_file "${settings_archives[0]}")"
readonly OMARCHY_SETTINGS_ARCHIVE_SHA256

set +e
OMARCHY_QKK="$("${PACMAN}" -Qkk -- omarchy 2>&1)"
OMARCHY_QKK_STATUS="$?"
OMARCHY_SETTINGS_QKK="$("${PACMAN}" -Qkk -- omarchy-settings 2>&1)"
OMARCHY_SETTINGS_QKK_STATUS="$?"
set -e
bounded_output 'omarchy file verification' "${OMARCHY_QKK}"
bounded_output 'omarchy-settings file verification' "${OMARCHY_SETTINGS_QKK}"
[[ "${OMARCHY_QKK_STATUS}" -eq 0 && "${OMARCHY_SETTINGS_QKK_STATUS}" -eq 0 ]] ||
  fail 'installed Omarchy package verification failed'
OMARCHY_ALTERED_COUNT="$("${AWK}" '/^omarchy: [0-9]+ total files, [0-9]+ altered files$/ { print $(NF - 2) }' <<<"${OMARCHY_QKK}")"
OMARCHY_SETTINGS_ALTERED_COUNT="$("${AWK}" '/^omarchy-settings: [0-9]+ total files, [0-9]+ altered files$/ { print $(NF - 2) }' <<<"${OMARCHY_SETTINGS_QKK}")"
OMARCHY_SETTINGS_UNVERIFIED_COUNT="$("${AWK}" 'index($0, "Permission denied") { count += 1 } END { print count + 0 }' <<<"${OMARCHY_SETTINGS_QKK}")"
readonly OMARCHY_ALTERED_COUNT OMARCHY_SETTINGS_ALTERED_COUNT OMARCHY_SETTINGS_UNVERIFIED_COUNT
for count in \
  "${OMARCHY_ALTERED_COUNT}" "${OMARCHY_SETTINGS_ALTERED_COUNT}" \
  "${OMARCHY_SETTINGS_UNVERIFIED_COUNT}"; do
  [[ "${count}" =~ ^[0-9]+$ ]] || fail 'package file-verification summary is malformed'
done

for omarchy_command in \
  "${USR_ROOT}/bin/omarchy-plugin-validate" "${USR_ROOT}/bin/omarchy-shell"; do
  [[ "$("${STAT}" -c '%u:%g:%a:%F:%h' -- "${omarchy_command}")" == \
    '0:0:755:regular file:1' ]] || fail "Omarchy command metadata is unsafe: ${omarchy_command}"
  command_owner="$("${PACMAN}" -Qo -- "${omarchy_command}")" ||
    fail "Omarchy command has no package owner: ${omarchy_command}"
  [[ "${command_owner}" == omarchy* ]] ||
    fail "Omarchy command has an unexpected package owner: ${omarchy_command}"
done
readonly OMARCHY_PLUGIN_VALIDATE_METADATA=root-owned-regular-0755
readonly OMARCHY_SHELL_METADATA=root-owned-regular-0755
"${GREP}" -Fq 'rescanPlugins' "${USR_ROOT}/bin/omarchy-shell" ||
  fail 'Omarchy shell lacks rescanPlugins'
readonly OMARCHY_SHELL_RESCAN_PLUGINS=present

USER_MANAGER_ENVIRONMENT="$("${SYSTEMCTL}" --user show-environment)" ||
  fail 'systemd user-manager environment query failed'
bounded_output 'systemd user-manager environment' "${USER_MANAGER_ENVIRONMENT}"
XDG_CONFIG_HOME="$(environment_value "${USER_MANAGER_ENVIRONMENT}" XDG_CONFIG_HOME)"
readonly XDG_CONFIG_HOME
XDG_DATA_HOME="$(environment_value "${USER_MANAGER_ENVIRONMENT}" XDG_DATA_HOME)"
readonly XDG_DATA_HOME
XDG_RUNTIME_DIR="$(environment_value "${USER_MANAGER_ENVIRONMENT}" XDG_RUNTIME_DIR)"
readonly XDG_RUNTIME_DIR
readonly EXPECTED_RUNTIME_DIRECTORY="${RUN_ROOT}/user/${EXPECTED_DESKTOP_UID}"
[[ "${XDG_RUNTIME_DIR}" == "${EXPECTED_RUNTIME_DIRECTORY}" ]] ||
  fail 'user-manager runtime directory differs from the fixed per-user path'
WAYLAND_DISPLAY="$(environment_value "${USER_MANAGER_ENVIRONMENT}" WAYLAND_DISPLAY)"
readonly WAYLAND_DISPLAY
OMARCHY_PATH="$(environment_value "${USER_MANAGER_ENVIRONMENT}" OMARCHY_PATH)"
readonly OMARCHY_PATH
readonly USER_MANAGER_ENVIRONMENT_SET=WAYLAND_DISPLAY,XDG_CONFIG_HOME,XDG_DATA_HOME,XDG_RUNTIME_DIR,OMARCHY_PATH

GRAPHICAL_SESSION_TARGET="$("${SYSTEMCTL}" --user is-active graphical-session.target)" ||
  fail 'graphical session target is not active'
readonly GRAPHICAL_SESSION_TARGET
[[ "${GRAPHICAL_SESSION_TARGET}" == active ]] || fail 'graphical session target is not active'
SESSION_ID="$("${LOGINCTL}" show-user "${EXPECTED_DESKTOP_UID}" -p Display --value)" ||
  fail 'active display session query failed'
readonly SESSION_ID
[[ "${SESSION_ID}" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] ||
  fail 'active display session identifier is malformed'
SESSION_TYPE="$("${LOGINCTL}" show-session "${SESSION_ID}" -p Type --value)" ||
  fail 'login session type query failed'
readonly SESSION_TYPE
[[ "${SESSION_TYPE}" == wayland ]] || fail 'active desktop session is not Wayland'
HYPRLAND_ACTIVE_VERSION="$("${HYPRCTL}" version | "${AWK}" 'NR == 1 { print $2 }')" ||
  fail 'Hyprland active-version query failed'
readonly HYPRLAND_ACTIVE_VERSION
[[ "${HYPRLAND_ACTIVE_VERSION}" == "${HYPRLAND_VERSION}" ]] ||
  fail 'active Hyprland version differs from its installed package'

RUNTIME_METADATA="$("${STAT}" -c '%u:%a' -- "${XDG_RUNTIME_DIR}")" ||
  fail 'runtime-directory metadata query failed'
readonly RUNTIME_METADATA
readonly RUNTIME_OWNER_UID="${RUNTIME_METADATA%%:*}"
readonly RUNTIME_MODE="${RUNTIME_METADATA#*:}"
RUNTIME_FILESYSTEM="$("${STAT}" -f -c '%T' -- "${XDG_RUNTIME_DIR}")"
readonly RUNTIME_FILESYSTEM
USER_STATE_FILESYSTEM="$("${STAT}" -f -c '%T' -- "${XDG_CONFIG_HOME}")"
readonly USER_STATE_FILESYSTEM

readonly PLUGIN_DIRECTORY="${XDG_CONFIG_HOME}/omarchy/plugins"
readonly SHELL_CONFIGURATION="${XDG_CONFIG_HOME}/omarchy/shell.json"
[[ -d "${PLUGIN_DIRECTORY}" && ! -L "${PLUGIN_DIRECTORY}" ]] ||
  fail 'Omarchy plugin directory is unavailable or unsafe'
[[ -z "$("${FIND}" "${PLUGIN_DIRECTORY}" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
  fail 'Omarchy plugin directory is not empty'
readonly PLUGIN_DIRECTORY_STATE=present-empty
[[ -f "${SHELL_CONFIGURATION}" && ! -L "${SHELL_CONFIGURATION}" ]] ||
  fail 'Omarchy shell configuration is unavailable or unsafe'
[[ "$("${STAT}" -c '%a:%h:%F' -- "${SHELL_CONFIGURATION}")" == \
  '600:1:regular file' ]] || fail 'Omarchy shell configuration metadata is unsafe'
"${GREP}" -Eq '"version"[[:space:]]*:[[:space:]]*1([[:space:]]*[,}])' \
  "${SHELL_CONFIGURATION}" || fail 'Omarchy shell configuration is not schema v1'
SHELL_CONFIGURATION_SHA256="$(sha256_file "${SHELL_CONFIGURATION}")"
readonly SHELL_CONFIGURATION_SHA256
readonly SHELL_CONFIGURATION_SCHEMA=v1
readonly SHELL_CONFIGURATION_MODE=0600

set +e
"${PACMAN}" -Q -- a-quo >/dev/null 2>&1
A_QUO_PACKAGE_STATUS="$?"
set -e
[[ "${A_QUO_PACKAGE_STATUS}" -eq 1 ]] || fail 'A Quo package absence was not established'
for absent_path in \
  "${USR_ROOT}/bin/a-quo" "${USR_ROOT}/bin/a-quo-daemon" \
  "${USR_ROOT}/lib/a-quo/a-quo-consent" \
  "${USR_ROOT}/lib/systemd/user/a-quo-daemon.service" \
  "${USR_ROOT}/lib/systemd/user-preset/90-a-quo.preset" \
  "${USR_ROOT}/share/a-quo/provider-registry-v1.json" \
  "${XDG_DATA_HOME}/a-quo" "${XDG_RUNTIME_DIR}/a-quo" \
  "${DISPOSABLE_MARKER}" "${BRIDGE_LOCK_DIRECTORY}"; do
  [[ ! -e "${absent_path}" && ! -L "${absent_path}" ]] ||
    fail "A Quo disabled-baseline path is present: ${absent_path}"
done
if "${AWK}" -F: '$1 == "a-quo-evaluator" { found=1 } END { exit found ? 0 : 1 }' \
  "${EVALUATOR_PASSWD}"; then
  fail 'A Quo evaluator account is present'
fi
readonly A_QUO_INSTALLED_STATE=absent
readonly A_QUO_RUNTIME_STATE=absent
readonly A_QUO_EVALUATOR_STATE=absent

PACKAGE_QUERY_AFTER="$("${PACMAN}" -Q)" || fail 'final complete package query failed'
bounded_output 'final complete package query' "${PACKAGE_QUERY_AFTER}"
PACKAGE_QUERY_SHA256_AFTER="$(printf '%s\n' "${PACKAGE_QUERY_AFTER}" |
  "${SORT}" | "${SHA256SUM}")" || fail 'final package-query hash failed'
PACKAGE_QUERY_SHA256_AFTER="${PACKAGE_QUERY_SHA256_AFTER%% *}"
readonly PACKAGE_QUERY_SHA256_AFTER
[[ "${PACKAGE_QUERY_SHA256_AFTER}" == "${PACKAGE_QUERY_SHA256_BEFORE}" ]] ||
  fail 'package state changed during collection'
[[ ! -e "${PACMAN_LOCK}" && ! -L "${PACMAN_LOCK}" ]] ||
  fail 'pacman database lock appeared during collection'
[[ "$(sha256_file "${SHELL_CONFIGURATION}")" == "${SHELL_CONFIGURATION_SHA256}" ]] ||
  fail 'Omarchy shell configuration changed during collection'
[[ -z "$("${FIND}" "${PLUGIN_DIRECTORY}" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
  fail 'Omarchy plugin directory changed during collection'
[[ "$("${SYSTEMCTL}" --user is-active graphical-session.target)" == \
  "${GRAPHICAL_SESSION_TARGET}" ]] || fail 'graphical session state changed during collection'
COLLECTOR_METADATA_AFTER="$("${STAT}" -c '%d:%i:%s:%f:%Y:%h' -- "${COLLECTOR_PATH}")" ||
  fail 'collector metadata became unavailable'
readonly COLLECTOR_METADATA_AFTER
[[ "${COLLECTOR_METADATA_AFTER}" == "${COLLECTOR_METADATA_BEFORE}" &&
  "$(sha256_file "${COLLECTOR_PATH}")" == "${COLLECTOR_SHA256}" ]] ||
  fail 'collector bytes or metadata changed during collection'

printf '%s\n' \
  'format=a-quo-omarchy-x86_64-read-only-observation-v1' \
  "profile_id=${PROFILE_ID}" \
  "profile_sha256=${PROFILE_SHA256}" \
  "evidence_namespace=${EVIDENCE_NAMESPACE}" \
  "collector_repository_path=${COLLECTOR_REPOSITORY_PATH}" \
  "collector_sha256=${COLLECTOR_SHA256}" \
  'observation_source=direct-tool-local-execution' \
  'observation_authority=none' \
  'observation_time=not-recorded' \
  'observation_time_authority=none' \
  'profile_authentication=external-pinned-git-object-required' \
  'execution_privilege=ordinary-desktop-user' \
  "architecture=${ARCHITECTURE}" \
  "hardware_vendor=${HARDWARE_VENDOR}" \
  "hardware_model=${HARDWARE_MODEL}" \
  "cpu_model=${CPU_MODEL}" \
  "cpu_core_count=${CPU_CORE_COUNT}" \
  "cpu_thread_count=${CPU_THREAD_COUNT}" \
  "os_name=${OS_NAME}" \
  "os_version=${OS_VERSION}" \
  "os_release_sha256=${OS_RELEASE_SHA256}" \
  "kernel_release=${KERNEL_RELEASE}" \
  "glibc_version=${GLIBC_VERSION}" \
  "pacman_version=${PACMAN_VERSION}" \
  "pacman_architecture=${PACMAN_ARCHITECTURE}" \
  "pacman_repository_name_set=${PACMAN_REPOSITORY_NAME_SET}" \
  "pacman_database_consistency=${PACMAN_DATABASE_CONSISTENCY}" \
  "pacman_lock_state=${PACMAN_LOCK_STATE}" \
  "installed_package_count=${PACKAGE_COUNT}" \
  "installed_package_query_sha256=${PACKAGE_QUERY_SHA256_BEFORE}" \
  "omarchy_package_query=${OMARCHY_QUERY}" \
  "omarchy_package_architecture=${OMARCHY_ARCHITECTURE}" \
  "omarchy_package_archive_sha256=${OMARCHY_ARCHIVE_SHA256}" \
  "omarchy_settings_package_query=${OMARCHY_SETTINGS_QUERY}" \
  "omarchy_settings_package_architecture=${OMARCHY_SETTINGS_ARCHITECTURE}" \
  "omarchy_settings_package_archive_sha256=${OMARCHY_SETTINGS_ARCHIVE_SHA256}" \
  "omarchy_package_altered_file_count=${OMARCHY_ALTERED_COUNT}" \
  "omarchy_settings_observed_altered_file_count=${OMARCHY_SETTINGS_ALTERED_COUNT}" \
  "omarchy_settings_root_only_unverified_file_count=${OMARCHY_SETTINGS_UNVERIFIED_COUNT}" \
  "hyprland_version=${HYPRLAND_ACTIVE_VERSION}" \
  "quickshell_version=${QUICKSHELL_VERSION}" \
  "uwsm_version=${UWSM_VERSION}" \
  "systemd_version=${SYSTEMD_VERSION}" \
  "session_type=${SESSION_TYPE}" \
  "wayland_display=${WAYLAND_DISPLAY}" \
  "graphical_session_target=${GRAPHICAL_SESSION_TARGET}" \
  "runtime_directory=${PROFILE_RUNTIME_DIRECTORY}" \
  "runtime_directory_owner_uid=${RUNTIME_OWNER_UID}" \
  "runtime_directory_mode=0${RUNTIME_MODE}" \
  "runtime_directory_filesystem=${RUNTIME_FILESYSTEM}" \
  "user_manager_environment_set=${USER_MANAGER_ENVIRONMENT_SET}" \
  "omarchy_path=${OMARCHY_PATH}" \
  "user_state_filesystem=${USER_STATE_FILESYSTEM}" \
  "omarchy_plugin_validate_metadata=${OMARCHY_PLUGIN_VALIDATE_METADATA}" \
  "omarchy_shell_metadata=${OMARCHY_SHELL_METADATA}" \
  "omarchy_shell_rescan_plugins=${OMARCHY_SHELL_RESCAN_PLUGINS}" \
  "omarchy_plugin_directory_state=${PLUGIN_DIRECTORY_STATE}" \
  "omarchy_shell_configuration_schema=${SHELL_CONFIGURATION_SCHEMA}" \
  "omarchy_shell_configuration_mode=${SHELL_CONFIGURATION_MODE}" \
  "omarchy_shell_configuration_sha256=${SHELL_CONFIGURATION_SHA256}" \
  "a_quo_installed_state=${A_QUO_INSTALLED_STATE}" \
  "a_quo_runtime_state=${A_QUO_RUNTIME_STATE}" \
  "a_quo_evaluator_state=${A_QUO_EVALUATOR_STATE}" \
  'formal_read_only_repeat=completed-non-authoritative' \
  'collector_mise_invoked=false' \
  'collector_network_command_invoked=false' \
  'collector_update_capable_command_invoked=false' \
  'physical_target_mutation_requested=false' \
  'relevant_state_before_after=unchanged' \
  'profile_match_claim=not-evaluated-by-collector' \
  'clean_system_claim=not-established' \
  'reproducibility_claim=not-established' \
  'source_to_binary_provenance=not-established' \
  'aarch64_gate_satisfied=false' \
  'maximum_authorized_stage=5' \
  'stage_6_owner_decision=required'
