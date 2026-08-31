#!/usr/bin/env bash

set -euo pipefail

# One-shot, interactive evaluator for the installed per-user service and the
# fixed-path direct-Wayland consent helper. This is not a developer-machine
# test. It requires a dedicated logged-in desktop account on an exactly marked
# disposable Omarchy target. The prompts require operator-observed decline and
# approval; this script contains no input-injection or auto-approval path.
# The harness cannot prove whether the input originated from a human.
readonly REQUIRED_ACKNOWLEDGEMENT='I-understand-this-runs-real-a-quo-consent-on-the-disposable-evaluator-account'
if [[ "${A_QUO_INSTALLED_CONSENT_LIFECYCLE_ACKNOWLEDGEMENT:-}" != \
  "${REQUIRED_ACKNOWLEDGEMENT}" ]]; then
  printf '%s\n' \
    'refusing installed consent evaluation without exact A_QUO_INSTALLED_CONSENT_LIFECYCLE_ACKNOWLEDGEMENT' >&2
  exit 1
fi

readonly EVALUATOR_ACCOUNT='a-quo-evaluator'
readonly EVALUATOR_HOME='/home/a-quo-evaluator'
readonly CROSS_UID_ACCOUNT='nobody'
readonly DISPOSABLE_MARKER='/etc/a-quo/disposable-omarchy-evaluator-v1'
readonly A_QUO='/usr/bin/a-quo'
readonly A_QUO_DAEMON='/usr/bin/a-quo-daemon'
readonly A_QUO_CONSENT='/usr/lib/a-quo/a-quo-consent'
readonly SERVICE_UNIT='/usr/lib/systemd/user/a-quo-daemon.service'
readonly PROVIDER_REGISTRY='/usr/share/a-quo/provider-registry-v1.json'
readonly TRUSTED_FONT='/usr/share/fonts/noto/NotoSans-Regular.ttf'
readonly SERVICE_NAME='a-quo-daemon.service'
readonly DEFAULT_STORE_ROOT="${EVALUATOR_HOME}/.local/share/a-quo"
readonly DEFAULT_STORE="${DEFAULT_STORE_ROOT}/personas.sqlite3"
readonly EXPECTED_HANDOFF_ROOT="${EVALUATOR_HOME}/.local/share/a-quo-installed-package-lifecycle-v1/trusted-consent-v2"
readonly USER_UNIT_ROOT="${EVALUATOR_HOME}/.config/systemd/user"
readonly USER_ENABLE_DIRECTORY="${USER_UNIT_ROOT}/graphical-session.target.wants"
readonly SERVICE_ENABLE_LINK="${USER_ENABLE_DIRECTORY}/${SERVICE_NAME}"

fail() {
  printf 'installed A Quo consent lifecycle refused: %s\n' "$1" >&2
  exit 1
}

require_environment() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "required environment variable ${name} is absent"
}

sha256_file() {
  local output
  output="$(/usr/bin/sha256sum -- "$1")"
  printf '%s\n' "${output%% *}"
}

require_real_regular_file() {
  local path="$1"
  local label="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} is not a real regular file"
}

require_safe_user_directory() {
  local path="$1"
  local metadata
  local ownership_and_mode
  local owner
  local mode
  [[ -d "${path}" && ! -L "${path}" ]] || fail "unsafe evaluator directory: ${path}"
  metadata="$(/usr/bin/stat -c '%u:%g %a %F' -- "${path}")"
  ownership_and_mode="${metadata% directory}"
  owner="${ownership_and_mode%% *}"
  mode="${ownership_and_mode##* }"
  [[ "${owner}" == "${EVALUATOR_UID}:${EVALUATOR_GID}" ]] ||
    fail "evaluator directory has unexpected ownership: ${path}"
  (( (8#${mode} & 8#077) == 0 )) ||
    fail "evaluator directory is not private: ${path}"
}

require_owned_nonwritable_user_directory() {
  local path="$1"
  local metadata
  local ownership_and_mode
  local owner
  local mode
  [[ -d "${path}" && ! -L "${path}" ]] || fail "unsafe evaluator directory: ${path}"
  metadata="$(/usr/bin/stat -c '%u:%g %a %F' -- "${path}")"
  ownership_and_mode="${metadata% directory}"
  owner="${ownership_and_mode%% *}"
  mode="${ownership_and_mode##* }"
  [[ "${owner}" == "${EVALUATOR_UID}:${EVALUATOR_GID}" ]] ||
    fail "evaluator directory has unexpected ownership: ${path}"
  (( (8#${mode} & 8#022) == 0 )) ||
    fail "evaluator directory is group/world writable: ${path}"
}

require_safe_root_path() {
  local path="$1"
  local final_kind="$2"
  local current='/'
  local part
  local metadata
  local owner
  local mode
  local kind
  local -a parts=()
  [[ "${path}" == /* && "${path}" != / ]] || fail "unsafe root path request: ${path}"
  metadata="$(/usr/bin/stat -c '%u %a %F' -- /)" || fail 'cannot inspect filesystem root'
  owner="${metadata%% *}"
  mode="${metadata#* }"
  kind="${mode#* }"
  mode="${mode%% *}"
  [[ "${owner}" == 0 && "${kind}" == directory ]] ||
    fail 'filesystem root has unexpected owner or type'
  (( (8#${mode} & 8#022) == 0 )) || fail 'filesystem root is group/world writable'
  IFS=/ read -r -a parts <<<"${path#/}"
  for part in "${parts[@]}"; do
    [[ -n "${part}" && "${part}" != . && "${part}" != .. ]] ||
      fail "unsafe root path component: ${path}"
    current="${current%/}/${part}"
    [[ ! -L "${current}" ]] || fail "root path contains a symlink: ${current}"
    metadata="$(/usr/bin/stat -c '%u %a %F' -- "${current}")" ||
      fail "root path component is unavailable: ${current}"
    owner="${metadata%% *}"
    mode="${metadata#* }"
    kind="${mode#* }"
    mode="${mode%% *}"
    [[ "${owner}" == 0 ]] || fail "root path component has the wrong owner: ${current}"
    (( (8#${mode} & 8#022) == 0 )) ||
      fail "root path component is group/world writable: ${current}"
    if [[ "${current}" == "${path}" ]]; then
      case "${final_kind}" in
        executable)
          [[ "${kind}" == 'regular file' && $((8#${mode} & 8#111)) -ne 0 ]] ||
            fail "trusted executable is not an executable regular file: ${path}"
          ;;
        regular)
          [[ "${kind}" == 'regular file' ]] ||
            fail "trusted file is not regular: ${path}"
          ;;
        *) fail "unknown safe-root final kind: ${final_kind}" ;;
      esac
    else
      [[ "${kind}" == directory ]] || fail "root path parent is not a directory: ${current}"
    fi
  done
}

if [[ "${EUID}" -ne 0 ]]; then
  fail 'the evaluator must run as root so it can authenticate the root-only disposable marker'
fi

for command_path in \
  /usr/bin/bash \
  /usr/bin/chmod \
  /usr/bin/cmp \
  /usr/bin/dd \
  /usr/bin/env \
  /usr/bin/find \
  /usr/bin/getent \
  /usr/bin/grep \
  /usr/bin/id \
  /usr/bin/install \
  /usr/bin/jq \
  /usr/bin/kill \
  /usr/bin/ln \
  /usr/bin/mktemp \
  /usr/bin/pacman \
  /usr/bin/readlink \
  /usr/bin/realpath \
  /usr/bin/rm \
  /usr/bin/rmdir \
  /usr/bin/runuser \
  /usr/bin/setsid \
  /usr/bin/sha256sum \
  /usr/bin/sleep \
  /usr/bin/ssh-keygen \
  /usr/bin/stat \
  /usr/bin/systemctl \
  /usr/bin/tee \
  /usr/bin/true \
  /usr/bin/wc; do
  [[ -x "${command_path}" && ! -d "${command_path}" ]] ||
    fail "required installed command is unavailable: ${command_path}"
done

require_real_regular_file "${DISPOSABLE_MARKER}" 'disposable evaluator marker'
if [[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${DISPOSABLE_MARKER}")" != \
  '0:0 400 regular file' ]]; then
  fail 'disposable evaluator marker must be root:root mode 0400'
fi
if ! /usr/bin/cmp -s -- "${DISPOSABLE_MARKER}" <(
  printf '%s\n' \
    'schema=a-quo-disposable-omarchy-evaluator-v1' \
    'account=a-quo-evaluator'
); then
  fail 'disposable evaluator marker has unexpected bytes'
fi

ACCOUNT_RECORD="$(/usr/bin/getent passwd "${EVALUATOR_ACCOUNT}")" ||
  fail 'dedicated evaluator account does not exist'
readonly ACCOUNT_RECORD
IFS=: read -r ACCOUNT_NAME _ EVALUATOR_UID EVALUATOR_GID _ ACCOUNT_HOME _ \
  <<<"${ACCOUNT_RECORD}"
readonly ACCOUNT_NAME EVALUATOR_UID EVALUATOR_GID ACCOUNT_HOME
if [[ "${ACCOUNT_NAME}" != "${EVALUATOR_ACCOUNT}" || \
  "${ACCOUNT_HOME}" != "${EVALUATOR_HOME}" || \
  ! "${EVALUATOR_UID}" =~ ^[1-9][0-9]*$ || \
  ! "${EVALUATOR_GID}" =~ ^[0-9]+$ ]]; then
  fail 'dedicated evaluator account identity or exact home is wrong'
fi
[[ "$(/usr/bin/id -u "${EVALUATOR_ACCOUNT}")" == "${EVALUATOR_UID}" ]] ||
  fail 'evaluator account UID lookup is inconsistent'
[[ "$(/usr/bin/id -g "${EVALUATOR_ACCOUNT}")" == "${EVALUATOR_GID}" ]] ||
  fail 'evaluator account GID lookup is inconsistent'
require_safe_user_directory "${EVALUATOR_HOME}"

CROSS_UID_RECORD="$(/usr/bin/getent passwd "${CROSS_UID_ACCOUNT}")" ||
  fail 'fixed cross-UID probe account does not exist'
readonly CROSS_UID_RECORD
IFS=: read -r CROSS_UID_NAME _ CROSS_UID _ _ _ _ <<<"${CROSS_UID_RECORD}"
readonly CROSS_UID_NAME CROSS_UID
if [[ "${CROSS_UID_NAME}" != "${CROSS_UID_ACCOUNT}" || \
  ! "${CROSS_UID}" =~ ^[1-9][0-9]*$ || "${CROSS_UID}" == "${EVALUATOR_UID}" ]]; then
  fail 'fixed cross-UID probe account is invalid or aliases the evaluator'
fi

require_environment A_QUO_EXPECTED_A_QUO_PACKAGE_QUERY
require_environment A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY
for evaluation_binding_name in \
  A_QUO_EVALUATION_PROFILE_ID \
  A_QUO_EVALUATION_PROFILE_SHA256 \
  A_QUO_EVALUATION_TARGET_KIND \
  A_QUO_EVALUATION_ARCHITECTURE \
  A_QUO_EVALUATION_EVIDENCE_NAMESPACE; do
  require_environment "${evaluation_binding_name}"
done
readonly EXPECTED_A_QUO_QUERY="${A_QUO_EXPECTED_A_QUO_PACKAGE_QUERY}"
readonly EXPECTED_OMARCHY_QUERY="${A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY}"
readonly EVALUATION_PROFILE_ID="${A_QUO_EVALUATION_PROFILE_ID}"
readonly EVALUATION_PROFILE_SHA256="${A_QUO_EVALUATION_PROFILE_SHA256}"
readonly EVALUATION_TARGET_KIND="${A_QUO_EVALUATION_TARGET_KIND}"
readonly EVALUATION_ARCHITECTURE="${A_QUO_EVALUATION_ARCHITECTURE}"
readonly EVALUATION_EVIDENCE_NAMESPACE="${A_QUO_EVALUATION_EVIDENCE_NAMESPACE}"
[[ "${EVALUATION_PROFILE_ID}|${EVALUATION_PROFILE_SHA256}|${EVALUATION_TARGET_KIND}|${EVALUATION_ARCHITECTURE}|${EVALUATION_EVIDENCE_NAMESPACE}" == \
  'a-quo-omarchy4-aarch64-dec29fa-v2|3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6d|virtual-reference-target|aarch64|phase-a-aarch64-dec29fa' ]] ||
  fail 'evaluation target binding is not the exact AArch64 reference profile tuple'
[[ "${EXPECTED_A_QUO_QUERY}" =~ ^a-quo[[:space:]][^[:space:]]+$ ]] ||
  fail 'A_QUO_EXPECTED_A_QUO_PACKAGE_QUERY must be one exact pacman -Q a-quo line'
[[ "${EXPECTED_OMARCHY_QUERY}" =~ ^omarchy(-dev)?[[:space:]][^[:space:]]+$ ]] ||
  fail 'A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY must be one exact supported Omarchy package query'
OBSERVED_A_QUO_QUERY="$(/usr/bin/pacman -Q a-quo)" || fail 'A Quo package is not installed'
readonly OBSERVED_A_QUO_QUERY
[[ "${OBSERVED_A_QUO_QUERY}" == "${EXPECTED_A_QUO_QUERY}" ]] ||
  fail 'installed A Quo package query does not match its caller-supplied pin'
readonly EXPECTED_OMARCHY_PACKAGE="${EXPECTED_OMARCHY_QUERY%% *}"
OBSERVED_OMARCHY_QUERY="$(/usr/bin/pacman -Q "${EXPECTED_OMARCHY_PACKAGE}")" ||
  fail 'pinned Omarchy package is not installed'
readonly OBSERVED_OMARCHY_QUERY
[[ "${OBSERVED_OMARCHY_QUERY}" == "${EXPECTED_OMARCHY_QUERY}" ]] ||
  fail 'installed Omarchy package query does not match its caller-supplied pin'
/usr/bin/pacman -Qkk a-quo >/dev/null || fail 'installed A Quo package files fail pacman verification'

require_safe_root_path "${A_QUO}" executable
require_safe_root_path "${A_QUO_DAEMON}" executable
require_safe_root_path "${A_QUO_CONSENT}" executable
require_safe_root_path "${SERVICE_UNIT}" regular
require_safe_root_path "${PROVIDER_REGISTRY}" regular
require_safe_root_path "${TRUSTED_FONT}" regular
[[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${A_QUO}")" == \
  '0:0 755 regular file' ]] || fail 'installed A Quo CLI must be root:root mode 0755'
[[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${A_QUO_DAEMON}")" == \
  '0:0 755 regular file' ]] || fail 'installed A Quo daemon must be root:root mode 0755'
[[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${A_QUO_CONSENT}")" == \
  '0:0 755 regular file' ]] || fail 'installed consent helper must be root:root mode 0755'
[[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${SERVICE_UNIT}")" == \
  '0:0 644 regular file' ]] || fail 'installed service unit must be root:root mode 0644'
[[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${PROVIDER_REGISTRY}")" == \
  '0:0 644 regular file' ]] || fail 'installed provider registry must be root:root mode 0644'
A_QUO_SHA256_BEFORE="$(sha256_file "${A_QUO}")"
DAEMON_SHA256_BEFORE="$(sha256_file "${A_QUO_DAEMON}")"
CONSENT_SHA256_BEFORE="$(sha256_file "${A_QUO_CONSENT}")"
UNIT_SHA256_BEFORE="$(sha256_file "${SERVICE_UNIT}")"
REGISTRY_SHA256_BEFORE="$(sha256_file "${PROVIDER_REGISTRY}")"
readonly A_QUO_SHA256_BEFORE DAEMON_SHA256_BEFORE CONSENT_SHA256_BEFORE
readonly UNIT_SHA256_BEFORE REGISTRY_SHA256_BEFORE
for package_path in \
  "${A_QUO}" \
  "${A_QUO_DAEMON}" \
  "${A_QUO_CONSENT}" \
  "${SERVICE_UNIT}" \
  "${PROVIDER_REGISTRY}"; do
  [[ "$(/usr/bin/pacman -Qoq -- "${package_path}")" == a-quo ]] ||
    fail "installed package does not own its contracted path: ${package_path}"
done
FONT_PACKAGE="$(/usr/bin/pacman -Qoq -- "${TRUSTED_FONT}")" ||
  fail 'trusted font is not owned by an installed package'
readonly FONT_PACKAGE
[[ -n "${FONT_PACKAGE}" && "${FONT_PACKAGE}" != *$'\n'* ]] ||
  fail 'trusted font has an ambiguous package owner'
FONT_PACKAGE_QUERY="$(/usr/bin/pacman -Q "${FONT_PACKAGE}")" ||
  fail 'trusted font package query failed'
readonly FONT_PACKAGE_QUERY
[[ "${FONT_PACKAGE_QUERY}" == "${FONT_PACKAGE} "* && \
  "${FONT_PACKAGE_QUERY}" != *$'\n'* ]] || fail 'trusted font package query is ambiguous'
FONT_SIZE="$(/usr/bin/stat -c '%s' -- "${TRUSTED_FONT}")"
readonly FONT_SIZE
[[ "${FONT_SIZE}" =~ ^[0-9]+$ && "${FONT_SIZE}" -gt 0 && \
  "${FONT_SIZE}" -le 4194304 ]] || fail 'trusted font size is outside the evaluator bound'
/usr/bin/pacman -Qkk "${FONT_PACKAGE}" >/dev/null ||
  fail 'trusted font package files fail pacman verification'
FONT_SHA256_BEFORE="$(sha256_file "${TRUSTED_FONT}")"
readonly FONT_SHA256_BEFORE

for required_unit_line in \
  'Type=simple' \
  'ExecStart=/usr/bin/a-quo-daemon --runtime-directory=%t' \
  'RuntimeDirectory=a-quo' \
  'RuntimeDirectoryMode=0700' \
  'UMask=0077' \
  'Restart=no'; do
  /usr/bin/grep -Fxq -- "${required_unit_line}" "${SERVICE_UNIT}" ||
    fail "installed unit is missing its contract line: ${required_unit_line}"
done
if /usr/bin/grep -Eiq -- \
  '(^|[^a-z])(busname|dbus|execstartpre|execstartpost|restart=always)([^a-z]|$)' \
  "${SERVICE_UNIT}"; then
  fail 'installed unit contains a forbidden authority, hook, or restart directive'
fi
if ! /usr/bin/cmp -s -- "${PROVIDER_REGISTRY}" <(
  printf '%s\n' \
    '{"providers":[],"schema":"urn:a-quo:omarchy-plugin-risk-provider-registry:v1"}'
); then
  fail 'installed provider registry is not the exact empty v1 registry'
fi

require_environment A_QUO_EVALUATOR_WAYLAND_DISPLAY
readonly WAYLAND_DISPLAY_VALUE="${A_QUO_EVALUATOR_WAYLAND_DISPLAY}"
[[ "${WAYLAND_DISPLAY_VALUE}" =~ ^wayland-[0-9]+$ ]] ||
  fail 'A_QUO_EVALUATOR_WAYLAND_DISPLAY must be one simple wayland-N socket name'
readonly EVALUATOR_RUNTIME_DIRECTORY="/run/user/${EVALUATOR_UID}"
readonly A_QUO_RUNTIME_DIRECTORY="${EVALUATOR_RUNTIME_DIRECTORY}/a-quo"
readonly CONSENT_SOCKET="${A_QUO_RUNTIME_DIRECTORY}/consent.sock"
require_safe_user_directory "${EVALUATOR_RUNTIME_DIRECTORY}"
readonly WAYLAND_SOCKET="${EVALUATOR_RUNTIME_DIRECTORY}/${WAYLAND_DISPLAY_VALUE}"
if [[ -L "${WAYLAND_SOCKET}" || ! -S "${WAYLAND_SOCKET}" || \
  "$(/usr/bin/stat -c '%u' -- "${WAYLAND_SOCKET}")" != "${EVALUATOR_UID}" ]]; then
  fail 'the evaluator account has no matching real Wayland socket in its runtime directory'
fi

run_as_evaluator() {
  /usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- /usr/bin/env -i \
    HOME="${EVALUATOR_HOME}" \
    USER="${EVALUATOR_ACCOUNT}" \
    LOGNAME="${EVALUATOR_ACCOUNT}" \
    PATH=/usr/bin:/bin \
    LANG=C.UTF-8 \
    LC_ALL=C \
    XDG_RUNTIME_DIR="${EVALUATOR_RUNTIME_DIRECTORY}" \
    WAYLAND_DISPLAY="${WAYLAND_DISPLAY_VALUE}" \
    "$@"
}

run_a_quo() {
  run_as_evaluator "${A_QUO}" "$@"
}

run_systemctl() {
  run_as_evaluator /usr/bin/systemctl --user --no-pager "$@"
}

MANAGER_ENVIRONMENT="$(run_systemctl show-environment)" ||
  fail 'cannot capture the evaluator user-manager environment'
readonly MANAGER_ENVIRONMENT
MANAGER_ENVIRONMENT_BYTES="$(/usr/bin/wc -c <<<"${MANAGER_ENVIRONMENT}")"
MANAGER_ENVIRONMENT_LINES="$(/usr/bin/wc -l <<<"${MANAGER_ENVIRONMENT}")"
readonly MANAGER_ENVIRONMENT_BYTES MANAGER_ENVIRONMENT_LINES
[[ "${MANAGER_ENVIRONMENT_BYTES}" =~ ^[0-9]+$ && \
  "${MANAGER_ENVIRONMENT_BYTES}" -le 65536 && \
  "${MANAGER_ENVIRONMENT_LINES}" =~ ^[0-9]+$ && \
  "${MANAGER_ENVIRONMENT_LINES}" -le 512 ]] ||
  fail 'user-manager environment exceeds the evaluator byte or line bound'
if ! /usr/bin/grep -Fxq -- "WAYLAND_DISPLAY=${WAYLAND_DISPLAY_VALUE}" \
  <<<"${MANAGER_ENVIRONMENT}"; then
  fail 'user manager lacks the exact Wayland display; evaluator will not import or change it'
fi
if ! /usr/bin/grep -Fxq -- "XDG_RUNTIME_DIR=${EVALUATOR_RUNTIME_DIRECTORY}" \
  <<<"${MANAGER_ENVIRONMENT}"; then
  fail 'user manager lacks the exact runtime directory; evaluator will not import or change it'
fi
if ! /usr/bin/grep -Fxq -- "HOME=${EVALUATOR_HOME}" <<<"${MANAGER_ENVIRONMENT}"; then
  fail 'user manager lacks the exact evaluator home; evaluator will not import or change it'
fi
if /usr/bin/grep -q '^XDG_DATA_HOME=' <<<"${MANAGER_ENVIRONMENT}"; then
  if ! /usr/bin/grep -Fxq -- "XDG_DATA_HOME=${EVALUATOR_HOME}/.local/share" \
    <<<"${MANAGER_ENVIRONMENT}"; then
    fail 'user manager has a divergent XDG_DATA_HOME; use the documented service drop-in instead'
  fi
fi
if /usr/bin/grep -q '^XDG_CONFIG_HOME=' <<<"${MANAGER_ENVIRONMENT}"; then
  if ! /usr/bin/grep -Fxq -- "XDG_CONFIG_HOME=${EVALUATOR_HOME}/.config" \
    <<<"${MANAGER_ENVIRONMENT}"; then
    fail 'user manager has a divergent XDG_CONFIG_HOME; enablement state would escape the evaluator boundary'
  fi
fi
if /usr/bin/grep -Eq '^(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT)=' \
  <<<"${MANAGER_ENVIRONMENT}"; then
  fail 'user manager contains a loader-injection variable; installed daemon identity is not trustworthy'
fi
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=LoadState --value)" == loaded ]] ||
  fail 'installed user service is not loaded by the evaluator user manager'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=FragmentPath --value)" == \
  "${SERVICE_UNIT}" ]] || fail 'effective user service does not use the installed unit fragment'
[[ -z "$(run_systemctl show "${SERVICE_NAME}" --property=DropInPaths --value)" ]] ||
  fail 'user service has drop-ins; the stock installed contract cannot be evaluated'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=NeedDaemonReload --value)" == no ]] ||
  fail 'user manager has stale unit state; daemon-reload is required before evaluation'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=Type --value)" == simple ]] ||
  fail 'effective user service type differs from the installed contract'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=RuntimeDirectory --value)" == a-quo ]] ||
  fail 'effective user service runtime directory differs from the installed contract'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=RuntimeDirectoryMode --value)" == 0700 ]] ||
  fail 'effective user service runtime-directory mode differs from the installed contract'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=UMask --value)" == 0077 ]] ||
  fail 'effective user service umask differs from the installed contract'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=Restart --value)" == no ]] ||
  fail 'effective user service restart policy differs from the installed contract'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=KillMode --value)" == control-group ]] ||
  fail 'effective user service does not stop the daemon and consent helper as one control group'
EFFECTIVE_EXEC_START="$(run_systemctl show "${SERVICE_NAME}" --property=ExecStart --value)"
readonly EFFECTIVE_EXEC_START
if [[ "$(/usr/bin/grep -Fo -- 'path=/usr/bin/a-quo-daemon' <<<"${EFFECTIVE_EXEC_START}" |
  /usr/bin/wc -l)" -ne 1 ]] || ! /usr/bin/grep -Fq -- \
  "path=/usr/bin/a-quo-daemon ; argv[]=/usr/bin/a-quo-daemon --runtime-directory=${EVALUATOR_RUNTIME_DIRECTORY} ; ignore_errors=no" \
  <<<"${EFFECTIVE_EXEC_START}"; then
  fail 'effective user service command differs from the installed contract'
fi
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=UnitFileState --value)" == disabled ]] ||
  fail 'installed user service must initially be disabled'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=ActiveState --value)" == inactive ]] ||
  fail 'installed user service must initially be inactive'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=MainPID --value)" == 0 ]] ||
  fail 'installed user service unexpectedly has a main process'
if [[ -e "${A_QUO_RUNTIME_DIRECTORY}" || -L "${A_QUO_RUNTIME_DIRECTORY}" ]]; then
  fail 'A Quo runtime directory must be absent before the one-shot evaluator'
fi
if [[ -e "${DEFAULT_STORE_ROOT}" || -L "${DEFAULT_STORE_ROOT}" ]]; then
  fail 'default evaluator persona state must be absent before the one-shot run'
fi
for state_parent in "${EVALUATOR_HOME}/.local" "${EVALUATOR_HOME}/.local/share"; do
  if [[ "${A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT+x}" == x ]]; then
    require_owned_nonwritable_user_directory "${state_parent}"
  else
    require_safe_user_directory "${state_parent}"
  fi
done
for service_parent in \
  "${EVALUATOR_HOME}/.config" \
  "${EVALUATOR_HOME}/.config/systemd" \
  "${USER_UNIT_ROOT}" \
  "${USER_ENABLE_DIRECTORY}"; do
  require_safe_user_directory "${service_parent}"
done
if /usr/bin/find "${USER_ENABLE_DIRECTORY}" -xdev -mindepth 1 -print -quit |
  /usr/bin/grep -q .; then
  fail 'evaluator service-enable directory must initially be empty'
fi
USER_UNIT_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i' -- "${USER_UNIT_ROOT}")"
USER_ENABLE_DIRECTORY_IDENTITY="$(/usr/bin/stat -c '%d:%i' -- "${USER_ENABLE_DIRECTORY}")"
readonly USER_UNIT_ROOT_IDENTITY USER_ENABLE_DIRECTORY_IDENTITY

HANDOFF_REQUESTED=false
HANDOFF_ROOT=''
HANDOFF_ROOT_IDENTITY=''
HANDOFF_PROOF_V1=''
HANDOFF_PROOF_V2=''
HANDOFF_MANIFEST=''
if [[ "${A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT+x}" == x ]]; then
  HANDOFF_REQUESTED=true
  HANDOFF_ROOT="${A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT}"
  [[ -n "${HANDOFF_ROOT}" && "${#HANDOFF_ROOT}" -le 1024 ]] ||
    fail 'A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT must be a non-empty bounded path'
  [[ "${HANDOFF_ROOT}" == "${EXPECTED_HANDOFF_ROOT}" ]] ||
    fail 'handoff root must be the exact joined package-lifecycle consent path'
  [[ "${HANDOFF_ROOT}" == "${EVALUATOR_HOME}/"* ]] ||
    fail 'handoff root must be a strict descendant of the evaluator home'
  case "${HANDOFF_ROOT}" in
    "${DEFAULT_STORE_ROOT}" | "${DEFAULT_STORE_ROOT}"/* | \
      "${EVALUATOR_HOME}/.config" | "${EVALUATOR_HOME}/.config"/* | \
      "${EVALUATOR_HOME}"/.a-quo-installed-consent-lifecycle.*)
      fail 'handoff root overlaps retained state, service configuration, or evaluator work paths'
      ;;
  esac
  HANDOFF_RELATIVE_PATH="${HANDOFF_ROOT#"${EVALUATOR_HOME}/"}"
  readonly HANDOFF_RELATIVE_PATH
  IFS=/ read -r -a HANDOFF_PARTS <<<"${HANDOFF_RELATIVE_PATH}"
  HANDOFF_CURRENT_PATH="${EVALUATOR_HOME}"
  require_safe_user_directory "${HANDOFF_CURRENT_PATH}"
  for handoff_part in "${HANDOFF_PARTS[@]}"; do
    [[ "${handoff_part}" =~ ^[A-Za-z0-9._-]{1,128}$ && \
      "${handoff_part}" != . && "${handoff_part}" != .. ]] ||
      fail 'handoff root contains a disallowed or ambiguous path component'
    HANDOFF_CURRENT_PATH="${HANDOFF_CURRENT_PATH}/${handoff_part}"
    require_owned_nonwritable_user_directory "${HANDOFF_CURRENT_PATH}"
  done
  readonly HANDOFF_CURRENT_PATH
  [[ -d "${HANDOFF_ROOT}" && ! -L "${HANDOFF_ROOT}" ]] ||
    fail 'handoff root must be a pre-existing real directory'
  [[ "$(/usr/bin/realpath -e -- "${HANDOFF_ROOT}")" == "${HANDOFF_ROOT}" ]] ||
    fail 'handoff root must already be canonical and contain no symlink component'
  [[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${HANDOFF_ROOT}")" == \
    "${EVALUATOR_UID}:${EVALUATOR_GID} 700 directory" ]] ||
    fail 'handoff root must be evaluator-owned mode 0700'
  [[ "$(/usr/bin/stat -c '%d' -- "${HANDOFF_ROOT}")" == \
    "$(/usr/bin/stat -c '%d' -- "${EVALUATOR_HOME}")" ]] ||
    fail 'handoff root must share the evaluator-home filesystem'
  if /usr/bin/find "${HANDOFF_ROOT}" -xdev -mindepth 1 -print -quit |
    /usr/bin/grep -q .; then
    fail 'handoff root must be empty before evaluation'
  fi
  HANDOFF_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i' -- "${HANDOFF_ROOT}")"
  HANDOFF_PROOF_V1="${HANDOFF_ROOT}/proof-v1.json"
  HANDOFF_PROOF_V2="${HANDOFF_ROOT}/proof-v2.json"
  HANDOFF_MANIFEST="${HANDOFF_ROOT}/handoff.manifest"
fi
readonly HANDOFF_REQUESTED HANDOFF_ROOT HANDOFF_ROOT_IDENTITY
readonly HANDOFF_PROOF_V1 HANDOFF_PROOF_V2 HANDOFF_MANIFEST
HANDOFF_PROOF_V1_SHA256=''
HANDOFF_PROOF_V1_SIZE=''
HANDOFF_PROOF_V2_SHA256=''
HANDOFF_PROOF_V2_SIZE=''
HANDOFF_MANIFEST_SHA256=''
HANDOFF_MANIFEST_SIZE=''
HANDOFF_STORE_SHA256=''

require_environment A_QUO_EVALUATOR_SIGNING_ARTIFACT
require_environment A_QUO_EVALUATOR_SIGNING_ARTIFACT_SHA256
readonly ARTIFACT_SOURCE="${A_QUO_EVALUATOR_SIGNING_ARTIFACT}"
readonly ARTIFACT_EXPECTED_SHA256="${A_QUO_EVALUATOR_SIGNING_ARTIFACT_SHA256}"
[[ "${ARTIFACT_EXPECTED_SHA256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'A_QUO_EVALUATOR_SIGNING_ARTIFACT_SHA256 must be lowercase SHA-256'
[[ "${ARTIFACT_SOURCE}" == /* ]] || fail 'signing artifact input must be an absolute path'
require_real_regular_file "${ARTIFACT_SOURCE}" 'signing artifact input'
ARTIFACT_SIZE="$(/usr/bin/stat -c '%s' -- "${ARTIFACT_SOURCE}")"
readonly ARTIFACT_SIZE
[[ "${ARTIFACT_SIZE}" =~ ^[0-9]+$ && "${ARTIFACT_SIZE}" -gt 0 && \
  "${ARTIFACT_SIZE}" -le 67108864 ]] ||
  fail 'signing artifact must be between 1 byte and 64 MiB for this evaluator'
[[ "$(/usr/bin/realpath -e -- "${ARTIFACT_SOURCE}")" == "${ARTIFACT_SOURCE}" ]] ||
  fail 'signing artifact input must already be canonical and contain no symlink component'
[[ "$(sha256_file "${ARTIFACT_SOURCE}")" == "${ARTIFACT_EXPECTED_SHA256}" ]] ||
  fail 'signing artifact input does not match its caller-supplied SHA-256 pin'
EVALUATOR_ARTIFACT_HASH_OUTPUT="$(run_as_evaluator /usr/bin/sha256sum -- \
  "${ARTIFACT_SOURCE}")" || fail 'evaluator account cannot read the pinned signing artifact'
readonly EVALUATOR_ARTIFACT_HASH_OUTPUT
[[ "${EVALUATOR_ARTIFACT_HASH_OUTPUT%% *}" == "${ARTIFACT_EXPECTED_SHA256}" ]] ||
  fail 'evaluator account observed different signing artifact bytes'

ARTIFACT_V2_SOURCE=''
ARTIFACT_V2_EXPECTED_SHA256=''
ARTIFACT_V2_SIZE=''
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  require_environment A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2
  require_environment A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256
  ARTIFACT_V2_SOURCE="${A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2}"
  ARTIFACT_V2_EXPECTED_SHA256="${A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256}"
  [[ "${ARTIFACT_V2_EXPECTED_SHA256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256 must be lowercase SHA-256'
  [[ "${ARTIFACT_V2_SOURCE}" == /* ]] ||
    fail 'v2 signing artifact input must be an absolute path'
  require_real_regular_file "${ARTIFACT_V2_SOURCE}" 'v2 signing artifact input'
  ARTIFACT_V2_SIZE="$(/usr/bin/stat -c '%s' -- "${ARTIFACT_V2_SOURCE}")"
  [[ "${ARTIFACT_V2_SIZE}" =~ ^[0-9]+$ && "${ARTIFACT_V2_SIZE}" -gt 0 && \
    "${ARTIFACT_V2_SIZE}" -le 67108864 ]] ||
    fail 'v2 signing artifact must be between 1 byte and 64 MiB for this evaluator'
  [[ "$(/usr/bin/realpath -e -- "${ARTIFACT_V2_SOURCE}")" == \
    "${ARTIFACT_V2_SOURCE}" ]] ||
    fail 'v2 signing artifact input must already be canonical and contain no symlink component'
  [[ "${ARTIFACT_V2_SOURCE}" != "${ARTIFACT_SOURCE}" && \
    "${ARTIFACT_V2_EXPECTED_SHA256}" != "${ARTIFACT_EXPECTED_SHA256}" ]] ||
    fail 'v2 signing artifact must be distinct from the v1 signing artifact'
  [[ "$(sha256_file "${ARTIFACT_V2_SOURCE}")" == \
    "${ARTIFACT_V2_EXPECTED_SHA256}" ]] ||
    fail 'v2 signing artifact input does not match its caller-supplied SHA-256 pin'
  EVALUATOR_ARTIFACT_V2_HASH_OUTPUT="$(run_as_evaluator /usr/bin/sha256sum -- \
    "${ARTIFACT_V2_SOURCE}")" ||
    fail 'evaluator account cannot read the pinned v2 signing artifact'
  [[ "${EVALUATOR_ARTIFACT_V2_HASH_OUTPUT%% *}" == \
    "${ARTIFACT_V2_EXPECTED_SHA256}" ]] ||
    fail 'evaluator account observed different v2 signing artifact bytes'
fi
readonly ARTIFACT_V2_SOURCE ARTIFACT_V2_EXPECTED_SHA256 ARTIFACT_V2_SIZE

installed_daemon_count() {
  local process
  local process_exe
  local process_uid
  local count=0
  for process in /proc/[0-9]*; do
    process_exe="$(/usr/bin/readlink -e -- "${process}/exe" 2>/dev/null || true)"
    [[ "${process_exe}" == "${A_QUO_DAEMON}" ]] || continue
    process_uid="$(/usr/bin/stat -c '%u' -- "${process}" 2>/dev/null || true)"
    [[ "${process_uid}" == "${EVALUATOR_UID}" ]] ||
      fail "installed daemon is already running under an unexpected UID: ${process##*/}"
    ((count += 1))
  done
  printf '%s\n' "${count}"
}

[[ "$(installed_daemon_count)" -eq 0 ]] ||
  fail 'an installed A Quo daemon is already running before evaluation'

TEMPORARY_ROOT=''
TEMPORARY_ROOT_IDENTITY=''
PRIVATE_KEY=''
STORE_ROOT_IDENTITY=''
PERSONA_ID=''
KEY_FINGERPRINT=''
REQUEST_PID=''
REQUEST_PGID=''
REQUEST_STARTTIME=''
REQUEST_CANDIDATE_PID=''
REQUEST_CANDIDATE_STARTTIME=''
REQUEST_CLEANUP_UNCERTAIN=false
SERVICE_TOUCHED=false

service_is_stopped() {
  local state
  local main_pid
  local daemon_count
  state="$(run_systemctl show "${SERVICE_NAME}" --property=ActiveState --value 2>/dev/null)" ||
    return 1
  main_pid="$(run_systemctl show "${SERVICE_NAME}" --property=MainPID --value 2>/dev/null)" ||
    return 1
  daemon_count="$(installed_daemon_count)" || return 1
  [[ "${state}" == inactive || "${state}" == failed ]] &&
    [[ "${main_pid}" == 0 && ! -e "${A_QUO_RUNTIME_DIRECTORY}" && \
      ! -L "${A_QUO_RUNTIME_DIRECTORY}" && "${daemon_count}" -eq 0 ]]
}

wait_for_service_stopped() {
  local attempt
  for ((attempt = 0; attempt < 100; attempt++)); do
    if service_is_stopped; then
      return 0
    fi
    /usr/bin/sleep 0.1
  done
  return 1
}

cleanup_request() {
  if [[ "${REQUEST_CLEANUP_UNCERTAIN}" == true ]]; then
    if [[ "${REQUEST_CANDIDATE_PID}" =~ ^[1-9][0-9]*$ && \
      "${REQUEST_CANDIDATE_STARTTIME}" =~ ^[1-9][0-9]*$ && \
      -r "/proc/${REQUEST_CANDIDATE_PID}/stat" && \
      "$(request_process_identity "${REQUEST_CANDIDATE_PID}")" == \
        *:"${REQUEST_CANDIDATE_STARTTIME}":* ]]; then
      /usr/bin/kill -TERM "${REQUEST_CANDIDATE_PID}" 2>/dev/null || true
    fi
    return 1
  fi
  [[ -n "${REQUEST_PID}" ]] || return 0
  local current_identity=''
  local attempt
  local status=0
  [[ "${REQUEST_PID}" =~ ^[1-9][0-9]*$ && \
    "${REQUEST_PGID}" == "${REQUEST_PID}" && \
    "${REQUEST_STARTTIME}" =~ ^[1-9][0-9]*$ ]] || return 1
  if [[ ! -r "/proc/${REQUEST_PID}/stat" ]]; then
    wait "${REQUEST_PID}" 2>/dev/null || true
    if /usr/bin/kill -0 -- "-${REQUEST_PGID}" 2>/dev/null; then
      return 1
    fi
    REQUEST_PID=''
    REQUEST_PGID=''
    REQUEST_STARTTIME=''
    return 0
  fi
  current_identity="$(request_process_identity "${REQUEST_PID}")" || return 1
  [[ "${current_identity}" == \
    "${REQUEST_PGID}:${REQUEST_PGID}:${REQUEST_STARTTIME}:"* ]] || return 1
  /usr/bin/kill -TERM -- "-${REQUEST_PGID}" 2>/dev/null || true
  for ((attempt = 0; attempt < 20; attempt++)); do
    if [[ -r "/proc/${REQUEST_PID}/stat" && \
      "$(request_process_identity "${REQUEST_PID}")" == *:Z ]]; then
      wait "${REQUEST_PID}" 2>/dev/null || true
    fi
    if ! /usr/bin/kill -0 -- "-${REQUEST_PGID}" 2>/dev/null; then
      wait "${REQUEST_PID}" 2>/dev/null || true
      REQUEST_PID=''
      REQUEST_PGID=''
      REQUEST_STARTTIME=''
      return 0
    fi
    /usr/bin/sleep 0.1
  done
  [[ -r "/proc/${REQUEST_PID}/stat" ]] || return 1
  current_identity="$(request_process_identity "${REQUEST_PID}")" || return 1
  [[ "${current_identity}" == \
    "${REQUEST_PGID}:${REQUEST_PGID}:${REQUEST_STARTTIME}:"[!Z] ]] || return 1
  /usr/bin/kill -KILL -- "-${REQUEST_PGID}" 2>/dev/null || true
  for ((attempt = 0; attempt < 20; attempt++)); do
    if [[ -r "/proc/${REQUEST_PID}/stat" && \
      "$(request_process_identity "${REQUEST_PID}")" == *:Z ]]; then
      wait "${REQUEST_PID}" 2>/dev/null || true
    fi
    if ! /usr/bin/kill -0 -- "-${REQUEST_PGID}" 2>/dev/null; then
      wait "${REQUEST_PID}" 2>/dev/null || true
      REQUEST_PID=''
      REQUEST_PGID=''
      REQUEST_STARTTIME=''
      return 0
    fi
    /usr/bin/sleep 0.1
  done
  status=1
  return "${status}"
}

service_enable_state_restored() {
  [[ -d "${USER_UNIT_ROOT}" && ! -L "${USER_UNIT_ROOT}" && \
    "$(/usr/bin/stat -c '%d:%i' -- "${USER_UNIT_ROOT}")" == \
      "${USER_UNIT_ROOT_IDENTITY}" && \
    -d "${USER_ENABLE_DIRECTORY}" && ! -L "${USER_ENABLE_DIRECTORY}" && \
    "$(/usr/bin/stat -c '%d:%i' -- "${USER_ENABLE_DIRECTORY}")" == \
      "${USER_ENABLE_DIRECTORY_IDENTITY}" ]] || return 1
  ! /usr/bin/find "${USER_ENABLE_DIRECTORY}" -xdev -mindepth 1 -print -quit |
    /usr/bin/grep -q .
}

cleanup_service() {
  [[ "${SERVICE_TOUCHED}" == true ]] || return 0
  local status=0
  if ! service_is_stopped; then
    run_systemctl stop --no-block "${SERVICE_NAME}" >/dev/null 2>&1 || status=1
    if ! wait_for_service_stopped; then
      run_systemctl kill --kill-whom=all --signal=KILL "${SERVICE_NAME}" \
        >/dev/null 2>&1 || status=1
      wait_for_service_stopped || status=1
    fi
  fi
  run_systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || status=1
  run_systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true
  wait_for_service_stopped || status=1
  [[ "$(run_systemctl show "${SERVICE_NAME}" --property=UnitFileState --value 2>/dev/null)" == disabled ]] ||
    status=1
  [[ "$(run_systemctl show "${SERVICE_NAME}" --property=ActiveState --value 2>/dev/null)" == inactive ]] ||
    status=1
  service_enable_state_restored || status=1
  return "${status}"
}

remove_disposable_store() {
  [[ -n "${STORE_ROOT_IDENTITY}" ]] || return 0
  [[ "${DEFAULT_STORE_ROOT}" == '/home/a-quo-evaluator/.local/share/a-quo' ]] || return 1
  [[ -d "${DEFAULT_STORE_ROOT}" && ! -L "${DEFAULT_STORE_ROOT}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%d:%i' -- "${DEFAULT_STORE_ROOT}")" == \
    "${STORE_ROOT_IDENTITY}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u:%g %a' -- "${DEFAULT_STORE_ROOT}")" == \
    "${EVALUATOR_UID}:${EVALUATOR_GID} 700" ]] || return 1
  if /usr/bin/find "${DEFAULT_STORE_ROOT}" -xdev -mindepth 1 \
    ! -type f -print -quit | /usr/bin/grep -q .; then
    return 1
  fi
  local state_file
  local base
  while IFS= read -r -d '' state_file; do
    base="${state_file##*/}"
    case "${base}" in
      personas.sqlite3 | personas.sqlite3-wal | personas.sqlite3-shm | personas.sqlite3-journal) ;;
      *) return 1 ;;
    esac
    [[ "$(/usr/bin/stat -c '%u:%g' -- "${state_file}")" == \
      "${EVALUATOR_UID}:${EVALUATOR_GID}" ]] || return 1
    run_as_evaluator /usr/bin/rm -f -- "${state_file}" || return 1
  done < <(/usr/bin/find "${DEFAULT_STORE_ROOT}" -xdev -mindepth 1 -type f -print0)
  run_as_evaluator /usr/bin/rmdir -- "${DEFAULT_STORE_ROOT}" || return 1
  [[ ! -e "${DEFAULT_STORE_ROOT}" && ! -L "${DEFAULT_STORE_ROOT}" ]]
}

handoff_root_is_pinned() {
  [[ "${HANDOFF_REQUESTED}" == true ]] || return 1
  [[ -d "${HANDOFF_ROOT}" && ! -L "${HANDOFF_ROOT}" && \
    "$(/usr/bin/realpath -e -- "${HANDOFF_ROOT}")" == "${HANDOFF_ROOT}" && \
    "$(/usr/bin/stat -c '%d:%i' -- "${HANDOFF_ROOT}")" == \
      "${HANDOFF_ROOT_IDENTITY}" && \
    "$(/usr/bin/stat -c '%u:%g %a %F' -- "${HANDOFF_ROOT}")" == \
      "${EVALUATOR_UID}:${EVALUATOR_GID} 700 directory" ]]
}

clear_handoff_outputs() {
  [[ "${HANDOFF_REQUESTED}" == true ]] || return 0
  handoff_root_is_pinned || return 1
  local output
  local metadata
  for output in \
    "${HANDOFF_PROOF_V1}" \
    "${HANDOFF_PROOF_V2}" \
    "${HANDOFF_MANIFEST}"; do
    if [[ -e "${output}" || -L "${output}" ]]; then
      [[ -f "${output}" && ! -L "${output}" ]] || return 1
      metadata="$(/usr/bin/stat -c '%u:%g %h %F' -- "${output}")" || return 1
      [[ "${metadata}" == "${EVALUATOR_UID}:${EVALUATOR_GID} 1 regular file" || \
        "${metadata}" == "${EVALUATOR_UID}:${EVALUATOR_GID} 2 regular file" ]] || return 1
      run_as_evaluator /usr/bin/rm -f -- "${output}" || return 1
    fi
  done
  ! /usr/bin/find "${HANDOFF_ROOT}" -xdev -mindepth 1 -print -quit |
    /usr/bin/grep -q .
}

validate_retained_store() {
  [[ -n "${STORE_ROOT_IDENTITY}" && \
    -d "${DEFAULT_STORE_ROOT}" && ! -L "${DEFAULT_STORE_ROOT}" && \
    "$(/usr/bin/stat -c '%d:%i' -- "${DEFAULT_STORE_ROOT}")" == \
      "${STORE_ROOT_IDENTITY}" && \
    "$(/usr/bin/stat -c '%u:%g %a %F' -- "${DEFAULT_STORE_ROOT}")" == \
      "${EVALUATOR_UID}:${EVALUATOR_GID} 700 directory" ]] || return 1
  local personas_json
  local binding_history_json
  personas_json="$(run_a_quo persona list --json)" || return 1
  /usr/bin/jq -e --arg persona_id "${PERSONA_ID}" '
    length == 1 and
    .[0].id == $persona_id and
    .[0].lifecycle_status == "active" and
    .[0].authority_disposition == "not_checked" and
    .[0].persona_authorization == "not_checked_by_listing" and
    .[0].quarantined == false
  ' <<<"${personas_json}" >/dev/null || return 1
  binding_history_json="$(run_a_quo persona key-binding-history \
    --fingerprint "${KEY_FINGERPRINT}" --json)" || return 1
  /usr/bin/jq -e --arg fingerprint "${KEY_FINGERPRINT}" '
    length == 2 and
    .[0].sequence == 1 and
    .[0].key_fingerprint == $fingerprint and
    .[0].event_type == "bound" and
    (.[0].locator_sha256 | type == "string") and
    .[1].sequence == 2 and
    .[1].key_fingerprint == $fingerprint and
    .[1].event_type == "unbound" and
    .[1].locator_sha256 == null and
    all(.[]; has("locator") | not)
  ' <<<"${binding_history_json}" >/dev/null || return 1
  [[ -f "${DEFAULT_STORE}" && ! -L "${DEFAULT_STORE}" ]] || return 1
  if /usr/bin/find "${DEFAULT_STORE_ROOT}" -xdev -mindepth 1 \
    ! -type f -print -quit | /usr/bin/grep -q .; then
    return 1
  fi
  local state_file
  local metadata
  while IFS= read -r -d '' state_file; do
    case "${state_file##*/}" in
      personas.sqlite3 | personas.sqlite3-wal | personas.sqlite3-shm | personas.sqlite3-journal) ;;
      *) return 1 ;;
    esac
    metadata="$(/usr/bin/stat -c '%u:%g %a %h %F' -- "${state_file}")" || return 1
    [[ "${metadata}" == \
      "${EVALUATOR_UID}:${EVALUATOR_GID} 600 1 regular file" ]] || return 1
  done < <(/usr/bin/find "${DEFAULT_STORE_ROOT}" -xdev -mindepth 1 -type f -print0)
}

print_handoff_manifest() {
  printf '%s\n' \
    'format=a-quo-installed-omarchy-preconsented-handoff-v2' \
    "store_path=${DEFAULT_STORE}" \
    "artifact_v1_sha256=${ARTIFACT_EXPECTED_SHA256}" \
    "artifact_v1_size=${ARTIFACT_SIZE}" \
    'proof_v1_file=proof-v1.json' \
    "proof_v1_sha256=${HANDOFF_PROOF_V1_SHA256}" \
    "proof_v1_size=${HANDOFF_PROOF_V1_SIZE}" \
    "artifact_v2_sha256=${ARTIFACT_V2_EXPECTED_SHA256}" \
    "artifact_v2_size=${ARTIFACT_V2_SIZE}" \
    'proof_v2_file=proof-v2.json' \
    "proof_v2_sha256=${HANDOFF_PROOF_V2_SHA256}" \
    "proof_v2_size=${HANDOFF_PROOF_V2_SIZE}" \
    "persona_id=${PERSONA_ID}" \
    "key_fingerprint=${KEY_FINGERPRINT}" \
    'trusted_consent_v1=operator-approved-installed-daemon' \
    'trusted_consent_v2=operator-approved-installed-daemon' \
    'input_origin=not-machine-verifiable'
}

validate_handoff_inventory() {
  local expected_links="$1"
  handoff_root_is_pinned || return 1
  [[ "$(/usr/bin/find "${HANDOFF_ROOT}" -xdev -mindepth 1 -maxdepth 1 \
    -printf . | /usr/bin/wc -c)" -eq 3 ]] || return 1
  [[ "$(/usr/bin/stat -c '%h' -- "${HANDOFF_PROOF_V1}")" == \
    "${expected_links}" && \
    "$(/usr/bin/stat -c '%h' -- "${HANDOFF_PROOF_V2}")" == \
    "${expected_links}" && \
    "$(/usr/bin/stat -c '%h' -- "${HANDOFF_MANIFEST}")" == \
      "${expected_links}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%s' -- "${HANDOFF_PROOF_V1}")" == \
    "${HANDOFF_PROOF_V1_SIZE}" && \
    "$(/usr/bin/stat -c '%s' -- "${HANDOFF_PROOF_V2}")" == \
      "${HANDOFF_PROOF_V2_SIZE}" && \
    "$(/usr/bin/stat -c '%s' -- "${HANDOFF_MANIFEST}")" == \
      "${HANDOFF_MANIFEST_SIZE}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${HANDOFF_PROOF_V1}")" == \
    "${EVALUATOR_UID}:${EVALUATOR_GID} 600 regular file" && \
    "$(/usr/bin/stat -c '%u:%g %a %F' -- "${HANDOFF_PROOF_V2}")" == \
    "${EVALUATOR_UID}:${EVALUATOR_GID} 600 regular file" && \
    "$(/usr/bin/stat -c '%u:%g %a %F' -- "${HANDOFF_MANIFEST}")" == \
      "${EVALUATOR_UID}:${EVALUATOR_GID} 600 regular file" ]] || return 1
  [[ ! -L "${HANDOFF_PROOF_V1}" && ! -L "${HANDOFF_PROOF_V2}" && \
    ! -L "${HANDOFF_MANIFEST}" && \
    "$(sha256_file "${HANDOFF_PROOF_V1}")" == \
      "${HANDOFF_PROOF_V1_SHA256}" && \
    "$(sha256_file "${HANDOFF_PROOF_V2}")" == \
      "${HANDOFF_PROOF_V2_SHA256}" && \
    "$(sha256_file "${HANDOFF_MANIFEST}")" == "${HANDOFF_MANIFEST_SHA256}" ]] || return 1
  /usr/bin/cmp -s -- "${HANDOFF_MANIFEST}" <(print_handoff_manifest)
}

create_handoff_outputs() {
  [[ "${HANDOFF_REQUESTED}" == true ]] || return 1
  handoff_root_is_pinned || return 1
  if /usr/bin/find "${HANDOFF_ROOT}" -xdev -mindepth 1 -print -quit |
    /usr/bin/grep -q .; then
    return 1
  fi
  [[ "$(/usr/bin/stat -c '%h' -- "${APPROVED_PROOF_V1}")" == 1 && \
    "$(/usr/bin/stat -c '%h' -- "${APPROVED_PROOF_V2}")" == 1 ]] || return 1
  HANDOFF_PROOF_V1_SHA256="$(sha256_file "${APPROVED_PROOF_V1}")" || return 1
  HANDOFF_PROOF_V1_SIZE="$(/usr/bin/stat -c '%s' -- "${APPROVED_PROOF_V1}")" || return 1
  HANDOFF_PROOF_V2_SHA256="$(sha256_file "${APPROVED_PROOF_V2}")" || return 1
  HANDOFF_PROOF_V2_SIZE="$(/usr/bin/stat -c '%s' -- "${APPROVED_PROOF_V2}")" || return 1
  [[ "${HANDOFF_PROOF_V1_SHA256}" =~ ^[0-9a-f]{64}$ && \
    "${HANDOFF_PROOF_V1_SIZE}" =~ ^[1-9][0-9]*$ && \
    "${HANDOFF_PROOF_V1_SIZE}" -le 1048576 && \
    "${HANDOFF_PROOF_V2_SHA256}" =~ ^[0-9a-f]{64}$ && \
    "${HANDOFF_PROOF_V2_SIZE}" =~ ^[1-9][0-9]*$ && \
    "${HANDOFF_PROOF_V2_SIZE}" -le 1048576 ]] || return 1
  local manifest_source="${TEMPORARY_ROOT}/handoff.manifest"
  [[ ! -e "${manifest_source}" && ! -L "${manifest_source}" ]] || return 1
  print_handoff_manifest | run_as_evaluator /usr/bin/dd \
    of="${manifest_source}" bs=4096 count=1 iflag=fullblock \
    oflag=excl,nofollow status=none ||
    return 1
  run_as_evaluator /usr/bin/chmod 0600 -- "${manifest_source}" || return 1
  [[ "$(/usr/bin/stat -c '%u:%g %a %h %F' -- "${manifest_source}")" == \
    "${EVALUATOR_UID}:${EVALUATOR_GID} 600 1 regular file" ]] || return 1
  /usr/bin/cmp -s -- "${manifest_source}" <(print_handoff_manifest) || return 1
  HANDOFF_MANIFEST_SHA256="$(sha256_file "${manifest_source}")" || return 1
  HANDOFF_MANIFEST_SIZE="$(/usr/bin/stat -c '%s' -- "${manifest_source}")" || return 1
  [[ "${HANDOFF_MANIFEST_SHA256}" =~ ^[0-9a-f]{64}$ && \
    "${HANDOFF_MANIFEST_SIZE}" =~ ^[1-9][0-9]*$ && \
    "$(/usr/bin/wc -l <"${manifest_source}")" -eq 17 ]] || return 1
  handoff_root_is_pinned || return 1
  run_as_evaluator /usr/bin/ln -- "${APPROVED_PROOF_V1}" "${HANDOFF_PROOF_V1}" || return 1
  run_as_evaluator /usr/bin/ln -- "${APPROVED_PROOF_V2}" "${HANDOFF_PROOF_V2}" || return 1
  run_as_evaluator /usr/bin/ln -- "${manifest_source}" "${HANDOFF_MANIFEST}" || return 1
  validate_handoff_inventory 2
}

remove_temporary_root() {
  case "${TEMPORARY_ROOT}" in
    "${EVALUATOR_HOME}"/.a-quo-installed-consent-lifecycle.*) ;;
    *) return 1 ;;
  esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" && \
    "$(/usr/bin/stat -c '%d:%i' -- "${TEMPORARY_ROOT}")" == \
      "${TEMPORARY_ROOT_IDENTITY}" && \
    "$(/usr/bin/stat -c '%u:%g' -- "${TEMPORARY_ROOT}")" == \
      "${EVALUATOR_UID}:${EVALUATOR_GID}" ]] || return 1
  if [[ -n "${PRIVATE_KEY}" && "${PRIVATE_KEY}" == "${TEMPORARY_ROOT}/"* ]]; then
    run_as_evaluator /usr/bin/rm -f -- "${PRIVATE_KEY}" "${PRIVATE_KEY}.pub" || return 1
  fi
  if /usr/bin/find "${TEMPORARY_ROOT}" -xdev -mindepth 1 \
    ! -type f -print -quit | /usr/bin/grep -q .; then
    return 1
  fi
  local temporary_file
  local file_uid
  while IFS= read -r -d '' temporary_file; do
    [[ "${temporary_file}" == "${TEMPORARY_ROOT}/"* && \
      -f "${temporary_file}" && ! -L "${temporary_file}" ]] || return 1
    file_uid="$(/usr/bin/stat -c '%u' -- "${temporary_file}")" || return 1
    [[ "${file_uid}" == 0 || "${file_uid}" == "${EVALUATOR_UID}" ]] || return 1
    case "${temporary_file##*/}" in
      exact-signing-artifact | exact-signing-artifact-v2 | \
        publisher-ed25519 | publisher-ed25519.pub | \
        decline.stdout | decline.stderr | declined-proof.json | approve.stdout | \
        approve.stderr | approved-proof-v1.json | altered-artifact | \
        approve-v2.stdout | approve-v2.stderr | approved-proof-v2.json | \
        altered-artifact-v2 | handoff.manifest) ;;
      *) return 1 ;;
    esac
    run_as_evaluator /usr/bin/rm -f -- "${temporary_file}" || return 1
  done < <(/usr/bin/find "${TEMPORARY_ROOT}" -xdev -mindepth 1 -type f -print0)
  run_as_evaluator /usr/bin/rmdir -- "${TEMPORARY_ROOT}" || return 1
  [[ ! -e "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]]
}

cleanup() {
  local status="$?"
  local cleanup_status=0
  local handoff_cleanup_status=0
  local request_cleanup_status=0
  local service_cleanup_status=0
  trap - EXIT INT TERM HUP
  cleanup_request || request_cleanup_status=1
  cleanup_service || service_cleanup_status=1
  clear_handoff_outputs || handoff_cleanup_status=1
  if [[ "${request_cleanup_status}" -eq 0 && \
    "${service_cleanup_status}" -eq 0 ]] && service_is_stopped; then
    if [[ -n "${STORE_ROOT_IDENTITY}" ]]; then
      remove_disposable_store || cleanup_status=1
    fi
    if [[ -n "${TEMPORARY_ROOT}" ]]; then
      remove_temporary_root || cleanup_status=1
    fi
  else
    cleanup_status=1
  fi
  if [[ "${request_cleanup_status}" -ne 0 || \
    "${service_cleanup_status}" -ne 0 || \
    "${handoff_cleanup_status}" -ne 0 ]]; then
    cleanup_status=1
  fi
  if [[ "${cleanup_status}" -ne 0 ]]; then
    printf '%s\n' 'evaluator cleanup failed or an exact cleanup identity changed' >&2
    [[ "${status}" -ne 0 ]] || status=1
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

TEMPORARY_ROOT="$(run_as_evaluator /usr/bin/mktemp -d \
  "${EVALUATOR_HOME}/.a-quo-installed-consent-lifecycle.XXXXXX")"
TEMPORARY_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i' -- "${TEMPORARY_ROOT}")"
readonly TEMPORARY_ROOT TEMPORARY_ROOT_IDENTITY
[[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] ||
  fail 'evaluator-created temporary root is not a real directory'
[[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${TEMPORARY_ROOT}")" == \
  "${EVALUATOR_UID}:${EVALUATOR_GID} 700 directory" ]] ||
  fail 'evaluator-created temporary root has unexpected owner, mode, or type'

readonly ARTIFACT_V1="${TEMPORARY_ROOT}/exact-signing-artifact"
run_as_evaluator /usr/bin/install -T -m 0400 -- \
  "${ARTIFACT_SOURCE}" "${ARTIFACT_V1}"
if [[ "$(sha256_file "${ARTIFACT_V1}")" != "${ARTIFACT_EXPECTED_SHA256}" || \
  "$(sha256_file "${ARTIFACT_SOURCE}")" != "${ARTIFACT_EXPECTED_SHA256}" ]]; then
  fail 'signing artifact changed while its private evaluator snapshot was created'
fi
ARTIFACT_V2=''
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  ARTIFACT_V2="${TEMPORARY_ROOT}/exact-signing-artifact-v2"
  run_as_evaluator /usr/bin/install -T -m 0400 -- \
    "${ARTIFACT_V2_SOURCE}" "${ARTIFACT_V2}"
  if [[ "$(sha256_file "${ARTIFACT_V2}")" != \
    "${ARTIFACT_V2_EXPECTED_SHA256}" || \
    "$(sha256_file "${ARTIFACT_V2_SOURCE}")" != \
      "${ARTIFACT_V2_EXPECTED_SHA256}" ]]; then
    fail 'v2 signing artifact changed while its private evaluator snapshot was created'
  fi
fi
readonly ARTIFACT_V2

SERVICE_TOUCHED=true
set +e
run_systemctl start "${SERVICE_NAME}" \
  >/dev/null 2>&1
MISSING_STORE_START_STATUS="$?"
set -e
wait_for_service_stopped || fail 'missing-store service failure did not settle without authority'
[[ ! -e "${CONSENT_SOCKET}" && ! -L "${CONSENT_SOCKET}" ]] ||
  fail 'missing-store service failure left a consent socket entry'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=MainPID --value)" == 0 ]] ||
  fail 'missing-store service failure retained a main process'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=Result --value)" == exit-code ]] ||
  fail 'startup with the store absent did not end in an exact exit-code failure'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=ExecMainCode --value)" == exited ]] ||
  fail 'startup with the store absent did not record a normal process exit'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=ExecMainStatus --value)" == 1 ]] ||
  fail 'startup with the store absent did not record the daemon fail-closed status'
[[ "${MISSING_STORE_START_STATUS}" -eq 0 || "${MISSING_STORE_START_STATUS}" -eq 1 ]] ||
  fail 'systemctl returned an unexpected status while observing startup with the store absent'
run_systemctl reset-failed "${SERVICE_NAME}" >/dev/null
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=ActiveState --value)" == inactive ]] ||
  fail 'service did not return to inactive after missing-store failure'

PRIVATE_KEY="${TEMPORARY_ROOT}/publisher-ed25519"
readonly PRIVATE_KEY
run_as_evaluator /usr/bin/ssh-keygen -q -t ed25519 -N '' \
  -C 'A Quo disposable installed consent evaluator; not a release identity' \
  -f "${PRIVATE_KEY}"
PERSONA_JSON="$(run_a_quo persona create \
  --label 'A Quo disposable installed consent evaluator' \
  --purpose project --json)" || fail 'disposable persona creation failed'
readonly PERSONA_JSON
PERSONA_ID="$(/usr/bin/jq -er '.id' <<<"${PERSONA_JSON}")"
readonly PERSONA_ID
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  [[ "${PERSONA_ID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
    fail 'disposable persona returned a non-canonical local ID'
fi
[[ -d "${DEFAULT_STORE_ROOT}" && ! -L "${DEFAULT_STORE_ROOT}" ]] ||
  fail 'persona creation did not create the exact default store root'
STORE_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i' -- "${DEFAULT_STORE_ROOT}")"
readonly STORE_ROOT_IDENTITY
[[ "$(/usr/bin/stat -c '%u:%g %a' -- "${DEFAULT_STORE_ROOT}")" == \
  "${EVALUATOR_UID}:${EVALUATOR_GID} 700" ]] ||
  fail 'default store root has unexpected owner or mode'
[[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${DEFAULT_STORE}")" == \
  "${EVALUATOR_UID}:${EVALUATOR_GID} 600 regular file" ]] ||
  fail 'default persona store has unexpected owner, mode, or type'
KEY_JSON="$(run_a_quo persona key-add \
  --persona-id "${PERSONA_ID}" --public-key "${PRIVATE_KEY}.pub" \
  --provider openssh-file --json)" || fail 'disposable key registration failed'
readonly KEY_JSON
KEY_FINGERPRINT="$(/usr/bin/jq -er '.fingerprint' <<<"${KEY_JSON}")"
readonly KEY_FINGERPRINT
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  [[ "${KEY_FINGERPRINT}" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] ||
    fail 'disposable key returned a non-canonical SHA-256 fingerprint'
fi
run_a_quo persona key-bind \
  --fingerprint "${KEY_FINGERPRINT}" --signing-key "${PRIVATE_KEY}" \
  --json >/dev/null

wait_for_service_ready() {
  local attempt
  for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ "$(run_systemctl show "${SERVICE_NAME}" --property=ActiveState --value 2>/dev/null)" == \
      active && -d "${A_QUO_RUNTIME_DIRECTORY}" && ! -L "${A_QUO_RUNTIME_DIRECTORY}" && \
      -S "${CONSENT_SOCKET}" && ! -L "${CONSENT_SOCKET}" ]]; then
      return 0
    fi
    /usr/bin/sleep 0.1
  done
  return 1
}

daemon_main_pid() {
  local pid
  pid="$(run_systemctl show "${SERVICE_NAME}" --property=MainPID --value)"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "${pid}"
}

verify_service_ready() {
  wait_for_service_ready || fail 'packaged user service did not become ready in time'
  require_safe_user_directory "${A_QUO_RUNTIME_DIRECTORY}"
  [[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${CONSENT_SOCKET}")" == \
    "${EVALUATOR_UID}:${EVALUATOR_GID} 600 socket" ]] ||
    fail 'consent socket has unexpected ownership, mode, or type'
  local pid
  pid="$(daemon_main_pid)" || fail 'packaged service has no valid main PID'
  [[ "$(/usr/bin/readlink -e -- "/proc/${pid}/exe")" == "${A_QUO_DAEMON}" ]] ||
    fail 'packaged service main process is not the installed daemon'
  [[ "$(/usr/bin/stat -c '%u' -- "/proc/${pid}")" == "${EVALUATOR_UID}" ]] ||
    fail 'packaged daemon does not run as the evaluator UID'
  /usr/bin/grep -zFxq -- "HOME=${EVALUATOR_HOME}" "/proc/${pid}/environ" ||
    fail 'packaged daemon lacks the exact evaluator home'
  /usr/bin/grep -zFxq -- "XDG_RUNTIME_DIR=${EVALUATOR_RUNTIME_DIRECTORY}" \
    "/proc/${pid}/environ" || fail 'packaged daemon lacks the exact runtime directory'
  /usr/bin/grep -zFxq -- "WAYLAND_DISPLAY=${WAYLAND_DISPLAY_VALUE}" \
    "/proc/${pid}/environ" || fail 'packaged daemon lacks the exact Wayland display'
  if /usr/bin/grep -zEq -- '^XDG_DATA_HOME=' "/proc/${pid}/environ" &&
    ! /usr/bin/grep -zFxq -- "XDG_DATA_HOME=${EVALUATOR_HOME}/.local/share" \
      "/proc/${pid}/environ"; then
    fail 'packaged daemon inherited a divergent data home'
  fi
  if /usr/bin/grep -zEq -- '^XDG_CONFIG_HOME=' "/proc/${pid}/environ" &&
    ! /usr/bin/grep -zFxq -- "XDG_CONFIG_HOME=${EVALUATOR_HOME}/.config" \
      "/proc/${pid}/environ"; then
    fail 'packaged daemon inherited a divergent config home'
  fi
  if /usr/bin/grep -zEq -- '^(LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT)=' \
    "/proc/${pid}/environ"; then
    fail 'packaged daemon inherited a loader-injection variable'
  fi
  [[ "$(installed_daemon_count)" -eq 1 ]] ||
    fail 'system does not have exactly one installed daemon under the evaluator UID'
  [[ "$(run_systemctl show "${SERVICE_NAME}" --property=MainPID --value)" == "${pid}" ]] ||
    fail 'packaged daemon main PID changed during readiness validation'
}

run_systemctl enable --now "${SERVICE_NAME}" >/dev/null
verify_service_ready
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=UnitFileState --value)" == enabled ]] ||
  fail 'explicit service enablement did not persist'
[[ -L "${SERVICE_ENABLE_LINK}" && \
  "$(/usr/bin/readlink -e -- "${SERVICE_ENABLE_LINK}")" == "${SERVICE_UNIT}" ]] ||
  fail 'explicit service enablement did not create the sole expected installed-unit link'
[[ "$(/usr/bin/find "${USER_ENABLE_DIRECTORY}" -xdev -mindepth 1 -maxdepth 1 \
  -printf '%f\n')" == "${SERVICE_NAME}" ]] ||
  fail 'explicit service enablement created unexpected entries'
/usr/bin/runuser -u "${CROSS_UID_ACCOUNT}" -- /usr/bin/env -i \
  PATH=/usr/bin:/bin LC_ALL=C /usr/bin/true ||
  fail 'cross-UID probe account could not execute the control command'
set +e
CROSS_UID_OUTPUT="$(/usr/bin/runuser -u "${CROSS_UID_ACCOUNT}" -- /usr/bin/env -i \
  PATH=/usr/bin:/bin LC_ALL=C /usr/bin/stat "${CONSENT_SOCKET}" \
  2>&1)"
CROSS_UID_STATUS="$?"
set -e
readonly CROSS_UID_OUTPUT CROSS_UID_STATUS
[[ "${CROSS_UID_STATUS}" -ne 0 ]] ||
  fail 'cross-UID account unexpectedly reached the private consent socket path'
[[ "${CROSS_UID_OUTPUT}" == *'Permission denied'* ]] ||
  fail 'cross-UID socket probe failed for a reason other than private-directory denial'

wait_for_live_helper() {
  local daemon_pid="$1"
  local attempt
  local child
  local helper_pid=''
  local ppid=''
  local key
  local value
  local environment_entry
  local environment_name
  for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ -r "/proc/${daemon_pid}/task/${daemon_pid}/children" ]]; then
      for child in $(<"/proc/${daemon_pid}/task/${daemon_pid}/children"); do
        if [[ "$(/usr/bin/readlink -e -- "/proc/${child}/exe" 2>/dev/null || true)" == \
          "${A_QUO_CONSENT}" ]]; then
          [[ -z "${helper_pid}" ]] || fail 'daemon launched overlapping consent helpers'
          helper_pid="${child}"
        fi
      done
    fi
    if [[ -n "${helper_pid}" ]]; then
      break
    fi
    if [[ -n "${REQUEST_PID}" ]] && ! /usr/bin/kill -0 "${REQUEST_PID}" 2>/dev/null; then
      fail 'request-sign exited before the packaged consent helper became inspectable'
    fi
    /usr/bin/sleep 0.1
  done
  [[ -n "${helper_pid}" ]] || fail 'packaged consent helper did not appear in time'
  [[ "$(/usr/bin/stat -c '%u' -- "/proc/${helper_pid}")" == "${EVALUATOR_UID}" ]] ||
    fail 'consent helper does not run as the evaluator UID'
  while IFS=$'\t' read -r key value; do
    if [[ "${key}" == 'PPid:' ]]; then
      ppid="${value}"
      break
    fi
  done <"/proc/${helper_pid}/status"
  [[ "${ppid}" == "${daemon_pid}" ]] || fail 'consent helper is not a direct daemon child'
  if /usr/bin/grep -zEq -- \
    '^(DBUS_SESSION_BUS_ADDRESS|DISPLAY|PATH|SSH_AUTH_SOCK|SSH_ASKPASS|LD_PRELOAD|LD_LIBRARY_PATH)=' \
    "/proc/${helper_pid}/environ"; then
    fail 'consent helper inherited a forbidden bus, X11, path, signer, or loader variable'
  fi
  while IFS= read -r -d '' environment_entry; do
    environment_name="${environment_entry%%=*}"
    case "${environment_name}" in
      WAYLAND_DISPLAY | XDG_RUNTIME_DIR | LANG | LANGUAGE | LC_ADDRESS | LC_ALL | \
        LC_COLLATE | LC_CTYPE | LC_IDENTIFICATION | LC_MEASUREMENT | LC_MESSAGES | \
        LC_MONETARY | LC_NAME | LC_NUMERIC | LC_PAPER | LC_TELEPHONE | LC_TIME) ;;
      *) fail "consent helper inherited an unapproved environment variable: ${environment_name}" ;;
    esac
  done <"/proc/${helper_pid}/environ"
  /usr/bin/grep -zFxq -- "WAYLAND_DISPLAY=${WAYLAND_DISPLAY_VALUE}" \
    "/proc/${helper_pid}/environ" || fail 'consent helper lacks the exact Wayland display'
  /usr/bin/grep -zFxq -- "XDG_RUNTIME_DIR=${EVALUATOR_RUNTIME_DIRECTORY}" \
    "/proc/${helper_pid}/environ" || fail 'consent helper lacks the exact runtime directory'
  /usr/bin/kill -0 "${helper_pid}" 2>/dev/null || fail 'consent helper exited during inspection'
  printf '%s\n' "${helper_pid}"
}

request_process_identity() {
  local pid="$1"
  local stat_record
  local stat_tail
  local -a fields=()
  IFS= read -r stat_record <"/proc/${pid}/stat" || return 1
  stat_tail="${stat_record##*) }"
  read -r -a fields <<<"${stat_tail}"
  [[ "${#fields[@]}" -ge 20 ]] || return 1
  printf '%s:%s:%s:%s\n' \
    "${fields[2]}" "${fields[3]}" "${fields[19]}" "${fields[0]}"
}

daemon_generation() {
  local pid
  local identity
  local process_group
  local session
  local starttime
  local state
  pid="$(daemon_main_pid)" || return 1
  identity="$(request_process_identity "${pid}")" || return 1
  IFS=: read -r process_group session starttime state <<<"${identity}"
  [[ "${process_group}" =~ ^[0-9]+$ && "${session}" =~ ^[0-9]+$ && \
    "${starttime}" =~ ^[1-9][0-9]*$ && "${state}" != Z ]] || return 1
  printf '%s:%s\n' "${pid}" "${starttime}"
}

start_sign_request() {
  local ARTIFACT="$1"
  local label="$2"
  local output="$3"
  local stdout_path="$4"
  local stderr_path="$5"
  local identity=''
  local attempt
  local candidate_pgid=''
  local candidate_pid=''
  local candidate_session=''
  local candidate_starttime=''
  local candidate_state=''
  [[ -z "${REQUEST_PID}" ]] || fail 'another request-sign process is already tracked'
  [[ "${ARTIFACT}" == "${ARTIFACT_V1}" || \
    ( "${HANDOFF_REQUESTED}" == true && "${ARTIFACT}" == "${ARTIFACT_V2}" ) ]] ||
    fail 'request-sign artifact is not an exact authenticated evaluator snapshot'
  set +e
  [[ "${stdout_path}" == "${TEMPORARY_ROOT}/"* && \
    "${stderr_path}" == "${TEMPORARY_ROOT}/"* && \
    ! -e "${stdout_path}" && ! -L "${stdout_path}" && \
    ! -e "${stderr_path}" && ! -L "${stderr_path}" ]] ||
    fail 'request capture paths are not fresh entries inside the evaluator work root'
  # shellcheck disable=SC2016 # The evaluator-side shell expands its own arguments.
  /usr/bin/setsid --wait /usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- \
    /usr/bin/env -i \
    HOME="${EVALUATOR_HOME}" \
    USER="${EVALUATOR_ACCOUNT}" \
    LOGNAME="${EVALUATOR_ACCOUNT}" \
    PATH=/usr/bin:/bin \
    LANG=C.UTF-8 \
    LC_ALL=C \
    XDG_RUNTIME_DIR="${EVALUATOR_RUNTIME_DIRECTORY}" \
    WAYLAND_DISPLAY="${WAYLAND_DISPLAY_VALUE}" \
    /usr/bin/bash -c '
      stdout_path="$1"
      stderr_path="$2"
      shift 2
      exec "$@" >"${stdout_path}" 2>"${stderr_path}"
    ' a-quo-request-capture "${stdout_path}" "${stderr_path}" \
    "${A_QUO}" request-sign "${ARTIFACT}" \
    --persona-id "${PERSONA_ID}" --kind software --label "${label}" \
    --output "${output}" &
  candidate_pid="$!"
  REQUEST_CANDIDATE_PID="${candidate_pid}"
  REQUEST_CANDIDATE_STARTTIME=''
  REQUEST_CLEANUP_UNCERTAIN=true
  set -e
  for ((attempt = 0; attempt < 20; attempt++)); do
    if [[ -r "/proc/${candidate_pid}/stat" ]]; then
      identity="$(request_process_identity "${candidate_pid}")" ||
        fail 'cannot inspect request process identity'
      IFS=: read -r candidate_pgid candidate_session candidate_starttime candidate_state \
        <<<"${identity}"
      if [[ "${candidate_starttime}" =~ ^[1-9][0-9]*$ ]]; then
        REQUEST_CANDIDATE_STARTTIME="${candidate_starttime}"
      fi
      if [[ "${candidate_pgid}" == "${candidate_pid}" && \
        "${candidate_session}" == "${candidate_pid}" && \
        "${candidate_starttime}" =~ ^[1-9][0-9]*$ && \
        "${candidate_state}" != Z ]]; then
        REQUEST_PID="${candidate_pid}"
        REQUEST_PGID="${candidate_pgid}"
        REQUEST_STARTTIME="${candidate_starttime}"
        REQUEST_CANDIDATE_PID=''
        REQUEST_CANDIDATE_STARTTIME=''
        REQUEST_CLEANUP_UNCERTAIN=false
        return 0
      fi
    fi
    if ! /usr/bin/kill -0 "${candidate_pid}" 2>/dev/null; then
      wait "${candidate_pid}" 2>/dev/null || true
      fail 'request-sign exited before its dedicated process group was authenticated'
    fi
    /usr/bin/sleep 0.1
  done
  fail 'request-sign did not establish its dedicated process group in time'
}

finish_sign_request() {
  REQUEST_STATUS=0
  [[ -n "${REQUEST_PID}" ]] || fail 'no request-sign process is tracked'
  set +e
  wait "${REQUEST_PID}"
  REQUEST_STATUS="$?"
  set -e
  if /usr/bin/kill -0 -- "-${REQUEST_PGID}" 2>/dev/null; then
    fail 'request process group retained a descendant after its leader exited'
  fi
  REQUEST_PID=''
  REQUEST_PGID=''
  REQUEST_STARTTIME=''
  REQUEST_CANDIDATE_PID=''
  REQUEST_CANDIDATE_STARTTIME=''
  REQUEST_CLEANUP_UNCERTAIN=false
}

DAEMON_PID="$(daemon_main_pid)" || fail 'cannot identify daemon before decline request'
readonly DAEMON_PID
DAEMON_GENERATION_INITIAL="$(daemon_generation)" ||
  fail 'cannot record the initial packaged daemon generation'
readonly DAEMON_GENERATION_INITIAL
readonly DECLINED_PROOF="${TEMPORARY_ROOT}/declined-proof.json"
printf 'DECLINE TEST: wait while the evaluator inspects the real helper for digest %s\n' \
  "${ARTIFACT_EXPECTED_SHA256}" >&2
start_sign_request \
  "${ARTIFACT_V1}" \
  'A Quo evaluator: DECLINE this exact request' \
  "${DECLINED_PROOF}" \
  "${TEMPORARY_ROOT}/decline.stdout" \
  "${TEMPORARY_ROOT}/decline.stderr"
wait_for_live_helper "${DAEMON_PID}" >/dev/null
printf '%s\n' 'DECLINE TEST: helper inspection passed; use the real A Quo window to decline now' >&2
REQUEST_STATUS=''
finish_sign_request
DECLINE_STATUS="${REQUEST_STATUS}"
readonly DECLINE_STATUS
[[ "${DECLINE_STATUS}" -ne 0 ]] || fail 'decline request unexpectedly returned success'
/usr/bin/grep -Fq -- 'signing request rejected: user declined' \
  "${TEMPORARY_ROOT}/decline.stderr" || fail 'decline request did not report an explicit user decline'
[[ ! -e "${DECLINED_PROOF}" && ! -L "${DECLINED_PROOF}" ]] ||
  fail 'declined request created a proof path'

readonly APPROVED_PROOF_V1="${TEMPORARY_ROOT}/approved-proof-v1.json"
printf 'APPROVAL TEST: wait while the evaluator inspects the real helper for digest %s\n' \
  "${ARTIFACT_EXPECTED_SHA256}" >&2
start_sign_request \
  "${ARTIFACT_V1}" \
  'A Quo evaluator: APPROVE V1 only after comparing the exact digest' \
  "${APPROVED_PROOF_V1}" \
  "${TEMPORARY_ROOT}/approve.stdout" \
  "${TEMPORARY_ROOT}/approve.stderr"
wait_for_live_helper "${DAEMON_PID}" >/dev/null
printf 'APPROVAL TEST: helper inspection passed; compare digest %s in the real window, then approve\n' \
  "${ARTIFACT_EXPECTED_SHA256}" >&2
REQUEST_STATUS=''
finish_sign_request
APPROVE_STATUS="${REQUEST_STATUS}"
readonly APPROVE_STATUS
[[ "${APPROVE_STATUS}" -eq 0 ]] || fail 'approved request did not return a proof'
require_real_regular_file "${APPROVED_PROOF_V1}" 'approved v1 proof'
[[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${APPROVED_PROOF_V1}")" == \
  "${EVALUATOR_UID}:${EVALUATOR_GID} 600 regular file" ]] ||
  fail 'approved v1 proof has unexpected ownership, mode, or type'
VERIFY_APPROVED_JSON="$(run_a_quo verify "${ARTIFACT_V1}" \
  --proof "${APPROVED_PROOF_V1}" --json)" || fail 'approved v1 proof verification failed'
readonly VERIFY_APPROVED_JSON
/usr/bin/jq -e --arg fingerprint "${KEY_FINGERPRINT}" '
  .artifact_integrity == "verified" and
  .signature == "verified" and
  .signer.key_fingerprint == $fingerprint
' <<<"${VERIFY_APPROVED_JSON}" >/dev/null ||
  fail 'approved v1 proof does not verify for the exact artifact and expected key'
[[ "$(sha256_file "${ARTIFACT_V1}")" == "${ARTIFACT_EXPECTED_SHA256}" ]] ||
  fail 'exact artifact changed during trusted consent'

readonly ALTERED_ARTIFACT="${TEMPORARY_ROOT}/altered-artifact"
run_as_evaluator /usr/bin/install -T -m 0600 -- \
  "${ARTIFACT_V1}" "${ALTERED_ARTIFACT}"
printf '%s' 'x' | run_as_evaluator /usr/bin/tee -a -- "${ALTERED_ARTIFACT}" >/dev/null
if run_a_quo verify "${ALTERED_ARTIFACT}" --proof "${APPROVED_PROOF_V1}" --json \
  >/dev/null 2>&1; then
  fail 'approved proof unexpectedly verified altered artifact bytes'
fi

APPROVED_PROOF_V2=''
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  APPROVED_PROOF_V2="${TEMPORARY_ROOT}/approved-proof-v2.json"
  printf 'APPROVAL V2 TEST: wait while the evaluator inspects the real helper for digest %s\n' \
    "${ARTIFACT_V2_EXPECTED_SHA256}" >&2
  start_sign_request \
    "${ARTIFACT_V2}" \
    'A Quo evaluator: APPROVE V2 only after comparing the exact digest' \
    "${APPROVED_PROOF_V2}" \
    "${TEMPORARY_ROOT}/approve-v2.stdout" \
    "${TEMPORARY_ROOT}/approve-v2.stderr"
  wait_for_live_helper "${DAEMON_PID}" >/dev/null
  printf 'APPROVAL V2 TEST: helper inspection passed; compare digest %s in the real window, then approve\n' \
    "${ARTIFACT_V2_EXPECTED_SHA256}" >&2
  REQUEST_STATUS=''
  finish_sign_request
  APPROVE_V2_STATUS="${REQUEST_STATUS}"
  readonly APPROVE_V2_STATUS
  [[ "${APPROVE_V2_STATUS}" -eq 0 ]] ||
    fail 'approved v2 request did not return a proof'
  require_real_regular_file "${APPROVED_PROOF_V2}" 'approved v2 proof'
  [[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${APPROVED_PROOF_V2}")" == \
    "${EVALUATOR_UID}:${EVALUATOR_GID} 600 regular file" ]] ||
    fail 'approved v2 proof has unexpected ownership, mode, or type'
  VERIFY_APPROVED_V2_JSON="$(run_a_quo verify "${ARTIFACT_V2}" \
    --proof "${APPROVED_PROOF_V2}" --json)" ||
    fail 'approved v2 proof verification failed'
  /usr/bin/jq -e --arg fingerprint "${KEY_FINGERPRINT}" '
    .artifact_integrity == "verified" and
    .signature == "verified" and
    .signer.key_fingerprint == $fingerprint
  ' <<<"${VERIFY_APPROVED_V2_JSON}" >/dev/null ||
    fail 'approved v2 proof does not verify for the exact artifact and expected key'
  [[ "$(sha256_file "${ARTIFACT_V2}")" == \
    "${ARTIFACT_V2_EXPECTED_SHA256}" ]] ||
    fail 'exact v2 artifact changed during trusted consent'

  ALTERED_ARTIFACT_V2="${TEMPORARY_ROOT}/altered-artifact-v2"
  readonly ALTERED_ARTIFACT_V2
  run_as_evaluator /usr/bin/install -T -m 0600 -- \
    "${ARTIFACT_V2}" "${ALTERED_ARTIFACT_V2}"
  printf '%s' 'x' | run_as_evaluator /usr/bin/tee -a -- \
    "${ALTERED_ARTIFACT_V2}" >/dev/null
  if run_a_quo verify "${ALTERED_ARTIFACT_V2}" \
    --proof "${APPROVED_PROOF_V2}" --json >/dev/null 2>&1; then
    fail 'approved v2 proof unexpectedly verified altered artifact bytes'
  fi
fi
readonly APPROVED_PROOF_V2

run_systemctl stop --no-block "${SERVICE_NAME}"
wait_for_service_stopped || fail 'ordinary stop did not settle and remove the scoped runtime directory'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=ActiveState --value)" == inactive ]] ||
  fail 'ordinary stop did not leave the service inactive'
run_systemctl start "${SERVICE_NAME}"
verify_service_ready
DAEMON_GENERATION_AFTER_RESTART="$(daemon_generation)" ||
  fail 'cannot record the restarted packaged daemon generation'
readonly DAEMON_GENERATION_AFTER_RESTART
[[ "${DAEMON_GENERATION_AFTER_RESTART}" != "${DAEMON_GENERATION_INITIAL}" ]] ||
  fail 'ordinary restart reused the prior daemon generation'

DAEMON_PID_BEFORE_KILL="$(daemon_main_pid)" || fail 'cannot identify daemon before forced death'
readonly DAEMON_PID_BEFORE_KILL
run_systemctl kill --kill-whom=main --signal=KILL "${SERVICE_NAME}"
wait_for_service_stopped || fail 'forced daemon death did not settle and remove its runtime directory'
if [[ -e "/proc/${DAEMON_PID_BEFORE_KILL}" && \
  "$(/usr/bin/readlink -e -- "/proc/${DAEMON_PID_BEFORE_KILL}/exe" 2>/dev/null || true)" == \
    "${A_QUO_DAEMON}" ]]; then
  fail 'forced daemon death left the same installed daemon PID active'
fi
run_systemctl reset-failed "${SERVICE_NAME}" >/dev/null
run_systemctl start "${SERVICE_NAME}"
verify_service_ready
DAEMON_GENERATION_AFTER_KILL="$(daemon_generation)" ||
  fail 'cannot record the post-kill packaged daemon generation'
readonly DAEMON_GENERATION_AFTER_KILL
[[ "${DAEMON_GENERATION_AFTER_KILL}" != "${DAEMON_GENERATION_AFTER_RESTART}" ]] ||
  fail 'forced-death restart reused the prior daemon generation'

run_systemctl stop --no-block "${SERVICE_NAME}" >/dev/null
wait_for_service_stopped || fail 'final service stop did not settle or retained runtime state'
run_systemctl disable "${SERVICE_NAME}" >/dev/null
run_systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true
wait_for_service_stopped || fail 'final service disable did not retain the stopped state'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=UnitFileState --value)" == disabled ]] ||
  fail 'final service state is not disabled'
[[ "$(run_systemctl show "${SERVICE_NAME}" --property=ActiveState --value)" == inactive ]] ||
  fail 'final service state is not inactive'
service_enable_state_restored ||
  fail 'final service disable did not restore the exact empty enablement directory'

run_a_quo persona key-unbind --fingerprint "${KEY_FINGERPRINT}" \
  >/dev/null
run_as_evaluator /usr/bin/rm -f -- "${PRIVATE_KEY}" "${PRIVATE_KEY}.pub"
[[ ! -e "${PRIVATE_KEY}" && ! -L "${PRIVATE_KEY}" && \
  ! -e "${PRIVATE_KEY}.pub" && ! -L "${PRIVATE_KEY}.pub" ]] ||
  fail 'disposable signer files were not removed after unbinding'
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  validate_retained_store ||
    fail 'post-unbind persona store does not contain the exact public handoff state'
  VERIFY_UNBOUND_V1_JSON="$(run_a_quo verify "${ARTIFACT_V1}" \
    --proof "${APPROVED_PROOF_V1}" --json)" ||
    fail 'approved v1 proof did not verify after the signer reference was removed'
  readonly VERIFY_UNBOUND_V1_JSON
  /usr/bin/jq -e --arg fingerprint "${KEY_FINGERPRINT}" '
    .artifact_integrity == "verified" and
    .signature == "verified" and
    .signer.key_fingerprint == $fingerprint and
    .local_registry.key_status == "active"
  ' <<<"${VERIFY_UNBOUND_V1_JSON}" >/dev/null ||
    fail 'retained public persona state does not recognize the approved v1 proof key'
  VERIFY_UNBOUND_V2_JSON="$(run_a_quo verify "${ARTIFACT_V2}" \
    --proof "${APPROVED_PROOF_V2}" --json)" ||
    fail 'approved v2 proof did not verify after the signer reference was removed'
  readonly VERIFY_UNBOUND_V2_JSON
  /usr/bin/jq -e --arg fingerprint "${KEY_FINGERPRINT}" '
    .artifact_integrity == "verified" and
    .signature == "verified" and
    .signer.key_fingerprint == $fingerprint and
    .local_registry.key_status == "active"
  ' <<<"${VERIFY_UNBOUND_V2_JSON}" >/dev/null ||
    fail 'retained public persona state does not recognize the approved v2 proof key'
fi

A_QUO_SHA256_AFTER="$(sha256_file "${A_QUO}")"
DAEMON_SHA256_AFTER="$(sha256_file "${A_QUO_DAEMON}")"
CONSENT_SHA256_AFTER="$(sha256_file "${A_QUO_CONSENT}")"
UNIT_SHA256_AFTER="$(sha256_file "${SERVICE_UNIT}")"
REGISTRY_SHA256_AFTER="$(sha256_file "${PROVIDER_REGISTRY}")"
FONT_SHA256_AFTER="$(sha256_file "${TRUSTED_FONT}")"
readonly A_QUO_SHA256_AFTER DAEMON_SHA256_AFTER CONSENT_SHA256_AFTER
readonly UNIT_SHA256_AFTER REGISTRY_SHA256_AFTER FONT_SHA256_AFTER
if [[ "${A_QUO_SHA256_AFTER}" != "${A_QUO_SHA256_BEFORE}" || \
  "${DAEMON_SHA256_AFTER}" != "${DAEMON_SHA256_BEFORE}" || \
  "${CONSENT_SHA256_AFTER}" != "${CONSENT_SHA256_BEFORE}" || \
  "${UNIT_SHA256_AFTER}" != "${UNIT_SHA256_BEFORE}" || \
  "${REGISTRY_SHA256_AFTER}" != "${REGISTRY_SHA256_BEFORE}" || \
  "${FONT_SHA256_AFTER}" != "${FONT_SHA256_BEFORE}" ]]; then
  fail 'installed package component bytes changed during the consent lifecycle'
fi
[[ "$(/usr/bin/pacman -Q a-quo)" == "${OBSERVED_A_QUO_QUERY}" ]] ||
  fail 'installed A Quo package query changed during the consent lifecycle'
/usr/bin/pacman -Qkk a-quo >/dev/null ||
  fail 'installed A Quo package files failed final pacman verification'
[[ "$(/usr/bin/pacman -Q "${FONT_PACKAGE}")" == "${FONT_PACKAGE_QUERY}" ]] ||
  fail 'trusted font package query changed during the consent lifecycle'
/usr/bin/pacman -Qkk "${FONT_PACKAGE}" >/dev/null ||
  fail 'trusted font package files failed final pacman verification'
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  create_handoff_outputs ||
    fail 'could not create the exact trusted-consent handoff outputs'
  HANDOFF_STORE_SHA256="$(sha256_file "${DEFAULT_STORE}")"
  [[ "${HANDOFF_STORE_SHA256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'retained public persona store has no canonical SHA-256'
fi
EVIDENCE_SCHEMA='urn:a-quo:evidence:installed-consent-lifecycle:v1'
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  EVIDENCE_SCHEMA='urn:a-quo:evidence:installed-consent-lifecycle:v2'
fi
readonly EVIDENCE_SCHEMA
EVIDENCE_JSON="$(
  /usr/bin/jq -n \
    --arg schema "${EVIDENCE_SCHEMA}" \
    --arg account "${EVALUATOR_ACCOUNT}" \
    --arg a_quo_query "${OBSERVED_A_QUO_QUERY}" \
    --arg omarchy_query "${OBSERVED_OMARCHY_QUERY}" \
    --arg profile_id "${EVALUATION_PROFILE_ID}" \
    --arg profile_sha256 "${EVALUATION_PROFILE_SHA256}" \
    --arg target_kind "${EVALUATION_TARGET_KIND}" \
    --arg architecture "${EVALUATION_ARCHITECTURE}" \
    --arg evidence_namespace "${EVALUATION_EVIDENCE_NAMESPACE}" \
    --arg font_package_query "${FONT_PACKAGE_QUERY}" \
    --arg font_sha256 "${FONT_SHA256_AFTER}" \
    --arg a_quo_sha256 "${A_QUO_SHA256_AFTER}" \
    --arg daemon_sha256 "${DAEMON_SHA256_AFTER}" \
    --arg consent_sha256 "${CONSENT_SHA256_AFTER}" \
    --arg unit_sha256 "${UNIT_SHA256_AFTER}" \
    --arg artifact_sha256 "${ARTIFACT_EXPECTED_SHA256}" \
    --arg artifact_v2_sha256 "${ARTIFACT_V2_EXPECTED_SHA256}" \
    --arg handoff_requested "${HANDOFF_REQUESTED}" \
    --arg handoff_root "${HANDOFF_ROOT}" \
    --arg handoff_proof_v1_sha256 "${HANDOFF_PROOF_V1_SHA256}" \
    --arg handoff_proof_v2_sha256 "${HANDOFF_PROOF_V2_SHA256}" \
    --arg handoff_manifest_sha256 "${HANDOFF_MANIFEST_SHA256}" \
    --arg handoff_store_path "${DEFAULT_STORE}" \
    --arg handoff_store_sha256 "${HANDOFF_STORE_SHA256}" \
    --arg persona_id "${PERSONA_ID}" \
    --arg key_fingerprint "${KEY_FINGERPRINT}" '
    {
      schema: $schema,
      result: "passed",
      target_profile: {
        profile_id: $profile_id,
        profile_sha256: $profile_sha256,
        binding_role: "package-target-policy",
        target_kind: $target_kind,
        architecture: $architecture,
        evidence_namespace: $evidence_namespace,
        cross_profile_evidence_accepted: false,
        aarch64_gate_satisfied_by_x86_64: false
      },
      evaluator: {
        account: $account,
        disposable_marker: "verified_exact_root_owned_mode_0400",
        wayland_context: "preexisting_evaluator_owned_socket_and_user_manager_environment",
        operator_interaction: "required_decline_then_approval_no_harness_automation",
        input_origin: "not_machine_verifiable",
        evaluator_owned_store_and_work_roots_cleanup: "verified_before_evidence_emission",
        clean_system_claim: "not_established_marker_only"
      },
      installed_software: {
        a_quo_package_query: $a_quo_query,
        omarchy_package_query: $omarchy_query,
        a_quo_cli_sha256: $a_quo_sha256,
        daemon_sha256: $daemon_sha256,
        consent_helper_sha256: $consent_sha256,
        service_unit_sha256: $unit_sha256,
        font_package_query: $font_package_query,
        trusted_font_sha256: $font_sha256,
        provider_registry: "empty_v1_root_owned"
      },
      service: {
        initial_state: "disabled_inactive",
        startup_with_store_absent: "exit_1_without_socket",
        explicit_enablement: "performed_by_evaluator_user",
        daemon_identity: "one_installed_binary_under_evaluator_uid",
        runtime_directory: "mode_0700",
        socket: "unix_socket_mode_0600_installed_daemon_protocol",
        cross_uid_path_access: "denied_by_private_runtime_directory",
        peer_credential_rejection: "not_exercised_beyond_filesystem_denial",
        ordinary_restart: "runtime_removed_then_new_daemon_generation_ready",
        forced_death: "runtime_removed_then_new_daemon_generation_ready",
        final_state: "disabled_inactive"
      },
      consent: {
        helper: "fixed_package_owned_direct_daemon_child",
        environment: "wayland_runtime_locale_only_no_bus_x11_path_agent_or_loader",
        decline: "no_proof_returned",
        approval: "proof_returned_and_verified",
        artifact_sha256: $artifact_sha256,
        altered_bytes: "verification_refused",
        secure_attention: "not_established",
        accessibility: "not_evaluated",
        fido_agent_pin_paths: "not_evaluated_file_key_only"
      },
      behavioral_analysis: "not_run",
      omarchy_plugin_lifecycle: "not_run",
      plugin_safety: "not_established",
      package_transaction: "not_run",
      clean_system_claim: "not_established_marker_only"
    }
    | if $handoff_requested == "true" then
        .evaluator.operator_interaction =
          "required_decline_v1_then_approval_v1_then_approval_v2_no_harness_automation"
        | .evaluator.evaluator_owned_store_and_work_roots_cleanup =
            "work_root_removed_store_retained_without_signing_locator_for_joined_consumer"
        | .consent = {
            helper: "fixed_package_owned_direct_daemon_child",
            environment: "wayland_runtime_locale_only_no_bus_x11_path_agent_or_loader",
            decline_v1: "no_proof_returned",
            approval_v1: "proof_returned_and_verified",
            approval_v2: "proof_returned_and_verified",
            artifact_v1_sha256: $artifact_sha256,
            artifact_v2_sha256: $artifact_v2_sha256,
            altered_bytes_v1: "verification_refused",
            altered_bytes_v2: "verification_refused",
            secure_attention: "not_established",
            accessibility: "not_evaluated",
            fido_agent_pin_paths: "not_evaluated_file_key_only"
          }
        | . + {
          handoff: {
            root: $handoff_root,
            format: "a-quo-installed-omarchy-preconsented-handoff-v2",
            artifact_v1_role:
              "caller_pinned_omarchy_plugin_v1_package_structural_validation_deferred_to_consumer",
            artifact_v2_role:
              "caller_pinned_omarchy_plugin_v2_package_structural_validation_deferred_to_consumer",
            proof_v1_sha256: $handoff_proof_v1_sha256,
            proof_v2_sha256: $handoff_proof_v2_sha256,
            manifest_sha256: $handoff_manifest_sha256,
            persona_id: $persona_id,
            key_fingerprint: $key_fingerprint,
            persona_store_path: $handoff_store_path,
            persona_store_sha256: $handoff_store_sha256,
            persona_store:
              "retained_public_state_signing_locator_removed_original_disposable_key_paths_removed",
            same_uid_private_key_copy_or_access_excluded: false,
            next_evaluator: "not_run_by_this_evaluator"
          }
        }
      else . end
  '
)"
readonly EVIDENCE_JSON

if [[ "${HANDOFF_REQUESTED}" != true ]]; then
  if ! remove_disposable_store; then
    fail 'disposable persona store could not be safely removed'
  fi
fi
if ! remove_temporary_root; then
  fail 'temporary evaluator work could not be safely removed'
fi
if [[ "${HANDOFF_REQUESTED}" == true ]]; then
  validate_handoff_inventory 1 ||
    fail 'trusted-consent handoff changed after temporary-link retirement'
  validate_retained_store ||
    fail 'retained public persona state changed after handoff creation'
  [[ "$(sha256_file "${DEFAULT_STORE}")" == "${HANDOFF_STORE_SHA256}" ]] ||
    fail 'retained public persona store bytes changed after handoff creation'
  [[ "$(sha256_file "${ARTIFACT_SOURCE}")" == "${ARTIFACT_EXPECTED_SHA256}" ]] ||
    fail 'caller-pinned v1 signing artifact changed before final handoff verification'
  [[ "$(sha256_file "${ARTIFACT_V2_SOURCE}")" == \
    "${ARTIFACT_V2_EXPECTED_SHA256}" ]] ||
    fail 'caller-pinned v2 signing artifact changed before final handoff verification'
  VERIFY_HANDOFF_V1_JSON="$(run_a_quo verify "${ARTIFACT_SOURCE}" \
    --proof "${HANDOFF_PROOF_V1}" --json)" ||
    fail 'retained v1 handoff proof does not verify for the caller-pinned v1 artifact'
  readonly VERIFY_HANDOFF_V1_JSON
  /usr/bin/jq -e --arg fingerprint "${KEY_FINGERPRINT}" '
    .artifact_integrity == "verified" and
    .signature == "verified" and
    .signer.key_fingerprint == $fingerprint and
    .local_registry.key_status == "active"
  ' <<<"${VERIFY_HANDOFF_V1_JSON}" >/dev/null ||
    fail 'retained v1 handoff proof or public persona evidence changed before handoff'
  VERIFY_HANDOFF_V2_JSON="$(run_a_quo verify "${ARTIFACT_V2_SOURCE}" \
    --proof "${HANDOFF_PROOF_V2}" --json)" ||
    fail 'retained v2 handoff proof does not verify for the caller-pinned v2 artifact'
  readonly VERIFY_HANDOFF_V2_JSON
  /usr/bin/jq -e --arg fingerprint "${KEY_FINGERPRINT}" '
    .artifact_integrity == "verified" and
    .signature == "verified" and
    .signer.key_fingerprint == $fingerprint and
    .local_registry.key_status == "active"
  ' <<<"${VERIFY_HANDOFF_V2_JSON}" >/dev/null ||
    fail 'retained v2 handoff proof or public persona evidence changed before handoff'
  if run_a_quo verify "${ARTIFACT_SOURCE}" \
    --proof "${HANDOFF_PROOF_V2}" --json >/dev/null 2>&1 || \
    run_a_quo verify "${ARTIFACT_V2_SOURCE}" \
      --proof "${HANDOFF_PROOF_V1}" --json >/dev/null 2>&1; then
    fail 'retained handoff proofs unexpectedly verified with swapped artifacts'
  fi
  validate_retained_store ||
    fail 'retained public persona state changed during final handoff verification'
  [[ "$(sha256_file "${DEFAULT_STORE}")" == "${HANDOFF_STORE_SHA256}" ]] ||
    fail 'retained public persona store bytes changed during final handoff verification'
  [[ "$(sha256_file "${ARTIFACT_SOURCE}")" == "${ARTIFACT_EXPECTED_SHA256}" ]] ||
    fail 'caller-pinned v1 signing artifact changed during final handoff verification'
  [[ "$(sha256_file "${ARTIFACT_V2_SOURCE}")" == \
    "${ARTIFACT_V2_EXPECTED_SHA256}" ]] ||
    fail 'caller-pinned v2 signing artifact changed during final handoff verification'
  validate_handoff_inventory 1 ||
    fail 'trusted-consent handoff changed during final proof verification'
fi
SERVICE_TOUCHED=false
trap - EXIT INT TERM HUP
printf '%s\n' "${EVIDENCE_JSON}"
