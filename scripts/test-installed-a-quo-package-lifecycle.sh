#!/usr/bin/bash

set +x
set -euo pipefail
export LC_ALL=C
export GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_LAZY_FETCH=1
export PATH=/usr/bin:/bin
umask 077

# One-shot destructive evaluator for a marked disposable Omarchy machine.
# It installs, upgrades, removes, and reinstalls the real host `a-quo` package.
readonly REQUIRED_ACKNOWLEDGEMENT='I-understand-this-mutates-the-disposable-a-quo-package-evaluator'
if [[ "${A_QUO_INSTALLED_PACKAGE_LIFECYCLE_ACKNOWLEDGEMENT:-}" != \
  "${REQUIRED_ACKNOWLEDGEMENT}" ]]; then
  printf '%s\n' \
    'refusing installed package lifecycle without exact A_QUO_INSTALLED_PACKAGE_LIFECYCLE_ACKNOWLEDGEMENT' >&2
  exit 1
fi

readonly EVALUATOR_ACCOUNT='a-quo-evaluator'
readonly EVALUATOR_HOME='/home/a-quo-evaluator'
readonly DISPOSABLE_MARKER='/etc/a-quo/disposable-omarchy-evaluator-v1'
readonly PERSONA_STATE_ROOT="${EVALUATOR_HOME}/.local/share/a-quo"
readonly PLUGINS_DIRECTORY="${EVALUATOR_HOME}/.config/omarchy/plugins"
readonly EVIDENCE_ROOT="${EVALUATOR_HOME}/.local/share/a-quo-installed-package-lifecycle-v1"
readonly EVIDENCE_SENTINEL="${EVIDENCE_ROOT}/preserved-state"
readonly CONSENT_HANDOFF_ROOT="${EVIDENCE_ROOT}/trusted-consent-v2"
readonly PACMAN_LOCK='/var/lib/pacman/db.lck'
readonly BRIDGE_LOCK_DIRECTORY='/run/a-quo-package-evaluator'
readonly BRIDGE_LOCK="${BRIDGE_LOCK_DIRECTORY}/lifecycle.lock"
readonly MAXIMUM_PACKAGE_BYTES=268435456
readonly JOINED_INPUT_LOCK_RELATIVE_PATH='packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1.lock'
readonly EVALUATION_PROFILE_ID='a-quo-omarchy4-aarch64-dec29fa-v2'
readonly EVALUATION_PROFILE_SHA256='3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6d'
readonly EVALUATION_TARGET_KIND='virtual-reference-target'
readonly EVALUATION_ARCHITECTURE='aarch64'
readonly EVALUATION_EVIDENCE_NAMESPACE='phase-a-aarch64-dec29fa'
readonly -a PACKAGE_LEAVES=(
  /usr/bin/a-quo
  /usr/bin/a-quo-daemon
  /usr/lib/a-quo/a-quo-consent
  /usr/lib/systemd/user/a-quo-daemon.service
  /usr/lib/systemd/user-preset/90-a-quo.preset
  /usr/share/a-quo/provider-registry-v1.json
  /usr/share/doc/a-quo/PACKAGING.md
  /usr/share/doc/a-quo/README.md
  /usr/share/doc/a-quo/SECURITY.md
  /usr/share/doc/a-quo/THREAT-MODEL.md
  /usr/share/licenses/a-quo/LICENSE
)

fail() {
  printf 'installed A Quo package lifecycle refused: %s\n' "$1" >&2
  exit 1
}

require_environment() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "required environment variable ${name} is absent"
}

sha256_file() {
  local result
  result="$(/usr/bin/sha256sum -- "$1")"
  printf '%s\n' "${result%% *}"
}

require_real_regular_file() {
  local path="$1"
  local label="$2"
  [[ -f "${path}" && ! -L "${path}" ]] || fail "${label} is not a real regular file"
}

require_safe_root_chain() {
  local path="$1"
  local label="$2"
  local current="${path}"
  local metadata
  local owner
  local mode
  while :; do
    [[ ! -L "${current}" ]] || fail "${label} path chain contains a symlink: ${current}"
    metadata="$(/usr/bin/stat -c '%u:%a:%F' -- "${current}")" ||
      fail "${label} path chain cannot be inspected: ${current}"
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    mode="${mode%%:*}"
    [[ "${owner}" == 0 ]] || fail "${label} path chain is not root-owned: ${current}"
    (( (8#${mode} & 8#022) == 0 )) ||
      fail "${label} path chain is group/world writable: ${current}"
    [[ "${current}" == / ]] && break
    current="${current%/*}"
    [[ -n "${current}" ]] || current=/
  done
}

require_bounded_safe_root_tree() {
  local path="$1"
  local label="$2"
  local maximum_entries="$3"
  local maximum_regular_bytes="$4"
  local root_device
  local entry
  local metadata
  local device
  local owner
  local mode
  local kind
  local size
  local entry_count=0
  local regular_bytes=0
  [[ -d "${path}" && ! -L "${path}" ]] || fail "${label} is not a real directory"
  require_safe_root_chain "${path}" "${label}"
  root_device="$(/usr/bin/stat -c '%d' -- "${path}")"
  while IFS= read -r -d '' entry; do
    metadata="$(/usr/bin/stat -c '%d:%u:%a:%F:%s' -- "${entry}")" ||
      fail "${label} entry cannot be inspected: ${entry}"
    IFS=: read -r device owner mode kind size <<<"${metadata}"
    [[ "${device}" == "${root_device}" && "${owner}" == 0 ]] ||
      fail "${label} entry is on another device or not root-owned: ${entry}"
    [[ "${mode}" =~ ^[0-7]+$ ]] || fail "${label} entry has an invalid mode: ${entry}"
    (( (8#${mode} & 8#022) == 0 )) ||
      fail "${label} entry is group/world writable: ${entry}"
    case "${kind}" in
      directory) ;;
      'regular file'|'regular empty file')
        [[ "${size}" =~ ^[0-9]+$ ]] || fail "${label} entry has an invalid size: ${entry}"
        ((regular_bytes += size))
        ;;
      *) fail "${label} contains a link or special entry: ${entry}" ;;
    esac
    ((entry_count += 1))
    (( entry_count <= maximum_entries && regular_bytes <= maximum_regular_bytes )) ||
      fail "${label} exceeds its closed entry or byte bound"
  done < <(/usr/bin/find "${path}" -xdev -print0 | /usr/bin/sort -z)
  (( entry_count > 0 )) || fail "${label} is empty"
}

require_root_package_input() {
  local path="$1"
  local expected_sha256="$2"
  local label="$3"
  local metadata
  local size
  [[ "${path}" == /* ]] || fail "${label} package path must be absolute"
  require_real_regular_file "${path}" "${label} package input"
  [[ "$(/usr/bin/realpath -e -- "${path}")" == "${path}" ]] ||
    fail "${label} package path must be canonical"
  require_safe_root_chain "${path}" "${label} package"
  metadata="$(/usr/bin/stat -c '%u:%a:%h:%F:%s' -- "${path}")"
  [[ "${metadata}" =~ ^0:([0-7]+):1:regular\ file:([1-9][0-9]*)$ ]] ||
    fail "${label} package must be one nonempty singly linked root-owned regular file"
  (( (8#${BASH_REMATCH[1]} & 8#022) == 0 )) ||
    fail "${label} package is group/world writable"
  size="${BASH_REMATCH[2]}"
  (( size <= MAXIMUM_PACKAGE_BYTES )) ||
    fail "${label} package exceeds the closed 256 MiB bound"
  [[ "$(sha256_file "${path}")" == "${expected_sha256}" ]] ||
    fail "${label} package does not match its caller-pinned SHA-256"
}

require_inert_joined_input() {
  local path="$1"
  local expected_device="$2"
  local label="$3"
  local metadata
  require_real_regular_file "${path}" "${label} joined input"
  metadata="$(/usr/bin/stat -c '%d:%u:%g:%a:%h:%F:%s' -- "${path}")"
  [[ "${metadata}" =~ ^${expected_device}:0:0:400:1:regular\ file:[1-9][0-9]*$ ]] ||
    fail "${label} joined input is not one root-owned mode-0400 file on the input filesystem"
}

lock_field() {
  local key="$1"
  local value
  [[ "$(/usr/bin/grep -c -- "^${key}=" "${JOINED_INPUT_LOCK}")" -eq 1 ]] ||
    fail "joined input lock field is missing or duplicated: ${key}"
  value="$(/usr/bin/sed -n "s/^${key}=//p" "${JOINED_INPUT_LOCK}")"
  [[ -n "${value}" && "${value}" != *$'\n'* ]] ||
    fail "joined input lock field is empty or multiline: ${key}"
  printf '%s\n' "${value}"
}

require_lock_field() {
  local key="$1"
  local expected="$2"
  [[ "$(lock_field "${key}")" == "${expected}" ]] ||
    fail "joined input lock field differs from the closed value: ${key}"
}

assert_joined_inputs() {
  local stage="$1"
  local joined_input_name
  [[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%F' -- \
      "${JOINED_INPUT_DIRECTORY}")" == "${JOINED_INPUT_DIRECTORY_IDENTITY}" ]] ||
    fail "joined input directory identity changed ${stage}"
  if ! /usr/bin/cmp -s -- \
    <(/usr/bin/printf '%s\n' "${JOINED_INPUT_NAMES[@]}") \
    <(/usr/bin/find "${JOINED_INPUT_DIRECTORY}" -xdev -mindepth 1 -maxdepth 1 \
      -printf '%f\n' | /usr/bin/sort); then
    fail "joined input inventory changed ${stage}"
  fi
  for joined_input_name in "${JOINED_INPUT_NAMES[@]}"; do
    require_inert_joined_input \
      "${JOINED_INPUT_DIRECTORY}/${joined_input_name}" \
      "${JOINED_INPUT_DEVICE}" "${joined_input_name} ${stage}"
  done
  [[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s' -- \
      "${JOINED_INPUT_LOCK}")" == "${JOINED_INPUT_LOCK_IDENTITY}" && \
    "$(sha256_file "${JOINED_INPUT_LOCK}")" == "${JOINED_INPUT_LOCK_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[0]}")" == \
      "${OLD_PACKAGE_EXPECTED_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[1]}")" == \
      "${NEW_PACKAGE_EXPECTED_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[2]}")" == \
      "${EVALUATION_PROFILE_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[3]}")" == \
      "${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[4]}")" == \
      "${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[5]}")" == \
      "$(lock_field policy_file_05 | /usr/bin/sed 's/.*|//')" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[6]}")" == \
      "${COMMITTED_VERIFIER_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[7]}")" == \
      "${COMMITTED_CONSENT_EVALUATOR_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[8]}")" == \
      "${COMMITTED_CORE_EVALUATOR_SHA256}" && \
    "$(sha256_file "${JOINED_INPUT_DIRECTORY}/${JOINED_INPUT_NAMES[9]}")" == \
      "${COMMITTED_BRIDGE_SHA256}" ]] ||
    fail "joined input bytes changed ${stage}"
}

require_safe_evaluator_directory() {
  local path="$1"
  local metadata
  [[ -d "${path}" && ! -L "${path}" ]] || fail "unsafe evaluator directory: ${path}"
  metadata="$(/usr/bin/stat -c '%u:%g:%a:%F' -- "${path}")"
  [[ "${metadata}" =~ ^${EVALUATOR_UID}:${EVALUATOR_GID}:([0-7]+):directory$ ]] ||
    fail "evaluator directory has unexpected ownership or type: ${path}"
  (( (8#${BASH_REMATCH[1]} & 8#022) == 0 )) ||
    fail "evaluator directory is group/world writable: ${path}"
}

assert_no_daemon_process() {
  local status
  set +e
  /usr/bin/pgrep -x a-quo-daemon >/dev/null 2>&1
  status="$?"
  set -e
  case "${status}" in
    0) fail 'an A Quo daemon process exists during the package lifecycle' ;;
    1) ;;
    *) fail 'A Quo daemon process state could not be inspected' ;;
  esac
}

assert_a_quo_package_absent() {
  local stage="$1"
  local query_output
  local query_status
  local local_entry
  set +e
  query_output="$(/usr/bin/pacman -Q a-quo 2>&1)"
  query_status="$?"
  set -e
  [[ "${query_status}" -eq 1 && \
    "${query_output}" == "error: package 'a-quo' was not found" ]] ||
    fail "A Quo absence is not specifically established ${stage}"
  /usr/bin/pacman -Dk >/dev/null ||
    fail "local Pacman database integrity is not established ${stage}"
  [[ -d /var/lib/pacman/local && ! -L /var/lib/pacman/local ]] ||
    fail "local Pacman database directory is unsafe ${stage}"
  require_safe_root_chain /var/lib/pacman/local 'local Pacman database directory'
  local_entry="$(
    /usr/bin/find /var/lib/pacman/local -xdev -mindepth 1 -maxdepth 1 \
      -name 'a-quo-*' -print -quit
  )"
  [[ -z "${local_entry}" ]] ||
    fail "an unregistered A Quo local-database entry exists ${stage}"
  for package_leaf in "${PACKAGE_LEAVES[@]}"; do
    [[ ! -e "${package_leaf}" && ! -L "${package_leaf}" && \
      ! -e "${package_leaf}.pacsave" && ! -L "${package_leaf}.pacsave" ]] ||
      fail "an A Quo package leaf exists ${stage}: ${package_leaf}"
  done
}

if (( EUID != 0 )); then
  fail 'the package lifecycle must run as root'
fi

for unsafe_environment_name in \
  BASH_ENV ENV GLIBC_TUNABLES LD_AUDIT LD_DEBUG LD_LIBRARY_PATH LD_PRELOAD; do
  [[ ! -v "${unsafe_environment_name}" ]] ||
    fail "inherited loader or shell override: ${unsafe_environment_name}"
done

for command_path in \
  /usr/bin/awk /usr/bin/basename /usr/bin/bsdtar /usr/bin/chmod \
  /usr/bin/chown /usr/bin/cmp /usr/bin/dd /usr/bin/env /usr/bin/find \
  /usr/bin/getent /usr/bin/git /usr/bin/grep /usr/bin/head /usr/bin/id \
  /usr/bin/install /usr/bin/jq /usr/bin/flock /usr/bin/mkdir /usr/bin/mktemp \
  /usr/bin/od /usr/bin/pacman /usr/bin/pacman-conf /usr/bin/pgrep \
  /usr/bin/printf /usr/bin/realpath /usr/bin/rm \
  /usr/bin/runuser /usr/bin/sed /usr/bin/sha256sum /usr/bin/sort \
  /usr/bin/stat /usr/bin/systemctl /usr/bin/tail /usr/bin/tr \
  /usr/bin/uname /usr/bin/unshare /usr/bin/vercmp /usr/bin/wc; do
  [[ -x "${command_path}" && ! -d "${command_path}" ]] ||
    fail "required installed command is unavailable: ${command_path}"
done
[[ "$(/usr/bin/uname -m)" == aarch64 && -f /etc/arch-release ]] ||
  fail 'the package lifecycle requires a native aarch64 Arch-family host'

readonly PACMAN_BINARY='/usr/bin/pacman'
require_real_regular_file "${PACMAN_BINARY}" 'Pacman binary'
require_safe_root_chain "${PACMAN_BINARY}" 'Pacman binary'
PACMAN_BINARY_IDENTITY="$({
  /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s:%Y:%Z' -- "${PACMAN_BINARY}"
})"
PACMAN_BINARY_SHA256="$(sha256_file "${PACMAN_BINARY}")"
  [[ "$({
  /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s:%Y:%Z' -- "${PACMAN_BINARY}"
})" == "${PACMAN_BINARY_IDENTITY}" && \
  "${PACMAN_BINARY_IDENTITY}" =~ ^[0-9]+:[0-9]+:0:0:[0-7]+:1:regular\ file:[0-9]+:[0-9]+:[0-9]+$ ]] ||
  fail 'Pacman binary identity changed or is unsafe during hashing'
[[ "$(/usr/bin/pacman -Qoq -- "${PACMAN_BINARY}")" == pacman ]] ||
  fail 'Pacman binary is not owned by the pacman package'
PACMAN_PACKAGE_QUERY="$(/usr/bin/pacman -Q pacman)" ||
  fail 'Pacman package query could not be read'
readonly PACMAN_BINARY_IDENTITY PACMAN_BINARY_SHA256 PACMAN_PACKAGE_QUERY
[[ "${PACMAN_PACKAGE_QUERY}" =~ ^pacman[[:space:]][^[:space:]]+$ ]] ||
  fail 'Pacman package query is not one exact line'
/usr/bin/pacman -Qkk pacman >/dev/null ||
  fail 'Pacman package integrity check failed before the lifecycle'

for git_environment_override in \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CEILING_DIRECTORIES GIT_COMMON_DIR \
  GIT_CONFIG GIT_CONFIG_COUNT \
  GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_CONFIG_PARAMETERS \
  GIT_CONFIG_SYSTEM GIT_DIR GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_EXEC_PATH \
  GIT_GRAFT_FILE GIT_INDEX_FILE GIT_NAMESPACE GIT_OBJECT_DIRECTORY \
  GIT_OPTIONAL_LOCKS GIT_QUARANTINE_PATH GIT_REPLACE_REF_BASE \
  GIT_SHALLOW_FILE GIT_WORK_TREE; do
  [[ ! -v "${git_environment_override}" ]] ||
    fail "inherited Git repository override: ${git_environment_override}"
done
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_OPTIONAL_LOCKS=0

require_real_regular_file "${DISPOSABLE_MARKER}" 'disposable evaluator marker'
require_safe_root_chain "${DISPOSABLE_MARKER}" 'disposable evaluator marker'
[[ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "${DISPOSABLE_MARKER}")" == \
  '0:0:400:regular file' ]] ||
  fail 'disposable evaluator marker must be root:root mode 0400'
/usr/bin/cmp -s -- "${DISPOSABLE_MARKER}" <(
  printf '%s\n' \
    'schema=a-quo-disposable-omarchy-evaluator-v1' \
    'account=a-quo-evaluator'
) || fail 'disposable evaluator marker has unexpected bytes'

ACCOUNT_RECORD="$(/usr/bin/getent passwd "${EVALUATOR_ACCOUNT}")" ||
  fail 'dedicated evaluator account does not exist'
readonly ACCOUNT_RECORD
IFS=: read -r ACCOUNT_NAME _ EVALUATOR_UID EVALUATOR_GID _ ACCOUNT_HOME _ \
  <<<"${ACCOUNT_RECORD}"
readonly ACCOUNT_NAME EVALUATOR_UID EVALUATOR_GID ACCOUNT_HOME
[[ "${ACCOUNT_NAME}" == "${EVALUATOR_ACCOUNT}" && \
  "${ACCOUNT_HOME}" == "${EVALUATOR_HOME}" && \
  "${EVALUATOR_UID}" =~ ^[1-9][0-9]*$ && \
  "${EVALUATOR_GID}" =~ ^[0-9]+$ ]] ||
  fail 'dedicated evaluator account identity or exact home is wrong'
[[ "$(/usr/bin/id -u "${EVALUATOR_ACCOUNT}")" == "${EVALUATOR_UID}" && \
  "$(/usr/bin/id -g "${EVALUATOR_ACCOUNT}")" == "${EVALUATOR_GID}" ]] ||
  fail 'evaluator account UID/GID lookup is inconsistent'
require_safe_evaluator_directory "${EVALUATOR_HOME}"
for evaluator_directory in \
  "${EVALUATOR_HOME}/.config" "${EVALUATOR_HOME}/.config/omarchy" \
  "${PLUGINS_DIRECTORY}"; do
  require_safe_evaluator_directory "${evaluator_directory}"
done
for optional_evaluator_directory in \
  "${EVALUATOR_HOME}/.local" "${EVALUATOR_HOME}/.local/share"; do
  if [[ -e "${optional_evaluator_directory}" || -L "${optional_evaluator_directory}" ]]; then
    require_safe_evaluator_directory "${optional_evaluator_directory}"
  fi
done

for required_name in \
  A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY \
  A_QUO_PACKAGE_LIFECYCLE_OLD_PACKAGE \
  A_QUO_PACKAGE_LIFECYCLE_OLD_PACKAGE_SHA256 \
  A_QUO_PACKAGE_LIFECYCLE_OLD_SOURCE_COMMIT \
  A_QUO_PACKAGE_LIFECYCLE_OLD_PACKAGE_QUERY \
  A_QUO_PACKAGE_LIFECYCLE_NEW_PACKAGE \
  A_QUO_PACKAGE_LIFECYCLE_NEW_PACKAGE_SHA256 \
  A_QUO_PACKAGE_LIFECYCLE_NEW_SOURCE_COMMIT \
  A_QUO_PACKAGE_LIFECYCLE_NEW_PACKAGE_QUERY \
  A_QUO_EVALUATOR_WAYLAND_DISPLAY \
  A_QUO_EVALUATOR_PACKAGE_V1 \
  A_QUO_EVALUATOR_PACKAGE_V1_SHA256 \
  A_QUO_EVALUATOR_PACKAGE_V2 \
  A_QUO_EVALUATOR_PACKAGE_V2_SHA256 \
  A_QUO_EVALUATOR_PLUGIN_ID \
  A_QUO_JOINED_INPUT_LOCK \
  A_QUO_JOINED_INPUT_LOCK_SHA256 \
  A_QUO_JOINED_INPUT_LOCK_COMMIT \
  A_QUO_JOINED_INPUT_DIRECTORY; do
  require_environment "${required_name}"
done

readonly OLD_PACKAGE_SOURCE="${A_QUO_PACKAGE_LIFECYCLE_OLD_PACKAGE}"
readonly OLD_PACKAGE_EXPECTED_SHA256="${A_QUO_PACKAGE_LIFECYCLE_OLD_PACKAGE_SHA256}"
readonly OLD_SOURCE_COMMIT="${A_QUO_PACKAGE_LIFECYCLE_OLD_SOURCE_COMMIT}"
readonly OLD_PACKAGE_QUERY="${A_QUO_PACKAGE_LIFECYCLE_OLD_PACKAGE_QUERY}"
readonly NEW_PACKAGE_SOURCE="${A_QUO_PACKAGE_LIFECYCLE_NEW_PACKAGE}"
readonly NEW_PACKAGE_EXPECTED_SHA256="${A_QUO_PACKAGE_LIFECYCLE_NEW_PACKAGE_SHA256}"
readonly NEW_SOURCE_COMMIT="${A_QUO_PACKAGE_LIFECYCLE_NEW_SOURCE_COMMIT}"
readonly NEW_PACKAGE_QUERY="${A_QUO_PACKAGE_LIFECYCLE_NEW_PACKAGE_QUERY}"
readonly EXPECTED_OMARCHY_QUERY="${A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY}"
readonly JOINED_INPUT_LOCK="${A_QUO_JOINED_INPUT_LOCK}"
readonly JOINED_INPUT_LOCK_SHA256="${A_QUO_JOINED_INPUT_LOCK_SHA256}"
readonly JOINED_INPUT_LOCK_COMMIT="${A_QUO_JOINED_INPUT_LOCK_COMMIT}"
readonly JOINED_INPUT_DIRECTORY="${A_QUO_JOINED_INPUT_DIRECTORY}"

for digest in \
  "${OLD_PACKAGE_EXPECTED_SHA256}" "${NEW_PACKAGE_EXPECTED_SHA256}" \
  "${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" \
  "${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}"; do
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || fail 'all package SHA-256 pins must be lowercase hex'
done
[[ "${OLD_PACKAGE_EXPECTED_SHA256}" != "${NEW_PACKAGE_EXPECTED_SHA256}" ]] ||
  fail 'old and new A Quo packages must be distinct exact bytes'
[[ "${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" != \
  "${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}" ]] ||
  fail 'v1 and v2 plugin fixtures must be distinct exact bytes'
for commit in "${OLD_SOURCE_COMMIT}" "${NEW_SOURCE_COMMIT}"; do
  [[ "${commit}" =~ ^[0-9a-f]{40}$ ]] ||
    fail 'A Quo source commits must be full lowercase Git object IDs'
done
[[ "${OLD_SOURCE_COMMIT}" != "${NEW_SOURCE_COMMIT}" ]] ||
  fail 'old and new A Quo source commits must be distinct'
[[ "${JOINED_INPUT_LOCK_SHA256}" =~ ^[0-9a-f]{64}$ ]] ||
  fail 'joined input lock SHA-256 must be lowercase hex'
[[ "${JOINED_INPUT_LOCK_COMMIT}" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'joined input lock commit must be one full lowercase Git object ID'
[[ "${OLD_PACKAGE_QUERY}" =~ ^a-quo[[:space:]][^[:space:]]+$ && \
  "${NEW_PACKAGE_QUERY}" =~ ^a-quo[[:space:]][^[:space:]]+$ ]] ||
  fail 'A Quo package queries must be exact pacman -Q lines'
readonly OLD_PACKAGE_VERSION="${OLD_PACKAGE_QUERY#* }"
readonly NEW_PACKAGE_VERSION="${NEW_PACKAGE_QUERY#* }"
(( $(/usr/bin/vercmp "${NEW_PACKAGE_VERSION}" "${OLD_PACKAGE_VERSION}") > 0 )) ||
  fail 'new A Quo package query must sort after old package query'

[[ "${EXPECTED_OMARCHY_QUERY}" =~ ^omarchy(-dev)?[[:space:]][^[:space:]]+$ ]] ||
  fail 'A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY must be one exact supported pacman -Q line'
readonly EXPECTED_OMARCHY_PACKAGE="${EXPECTED_OMARCHY_QUERY%%[[:space:]]*}"
[[ "${EXPECTED_OMARCHY_PACKAGE}" == omarchy || \
  "${EXPECTED_OMARCHY_PACKAGE}" == omarchy-dev ]] ||
  fail 'derived Omarchy package name is outside the closed supported set'
[[ "$(/usr/bin/pacman -Q -- "${EXPECTED_OMARCHY_PACKAGE}")" == \
  "${EXPECTED_OMARCHY_QUERY}" ]] ||
  fail 'installed Omarchy package query does not match its caller pin'

[[ "${JOINED_INPUT_DIRECTORY}" == /* && "${JOINED_INPUT_DIRECTORY}" != / && \
  -d "${JOINED_INPUT_DIRECTORY}" && ! -L "${JOINED_INPUT_DIRECTORY}" && \
  "$(/usr/bin/realpath -e -- "${JOINED_INPUT_DIRECTORY}")" == \
    "${JOINED_INPUT_DIRECTORY}" ]] ||
  fail 'joined input directory must be an absolute canonical non-root directory'
require_safe_root_chain "${JOINED_INPUT_DIRECTORY}" 'joined input directory'
JOINED_INPUT_DEVICE="$(/usr/bin/stat -c '%d' -- "${JOINED_INPUT_DIRECTORY}")"
readonly JOINED_INPUT_DEVICE
[[ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "${JOINED_INPUT_DIRECTORY}")" == \
  '0:0:700:directory' ]] ||
  fail 'joined input directory must be root:root mode 0700'
JOINED_INPUT_DIRECTORY_IDENTITY="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%F' -- \
  "${JOINED_INPUT_DIRECTORY}")"
readonly JOINED_INPUT_DIRECTORY_IDENTITY
readonly -a JOINED_INPUT_NAMES=(
  'a-quo-0.1.0.r51.g50945229817f-1-aarch64.pkg.tar.zst'
  'a-quo-0.1.0.r61.g81658b7f8d48-1-aarch64.pkg.tar.zst'
  'aarch64-target.profile'
  'aquo.test.joined-lifecycle-1.0.0.pkg.tar.zst'
  'aquo.test.joined-lifecycle-2.0.0.pkg.tar.zst'
  'arch-package-target-resolver.sh'
  'arch-package-verifier.sh'
  'consent-lifecycle-evaluator.sh'
  'omarchy-core-lifecycle-evaluator.sh'
  'package-lifecycle-bridge.sh'
)
if ! /usr/bin/cmp -s -- \
  <(/usr/bin/printf '%s\n' "${JOINED_INPUT_NAMES[@]}") \
  <(/usr/bin/find "${JOINED_INPUT_DIRECTORY}" -xdev -mindepth 1 -maxdepth 1 \
    -printf '%f\n' | /usr/bin/sort); then
  fail 'joined input directory differs from the exact ten-file inventory'
fi
for joined_input_name in "${JOINED_INPUT_NAMES[@]}"; do
  require_inert_joined_input \
    "${JOINED_INPUT_DIRECTORY}/${joined_input_name}" \
    "${JOINED_INPUT_DEVICE}" "${joined_input_name}"
done
[[ "${OLD_PACKAGE_SOURCE}" == \
    "${JOINED_INPUT_DIRECTORY}/a-quo-0.1.0.r51.g50945229817f-1-aarch64.pkg.tar.zst" && \
  "${NEW_PACKAGE_SOURCE}" == \
    "${JOINED_INPUT_DIRECTORY}/a-quo-0.1.0.r61.g81658b7f8d48-1-aarch64.pkg.tar.zst" && \
  "${A_QUO_EVALUATOR_PACKAGE_V1}" == \
    "${JOINED_INPUT_DIRECTORY}/aquo.test.joined-lifecycle-1.0.0.pkg.tar.zst" && \
  "${A_QUO_EVALUATOR_PACKAGE_V2}" == \
    "${JOINED_INPUT_DIRECTORY}/aquo.test.joined-lifecycle-2.0.0.pkg.tar.zst" ]] ||
  fail 'package inputs do not use the exact joined input directory paths'

require_root_package_input "${OLD_PACKAGE_SOURCE}" \
  "${OLD_PACKAGE_EXPECTED_SHA256}" old-A-Quo
require_root_package_input "${NEW_PACKAGE_SOURCE}" \
  "${NEW_PACKAGE_EXPECTED_SHA256}" new-A-Quo
require_root_package_input "${A_QUO_EVALUATOR_PACKAGE_V1}" \
  "${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" plugin-fixture-v1
require_root_package_input "${A_QUO_EVALUATOR_PACKAGE_V2}" \
  "${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}" plugin-fixture-v2

[[ "${A_QUO_EVALUATOR_WAYLAND_DISPLAY}" =~ ^wayland-[0-9]+$ ]] ||
  fail 'A_QUO_EVALUATOR_WAYLAND_DISPLAY must be one simple wayland-N socket name'
readonly EVALUATOR_RUNTIME_DIRECTORY="/run/user/${EVALUATOR_UID}"
require_safe_evaluator_directory "${EVALUATOR_RUNTIME_DIRECTORY}"
readonly WAYLAND_SOCKET="${EVALUATOR_RUNTIME_DIRECTORY}/${A_QUO_EVALUATOR_WAYLAND_DISPLAY}"
[[ -S "${WAYLAND_SOCKET}" && ! -L "${WAYLAND_SOCKET}" && \
  "$(/usr/bin/stat -c '%u' -- "${WAYLAND_SOCKET}")" == "${EVALUATOR_UID}" ]] ||
  fail 'the evaluator account has no matching real Wayland socket'
[[ "${A_QUO_EVALUATOR_PLUGIN_ID}" =~ ^[[:alnum:]][[:alnum:]_.-]{0,254}$ && \
  "${A_QUO_EVALUATOR_PLUGIN_ID}" != *..* && \
  "${A_QUO_EVALUATOR_PLUGIN_ID}" != omarchy.* ]] ||
  fail 'A_QUO_EVALUATOR_PLUGIN_ID is invalid or reserved'
[[ ! -e "${PERSONA_STATE_ROOT}" && ! -L "${PERSONA_STATE_ROOT}" ]] ||
  fail 'installed-core persona root must be absent before package mutation'
[[ ! -e "${PLUGINS_DIRECTORY}/${A_QUO_EVALUATOR_PLUGIN_ID}" && \
  ! -L "${PLUGINS_DIRECTORY}/${A_QUO_EVALUATOR_PLUGIN_ID}" ]] ||
  fail 'installed-core plugin target must be absent before package mutation'
[[ ! -e "${EVIDENCE_ROOT}" && ! -L "${EVIDENCE_ROOT}" ]] ||
  fail 'package-lifecycle evidence root must be absent before this one-shot run'

assert_a_quo_package_absent 'before preflight'
assert_no_daemon_process
[[ ! -e "${PACMAN_LOCK}" && ! -L "${PACMAN_LOCK}" ]] ||
  fail 'pacman database lock exists before the package lifecycle'

for enablement_root in \
  /etc/systemd/user /run/systemd/user \
  "${EVALUATOR_HOME}/.config/systemd/user" \
  "${EVALUATOR_RUNTIME_DIRECTORY}/systemd/user"; do
  if [[ -d "${enablement_root}" && -n "$(
    /usr/bin/find "${enablement_root}" -xdev -type l \
      -name a-quo-daemon.service -print -quit
  )" ]]; then
    fail 'A Quo user service is enabled before package installation'
  fi
done

set +e
PREFLIGHT_UNIT_OUTPUT="$(
  /usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- \
    /usr/bin/env -i HOME="${EVALUATOR_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
      XDG_RUNTIME_DIR="${EVALUATOR_RUNTIME_DIRECTORY}" \
      /usr/bin/systemctl --user --no-pager is-active a-quo-daemon.service 2>&1
)"
PREFLIGHT_UNIT_STATUS="$?"
PREFLIGHT_ENABLED_OUTPUT="$(
  /usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- \
    /usr/bin/env -i HOME="${EVALUATOR_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
      XDG_RUNTIME_DIR="${EVALUATOR_RUNTIME_DIRECTORY}" \
      /usr/bin/systemctl --user --no-pager is-enabled a-quo-daemon.service 2>&1
)"
PREFLIGHT_ENABLED_STATUS="$?"
PREFLIGHT_GLOBAL_OUTPUT="$(
  /usr/bin/env -i HOME=/root LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/systemctl --global --no-pager is-enabled a-quo-daemon.service 2>&1
)"
PREFLIGHT_GLOBAL_STATUS="$?"
set -e
readonly PREFLIGHT_UNIT_OUTPUT PREFLIGHT_UNIT_STATUS
readonly PREFLIGHT_ENABLED_OUTPUT PREFLIGHT_ENABLED_STATUS
readonly PREFLIGHT_GLOBAL_OUTPUT PREFLIGHT_GLOBAL_STATUS
[[ "${PREFLIGHT_UNIT_STATUS}" -eq 4 && "${PREFLIGHT_UNIT_OUTPUT}" == inactive && \
  "${PREFLIGHT_ENABLED_STATUS}" -eq 4 && "${PREFLIGHT_ENABLED_OUTPUT}" == not-found && \
  "${PREFLIGHT_GLOBAL_STATUS}" -eq 4 && "${PREFLIGHT_GLOBAL_OUTPUT}" == not-found ]] ||
  fail 'A Quo user unit is not exactly absent and disabled before package installation'

readonly BRIDGE_RELATIVE_PATH='scripts/test-installed-a-quo-package-lifecycle.sh'
SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly EVALUATION_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly EXPECTED_BRIDGE_PATH="${REPOSITORY_ROOT}/${BRIDGE_RELATIVE_PATH}"
EXECUTING_BRIDGE_PATH="$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")" ||
  fail 'executing package lifecycle bridge path could not be resolved'
readonly EXECUTING_BRIDGE_PATH
[[ "${SCRIPT_DIRECTORY}" == "${REPOSITORY_ROOT}/scripts" && \
  "${EXECUTING_BRIDGE_PATH}" == "${EXPECTED_BRIDGE_PATH}" ]] ||
  fail 'package lifecycle bridge is not executing from its canonical repository path'
require_real_regular_file "${EXECUTING_BRIDGE_PATH}" 'executing package lifecycle bridge'
require_safe_root_chain "${EXECUTING_BRIDGE_PATH}" 'executing package lifecycle bridge'
require_safe_root_chain "${REPOSITORY_ROOT}" 'source checkout'
require_bounded_safe_root_tree "${REPOSITORY_ROOT}/.git" \
  'source checkout Git metadata' 65536 1073741824
for expected_file in \
  "${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh" \
  "${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh" \
  "${SCRIPT_DIRECTORY}/test-installed-a-quo-consent-lifecycle.sh" \
  "${SCRIPT_DIRECTORY}/test-installed-omarchy-core-lifecycle.sh"; do
  [[ -f "${expected_file}" && ! -L "${expected_file}" && -x "${expected_file}" ]] ||
    fail "required source-checkout evaluator is missing or unsafe: ${expected_file}"
  require_safe_root_chain "${expected_file}" 'source-checkout evaluator'
done
[[ "$(/usr/bin/git -C "${REPOSITORY_ROOT}" rev-parse --is-shallow-repository)" == false ]] ||
  fail 'source checkout must contain complete non-shallow history'
GIT_COMMON_DIRECTORY="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" rev-parse --path-format=absolute --git-common-dir
})" || fail 'source checkout Git common directory could not be inspected'
readonly GIT_COMMON_DIRECTORY
[[ "${GIT_COMMON_DIRECTORY}" == "${REPOSITORY_ROOT}/.git" ]] ||
  fail 'source checkout must be one standalone checkout, not a linked worktree'
[[ ! -e "${GIT_COMMON_DIRECTORY}/info/grafts" && \
  ! -L "${GIT_COMMON_DIRECTORY}/info/grafts" ]] ||
  fail 'source checkout contains a legacy graft file'
for alternate_file in \
  "${GIT_COMMON_DIRECTORY}/objects/info/alternates" \
  "${GIT_COMMON_DIRECTORY}/objects/info/http-alternates"; do
  [[ ! -e "${alternate_file}" && ! -L "${alternate_file}" ]] ||
    fail 'source checkout uses an alternate Git object store'
done
require_safe_root_chain "${GIT_COMMON_DIRECTORY}" 'source checkout Git common directory'
set +e
PARTIAL_CLONE_CONFIGURATION="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" config --local --get-regexp \
    '^(extensions\.partialclone|remote\..*\.promisor)$'
})"
PARTIAL_CLONE_STATUS="$?"
set -e
readonly PARTIAL_CLONE_CONFIGURATION PARTIAL_CLONE_STATUS
[[ "${PARTIAL_CLONE_STATUS}" -eq 1 && -z "${PARTIAL_CLONE_CONFIGURATION}" ]] ||
  fail 'source checkout has partial-clone or promisor configuration'
REPLACEMENT_REF="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" for-each-ref --count=1 \
    --format='%(refname)' refs/replace
})" || fail 'source checkout replacement refs could not be inspected'
readonly REPLACEMENT_REF
[[ -z "${REPLACEMENT_REF}" ]] || fail 'source checkout contains replacement refs'
SOURCE_HEAD="$(/usr/bin/git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)" ||
  fail 'source checkout HEAD could not be inspected'
readonly SOURCE_HEAD
[[ "${SOURCE_HEAD}" =~ ^[0-9a-f]{40}$ ]] || fail 'source checkout HEAD is not a full object ID'
BRIDGE_TREE_ENTRY="$(
  /usr/bin/git -C "${REPOSITORY_ROOT}" ls-tree "${SOURCE_HEAD}" -- \
    "${BRIDGE_RELATIVE_PATH}"
)" || fail 'committed package lifecycle bridge tree entry could not be inspected'
readonly BRIDGE_TREE_ENTRY
BRIDGE_TREE_METADATA="${BRIDGE_TREE_ENTRY%%$'\t'*}"
BRIDGE_TREE_PATH="${BRIDGE_TREE_ENTRY#*$'\t'}"
readonly BRIDGE_TREE_METADATA BRIDGE_TREE_PATH
[[ "${BRIDGE_TREE_PATH}" == "${BRIDGE_RELATIVE_PATH}" && \
  "${BRIDGE_TREE_METADATA}" =~ ^100755\ blob\ [0-9a-f]{40}$ ]] ||
  fail 'package lifecycle bridge is not one tracked executable blob at HEAD'
mapfile -d '' -t TRACKED_SOURCE_PATHS < <(
  /usr/bin/git -C "${REPOSITORY_ROOT}" ls-files -z
)
readonly TRACKED_SOURCE_PATHS
(( ${#TRACKED_SOURCE_PATHS[@]} > 0 && ${#TRACKED_SOURCE_PATHS[@]} <= 4096 )) ||
  fail 'source checkout tracked-file count is empty or outside the closed bound'
for tracked_source_path in "${TRACKED_SOURCE_PATHS[@]}"; do
  [[ "${tracked_source_path}" != /* && \
    "${tracked_source_path}" != ../* && \
    "${tracked_source_path}" != */../* && \
    "${tracked_source_path}" != *'//' ]] ||
    fail 'source checkout contains a non-normalized tracked path'
  require_real_regular_file "${REPOSITORY_ROOT}/${tracked_source_path}" \
    'source checkout tracked file'
  require_safe_root_chain "${REPOSITORY_ROOT}/${tracked_source_path}" \
    'source checkout tracked file'
done
SOURCE_STATUS="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" -c core.fsmonitor=false \
    status --porcelain=v1 --untracked-files=normal
})" || fail 'source checkout cleanliness could not be inspected'
readonly SOURCE_STATUS
[[ -z "${SOURCE_STATUS}" ]] || fail 'source checkout must be clean before package mutation'
for commit in "${OLD_SOURCE_COMMIT}" "${NEW_SOURCE_COMMIT}"; do
  /usr/bin/git -C "${REPOSITORY_ROOT}" cat-file -e "${commit}^{commit}" 2>/dev/null ||
    fail "A Quo source commit is unavailable: ${commit}"
  /usr/bin/git -C "${REPOSITORY_ROOT}" merge-base --is-ancestor \
    "${commit}" "${SOURCE_HEAD}" || fail "A Quo source commit is not reachable from HEAD: ${commit}"
done
/usr/bin/git -C "${REPOSITORY_ROOT}" merge-base --is-ancestor \
  "${OLD_SOURCE_COMMIT}" "${NEW_SOURCE_COMMIT}" ||
  fail 'old A Quo source commit is not an ancestor of new source commit'

COMMITTED_BRIDGE_SHA256="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" show \
    "${SOURCE_HEAD}:${BRIDGE_RELATIVE_PATH}" | /usr/bin/sha256sum
})"
COMMITTED_BRIDGE_SHA256="${COMMITTED_BRIDGE_SHA256%% *}"
EXECUTING_BRIDGE_IDENTITY="$({
  /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s:%Y:%Z' -- \
    "${EXECUTING_BRIDGE_PATH}"
})"
EXECUTING_BRIDGE_SHA256="$(sha256_file "${EXECUTING_BRIDGE_PATH}")"
EXECUTING_BRIDGE_POST_HASH_IDENTITY="$({
  /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s:%Y:%Z' -- \
    "${EXECUTING_BRIDGE_PATH}"
})"
readonly COMMITTED_BRIDGE_SHA256 EXECUTING_BRIDGE_IDENTITY
readonly EXECUTING_BRIDGE_SHA256 EXECUTING_BRIDGE_POST_HASH_IDENTITY
[[ "${EXECUTING_BRIDGE_IDENTITY}" =~ \
    ^[0-9]+:[0-9]+:0:0:755:1:regular\ file:[0-9]+:[0-9]+:[0-9]+$ && \
  "${EXECUTING_BRIDGE_POST_HASH_IDENTITY}" == "${EXECUTING_BRIDGE_IDENTITY}" ]] ||
  fail 'executing package lifecycle bridge identity changed during hashing'
[[ "${EXECUTING_BRIDGE_SHA256}" == "${COMMITTED_BRIDGE_SHA256}" ]] ||
  fail 'executing package lifecycle bridge differs from current committed policy'

COMMITTED_VERIFIER_SHA256="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" show \
    "${SOURCE_HEAD}:scripts/verify-arch-package-skeleton.sh" | /usr/bin/sha256sum
})"
COMMITTED_VERIFIER_SHA256="${COMMITTED_VERIFIER_SHA256%% *}"
COMMITTED_CORE_EVALUATOR_SHA256="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" show \
    "${SOURCE_HEAD}:scripts/test-installed-omarchy-core-lifecycle.sh" | /usr/bin/sha256sum
})"
COMMITTED_CORE_EVALUATOR_SHA256="${COMMITTED_CORE_EVALUATOR_SHA256%% *}"
COMMITTED_CONSENT_EVALUATOR_SHA256="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" show \
    "${SOURCE_HEAD}:scripts/test-installed-a-quo-consent-lifecycle.sh" | /usr/bin/sha256sum
})"
COMMITTED_CONSENT_EVALUATOR_SHA256="${COMMITTED_CONSENT_EVALUATOR_SHA256%% *}"
readonly COMMITTED_VERIFIER_SHA256 COMMITTED_CORE_EVALUATOR_SHA256
readonly COMMITTED_CONSENT_EVALUATOR_SHA256
[[ "$(sha256_file "${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh")" == \
    "${COMMITTED_VERIFIER_SHA256}" && \
  "$(sha256_file "${SCRIPT_DIRECTORY}/test-installed-a-quo-consent-lifecycle.sh")" == \
    "${COMMITTED_CONSENT_EVALUATOR_SHA256}" && \
  "$(sha256_file "${SCRIPT_DIRECTORY}/test-installed-omarchy-core-lifecycle.sh")" == \
    "${COMMITTED_CORE_EVALUATOR_SHA256}" ]] ||
  fail 'working package verifier, consent evaluator, or installed-core evaluator differs from current committed policy'

readonly EXPECTED_JOINED_INPUT_LOCK_PATH="${REPOSITORY_ROOT}/${JOINED_INPUT_LOCK_RELATIVE_PATH}"
[[ "${JOINED_INPUT_LOCK}" == "${EXPECTED_JOINED_INPUT_LOCK_PATH}" ]] ||
  fail 'joined input lock is not the canonical repository path'
require_real_regular_file "${JOINED_INPUT_LOCK}" 'joined input lock'
require_safe_root_chain "${JOINED_INPUT_LOCK}" 'joined input lock'
JOINED_INPUT_LOCK_IDENTITY="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s' -- \
  "${JOINED_INPUT_LOCK}")"
readonly JOINED_INPUT_LOCK_IDENTITY
[[ "$(sha256_file "${JOINED_INPUT_LOCK}")" == "${JOINED_INPUT_LOCK_SHA256}" ]] ||
  fail 'joined input lock differs from its caller-pinned SHA-256'
/usr/bin/git -C "${REPOSITORY_ROOT}" cat-file -e \
  "${JOINED_INPUT_LOCK_COMMIT}^{commit}" 2>/dev/null ||
  fail 'joined input lock commit is unavailable'
/usr/bin/git -C "${REPOSITORY_ROOT}" merge-base --is-ancestor \
  "${JOINED_INPUT_LOCK_COMMIT}" "${SOURCE_HEAD}" ||
  fail 'joined input lock commit is not reachable from source HEAD'
JOINED_INPUT_LOCK_TREE_ENTRY="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" ls-tree \
    "${JOINED_INPUT_LOCK_COMMIT}" -- "${JOINED_INPUT_LOCK_RELATIVE_PATH}"
})" || fail 'joined input lock tree entry could not be inspected'
readonly JOINED_INPUT_LOCK_TREE_ENTRY
[[ "${JOINED_INPUT_LOCK_TREE_ENTRY}" =~ \
  ^100644\ blob\ [0-9a-f]{40}$'\t'${JOINED_INPUT_LOCK_RELATIVE_PATH}$ ]] ||
  fail 'joined input lock is not one regular tracked blob at its expected commit'
COMMITTED_JOINED_INPUT_LOCK_SHA256="$({
  /usr/bin/git -C "${REPOSITORY_ROOT}" show \
    "${JOINED_INPUT_LOCK_COMMIT}:${JOINED_INPUT_LOCK_RELATIVE_PATH}" | \
    /usr/bin/sha256sum
})"
COMMITTED_JOINED_INPUT_LOCK_SHA256="${COMMITTED_JOINED_INPUT_LOCK_SHA256%% *}"
readonly COMMITTED_JOINED_INPUT_LOCK_SHA256
[[ "${COMMITTED_JOINED_INPUT_LOCK_SHA256}" == "${JOINED_INPUT_LOCK_SHA256}" ]] ||
  fail 'joined input lock Git object differs from the caller-pinned SHA-256'
/usr/bin/cmp -s -- "${JOINED_INPUT_LOCK}" <(
  /usr/bin/git -C "${REPOSITORY_ROOT}" show \
    "${JOINED_INPUT_LOCK_COMMIT}:${JOINED_INPUT_LOCK_RELATIVE_PATH}"
) || fail 'working joined input lock differs from its expected committed bytes'
[[ "$(/usr/bin/wc -l <"${JOINED_INPUT_LOCK}")" -eq 66 ]] ||
  fail 'joined input lock does not have the exact closed field count'

for lock_expectation in \
  'format|a-quo-omarchy-joined-lifecycle-input-lock-v1' \
  'lock_id|a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1' \
  'state|reviewed-input-selection' \
  'lock_authority|exact-byte-selection-only' \
  'evaluator_arming|not-authorized' \
  'build_authorization|not-established' \
  'runnable|false' \
  'retention|caller-supplied-local-exact-bytes-required' \
  'durable_retention|not-established' \
  'lock_authentication|external-pinned-git-object-required' \
  'self_authentication|none' \
  'lock_repository|https://github.com/SurreptitiousFabric/a-quo.git' \
  'lock_path|packaging/evaluation-input-locks/a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1.lock' \
  'profile_repository|https://github.com/SurreptitiousFabric/a-quo.git' \
  'profile_commit|e13e74dca3472e54501b35c9b57ee89f57c6aed3' \
  'profile_path|packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile' \
  'profile_id|a-quo-omarchy4-aarch64-dec29fa-v2' \
  'profile_sha256|3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6' \
  'profile_state|bootstrap-unarmed' \
  'profile_armable|false' \
  'profile_field_count|129' \
  'target_kind|virtual-reference-target' \
  'architecture|aarch64' \
  'evidence_namespace|phase-a-aarch64-dec29fa' \
  'policy_repository|https://github.com/SurreptitiousFabric/a-quo.git' \
  'policy_commit_authentication|not-established' \
  'input_class|10-evaluator-scripts-and-fixture-input-lock' \
  'selected_input_scope|two-a-quo-packages-two-joined-fixtures-six-policy-files' \
  'artifact_count|4' \
  'fixture_registry_path|fixtures/omarchy/joined-lifecycle-v1/sources.json' \
  'fixture_registry_sha256|73037188e202b9e06f8c402e494ad0aaf9a072deeac343b4b24cd5ca00e4fda0' \
  'fixture_source_commit|54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04' \
  'fixture_v1_source_tree|8672d1283d23be50affecbd79f4a94f49f51c4d4' \
  'fixture_v2_source_tree|70d9948522bf458b70bf2b053958661814fbfb82' \
  'fixture_reproducibility|deterministic-same-host-contract-only' \
  'policy_file_count|6' \
  'object_count|10' \
  'input_class_10_exact_selection_closed|true' \
  'profile_unresolved_input_count|10' \
  'remaining_input_count_if_lock_is_adopted|9' \
  'package_static_verification|not-performed-by-input-lock' \
  'package_signatures|absent' \
  'fixture_signatures|absent' \
  'source_to_binary_provenance|not-established' \
  'evaluator_execution|forbidden' \
  'package_manager_execution|forbidden' \
  'network_access|forbidden' \
  'mount_execution|forbidden' \
  'vm_execution|forbidden' \
  'physical_target_evidence|false' \
  'clean_system_claim|not-established' \
  'lifecycle_evidence|false' \
  'aarch64_evaluation_gate_satisfied|false' \
  'cross_profile_evidence_accepted|false' \
  'safety|not-established'; do
  IFS='|' read -r lock_key lock_value <<<"${lock_expectation}"
  require_lock_field "${lock_key}" "${lock_value}"
done
require_lock_field artifact_01 \
  "old-a-quo-package|${JOINED_INPUT_NAMES[0]}|arch-package|${OLD_SOURCE_COMMIT}|${OLD_PACKAGE_VERSION}|12089177|${OLD_PACKAGE_EXPECTED_SHA256}"
require_lock_field artifact_02 \
  "new-a-quo-package|${JOINED_INPUT_NAMES[1]}|arch-package|${NEW_SOURCE_COMMIT}|${NEW_PACKAGE_VERSION}|12169663|${NEW_PACKAGE_EXPECTED_SHA256}"
require_lock_field artifact_03 \
  "joined-fixture-v1|${JOINED_INPUT_NAMES[3]}|omarchy-plugin-package|54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04|1.0.0|1119|${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}"
require_lock_field artifact_04 \
  "joined-fixture-v2|${JOINED_INPUT_NAMES[4]}|omarchy-plugin-package|54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04|2.0.0|1159|${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}"

JOINED_POLICY_COMMIT="$(lock_field policy_commit)"
readonly JOINED_POLICY_COMMIT
[[ "${JOINED_POLICY_COMMIT}" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'joined input policy commit is malformed'
/usr/bin/git -C "${REPOSITORY_ROOT}" cat-file -e \
  "${JOINED_POLICY_COMMIT}^{commit}" 2>/dev/null ||
  fail 'joined input policy commit is unavailable'
/usr/bin/git -C "${REPOSITORY_ROOT}" merge-base --is-ancestor \
  "${JOINED_POLICY_COMMIT}" "${JOINED_INPUT_LOCK_COMMIT}" ||
  fail 'joined input policy commit is not an ancestor of the lock commit'
readonly -a JOINED_POLICY_RECORDS=(
  'package-lifecycle-bridge|package-lifecycle-bridge.sh|scripts/test-installed-a-quo-package-lifecycle.sh'
  'consent-lifecycle-evaluator|consent-lifecycle-evaluator.sh|scripts/test-installed-a-quo-consent-lifecycle.sh'
  'omarchy-core-lifecycle-evaluator|omarchy-core-lifecycle-evaluator.sh|scripts/test-installed-omarchy-core-lifecycle.sh'
  'arch-package-verifier|arch-package-verifier.sh|scripts/verify-arch-package-skeleton.sh'
  'arch-package-target-resolver|arch-package-target-resolver.sh|scripts/resolve-arch-package-target.sh'
  'aarch64-target-profile|aarch64-target.profile|packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile'
)
policy_index=0
for policy_mapping in "${JOINED_POLICY_RECORDS[@]}"; do
  ((policy_index += 1))
  IFS='|' read -r policy_role policy_input_name policy_source_path \
    <<<"${policy_mapping}"
  policy_record="$(lock_field "policy_file_$(/usr/bin/printf '%02d' "${policy_index}")")"
  IFS='|' read -r observed_role observed_input_name observed_source_path \
    observed_git_mode observed_git_blob observed_size observed_sha256 \
    <<<"${policy_record}"
  [[ "${observed_role}" == "${policy_role}" && \
    "${observed_input_name}" == "${policy_input_name}" && \
    "${observed_source_path}" == "${policy_source_path}" && \
    "${observed_git_mode}" =~ ^100(644|755)$ && \
    "${observed_git_blob}" =~ ^[0-9a-f]{40}$ && \
    "${observed_size}" =~ ^[1-9][0-9]*$ && \
    "${observed_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "joined input policy record is malformed or reordered: ${policy_role}"
  policy_tree_entry="$({
    /usr/bin/git -C "${REPOSITORY_ROOT}" ls-tree \
      "${JOINED_POLICY_COMMIT}" -- "${policy_source_path}"
  })" || fail "joined policy tree entry could not be inspected: ${policy_source_path}"
  [[ "${policy_tree_entry}" == \
    "${observed_git_mode} blob ${observed_git_blob}"$'\t'"${policy_source_path}" ]] ||
    fail "joined policy Git blob differs from the lock: ${policy_source_path}"
  policy_source="${REPOSITORY_ROOT}/${policy_source_path}"
  policy_input="${JOINED_INPUT_DIRECTORY}/${policy_input_name}"
  [[ "$(/usr/bin/stat -c '%s' -- "${policy_source}")" == "${observed_size}" && \
    "$(sha256_file "${policy_source}")" == "${observed_sha256}" && \
    "$(sha256_file "${policy_input}")" == "${observed_sha256}" ]] ||
    fail "joined policy source or inert input differs from the lock: ${policy_source_path}"
  /usr/bin/cmp -s -- "${policy_source}" "${policy_input}" ||
    fail "joined policy source and inert input differ: ${policy_source_path}"
done
(( policy_index == 6 )) || fail 'joined policy verification did not consume six files'
assert_joined_inputs 'after class-10 policy verification'

# Root must be able to create an isolated network namespace before any package
# or user-state mutation. Every pacman transaction and inherited hook runs in it.
/usr/bin/env -i LC_ALL=C PATH=/usr/bin:/bin \
  /usr/bin/unshare --net -- /usr/bin/true ||
  fail 'a fresh network namespace is unavailable for real pacman transactions'

[[ -d "${BRIDGE_LOCK_DIRECTORY}" && ! -L "${BRIDGE_LOCK_DIRECTORY}" && \
  "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "${BRIDGE_LOCK_DIRECTORY}")" == \
    '0:0:700:directory' ]] ||
  fail 'pre-provisioned package lifecycle bridge lock directory is unsafe or absent'
require_safe_root_chain "${BRIDGE_LOCK_DIRECTORY}" 'package lifecycle bridge lock directory'
[[ ! -L "${BRIDGE_LOCK}" && -f "${BRIDGE_LOCK}" ]] ||
  fail 'pre-provisioned package lifecycle bridge lock is absent or not a real regular file'
[[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%F' -- "${BRIDGE_LOCK}")" == \
  '0:0:600:1:regular file' ]] ||
  fail 'pre-provisioned package lifecycle bridge lock is unsafe'
require_safe_root_chain "${BRIDGE_LOCK}" 'package lifecycle bridge lock'
exec 9<>"${BRIDGE_LOCK}"
/usr/bin/flock -n 9 || fail 'another A Quo package lifecycle bridge owns the root lock'
BRIDGE_LOCK_IDENTITY="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%F' -- "/proc/self/fd/9")"
readonly BRIDGE_LOCK_IDENTITY
[[ "${BRIDGE_LOCK_IDENTITY}" == *':0:0:600:1:regular file' ]] ||
  fail 'opened package lifecycle bridge lock has unsafe metadata'

TEMPORARY_ROOT=''
TEMPORARY_ROOT_IDENTITY=''
MUTATION_STARTED=false
CURRENT_STAGE=preflight
remove_temporary_root() {
  [[ "${TEMPORARY_ROOT}" == /var/tmp/a-quo-installed-package-lifecycle.* ]] || return 1
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" && \
    "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "${TEMPORARY_ROOT}")" == \
      "${TEMPORARY_ROOT_IDENTITY}:0:0:700" ]] || return 1
  /usr/bin/rm -rf -- "${TEMPORARY_ROOT}" || return 1
  [[ ! -e "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]]
}
cleanup() {
  local status="$?"
  local installed_query=absent
  trap - EXIT
  if [[ "${status}" -ne 0 && "${MUTATION_STARTED}" == true ]]; then
    installed_query="$(
      /usr/bin/pacman -Q a-quo 2>/dev/null || printf '%s' 'absent-or-query-failed'
    )"
    printf 'package lifecycle stopped without automatic reversal: stage=%s installed=%q\n' \
      "${CURRENT_STAGE}" "${installed_query}" >&2
    if [[ -n "${TEMPORARY_ROOT}" ]]; then
      printf 'private failure evidence retained for disposable-target diagnosis: %s\n' \
        "${TEMPORARY_ROOT}" >&2
    fi
  elif [[ -n "${TEMPORARY_ROOT}" ]] && ! remove_temporary_root; then
    printf 'package lifecycle temporary cleanup failed: %s\n' "${TEMPORARY_ROOT}" >&2
    [[ "${status}" -ne 0 ]] || status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

TEMPORARY_ROOT="$(/usr/bin/mktemp -d /var/tmp/a-quo-installed-package-lifecycle.XXXXXX)"
/usr/bin/chown 0:0 -- "${TEMPORARY_ROOT}"
/usr/bin/chmod 0700 -- "${TEMPORARY_ROOT}"
TEMPORARY_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i' -- "${TEMPORARY_ROOT}")"
readonly TEMPORARY_ROOT TEMPORARY_ROOT_IDENTITY
readonly OLD_SNAPSHOT_DIRECTORY="${TEMPORARY_ROOT}/old"
readonly NEW_SNAPSHOT_DIRECTORY="${TEMPORARY_ROOT}/new"
/usr/bin/mkdir -m 0700 -- \
  "${OLD_SNAPSHOT_DIRECTORY}" "${NEW_SNAPSHOT_DIRECTORY}"

snapshot_package() {
  local source="$1"
  local expected_sha256="$2"
  local destination="$3"
  local label="$4"
  local before
  local after
  local observed
  before="$(/usr/bin/stat -c '%d:%i:%s:%f:%Y:%Z' -- "${source}")"
  /usr/bin/dd if="${source}" of="${destination}" bs=1048576 count=257 \
    iflag=fullblock,nofollow,nonblock status=none || fail "${label} snapshot copy failed"
  after="$(/usr/bin/stat -c '%d:%i:%s:%f:%Y:%Z' -- "${source}")"
  [[ "${before}" == "${after}" ]] || fail "${label} package changed during snapshot"
  /usr/bin/chown 0:0 -- "${destination}"
  /usr/bin/chmod 0400 -- "${destination}"
  observed="$(sha256_file "${destination}")"
  [[ "${observed}" == "${expected_sha256}" ]] || fail "${label} snapshot digest mismatch"
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%F' -- "${destination}")" == \
    '0:0:400:1:regular file' ]] || fail "${label} snapshot metadata is unsafe"
}

OLD_PACKAGE_SNAPSHOT="${OLD_SNAPSHOT_DIRECTORY}/$(/usr/bin/basename -- "${OLD_PACKAGE_SOURCE}")"
NEW_PACKAGE_SNAPSHOT="${NEW_SNAPSHOT_DIRECTORY}/$(/usr/bin/basename -- "${NEW_PACKAGE_SOURCE}")"
readonly OLD_PACKAGE_SNAPSHOT NEW_PACKAGE_SNAPSHOT
snapshot_package "${OLD_PACKAGE_SOURCE}" "${OLD_PACKAGE_EXPECTED_SHA256}" \
  "${OLD_PACKAGE_SNAPSHOT}" old-A-Quo
snapshot_package "${NEW_PACKAGE_SOURCE}" "${NEW_PACKAGE_EXPECTED_SHA256}" \
  "${NEW_PACKAGE_SNAPSHOT}" new-A-Quo

readonly COMMITTED_VERIFIER="${TEMPORARY_ROOT}/verify-arch-package-skeleton.sh"
readonly COMMITTED_CONSENT_EVALUATOR="${TEMPORARY_ROOT}/test-installed-a-quo-consent-lifecycle.sh"
readonly COMMITTED_CORE_EVALUATOR="${TEMPORARY_ROOT}/test-installed-omarchy-core-lifecycle.sh"
/usr/bin/git -C "${REPOSITORY_ROOT}" show \
  "${SOURCE_HEAD}:scripts/verify-arch-package-skeleton.sh" >"${COMMITTED_VERIFIER}"
/usr/bin/git -C "${REPOSITORY_ROOT}" show \
  "${SOURCE_HEAD}:scripts/test-installed-a-quo-consent-lifecycle.sh" \
  >"${COMMITTED_CONSENT_EVALUATOR}"
/usr/bin/git -C "${REPOSITORY_ROOT}" show \
  "${SOURCE_HEAD}:scripts/test-installed-omarchy-core-lifecycle.sh" >"${COMMITTED_CORE_EVALUATOR}"
/usr/bin/chown 0:0 -- \
  "${COMMITTED_VERIFIER}" "${COMMITTED_CONSENT_EVALUATOR}" "${COMMITTED_CORE_EVALUATOR}"
/usr/bin/chmod 0500 -- \
  "${COMMITTED_VERIFIER}" "${COMMITTED_CONSENT_EVALUATOR}" "${COMMITTED_CORE_EVALUATOR}"
[[ "$(sha256_file "${COMMITTED_VERIFIER}")" == "${COMMITTED_VERIFIER_SHA256}" && \
  "$(sha256_file "${COMMITTED_CONSENT_EVALUATOR}")" == \
    "${COMMITTED_CONSENT_EVALUATOR_SHA256}" && \
  "$(sha256_file "${COMMITTED_CORE_EVALUATOR}")" == \
    "${COMMITTED_CORE_EVALUATOR_SHA256}" ]] ||
  fail 'private committed evaluator snapshots do not match their expected hashes'

readonly OLD_PACKAGE_VERIFICATION_RECEIPT="${TEMPORARY_ROOT}/old-package-verification.receipt"
readonly NEW_PACKAGE_VERIFICATION_RECEIPT="${TEMPORARY_ROOT}/new-package-verification.receipt"
readonly EXPECTED_PACKAGE_TARGET_RECEIPT="${TEMPORARY_ROOT}/expected-package-target.receipt"
readonly OLD_PACKAGE_TARGET_RECEIPT="${TEMPORARY_ROOT}/old-package-target.receipt"
readonly NEW_PACKAGE_TARGET_RECEIPT="${TEMPORARY_ROOT}/new-package-target.receipt"
A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${COMMITTED_VERIFIER}" "${OLD_PACKAGE_SNAPSHOT}" "${OLD_SOURCE_COMMIT}" \
    "${EVALUATION_PROFILE}" >"${OLD_PACKAGE_VERIFICATION_RECEIPT}"
A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${COMMITTED_VERIFIER}" "${NEW_PACKAGE_SNAPSHOT}" "${NEW_SOURCE_COMMIT}" \
    "${EVALUATION_PROFILE}" >"${NEW_PACKAGE_VERIFICATION_RECEIPT}"
[[ "$(/usr/bin/head -n 1 -- "${OLD_PACKAGE_VERIFICATION_RECEIPT}")" == \
    "verified passive A Quo package skeleton: ${OLD_PACKAGE_SNAPSHOT}" && \
  "$(/usr/bin/head -n 1 -- "${NEW_PACKAGE_VERIFICATION_RECEIPT}")" == \
    "verified passive A Quo package skeleton: ${NEW_PACKAGE_SNAPSHOT}" ]] ||
  fail 'package verifier receipt does not identify its exact package snapshot'
/usr/bin/tail -n +2 -- "${OLD_PACKAGE_VERIFICATION_RECEIPT}" >"${OLD_PACKAGE_TARGET_RECEIPT}"
/usr/bin/tail -n +2 -- "${NEW_PACKAGE_VERIFICATION_RECEIPT}" >"${NEW_PACKAGE_TARGET_RECEIPT}"
printf '%s\n' \
  "profile_id=${EVALUATION_PROFILE_ID}" \
  "profile_sha256=${EVALUATION_PROFILE_SHA256}" \
  'profile_binding_role=package-target-policy' \
  "package_target_kind=${EVALUATION_TARGET_KIND}" \
  "architecture=${EVALUATION_ARCHITECTURE}" \
  "verification_host_architecture=${EVALUATION_ARCHITECTURE}" \
  'verification_host_profile_match=not-established' \
  'native_hardware_claim=not-established' \
  'physical_target_evidence=false' \
  "evidence_namespace=${EVALUATION_EVIDENCE_NAMESPACE}" \
  'needed_evidence=native-aarch64-package-regression' \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false' >"${EXPECTED_PACKAGE_TARGET_RECEIPT}"
/usr/bin/cmp -s -- "${EXPECTED_PACKAGE_TARGET_RECEIPT}" \
  "${OLD_PACKAGE_TARGET_RECEIPT}" ||
  fail 'old package verifier receipt is missing, duplicated, reordered, or cross-profile'
/usr/bin/cmp -s -- "${EXPECTED_PACKAGE_TARGET_RECEIPT}" \
  "${NEW_PACKAGE_TARGET_RECEIPT}" ||
  fail 'new package verifier receipt is missing, duplicated, reordered, or cross-profile'
/usr/bin/cmp -s -- "${OLD_PACKAGE_TARGET_RECEIPT}" \
  "${NEW_PACKAGE_TARGET_RECEIPT}" ||
  fail 'old and new package verifier receipts bind different target profiles'

read_package_version() {
  local package="$1"
  local output="$2"
  local -a versions=()
  local size
  /usr/bin/bsdtar -xOf "${package}" .PKGINFO >"${output}" ||
    fail 'verified package metadata could not be read'
  size="$(/usr/bin/stat -c '%s' -- "${output}")"
  if [[ ! "${size}" =~ ^[1-9][0-9]*$ ]] || (( size > 65536 )); then
    fail 'verified package metadata is outside the closed byte bound'
  fi
  if /usr/bin/grep -Eq '^(backup|install) = ' "${output}"; then
    fail 'verified package unexpectedly declares backup files or an install script'
  fi
  mapfile -t versions < <(/usr/bin/sed -n 's/^pkgver = //p' "${output}")
  (( ${#versions[@]} == 1 )) || fail 'package has ambiguous version metadata'
  printf '%s\n' "${versions[0]}"
}
readonly OLD_PKGINFO="${TEMPORARY_ROOT}/old.PKGINFO"
readonly NEW_PKGINFO="${TEMPORARY_ROOT}/new.PKGINFO"
[[ "$(read_package_version "${OLD_PACKAGE_SNAPSHOT}" "${OLD_PKGINFO}")" == \
  "${OLD_PACKAGE_VERSION}" ]] || fail 'old package query disagrees with verified package metadata'
[[ "$(read_package_version "${NEW_PACKAGE_SNAPSHOT}" "${NEW_PKGINFO}")" == \
  "${NEW_PACKAGE_VERSION}" ]] || fail 'new package query disagrees with verified package metadata'

mapfile -t OLD_DEPENDENCIES < <(/usr/bin/sed -n 's/^depend = //p' "${OLD_PKGINFO}")
mapfile -t NEW_DEPENDENCIES < <(/usr/bin/sed -n 's/^depend = //p' "${NEW_PKGINFO}")
readonly OLD_DEPENDENCIES NEW_DEPENDENCIES
(( ${#OLD_DEPENDENCIES[@]} > 0 && ${#NEW_DEPENDENCIES[@]} > 0 )) ||
  fail 'verified packages contain no declared dependency set'
/usr/bin/pacman -T -- "${OLD_DEPENDENCIES[@]}" >/dev/null ||
  fail 'an old-package dependency is not already satisfied locally'
/usr/bin/pacman -T -- "${NEW_DEPENDENCIES[@]}" >/dev/null ||
  fail 'a new-package dependency is not already satisfied locally'

write_effective_pacman_config() {
  local output="$1"
  /usr/bin/pacman-conf >"${output}" || fail 'effective pacman configuration could not be read'
  local size
  size="$(/usr/bin/stat -c '%s' -- "${output}")"
  if [[ ! "${size}" =~ ^[1-9][0-9]*$ ]] || (( size > 1048576 )); then
    fail 'effective pacman configuration is outside the closed byte bound'
  fi
}

declare -a PACMAN_INCLUDE_FILES=()
while IFS= read -r pacman_config_line; do
  pacman_config_line="${pacman_config_line#"${pacman_config_line%%[![:space:]]*}"}"
  [[ "${pacman_config_line}" == Include* ]] || continue
  [[ "${pacman_config_line}" =~ ^Include[[:space:]]*=[[:space:]]*([^[:space:]#]+)[[:space:]]*(#.*)?$ ]] ||
    fail 'target pacman configuration has an unsupported Include directive'
  pacman_include_file="${BASH_REMATCH[1]}"
  [[ "${pacman_include_file}" =~ ^/etc/pacman\.d/[A-Za-z0-9._/-]+$ && \
    "${pacman_include_file}" != *'/../'* && \
    "${pacman_include_file}" != *'/./'* && \
    "${pacman_include_file}" != *'//' ]] ||
    fail 'target pacman Include is not one normalized file below /etc/pacman.d'
  if [[ " ${PACMAN_INCLUDE_FILES[*]} " != *" ${pacman_include_file} "* ]]; then
    PACMAN_INCLUDE_FILES+=("${pacman_include_file}")
  fi
done </etc/pacman.conf
readonly PACMAN_INCLUDE_FILES
(( ${#PACMAN_INCLUDE_FILES[@]} > 0 && ${#PACMAN_INCLUDE_FILES[@]} <= 32 )) ||
  fail 'target pacman Include set is empty or outside the closed count bound'
for pacman_include_file in "${PACMAN_INCLUDE_FILES[@]}"; do
  require_real_regular_file "${pacman_include_file}" 'target pacman Include'
  require_safe_root_chain "${pacman_include_file}" 'target pacman Include'
  if /usr/bin/grep -Eq '^[[:space:]]*Include[[:space:]]*=' "${pacman_include_file}"; then
    fail 'nested target pacman Include directives are unsupported'
  fi
done

write_hook_inventory() {
  local output="$1"
  local hook_directory
  local hook_path
  local count=0
  local total_bytes=0
  local size
  : >"${output}"
  for hook_directory in "${EFFECTIVE_HOOK_DIRECTORIES[@]}"; do
    if [[ ! -e "${hook_directory}" && ! -L "${hook_directory}" ]]; then
      require_safe_root_chain "${hook_directory%/*}" \
        'absent effective pacman hook directory parent'
      printf 'absent\0%s\0' "${hook_directory}" >>"${output}"
      continue
    fi
    [[ -d "${hook_directory}" && ! -L "${hook_directory}" ]] ||
      fail "effective pacman hook path is not a real directory: ${hook_directory}"
    require_safe_root_chain "${hook_directory}" 'effective pacman hook directory'
    while IFS= read -r -d '' hook_path; do
      require_real_regular_file "${hook_path}" 'effective pacman hook'
      require_safe_root_chain "${hook_path}" 'effective pacman hook'
      size="$(/usr/bin/stat -c '%s' -- "${hook_path}")"
      [[ "${size}" =~ ^[0-9]+$ ]] || fail 'effective pacman hook has an invalid size'
      ((count += 1, total_bytes += size))
      (( count <= 256 && total_bytes <= 8388608 )) ||
        fail 'effective pacman hook inventory exceeds the closed bound'
      printf 'file\0%s\0%s\0%s\0' \
        "${hook_path}" \
        "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' -- "${hook_path}")" \
        "$(sha256_file "${hook_path}")" >>"${output}"
    done < <(/usr/bin/find "${hook_directory}" -xdev -mindepth 1 -maxdepth 1 \
      -print0 | /usr/bin/sort -z)
  done
  (( count > 0 )) || fail 'effective pacman hook inventory is empty'
}

require_real_regular_file /etc/pacman.conf 'target pacman configuration'
require_safe_root_chain /etc/pacman.conf 'target pacman configuration'
mapfile -t CONFIGURED_HOOK_DIRECTORIES < <(/usr/bin/pacman-conf HookDir)
(( ${#CONFIGURED_HOOK_DIRECTORIES[@]} > 0 && \
  ${#CONFIGURED_HOOK_DIRECTORIES[@]} <= 16 )) ||
  fail 'effective pacman HookDir set is empty or outside the closed count bound'
declare -a EFFECTIVE_HOOK_DIRECTORIES=(/usr/share/libalpm/hooks)
for configured_hook_directory in "${CONFIGURED_HOOK_DIRECTORIES[@]}"; do
  configured_hook_directory="${configured_hook_directory%/}"
  [[ "${configured_hook_directory}" =~ ^/[A-Za-z0-9._/-]+$ && \
    "${configured_hook_directory}" != *'/../'* && \
    "${configured_hook_directory}" != *'/./'* && \
    "${configured_hook_directory}" != *'//' ]] ||
    fail 'effective pacman HookDir is not one normalized absolute path'
  if [[ " ${EFFECTIVE_HOOK_DIRECTORIES[*]} " != *" ${configured_hook_directory} "* ]]; then
    EFFECTIVE_HOOK_DIRECTORIES+=("${configured_hook_directory}")
  fi
done
readonly CONFIGURED_HOOK_DIRECTORIES EFFECTIVE_HOOK_DIRECTORIES
mapfile -t PACMAN_REPOSITORIES < <(/usr/bin/pacman-conf --repo-list)
readonly PACMAN_REPOSITORIES
readonly PACMAN_REPOSITORY_COUNT="${#PACMAN_REPOSITORIES[@]}"
(( PACMAN_REPOSITORY_COUNT > 0 && PACMAN_REPOSITORY_COUNT <= 64 )) ||
  fail 'configured pacman repository count is empty or outside the closed bound'
readonly PACMAN_EFFECTIVE_CONFIG="${TEMPORARY_ROOT}/pacman-effective.conf"
readonly PACMAN_HOOK_INVENTORY="${TEMPORARY_ROOT}/pacman-hooks.inventory"
write_effective_pacman_config "${PACMAN_EFFECTIVE_CONFIG}"
write_hook_inventory "${PACMAN_HOOK_INVENTORY}"
PACMAN_EFFECTIVE_CONFIG_SHA256="$(sha256_file "${PACMAN_EFFECTIVE_CONFIG}")"
PACMAN_HOOK_INVENTORY_SHA256="$(sha256_file "${PACMAN_HOOK_INVENTORY}")"
PACMAN_VERSION="$(/usr/bin/pacman --version | /usr/bin/sed -n \
  's/.*Pacman v\([^ ]*\).*/\1/p' | /usr/bin/head -n 1)"
readonly PACMAN_EFFECTIVE_CONFIG_SHA256 PACMAN_HOOK_INVENTORY_SHA256 PACMAN_VERSION
[[ -n "${PACMAN_VERSION}" ]] || fail 'target pacman version could not be identified'

assert_static_inputs() {
  local stage="$1"
  local current_status
  local rechecked_config="${TEMPORARY_ROOT}/pacman-effective.recheck"
  local rechecked_hooks="${TEMPORARY_ROOT}/pacman-hooks.recheck"
  assert_joined_inputs "${stage}"
  [[ "$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")" == \
      "${EXECUTING_BRIDGE_PATH}" && \
    "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s:%Y:%Z' -- \
      "${EXECUTING_BRIDGE_PATH}")" == "${EXECUTING_BRIDGE_IDENTITY}" && \
    "$(sha256_file "${EXECUTING_BRIDGE_PATH}")" == \
      "${COMMITTED_BRIDGE_SHA256}" ]] ||
    fail "executing package lifecycle bridge changed ${stage}"
  [[ "$(sha256_file "${OLD_PACKAGE_SNAPSHOT}")" == "${OLD_PACKAGE_EXPECTED_SHA256}" && \
    "$(sha256_file "${NEW_PACKAGE_SNAPSHOT}")" == "${NEW_PACKAGE_EXPECTED_SHA256}" && \
    "$(sha256_file "${COMMITTED_VERIFIER}")" == "${COMMITTED_VERIFIER_SHA256}" && \
    "$(sha256_file "${COMMITTED_CONSENT_EVALUATOR}")" == \
      "${COMMITTED_CONSENT_EVALUATOR_SHA256}" && \
    "$(sha256_file "${COMMITTED_CORE_EVALUATOR}")" == \
      "${COMMITTED_CORE_EVALUATOR_SHA256}" ]] || fail "private inputs changed ${stage}"
  [[ "$(/usr/bin/git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)" == \
    "${SOURCE_HEAD}" ]] || fail "source checkout HEAD changed ${stage}"
  current_status="$({
    /usr/bin/git -C "${REPOSITORY_ROOT}" -c core.fsmonitor=false \
      status --porcelain=v1 --untracked-files=normal
  })" || fail "source checkout cleanliness could not be reinspected ${stage}"
  [[ -z "${current_status}" ]] || fail "source checkout changed ${stage}"
  [[ "$(/usr/bin/pacman -Q -- "${EXPECTED_OMARCHY_PACKAGE}")" == \
    "${EXPECTED_OMARCHY_QUERY}" ]] || fail "pinned Omarchy package changed ${stage}"
  [[ "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s:%Y:%Z' -- \
      "${PACMAN_BINARY}")" == "${PACMAN_BINARY_IDENTITY}" && \
    "$(sha256_file "${PACMAN_BINARY}")" == "${PACMAN_BINARY_SHA256}" && \
    "$(/usr/bin/pacman -Qoq -- "${PACMAN_BINARY}")" == pacman && \
    "$(/usr/bin/pacman -Q pacman)" == "${PACMAN_PACKAGE_QUERY}" ]] ||
    fail "Pacman binary or package identity changed ${stage}"
  /usr/bin/pacman -Qkk pacman >/dev/null ||
    fail "Pacman package integrity changed ${stage}"
  [[ "$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%F' -- "/proc/self/fd/9")" == \
      "${BRIDGE_LOCK_IDENTITY}" && \
    "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F' -- "${BRIDGE_LOCK}")" == \
      "${BRIDGE_LOCK_IDENTITY}" ]] || fail "bridge lock identity changed ${stage}"
  write_effective_pacman_config "${rechecked_config}"
  write_hook_inventory "${rechecked_hooks}"
  [[ "$(sha256_file "${rechecked_config}")" == \
      "${PACMAN_EFFECTIVE_CONFIG_SHA256}" && \
    "$(sha256_file "${rechecked_hooks}")" == \
      "${PACMAN_HOOK_INVENTORY_SHA256}" ]] ||
    fail "effective pacman configuration or hook inventory changed ${stage}"
  [[ ! -e "${PACMAN_LOCK}" && ! -L "${PACMAN_LOCK}" ]] ||
    fail "pacman database lock appeared ${stage}"
}
assert_static_inputs 'before any package or user-state mutation'

MUTATION_STARTED=true
CURRENT_STAGE=seed-package-independent-user-state
for evaluator_state_parent in \
  "${EVALUATOR_HOME}/.local" "${EVALUATOR_HOME}/.local/share" "${EVIDENCE_ROOT}"; do
  if [[ ! -e "${evaluator_state_parent}" && ! -L "${evaluator_state_parent}" ]]; then
    /usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- \
      /usr/bin/env -i HOME="${EVALUATOR_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
        /usr/bin/install -d -m 0700 -- "${evaluator_state_parent}"
  fi
  require_safe_evaluator_directory "${evaluator_state_parent}"
done
/usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- \
  /usr/bin/env -i HOME="${EVALUATOR_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/install -d -m 0700 -- "${CONSENT_HANDOFF_ROOT}"
require_safe_evaluator_directory "${CONSENT_HANDOFF_ROOT}"
if /usr/bin/find "${CONSENT_HANDOFF_ROOT}" -xdev -mindepth 1 -print -quit |
  /usr/bin/grep -q .; then
  fail 'trusted-consent handoff root is not empty before package installation'
fi
printf '%s\n' 'package lifecycle preservation sentinel' | \
  /usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- \
    /usr/bin/env -i HOME="${EVALUATOR_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
      /usr/bin/dd of="${EVIDENCE_SENTINEL}" bs=40 count=1 \
        iflag=fullblock oflag=excl,nofollow status=none
EVIDENCE_SENTINEL_SHA256="$(sha256_file "${EVIDENCE_SENTINEL}")"
EVIDENCE_SENTINEL_STAT="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s' -- "${EVIDENCE_SENTINEL}")"
readonly EVIDENCE_SENTINEL_SHA256 EVIDENCE_SENTINEL_STAT
[[ "${EVIDENCE_SENTINEL_STAT}" == \
  *":${EVALUATOR_UID}:${EVALUATOR_GID}:600:1:regular file:40" ]] ||
  fail 'package lifecycle preservation sentinel has unsafe metadata'

run_pacman_transaction() {
  /usr/bin/env -i HOME=/root LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/unshare --net -- /usr/bin/pacman --noconfirm "$@"
}

assert_preservation_sentinel() {
  local stage="$1"
  [[ "$(sha256_file "${EVIDENCE_SENTINEL}")" == "${EVIDENCE_SENTINEL_SHA256}" && \
    "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%F:%s' -- "${EVIDENCE_SENTINEL}")" == \
      "${EVIDENCE_SENTINEL_STAT}" ]] || fail "seeded user state changed ${stage}"
}

readonly EXPECTED_FILE_INVENTORY="${TEMPORARY_ROOT}/expected-files"
printf '%s\n' \
  usr/bin/a-quo usr/bin/a-quo-daemon usr/lib/a-quo/a-quo-consent \
  usr/lib/systemd/user/a-quo-daemon.service \
  usr/lib/systemd/user-preset/90-a-quo.preset \
  usr/share/a-quo/provider-registry-v1.json \
  usr/share/doc/a-quo/PACKAGING.md usr/share/doc/a-quo/README.md \
  usr/share/doc/a-quo/SECURITY.md usr/share/doc/a-quo/THREAT-MODEL.md \
  usr/share/licenses/a-quo/LICENSE | /usr/bin/sort >"${EXPECTED_FILE_INVENTORY}"

readonly EXPECTED_PACKAGE_INVENTORY="${TEMPORARY_ROOT}/expected-package-inventory"
printf '%s\n' \
  usr usr/bin usr/bin/a-quo usr/bin/a-quo-daemon \
  usr/lib usr/lib/a-quo usr/lib/a-quo/a-quo-consent \
  usr/lib/systemd usr/lib/systemd/user \
  usr/lib/systemd/user/a-quo-daemon.service \
  usr/lib/systemd/user-preset \
  usr/lib/systemd/user-preset/90-a-quo.preset \
  usr/share usr/share/a-quo usr/share/a-quo/provider-registry-v1.json \
  usr/share/doc usr/share/doc/a-quo usr/share/doc/a-quo/PACKAGING.md \
  usr/share/doc/a-quo/README.md usr/share/doc/a-quo/SECURITY.md \
  usr/share/doc/a-quo/THREAT-MODEL.md usr/share/licenses \
  usr/share/licenses/a-quo usr/share/licenses/a-quo/LICENSE | \
  /usr/bin/sort >"${EXPECTED_PACKAGE_INVENTORY}"

run_evaluator_systemctl() {
  /usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- \
    /usr/bin/env -i HOME="${EVALUATOR_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
      XDG_RUNTIME_DIR="${EVALUATOR_RUNTIME_DIRECTORY}" \
      /usr/bin/systemctl --user --no-pager "$@"
}

run_global_systemctl() {
  /usr/bin/env -i HOME=/root LC_ALL=C PATH=/usr/bin:/bin \
    /usr/bin/systemctl --global --no-pager "$@"
}

assert_no_enablement_or_process() {
  local expected_unit_state="$1"
  local active_output
  local active_status
  local enabled_output
  local enabled_status
  local global_output
  local global_status
  local expected_active_status
  local expected_enabled_output
  local expected_enabled_status
  assert_no_daemon_process
  for enablement_root in \
    /etc/systemd/user /run/systemd/user \
    "${EVALUATOR_HOME}/.config/systemd/user" \
    "${EVALUATOR_RUNTIME_DIRECTORY}/systemd/user"; do
    if [[ -d "${enablement_root}" && -n "$(
      /usr/bin/find "${enablement_root}" -xdev -type l \
        -name a-quo-daemon.service -print -quit
    )" ]]; then
      fail 'package lifecycle created or retained A Quo service enablement'
    fi
  done
  set +e
  active_output="$(run_evaluator_systemctl is-active a-quo-daemon.service 2>&1)"
  active_status="$?"
  enabled_output="$(run_evaluator_systemctl is-enabled a-quo-daemon.service 2>&1)"
  enabled_status="$?"
  global_output="$(run_global_systemctl is-enabled a-quo-daemon.service 2>&1)"
  global_status="$?"
  set -e
  case "${expected_unit_state}" in
    installed)
      expected_active_status=3
      expected_enabled_status=1
      expected_enabled_output=disabled
      ;;
    absent)
      expected_active_status=4
      expected_enabled_status=4
      expected_enabled_output=not-found
      ;;
    *) fail 'unknown expected user-unit state' ;;
  esac
  [[ "${active_status}" -eq "${expected_active_status}" && \
    "${active_output}" == inactive && \
    "${enabled_status}" -eq "${expected_enabled_status}" && \
    "${enabled_output}" == "${expected_enabled_output}" && \
    "${global_status}" -eq "${expected_enabled_status}" && \
    "${global_output}" == "${expected_enabled_output}" ]] ||
    fail "A Quo evaluator service boundary differs: expected=${expected_unit_state} active=${active_status} enabled=${enabled_status} global=${global_status}"
}

assert_service_disabled() {
  assert_no_enablement_or_process installed
}

assert_absent_transition_boundary() {
  local stage="$1"
  assert_a_quo_package_absent "${stage}"
  assert_no_enablement_or_process absent
  [[ ! -e "${PACMAN_LOCK}" && ! -L "${PACMAN_LOCK}" ]] ||
    fail "Pacman database lock exists ${stage}"
}

assert_installed_transition_boundary() {
  local expected_query="$1"
  local stage="$2"
  [[ "$(/usr/bin/pacman -Q a-quo)" == "${expected_query}" ]] ||
    fail "installed A Quo package changed ${stage}"
  /usr/bin/pacman -Qkk a-quo >/dev/null ||
    fail "installed A Quo package integrity changed ${stage}"
  assert_service_disabled
  [[ ! -e "${PACMAN_LOCK}" && ! -L "${PACMAN_LOCK}" ]] ||
    fail "Pacman database lock exists ${stage}"
}

assert_installed_package() {
  local expected_query="$1"
  local package_snapshot="$2"
  local stage="$3"
  local dependency_set="$4"
  local extracted="${TEMPORARY_ROOT}/extracted-${stage}"
  local observed_inventory="${TEMPORARY_ROOT}/registered-${stage}"
  local relative
  local mode
  [[ "$(/usr/bin/pacman -Q a-quo)" == "${expected_query}" ]] ||
    fail "installed package query differs ${stage}"
  /usr/bin/pacman -Qkk a-quo >/dev/null || fail "pacman integrity check failed ${stage}"
  /usr/bin/pacman -Qlq a-quo | \
    /usr/bin/sed 's|^/||; s|/$||' | /usr/bin/sort -u >"${observed_inventory}"
  /usr/bin/cmp -s -- "${EXPECTED_PACKAGE_INVENTORY}" "${observed_inventory}" ||
    fail "registered package inventory differs ${stage}"
  /usr/bin/mkdir -m 0700 -- "${extracted}"
  /usr/bin/bsdtar --no-same-owner -xf "${package_snapshot}" -C "${extracted}"
  while IFS= read -r relative; do
    [[ "$(/usr/bin/pacman -Qoq -- "/${relative}")" == a-quo ]] ||
      fail "installed file is not package-owned ${stage}: ${relative}"
    [[ -f "/${relative}" && ! -L "/${relative}" ]] ||
      fail "installed file is missing or unsafe ${stage}: ${relative}"
    /usr/bin/cmp -s -- "${extracted}/${relative}" "/${relative}" ||
      fail "installed file bytes differ ${stage}: ${relative}"
    mode=644
    case "${relative}" in
      usr/bin/a-quo|usr/bin/a-quo-daemon|usr/lib/a-quo/a-quo-consent) mode=755 ;;
    esac
    [[ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "/${relative}")" == \
      "0:0:${mode}:regular file" ]] || fail "installed metadata differs ${stage}: ${relative}"
  done <"${EXPECTED_FILE_INVENTORY}"
  case "${dependency_set}" in
    old) /usr/bin/pacman -T -- "${OLD_DEPENDENCIES[@]}" >/dev/null ;;
    new) /usr/bin/pacman -T -- "${NEW_DEPENDENCIES[@]}" >/dev/null ;;
    *) fail "unknown dependency set during ${stage}" ;;
  esac || fail "declared dependencies are not satisfied ${stage}"
  [[ "$(< /usr/share/a-quo/provider-registry-v1.json)" == \
    '{"providers":[],"schema":"urn:a-quo:omarchy-plugin-risk-provider-registry:v1"}' ]] ||
    fail "optional reviewer registry is not empty ${stage}"
  assert_service_disabled
  assert_preservation_sentinel "${stage}"
}

assert_consent_to_core_binding() {
  local consent_evidence="$1"
  local core_evidence="$2"
  local proof_v1_sha256
  local proof_v2_sha256
  local manifest_sha256
  local store_sha256

  /usr/bin/jq -e -n \
    --arg expected_v1_sha256 "${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" \
    --arg expected_v2_sha256 "${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}" \
    --arg profile_id "${EVALUATION_PROFILE_ID}" \
    --arg profile_sha256 "${EVALUATION_PROFILE_SHA256}" \
    --arg target_kind "${EVALUATION_TARGET_KIND}" \
    --arg architecture "${EVALUATION_ARCHITECTURE}" \
    --arg evidence_namespace "${EVALUATION_EVIDENCE_NAMESPACE}" \
    --slurpfile consent "${consent_evidence}" \
    --slurpfile core "${core_evidence}" '
      ($consent | length) == 1 and
      ($core | length) == 1 and
      $consent[0] as $c |
      $core[0] as $k |
      $c.target_profile == $k.target_profile and
      $c.target_profile == {
        profile_id: $profile_id,
        profile_sha256: $profile_sha256,
        binding_role: "package-target-policy",
        target_kind: $target_kind,
        architecture: $architecture,
        evidence_namespace: $evidence_namespace,
        cross_profile_evidence_accepted: false,
        aarch64_gate_satisfied_by_x86_64: false
      } and
      $c.consent.artifact_v1_sha256 == $expected_v1_sha256 and
      $c.consent.artifact_v2_sha256 == $expected_v2_sha256 and
      $k.subject.v1.package_sha256 == $expected_v1_sha256 and
      $k.subject.v2.package_sha256 == $expected_v2_sha256 and
      $c.handoff.proof_v1_sha256 == $k.subject.v1.proof_sha256 and
      $c.handoff.proof_v2_sha256 == $k.subject.v2.proof_sha256 and
      $c.handoff.proof_v1_sha256 != $c.handoff.proof_v2_sha256 and
      $c.handoff.manifest_sha256 == $k.preconsented_handoff.manifest_sha256 and
      $c.handoff.persona_id == $k.preconsented_handoff.persona_id and
      $c.handoff.key_fingerprint == $k.preconsented_handoff.key_fingerprint and
      $c.handoff.persona_store_path == $k.preconsented_handoff.persona_store_path and
      $c.handoff.persona_store_sha256 == $k.preconsented_handoff.persona_store_sha256 and
      $c.handoff.root == $k.retained_state.handoff_root and
      $c.handoff.persona_store_path == $k.retained_state.persona_store and
      $k.preconsented_handoff.exact_packages_and_proofs_binding == "verified" and
      $k.preconsented_handoff.reported_consent_v1 ==
        "operator-approved-installed-daemon" and
      $k.preconsented_handoff.reported_consent_v2 ==
        "operator-approved-installed-daemon" and
      $c.evaluator.input_origin ==
        $k.preconsented_handoff.operator_input_origin and
      $k.preconsented_handoff.secure_attention == "not_established" and
      $k.trusted_consent == "not_established_by_core_alone" and
      $k.reported_signing_consent ==
        "operator_approved_installed_daemon_proofs_consumed" and
      $k.installation_trusted_consent ==
        "not_established_cli_acknowledgements_only" and
      $k.preconsented_handoff.handoff_origin_authentication ==
        "not_established_same_uid_directory"
    ' >/dev/null || fail 'consent and core evidence do not bind the same exact handoff'

  proof_v1_sha256="$(/usr/bin/jq -er '.handoff.proof_v1_sha256' "${consent_evidence}")"
  proof_v2_sha256="$(/usr/bin/jq -er '.handoff.proof_v2_sha256' "${consent_evidence}")"
  manifest_sha256="$(/usr/bin/jq -er '.handoff.manifest_sha256' "${consent_evidence}")"
  store_sha256="$(/usr/bin/jq -er '.handoff.persona_store_sha256' "${consent_evidence}")"
  [[ "${proof_v1_sha256}" =~ ^[0-9a-f]{64}$ && \
    "${proof_v2_sha256}" =~ ^[0-9a-f]{64}$ && \
    "${proof_v1_sha256}" != "${proof_v2_sha256}" && \
    "${manifest_sha256}" =~ ^[0-9a-f]{64}$ && \
    "${store_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'consent-to-core evidence contains a malformed retained-state digest'
  [[ "$({
      /usr/bin/find "${CONSENT_HANDOFF_ROOT}" -xdev -mindepth 1 -maxdepth 1 \
        -printf '%f\n' | /usr/bin/sort
    })" == $'handoff.manifest\nproof-v1.json\nproof-v2.json' ]] ||
    fail 'live consent handoff inventory changed before outer binding'
  [[ "$({
      /usr/bin/stat -c '%u:%g %a %h %F' -- \
        "${CONSENT_HANDOFF_ROOT}/proof-v1.json"
    })" == "${EVALUATOR_UID}:${EVALUATOR_GID} 600 1 regular file" && \
    "$({
      /usr/bin/stat -c '%u:%g %a %h %F' -- \
        "${CONSENT_HANDOFF_ROOT}/proof-v2.json"
    })" == "${EVALUATOR_UID}:${EVALUATOR_GID} 600 1 regular file" && \
    "$({
      /usr/bin/stat -c '%u:%g %a %h %F' -- \
        "${CONSENT_HANDOFF_ROOT}/handoff.manifest"
    })" == "${EVALUATOR_UID}:${EVALUATOR_GID} 600 1 regular file" && \
    "$({
      /usr/bin/stat -c '%u:%g %a %h %F' -- "${PERSONA_STATE_ROOT}/personas.sqlite3"
    })" == "${EVALUATOR_UID}:${EVALUATOR_GID} 600 1 regular file" ]] ||
    fail 'live consent-to-core binding files have unsafe metadata'
  [[ "$(sha256_file "${CONSENT_HANDOFF_ROOT}/proof-v1.json")" == \
      "${proof_v1_sha256}" && \
    "$(sha256_file "${CONSENT_HANDOFF_ROOT}/proof-v2.json")" == \
      "${proof_v2_sha256}" && \
    "$(sha256_file "${CONSENT_HANDOFF_ROOT}/handoff.manifest")" == "${manifest_sha256}" && \
    "$(sha256_file "${PERSONA_STATE_ROOT}/personas.sqlite3")" == "${store_sha256}" ]] ||
    fail 'live consent-to-core handoff differs from the root-captured consent evidence'
}

CURRENT_STAGE=install-old
assert_static_inputs 'immediately before old-package installation'
assert_absent_transition_boundary 'immediately before old-package installation'
run_pacman_transaction -U -- "${OLD_PACKAGE_SNAPSHOT}"
assert_installed_package "${OLD_PACKAGE_QUERY}" "${OLD_PACKAGE_SNAPSHOT}" old-install old

CURRENT_STAGE=upgrade-new
assert_static_inputs 'immediately before new-package upgrade'
assert_installed_transition_boundary "${OLD_PACKAGE_QUERY}" \
  'immediately before new-package upgrade'
run_pacman_transaction -U -- "${NEW_PACKAGE_SNAPSHOT}"
assert_installed_package "${NEW_PACKAGE_QUERY}" "${NEW_PACKAGE_SNAPSHOT}" new-upgrade new
[[ ! -e "${PERSONA_STATE_ROOT}" && ! -L "${PERSONA_STATE_ROOT}" ]] ||
  fail 'package transactions created the installed-core persona root'

CURRENT_STAGE=installed-trusted-consent-v1-v2
readonly CONSENT_EVIDENCE="${TEMPORARY_ROOT}/installed-consent-evidence.json"
/usr/bin/env -i \
  PATH=/usr/bin:/bin \
  A_QUO_INSTALLED_CONSENT_LIFECYCLE_ACKNOWLEDGEMENT=I-understand-this-runs-real-a-quo-consent-on-the-disposable-evaluator-account \
  A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT="${CONSENT_HANDOFF_ROOT}" \
  A_QUO_EXPECTED_A_QUO_PACKAGE_QUERY="${NEW_PACKAGE_QUERY}" \
  A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY="${EXPECTED_OMARCHY_QUERY}" \
  A_QUO_EVALUATION_PROFILE_ID="${EVALUATION_PROFILE_ID}" \
  A_QUO_EVALUATION_PROFILE_SHA256="${EVALUATION_PROFILE_SHA256}" \
  A_QUO_EVALUATION_TARGET_KIND="${EVALUATION_TARGET_KIND}" \
  A_QUO_EVALUATION_ARCHITECTURE="${EVALUATION_ARCHITECTURE}" \
  A_QUO_EVALUATION_EVIDENCE_NAMESPACE="${EVALUATION_EVIDENCE_NAMESPACE}" \
  A_QUO_EVALUATOR_WAYLAND_DISPLAY="${A_QUO_EVALUATOR_WAYLAND_DISPLAY}" \
  A_QUO_EVALUATOR_SIGNING_ARTIFACT="${A_QUO_EVALUATOR_PACKAGE_V1}" \
  A_QUO_EVALUATOR_SIGNING_ARTIFACT_SHA256="${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" \
  A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2="${A_QUO_EVALUATOR_PACKAGE_V2}" \
  A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256="${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}" \
  /usr/bin/unshare --net -- "${COMMITTED_CONSENT_EVALUATOR}" >"${CONSENT_EVIDENCE}"
/usr/bin/jq -s -e --arg expected_query "${NEW_PACKAGE_QUERY}" \
  --arg artifact_v1_sha256 "${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" \
  --arg artifact_v2_sha256 "${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}" \
  --arg profile_id "${EVALUATION_PROFILE_ID}" \
  --arg profile_sha256 "${EVALUATION_PROFILE_SHA256}" \
  --arg target_kind "${EVALUATION_TARGET_KIND}" \
  --arg architecture "${EVALUATION_ARCHITECTURE}" \
  --arg evidence_namespace "${EVALUATION_EVIDENCE_NAMESPACE}" '
  length == 1 and
  (.[0] |
    .schema == "urn:a-quo:evidence:installed-consent-lifecycle:v2" and
    .result == "passed" and
    .installed_software.a_quo_package_query == $expected_query and
    .target_profile == {
      profile_id: $profile_id,
      profile_sha256: $profile_sha256,
      binding_role: "package-target-policy",
      target_kind: $target_kind,
      architecture: $architecture,
      evidence_namespace: $evidence_namespace,
      cross_profile_evidence_accepted: false,
      aarch64_gate_satisfied_by_x86_64: false
    } and
    .evaluator.operator_interaction ==
      "required_decline_v1_then_approval_v1_then_approval_v2_no_harness_automation" and
    .consent.decline_v1 == "no_proof_returned" and
    .consent.approval_v1 == "proof_returned_and_verified" and
    .consent.approval_v2 == "proof_returned_and_verified" and
    .consent.artifact_v1_sha256 == $artifact_v1_sha256 and
    .consent.artifact_v2_sha256 == $artifact_v2_sha256 and
    .consent.altered_bytes_v1 == "verification_refused" and
    .consent.altered_bytes_v2 == "verification_refused" and
    .handoff.format == "a-quo-installed-omarchy-preconsented-handoff-v2" and
    (.handoff.proof_v1_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.handoff.proof_v2_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    .handoff.proof_v1_sha256 != .handoff.proof_v2_sha256 and
    (.handoff.manifest_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    .handoff.persona_store_path ==
      "/home/a-quo-evaluator/.local/share/a-quo/personas.sqlite3" and
    (.handoff.persona_store_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    .handoff.persona_store ==
      "retained_public_state_signing_locator_removed_original_disposable_key_paths_removed" and
    .handoff.same_uid_private_key_copy_or_access_excluded == false and
    .handoff.next_evaluator == "not_run_by_this_evaluator" and
    .evaluator.input_origin == "not_machine_verifiable" and
    .behavioral_analysis == "not_run" and
    .omarchy_plugin_lifecycle == "not_run" and
    .plugin_safety == "not_established" and
    .clean_system_claim == "not_established_marker_only")
' "${CONSENT_EVIDENCE}" >/dev/null ||
  fail 'installed-consent evaluator returned invalid or overstated evidence'
[[ -d "${CONSENT_HANDOFF_ROOT}" && ! -L "${CONSENT_HANDOFF_ROOT}" && \
  -f "${CONSENT_HANDOFF_ROOT}/handoff.manifest" && \
  ! -L "${CONSENT_HANDOFF_ROOT}/handoff.manifest" && \
  -f "${CONSENT_HANDOFF_ROOT}/proof-v1.json" && \
  ! -L "${CONSENT_HANDOFF_ROOT}/proof-v1.json" && \
  -f "${CONSENT_HANDOFF_ROOT}/proof-v2.json" && \
  ! -L "${CONSENT_HANDOFF_ROOT}/proof-v2.json" ]] ||
  fail 'installed-consent evaluator did not retain the exact handoff inventory'
[[ -d "${PERSONA_STATE_ROOT}" && ! -L "${PERSONA_STATE_ROOT}" ]] ||
  fail 'installed-consent evaluator did not retain its public persona state'
assert_installed_package "${NEW_PACKAGE_QUERY}" "${NEW_PACKAGE_SNAPSHOT}" \
  post-installed-consent new

CURRENT_STAGE=installed-preconsented-core-v2-lifecycle
readonly CORE_EVIDENCE="${TEMPORARY_ROOT}/installed-core-evidence.json"
/usr/bin/env -i \
  PATH=/usr/bin:/bin \
  A_QUO_INSTALLED_OMARCHY_CORE_LIFECYCLE_ACKNOWLEDGEMENT=I-understand-this-mutates-the-disposable-a-quo-evaluator-account \
  A_QUO_INSTALLED_OMARCHY_PRECONSENTED_HANDOFF_ROOT="${CONSENT_HANDOFF_ROOT}" \
  A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY="${EXPECTED_OMARCHY_QUERY}" \
  A_QUO_EVALUATION_PROFILE_ID="${EVALUATION_PROFILE_ID}" \
  A_QUO_EVALUATION_PROFILE_SHA256="${EVALUATION_PROFILE_SHA256}" \
  A_QUO_EVALUATION_TARGET_KIND="${EVALUATION_TARGET_KIND}" \
  A_QUO_EVALUATION_ARCHITECTURE="${EVALUATION_ARCHITECTURE}" \
  A_QUO_EVALUATION_EVIDENCE_NAMESPACE="${EVALUATION_EVIDENCE_NAMESPACE}" \
  A_QUO_EVALUATOR_WAYLAND_DISPLAY="${A_QUO_EVALUATOR_WAYLAND_DISPLAY}" \
  A_QUO_EVALUATOR_PACKAGE_V1="${A_QUO_EVALUATOR_PACKAGE_V1}" \
  A_QUO_EVALUATOR_PACKAGE_V1_SHA256="${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" \
  A_QUO_EVALUATOR_PACKAGE_V2="${A_QUO_EVALUATOR_PACKAGE_V2}" \
  A_QUO_EVALUATOR_PACKAGE_V2_SHA256="${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}" \
  A_QUO_EVALUATOR_PLUGIN_ID="${A_QUO_EVALUATOR_PLUGIN_ID}" \
  /usr/bin/unshare --net -- "${COMMITTED_CORE_EVALUATOR}" >"${CORE_EVIDENCE}"
/usr/bin/jq -s -e --arg expected_query "${NEW_PACKAGE_QUERY}" \
  --arg expected_v1_sha256 "${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" \
  --arg expected_v2_sha256 "${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}" \
  --arg profile_id "${EVALUATION_PROFILE_ID}" \
  --arg profile_sha256 "${EVALUATION_PROFILE_SHA256}" \
  --arg target_kind "${EVALUATION_TARGET_KIND}" \
  --arg architecture "${EVALUATION_ARCHITECTURE}" \
  --arg evidence_namespace "${EVALUATION_EVIDENCE_NAMESPACE}" '
  length == 1 and
  (.[0] |
    .schema == "urn:a-quo:evidence:installed-omarchy-core-lifecycle:v2" and
    .result == "passed" and
    .mode == "preconsented_joined_v2_lifecycle" and
    .installed_software.a_quo_package_query == $expected_query and
    .target_profile == {
      profile_id: $profile_id,
      profile_sha256: $profile_sha256,
      binding_role: "package-target-policy",
      target_kind: $target_kind,
      architecture: $architecture,
      evidence_namespace: $evidence_namespace,
      cross_profile_evidence_accepted: false,
      aarch64_gate_satisfied_by_x86_64: false
    } and
    .subject.v1.package_sha256 == $expected_v1_sha256 and
    .subject.v2.package_sha256 == $expected_v2_sha256 and
    (.subject.v1.proof_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.subject.v2.proof_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    .subject.v1.proof_sha256 != .subject.v2.proof_sha256 and
    (.subject.v1.managed_tree_sha256_before_update |
      type == "string" and test("^[0-9a-f]{64}$")) and
    (.subject.v2.managed_tree_sha256_before_downgrade_refusal |
      type == "string" and test("^[0-9a-f]{64}$")) and
    (.subject.v2.managed_tree_sha256_before_uninstall |
      type == "string" and test("^[0-9a-f]{64}$")) and
    (.lifecycle.install | type == "object") and
    (.lifecycle.update | type == "object") and
    .lifecycle.inspect_v1 == "passed_exact_v1_package_proof_and_active_local_publisher" and
    .lifecycle.inspect_v2 == "passed_exact_v2_package_proof_and_active_local_publisher" and
    .lifecycle.previous_release_recovery_full_tree_match == true and
    .lifecycle.downgrade_refused == true and
    .lifecycle.downgrade_final_managed_tree_unchanged == true and
    .lifecycle.uninstall_quarantine_full_tree_match == true and
    (.lifecycle.uninstall | type == "object") and
    (.retained_state.install_staging | type == "string" and length > 0) and
    (.retained_state.previous_release_recovery | type == "string" and length > 0) and
    .retained_state.previous_release_recovery_managed_tree_sha256 ==
      .subject.v1.managed_tree_sha256_before_update and
    (.retained_state.uninstall_recovery_quarantine | type == "string" and length > 0) and
    .subject.v2.managed_tree_sha256_before_downgrade_refusal ==
      .subject.v2.managed_tree_sha256_before_uninstall and
    .retained_state.uninstall_recovery_quarantine_managed_tree_sha256 ==
      .subject.v2.managed_tree_sha256_before_uninstall and
    .signing_operations_this_core_invocation == "none" and
    .private_key_access_this_core_invocation == "none" and
    .behavioral_analysis == "not_run" and
    .trusted_consent == "not_established_by_core_alone" and
    .reported_signing_consent == "operator_approved_installed_daemon_proofs_consumed" and
    .installation_trusted_consent == "not_established_cli_acknowledgements_only" and
    .plugin_safety == "not_established" and
    .clean_system_claim == "not_established_marker_only")
' "${CORE_EVIDENCE}" >/dev/null ||
  fail 'installed-core evaluator returned invalid or overstated evidence'
CURRENT_STAGE=validate-consent-to-core-binding
assert_consent_to_core_binding "${CONSENT_EVIDENCE}" "${CORE_EVIDENCE}"
[[ -d "${PERSONA_STATE_ROOT}" && ! -L "${PERSONA_STATE_ROOT}" ]] ||
  fail 'installed-core evaluator did not retain its persona state'
assert_installed_package "${NEW_PACKAGE_QUERY}" "${NEW_PACKAGE_SNAPSHOT}" \
  post-installed-preconsented-core new

retained_state_manifest() {
  local output="$1"
  shift
  : >"${output}"
  local root
  local entry
  local kind
  local size
  local entries_file
  local entries_file_size
  local root_index=0
  local entry_count=0
  local regular_bytes=0
  for root in "$@"; do
    [[ -d "${root}" && ! -L "${root}" ]] || fail "retained state root is unsafe: ${root}"
    entries_file="${output}.entries-${root_index}"
    if ! /usr/bin/find "${root}" -xdev -print0 | /usr/bin/sort -z >"${entries_file}"; then
      fail "retained state enumeration failed: ${root}"
    fi
    entries_file_size="$(/usr/bin/stat -c '%s' -- "${entries_file}")"
    [[ "${entries_file_size}" =~ ^[1-9][0-9]*$ ]] ||
      fail "retained state enumeration is empty: ${root}"
    (( entries_file_size <= 4194304 )) ||
      fail "retained state enumeration exceeds the post-enumeration byte bound: ${root}"
    while IFS= read -r -d '' entry; do
      ((entry_count += 1))
      (( entry_count <= 4096 )) ||
        fail 'retained state exceeds the post-enumeration entry bound'
      if [[ -d "${entry}" && ! -L "${entry}" ]]; then
        kind=directory
      elif [[ -f "${entry}" && ! -L "${entry}" ]]; then
        kind='file'
        size="$(/usr/bin/stat -c '%s' -- "${entry}")"
        [[ "${size}" =~ ^[0-9]+$ ]] || fail "retained file has invalid size: ${entry}"
        ((regular_bytes += size))
        (( size <= 67108864 && regular_bytes <= 536870912 )) ||
          fail 'retained state exceeds the post-enumeration regular-file byte bound'
      else
        fail "retained state contains a link or special entry: ${entry}"
      fi
      printf '%s\0%s\0%s\0' "${entry}" "${kind}" \
        "$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s' -- "${entry}")" >>"${output}"
      if [[ "${kind}" == file ]]; then
        printf '%s\0' "$(sha256_file "${entry}")" >>"${output}"
      fi
    done <"${entries_file}"
    ((root_index += 1))
  done
}

readonly RETAINED_BEFORE_REMOVE="${TEMPORARY_ROOT}/retained-before-remove"
readonly RETAINED_AFTER_REMOVE="${TEMPORARY_ROOT}/retained-after-remove"
readonly RETAINED_AFTER_REINSTALL="${TEMPORARY_ROOT}/retained-after-reinstall"
retained_state_manifest "${RETAINED_BEFORE_REMOVE}" \
  "${EVIDENCE_ROOT}" "${PERSONA_STATE_ROOT}" "${PLUGINS_DIRECTORY}"

CURRENT_STAGE=remove
assert_static_inputs 'immediately before package removal'
assert_installed_transition_boundary "${NEW_PACKAGE_QUERY}" \
  'immediately before package removal'
run_pacman_transaction -R -- a-quo
assert_a_quo_package_absent 'after package removal'
assert_no_enablement_or_process absent
retained_state_manifest "${RETAINED_AFTER_REMOVE}" \
  "${EVIDENCE_ROOT}" "${PERSONA_STATE_ROOT}" "${PLUGINS_DIRECTORY}"
/usr/bin/cmp -s -- "${RETAINED_BEFORE_REMOVE}" "${RETAINED_AFTER_REMOVE}" ||
  fail 'retained user evidence changed during package removal'

CURRENT_STAGE=reinstall-new
assert_static_inputs 'immediately before new-package reinstall'
assert_absent_transition_boundary 'immediately before new-package reinstall'
run_pacman_transaction -U -- "${NEW_PACKAGE_SNAPSHOT}"
assert_installed_package "${NEW_PACKAGE_QUERY}" "${NEW_PACKAGE_SNAPSHOT}" new-reinstall new
retained_state_manifest "${RETAINED_AFTER_REINSTALL}" \
  "${EVIDENCE_ROOT}" "${PERSONA_STATE_ROOT}" "${PLUGINS_DIRECTORY}"
/usr/bin/cmp -s -- "${RETAINED_BEFORE_REMOVE}" "${RETAINED_AFTER_REINSTALL}" ||
  fail 'retained user evidence changed during package reinstall'
assert_static_inputs 'during the complete package lifecycle'

EVIDENCE_JSON="$({
  /usr/bin/jq -n \
    --arg old_query "${OLD_PACKAGE_QUERY}" \
    --arg old_sha256 "${OLD_PACKAGE_EXPECTED_SHA256}" \
    --arg old_commit "${OLD_SOURCE_COMMIT}" \
    --arg new_query "${NEW_PACKAGE_QUERY}" \
    --arg new_sha256 "${NEW_PACKAGE_EXPECTED_SHA256}" \
    --arg new_commit "${NEW_SOURCE_COMMIT}" \
    --arg policy_commit "${SOURCE_HEAD}" \
    --arg policy_bridge_sha256 "${COMMITTED_BRIDGE_SHA256}" \
    --arg joined_input_lock_commit "${JOINED_INPUT_LOCK_COMMIT}" \
    --arg joined_input_lock_sha256 "${JOINED_INPUT_LOCK_SHA256}" \
    --arg joined_policy_commit "${JOINED_POLICY_COMMIT}" \
    --arg profile_id "${EVALUATION_PROFILE_ID}" \
    --arg profile_sha256 "${EVALUATION_PROFILE_SHA256}" \
    --arg target_kind "${EVALUATION_TARGET_KIND}" \
    --arg architecture "${EVALUATION_ARCHITECTURE}" \
    --arg evidence_namespace "${EVALUATION_EVIDENCE_NAMESPACE}" \
    --arg pacman_package_query "${PACMAN_PACKAGE_QUERY}" \
    --arg pacman_version "${PACMAN_VERSION}" \
    --arg pacman_binary_sha256 "${PACMAN_BINARY_SHA256}" \
    --arg pacman_binary_identity "${PACMAN_BINARY_IDENTITY}" \
    --arg pacman_effective_config_sha256 "${PACMAN_EFFECTIVE_CONFIG_SHA256}" \
    --arg pacman_hook_inventory_sha256 "${PACMAN_HOOK_INVENTORY_SHA256}" \
    --argjson pacman_repository_count "${PACMAN_REPOSITORY_COUNT}" \
    --slurpfile consent "${CONSENT_EVIDENCE}" \
    --slurpfile core "${CORE_EVIDENCE}" '
    {
      schema: "urn:a-quo:evidence:installed-package-lifecycle:v2",
      result: "passed",
      target_profile: {
        profile_id: $profile_id,
        profile_sha256: $profile_sha256,
        binding_role: "package-target-policy",
        target_kind: $target_kind,
        architecture: $architecture,
        evidence_namespace: $evidence_namespace,
        old_and_new_verifier_receipts_match: true,
        cross_profile_evidence_accepted: false,
        aarch64_gate_satisfied_by_x86_64: false
      },
      sequence: [
        "install_old",
        "upgrade_new",
        "trusted_signing_consent_for_plugin_v1",
        "trusted_signing_consent_for_plugin_v2",
        "inspect_plugin_v1_and_v2",
        "install_plugin_v1",
        "update_plugin_v2",
        "refuse_plugin_v1_downgrade_with_final_managed_tree_unchanged",
        "uninstall_plugin_v2_to_retained_quarantine",
        "remove_a_quo",
        "reinstall_new_a_quo"
      ],
      old: {query: $old_query, sha256: $old_sha256, source_commit: $old_commit},
      new: {query: $new_query, sha256: $new_sha256, source_commit: $new_commit},
      policy_commit: $policy_commit,
      policy_bridge_sha256: $policy_bridge_sha256,
      joined_input_lock: {
        lock_id: "a-quo-omarchy4-aarch64-dec29fa-joined-lifecycle-v1",
        lock_commit: $joined_input_lock_commit,
        lock_sha256: $joined_input_lock_sha256,
        policy_commit: $joined_policy_commit,
        input_class: "10-evaluator-scripts-and-fixture-input-lock",
        architecture: "aarch64",
        evidence_namespace: "phase-a-aarch64-dec29fa",
        locked_object_count: 10,
        exact_input_selection_revalidated: true,
        input_class_10_exact_selection_closed: true,
        remaining_input_count_if_lock_is_adopted: 9,
        offline_sealed_snapshot_verification_by_bridge: false,
        runtime_revalidation:
          "exact_root_owned_mode_0400_hash_git_blob_and_committed_lock_checks",
        external_lock_authentication_established_by_bridge: false,
        evaluator_arming_authorized_by_lock: false,
        bridge_execution_authority:
          "separate_exact_acknowledgement_and_disposable_target_gates",
        cross_profile_evidence_accepted: false,
        aarch64_evaluation_gate_satisfied_by_input_selection_alone: false
      },
      consent_evidence: $consent[0],
      core_evidence: $core[0],
      real_root_package_lifecycle_tested: true,
      retained_user_state_preserved_across_remove_reinstall: true,
      package_dependencies_satisfied_locally: true,
      pacman: {
        package_query: $pacman_package_query,
        version: $pacman_version,
        binary_sha256: $pacman_binary_sha256,
        binary_identity: $pacman_binary_identity,
        effective_config_sha256: $pacman_effective_config_sha256,
        configured_repository_count: $pacman_repository_count,
        effective_hook_inventory_sha256: $pacman_hook_inventory_sha256,
        runtime_dependency_identity_pinned: false
      },
      local_package_transactions_requested: true,
      repository_sync_or_dependency_acquisition_requested: false,
      pacman_process_trees_fresh_network_namespace: true,
      nested_consent_and_core_process_trees_fresh_network_namespace: true,
      inherited_descriptor_or_unix_socket_isolation_established: false,
      hook_host_service_delegation_excluded: false,
      whole_machine_network_silence: false,
      package_archive_install_script_present: false,
      package_backup_entries_present: false,
      package_archive_resource_containment_established: false,
      libalpm_hook_execution: "target_effective_policy_applied; exact_triggered_subset_not_independently_enumerated",
      package_signatures_verified: false,
      source_to_binary_provenance_established: false,
      source_checkout_is_independently_authenticated: false,
      script_requested_service_start_or_enable: true,
      service_ever_started_or_enabled_established: true,
      evaluator_and_global_service_disabled_at_sampled_boundaries: true,
      service_inactive_at_sampled_boundaries: true,
      unit_absent_at_post_removal_sample: true,
      other_user_runtime_enablement_checked: false,
      live_service_tested: true,
      trusted_signing_consent_tested: true,
      trusted_installation_consent_tested: false,
      consent_to_core_handoff_binding:
        "verified_exact_v1_v2_packages_proofs_manifest_persona_fingerprint_and_store",
      behavioral_analysis: "not_run",
      plugin_safety: "not_established",
      clean_system_claim: "not_established_disposable_marker_only",
      joined_plugin_install_update_downgrade_refusal_uninstall_tested: true,
      a_quo_package_downgrade_refusal_tested: false,
      joined_plugin_downgrade_refusal_tested: true,
      joined_plugin_rollback_failure_tested: false,
      interruption_recovery_tested: false,
      removal_then_reinstall_is_rollback: false,
      unrelated_pacman_process_exclusion_established: false,
      retained_state_post_enumeration_bounds_applied: true,
      retained_state_enumeration_resource_contained: false,
      retained_state_same_uid_race_excluded: false,
      automatic_reversal_on_failure: false,
      temporary_work_cleanup: "verified_before_evidence_emission"
    }
  '
})"
readonly EVIDENCE_JSON
CURRENT_STAGE=cleanup
if ! remove_temporary_root; then
  fail 'package lifecycle temporary work could not be safely removed'
fi
trap - EXIT
printf '%s\n' "${EVIDENCE_JSON}"
