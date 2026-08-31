#!/usr/bin/env bash

set -euo pipefail

# One-shot, destructive evaluator contract. This script is intentionally not a
# general developer-machine test. Its caller must provision the exact marker
# verified below and supply all of these explicit pins:
#
#   A_QUO_INSTALLED_OMARCHY_CORE_LIFECYCLE_ACKNOWLEDGEMENT
#   A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY       (exact `pacman -Q` output)
#   A_QUO_EVALUATOR_WAYLAND_DISPLAY           (a wayland-N socket name)
#   A_QUO_EVALUATOR_PACKAGE_V1                (canonical absolute path)
#   A_QUO_EVALUATOR_PACKAGE_V1_SHA256         (lowercase SHA-256)
#   A_QUO_EVALUATOR_PACKAGE_V2                (canonical absolute path)
#   A_QUO_EVALUATOR_PACKAGE_V2_SHA256         (lowercase SHA-256)
#   A_QUO_EVALUATOR_PLUGIN_ID                  (the shared exact plugin ID)
#
# It retains the fixed persona store and A Quo-managed staging/recovery trees
# as evidence. Its only deletion targets are the identity-checked mktemp work
# directory and the disposable key held inside that directory.
readonly REQUIRED_ACKNOWLEDGEMENT='I-understand-this-mutates-the-disposable-a-quo-evaluator-account'
if [[ "${A_QUO_INSTALLED_OMARCHY_CORE_LIFECYCLE_ACKNOWLEDGEMENT:-}" != \
  "${REQUIRED_ACKNOWLEDGEMENT}" ]]; then
  printf '%s\n' \
    'refusing installed lifecycle evaluation without exact A_QUO_INSTALLED_OMARCHY_CORE_LIFECYCLE_ACKNOWLEDGEMENT' >&2
  exit 1
fi

readonly EVALUATOR_ACCOUNT='a-quo-evaluator'
readonly EVALUATOR_HOME='/home/a-quo-evaluator'
readonly DISPOSABLE_MARKER='/etc/a-quo/disposable-omarchy-evaluator-v1'
readonly A_QUO='/usr/bin/a-quo'
readonly PROVIDER_REGISTRY='/usr/share/a-quo/provider-registry-v1.json'
readonly PLUGINS_DIRECTORY="${EVALUATOR_HOME}/.config/omarchy/plugins"
readonly PERSONA_STATE_ROOT="${EVALUATOR_HOME}/.local/share/a-quo-installed-omarchy-evaluator-v1"
readonly PERSONA_STORE="${PERSONA_STATE_ROOT}/personas.sqlite3"

fail() {
  printf 'installed Omarchy core lifecycle refused: %s\n' "$1" >&2
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
  [[ -d "${path}" && ! -L "${path}" ]] || fail "unsafe evaluator directory: ${path}"
  metadata="$(/usr/bin/stat -c '%u:%g %a %F' -- "${path}")"
  local ownership_and_mode="${metadata% directory}"
  local owner="${ownership_and_mode%% *}"
  local mode="${ownership_and_mode##* }"
  [[ "${owner}" == "${EVALUATOR_UID}:${EVALUATOR_GID}" ]] ||
    fail "evaluator directory has unexpected ownership: ${path}"
  (( (8#${mode} & 8#022) == 0 )) ||
    fail "evaluator directory is group/world writable: ${path}"
}

if [[ "${EUID}" -ne 0 ]]; then
  fail 'the evaluator must run as root so it can authenticate the root-only disposable marker'
fi

for command_path in \
  /usr/bin/bsdtar \
  /usr/bin/chmod \
  /usr/bin/chown \
  /usr/bin/cmp \
  /usr/bin/env \
  /usr/bin/find \
  /usr/bin/getent \
  /usr/bin/grep \
  /usr/bin/id \
  /usr/bin/install \
  /usr/bin/jq \
  /usr/bin/mktemp \
  /usr/bin/pacman \
  /usr/bin/readlink \
  /usr/bin/realpath \
  /usr/bin/rm \
  /usr/bin/runuser \
  /usr/bin/sha256sum \
  /usr/bin/ssh-keygen \
  /usr/bin/stat \
  /usr/bin/sort; do
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

require_environment A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY
readonly EXPECTED_OMARCHY_QUERY="${A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY}"
if [[ ! "${EXPECTED_OMARCHY_QUERY}" =~ ^omarchy(-dev)?[[:space:]][^[:space:]]+$ ]]; then
  fail 'A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY must be one exact supported pacman -Q line'
fi
readonly EXPECTED_OMARCHY_PACKAGE="${EXPECTED_OMARCHY_QUERY%%[[:space:]]*}"
if [[ "${EXPECTED_OMARCHY_PACKAGE}" != omarchy && \
  "${EXPECTED_OMARCHY_PACKAGE}" != omarchy-dev ]]; then
  fail 'derived Omarchy package name is outside the closed supported set'
fi
OBSERVED_OMARCHY_QUERY="$(
  /usr/bin/pacman -Q -- "${EXPECTED_OMARCHY_PACKAGE}"
)" ||
  fail 'the pinned Omarchy package is not installed'
readonly OBSERVED_OMARCHY_QUERY
[[ "${OBSERVED_OMARCHY_QUERY}" == "${EXPECTED_OMARCHY_QUERY}" ]] ||
  fail 'installed Omarchy package query does not match the caller-supplied pin'

require_real_regular_file "${A_QUO}" 'installed A Quo CLI'
if [[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${A_QUO}")" != \
  '0:0 755 regular file' ]]; then
  fail 'installed /usr/bin/a-quo must be root:root mode 0755'
fi
INSTALLED_A_QUO_QUERY="$(/usr/bin/pacman -Q a-quo)" ||
  fail 'the installed A Quo binary is not backed by the a-quo package query'
readonly INSTALLED_A_QUO_QUERY
[[ "$(/usr/bin/pacman -Qoq -- "${A_QUO}")" == 'a-quo' ]] ||
  fail 'installed /usr/bin/a-quo is not owned by the a-quo package'
INSTALLED_A_QUO_SHA256="$(sha256_file "${A_QUO}")"
readonly INSTALLED_A_QUO_SHA256

require_real_regular_file "${PROVIDER_REGISTRY}" 'installed provider registry'
if [[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${PROVIDER_REGISTRY}")" != \
  '0:0 644 regular file' ]]; then
  fail 'installed provider registry must be root:root mode 0644'
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
require_safe_user_directory "${EVALUATOR_RUNTIME_DIRECTORY}"
readonly WAYLAND_SOCKET="${EVALUATOR_RUNTIME_DIRECTORY}/${WAYLAND_DISPLAY_VALUE}"
if [[ -L "${WAYLAND_SOCKET}" || ! -S "${WAYLAND_SOCKET}" || \
  "$(/usr/bin/stat -c '%u' -- "${WAYLAND_SOCKET}")" != "${EVALUATOR_UID}" ]]; then
  fail 'the evaluator account has no matching real Wayland socket in its runtime directory'
fi

for path in \
  "${EVALUATOR_HOME}/.config" \
  "${EVALUATOR_HOME}/.config/omarchy" \
  "${PLUGINS_DIRECTORY}"; do
  require_safe_user_directory "${path}"
done
for path in "${EVALUATOR_HOME}/.local" "${EVALUATOR_HOME}/.local/share"; do
  if [[ -e "${path}" || -L "${path}" ]]; then
    require_safe_user_directory "${path}"
  fi
done
if [[ -e "${PERSONA_STATE_ROOT}" || -L "${PERSONA_STATE_ROOT}" ]]; then
  fail 'the fixed evaluator persona-state root must be absent before this one-shot run'
fi

require_environment A_QUO_EVALUATOR_PACKAGE_V1
require_environment A_QUO_EVALUATOR_PACKAGE_V1_SHA256
require_environment A_QUO_EVALUATOR_PACKAGE_V2
require_environment A_QUO_EVALUATOR_PACKAGE_V2_SHA256
require_environment A_QUO_EVALUATOR_PLUGIN_ID
readonly PACKAGE_V1_SOURCE="${A_QUO_EVALUATOR_PACKAGE_V1}"
readonly PACKAGE_V1_EXPECTED_SHA256="${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}"
readonly PACKAGE_V2_SOURCE="${A_QUO_EVALUATOR_PACKAGE_V2}"
readonly PACKAGE_V2_EXPECTED_SHA256="${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}"
readonly PLUGIN_ID="${A_QUO_EVALUATOR_PLUGIN_ID}"
for digest in "${PACKAGE_V1_EXPECTED_SHA256}" "${PACKAGE_V2_EXPECTED_SHA256}"; do
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || fail 'package SHA-256 pins must be lowercase hex'
done
[[ "${PACKAGE_V1_EXPECTED_SHA256}" != "${PACKAGE_V2_EXPECTED_SHA256}" ]] ||
  fail 'v1 and v2 must be distinct exact package bytes'
if [[ ! "${PLUGIN_ID}" =~ ^[[:alnum:]][[:alnum:]_.-]{0,254}$ || \
  "${PLUGIN_ID}" == *..* || "${PLUGIN_ID}" == omarchy.* ]]; then
  fail 'A_QUO_EVALUATOR_PLUGIN_ID is invalid or reserved'
fi

readonly LIVE_TARGET="${PLUGINS_DIRECTORY}/${PLUGIN_ID}"
if [[ -e "${LIVE_TARGET}" || -L "${LIVE_TARGET}" ]]; then
  fail 'the exact evaluator plugin target must be absent before installation'
fi

TEMPORARY_ROOT=''
TEMPORARY_ROOT_IDENTITY=''
PRIVATE_KEY=''
remove_temporary_root() {
  case "${TEMPORARY_ROOT}" in
    "${EVALUATOR_HOME}"/.a-quo-installed-core-lifecycle.*) ;;
    *) return 1 ;;
  esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" && \
    "$(/usr/bin/stat -c '%d:%i' -- "${TEMPORARY_ROOT}")" == \
      "${TEMPORARY_ROOT_IDENTITY}" && \
    "$(/usr/bin/stat -c '%u:%g' -- "${TEMPORARY_ROOT}")" == \
      "${EVALUATOR_UID}:${EVALUATOR_GID}" ]] || return 1
  if [[ -n "${PRIVATE_KEY}" && "${PRIVATE_KEY}" == "${TEMPORARY_ROOT}/"* ]]; then
    /usr/bin/rm -f -- "${PRIVATE_KEY}" "${PRIVATE_KEY}.pub" || return 1
  fi
  /usr/bin/rm -rf -- "${TEMPORARY_ROOT}" || return 1
  [[ ! -e "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]]
}

cleanup() {
  local status="$?"
  trap - EXIT
  if [[ -n "${TEMPORARY_ROOT}" ]] && ! remove_temporary_root; then
    printf 'evaluator work cleanup failed or its exact identity changed: %s\n' \
      "${TEMPORARY_ROOT}" >&2
    [[ "${status}" -ne 0 ]] || status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

TEMPORARY_ROOT="$(/usr/bin/mktemp -d \
  "${EVALUATOR_HOME}/.a-quo-installed-core-lifecycle.XXXXXX")"
/usr/bin/chown "${EVALUATOR_UID}:${EVALUATOR_GID}" -- "${TEMPORARY_ROOT}"
/usr/bin/chmod 0700 -- "${TEMPORARY_ROOT}"
TEMPORARY_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i' -- "${TEMPORARY_ROOT}")"
readonly TEMPORARY_ROOT TEMPORARY_ROOT_IDENTITY

run_as_evaluator() {
  /usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" -- /usr/bin/env -i \
    HOME="${EVALUATOR_HOME}" \
    USER="${EVALUATOR_ACCOUNT}" \
    LOGNAME="${EVALUATOR_ACCOUNT}" \
    PATH=/usr/bin:/bin \
    LANG=C.UTF-8 \
    LC_ALL=C \
    XDG_CONFIG_HOME="${EVALUATOR_HOME}/.config" \
    XDG_DATA_HOME="${EVALUATOR_HOME}/.local/share" \
    XDG_RUNTIME_DIR="${EVALUATOR_RUNTIME_DIRECTORY}" \
    WAYLAND_DISPLAY="${WAYLAND_DISPLAY_VALUE}" \
    "$@"
}

run_a_quo() {
  run_as_evaluator /usr/bin/a-quo "$@"
}

snapshot_package() {
  local source_path="$1"
  local expected_sha256="$2"
  local destination_path="$3"
  local before_sha256
  local snapshot_sha256
  local after_sha256

  [[ "${source_path}" == /* ]] || fail 'package inputs must be absolute paths'
  require_real_regular_file "${source_path}" 'package input'
  [[ "$(/usr/bin/realpath -e -- "${source_path}")" == "${source_path}" ]] ||
    fail 'package input path must already be canonical and contain no symlink component'
  before_sha256="$(sha256_file "${source_path}")"
  [[ "${before_sha256}" == "${expected_sha256}" ]] ||
    fail 'package input does not match its caller-supplied SHA-256 pin'
  /usr/bin/install -T -o "${EVALUATOR_UID}" -g "${EVALUATOR_GID}" -m 0400 -- \
    "${source_path}" "${destination_path}"
  snapshot_sha256="$(sha256_file "${destination_path}")"
  after_sha256="$(sha256_file "${source_path}")"
  if [[ "${snapshot_sha256}" != "${expected_sha256}" || \
    "${after_sha256}" != "${expected_sha256}" ]]; then
    fail 'package input changed while its private evaluator snapshot was created'
  fi
}

archive_manifest_sha256() {
  local output
  output="$(/usr/bin/bsdtar -xOf "$1" manifest.json | /usr/bin/sha256sum)"
  printf '%s\n' "${output%% *}"
}

assert_lifecycle_outcome() {
  local path="$1"
  local action="$2"
  /usr/bin/jq -e --arg plugin_id "${PLUGIN_ID}" '
    .plugin_id == $plugin_id and
    .a_quo_enablement_action == "not_performed" and
    .shell_rescan == "passed" and
    .disk_purge == "not_performed" and
    .behavioral_analysis == "not_run" and
    .trusted_consent == "not_run" and
    .runtime_safety == "not_evaluated"
  ' "${path}" >/dev/null || fail "${action} returned overstated or incomplete evidence"
}

assert_reference_observation() {
  local path="$1"
  /usr/bin/jq -e --arg plugin_id "${PLUGIN_ID}" '
    type == "object" and
    (keys == ["plugin_id", "shell_config_sha256", "shell_config_source", "state"]) and
    (.plugin_id | type == "string") and .plugin_id == $plugin_id and
    (.state | type == "string") and
    .state == "not_referenced" and
    (.shell_config_source | type == "string") and
    (.shell_config_source == "user" or .shell_config_source == "system_default") and
    (.shell_config_sha256 | type == "string") and
    (.shell_config_sha256 | test("^[0-9a-f]{64}$"))
  ' "${path}" >/dev/null || fail 'Omarchy reference observation is not exact and unreferenced'
}

require_canonical_retained_directory() {
  local path="$1"
  local label="$2"
  require_safe_user_directory "${path}"
  [[ "$(/usr/bin/realpath -e -- "${path}")" == "${path}" ]] ||
    fail "${label} path is not canonical"
}

require_private_retained_directory() {
  local path="$1"
  local label="$2"
  require_canonical_retained_directory "${path}" "${label}"
  [[ "$(/usr/bin/stat -c '%a' -- "${path}")" == '700' ]] ||
    fail "${label} is not mode 0700"
}

require_safe_user_file() {
  local path="$1"
  local expected_mode="$2"
  local label="$3"
  require_real_regular_file "${path}" "${label}"
  [[ "$(/usr/bin/stat -c '%u:%g %a %F' -- "${path}")" == \
    "${EVALUATOR_UID}:${EVALUATOR_GID} ${expected_mode} regular file" ]] ||
    fail "${label} has unexpected ownership or mode"
}

require_direct_retained_directory() {
  local path="$1"
  local prefix="$2"
  local label="$3"
  local relative="${path#"${PLUGINS_DIRECTORY}"/}"
  [[ "${relative}" != "${path}" && "${relative}" == "${prefix}"* && \
    "${relative}" != */* ]] || fail "${label} is outside its exact retained namespace"
  require_private_retained_directory "${path}" "${label}"
}

require_update_recovery_directory() {
  local path="$1"
  local label="$2"
  local relative="${path#"${PLUGINS_DIRECTORY}"/}"
  local recovery_root="${path%/plugin}"
  local recovery_relative="${recovery_root#"${PLUGINS_DIRECTORY}"/}"
  [[ "${relative}" != "${path}" && "${path}" == "${recovery_root}/plugin" && \
    "${recovery_relative}" == .a-quo-update-* && \
    "${recovery_relative}" != */* ]] ||
    fail "${label} is outside its exact retained namespace"
  require_private_retained_directory "${recovery_root}" "${label} root"
  require_canonical_retained_directory "${path}" "${label}"
}

managed_tree_sha256() {
  local root="$1"
  local output
  output="$(
    (
      cd -- "${root}"
      while IFS= read -r -d '' entry; do
        local entry_type
        if [[ -d "${entry}" && ! -L "${entry}" ]]; then
          entry_type='directory'
        elif [[ -f "${entry}" && ! -L "${entry}" ]]; then
          entry_type='file'
        else
          fail 'managed tree contains an unsupported entry while hashing'
        fi
        printf '%s\0%s\0%s\0' \
          "${entry}" "${entry_type}" "$(/usr/bin/stat -c '%u:%g %a %s' -- "${entry}")"
        if [[ "${entry_type}" == 'file' ]]; then
          printf '%s\0' "$(sha256_file "${entry}")"
        fi
      done < <(/usr/bin/find . -xdev -print0 | /usr/bin/sort -z)
    ) | /usr/bin/sha256sum
  )"
  printf '%s\n' "${output%% *}"
}

assert_install_receipt() {
  local plugin_directory="$1"
  local expected_version="$2"
  local expected_package_sha256="$3"
  local label="$4"
  local receipt="${plugin_directory}/.a-quo-install.json"
  require_safe_user_file "${receipt}" '600' "${label} receipt"
  /usr/bin/jq -e \
    --arg plugin_id "${PLUGIN_ID}" \
    --arg version "${expected_version}" \
    --arg package_sha256 "${expected_package_sha256}" \
    --arg persona_id "${PERSONA_ID}" \
    --arg key_fingerprint "${KEY_FINGERPRINT}" '
      type == "object" and
      .schema_version == 1 and
      .plugin_id == $plugin_id and
      .version == $version and
      .package_sha256 == $package_sha256 and
      .publisher_persona_id == $persona_id and
      .publisher_key_fingerprint == $key_fingerprint and
      (.installed_at_unix_seconds | type == "number")
    ' "${receipt}" >/dev/null || fail "${label} receipt does not bind the expected release"
}

readonly PACKAGE_V1="${TEMPORARY_ROOT}/package-v1.tar.zst"
readonly PACKAGE_V2="${TEMPORARY_ROOT}/package-v2.tar.zst"
snapshot_package "${PACKAGE_V1_SOURCE}" "${PACKAGE_V1_EXPECTED_SHA256}" "${PACKAGE_V1}"
snapshot_package "${PACKAGE_V2_SOURCE}" "${PACKAGE_V2_EXPECTED_SHA256}" "${PACKAGE_V2}"

PRIVATE_KEY="${TEMPORARY_ROOT}/publisher-ed25519"
readonly PRIVATE_KEY
run_as_evaluator /usr/bin/ssh-keygen -q -t ed25519 -N '' \
  -C 'A Quo disposable installed evaluator; not a release identity' -f "${PRIVATE_KEY}"

readonly PERSONA_JSON="${TEMPORARY_ROOT}/persona.json"
readonly KEY_JSON="${TEMPORARY_ROOT}/key.json"
readonly BINDING_JSON="${TEMPORARY_ROOT}/binding.json"
run_a_quo --store "${PERSONA_STORE}" persona create \
  --label 'A Quo disposable installed evaluator' --purpose project --json >"${PERSONA_JSON}"
PERSONA_ID="$(/usr/bin/jq -er '.id' "${PERSONA_JSON}")"
readonly PERSONA_ID
run_a_quo --store "${PERSONA_STORE}" persona key-add \
  --persona-id "${PERSONA_ID}" --public-key "${PRIVATE_KEY}.pub" \
  --provider openssh-file --json >"${KEY_JSON}"
KEY_FINGERPRINT="$(/usr/bin/jq -er '.fingerprint' "${KEY_JSON}")"
readonly KEY_FINGERPRINT
run_a_quo --store "${PERSONA_STORE}" persona key-bind \
  --fingerprint "${KEY_FINGERPRINT}" --signing-key "${PRIVATE_KEY}" \
  --json >"${BINDING_JSON}"

readonly PROOF_V1="${TEMPORARY_ROOT}/package-v1.a-quo-proof.json"
readonly PROOF_V2="${TEMPORARY_ROOT}/package-v2.a-quo-proof.json"
run_a_quo --store "${PERSONA_STORE}" sign "${PACKAGE_V1}" \
  --key "${PRIVATE_KEY}" --public-key "${PRIVATE_KEY}.pub" \
  --persona-id "${PERSONA_ID}" --output "${PROOF_V1}" \
  >"${TEMPORARY_ROOT}/sign-v1.log"
run_a_quo --store "${PERSONA_STORE}" sign "${PACKAGE_V2}" \
  --key "${PRIVATE_KEY}" --public-key "${PRIVATE_KEY}.pub" \
  --persona-id "${PERSONA_ID}" --output "${PROOF_V2}" \
  >"${TEMPORARY_ROOT}/sign-v2.log"

readonly VERIFY_V1="${TEMPORARY_ROOT}/verify-v1.json"
readonly VERIFY_V2="${TEMPORARY_ROOT}/verify-v2.json"
run_a_quo --store "${PERSONA_STORE}" verify "${PACKAGE_V1}" \
  --proof "${PROOF_V1}" --json >"${VERIFY_V1}"
run_a_quo --store "${PERSONA_STORE}" verify "${PACKAGE_V2}" \
  --proof "${PROOF_V2}" --json >"${VERIFY_V2}"
for verification in "${VERIFY_V1}" "${VERIFY_V2}"; do
  /usr/bin/jq -e '
    .artifact_integrity == "verified" and .signature == "verified"
  ' "${verification}" >/dev/null || fail 'direct package signature did not verify'
done

readonly INSPECTION_V1="${TEMPORARY_ROOT}/inspection-v1.json"
readonly INSPECTION_V2="${TEMPORARY_ROOT}/inspection-v2.json"
run_a_quo --store "${PERSONA_STORE}" omarchy inspect "${PACKAGE_V1}" \
  --proof "${PROOF_V1}" --json >"${INSPECTION_V1}"
run_a_quo --store "${PERSONA_STORE}" omarchy inspect "${PACKAGE_V2}" \
  --proof "${PROOF_V2}" --json >"${INSPECTION_V2}"
for inspection in "${INSPECTION_V1}" "${INSPECTION_V2}"; do
  /usr/bin/jq -e --arg plugin_id "${PLUGIN_ID}" '
    .manifest.id == $plugin_id and
    (.manifest.version | type == "string" and length > 0) and
    .publisher_evidence.registry_status == "active" and
    .publisher_evidence.signed_label_agreement == true and
    .omarchy_manifest_validation == "not_run" and
    .runtime_safety == "not_evaluated" and
    .a_quo_enablement_action == "not_performed"
  ' "${inspection}" >/dev/null || fail 'package inspection did not validate the expected manifest and publisher'
done
VERSION_V1="$(/usr/bin/jq -er '.manifest.version' "${INSPECTION_V1}")"
VERSION_V2="$(/usr/bin/jq -er '.manifest.version' "${INSPECTION_V2}")"
readonly VERSION_V1 VERSION_V2
[[ "${VERSION_V1}" != "${VERSION_V2}" ]] || fail 'v1 and v2 manifests use the same version'
PACKAGE_V1_MANIFEST_SHA256="$(archive_manifest_sha256 "${PACKAGE_V1}")"
PACKAGE_V2_MANIFEST_SHA256="$(archive_manifest_sha256 "${PACKAGE_V2}")"
readonly PACKAGE_V1_MANIFEST_SHA256 PACKAGE_V2_MANIFEST_SHA256

SENTINEL_ROOT=''
for refusal_case in missing-yes missing-analysis-acknowledgement; do
  SENTINEL_ROOT="${TEMPORARY_ROOT}/no-io-${refusal_case}"
  if [[ "${refusal_case}" == missing-yes ]]; then
    if run_a_quo --store "${SENTINEL_ROOT}/personas.sqlite3" \
      omarchy install "${PACKAGE_V1}" --proof "${PROOF_V1}" \
      --plugins-directory "${SENTINEL_ROOT}/plugins" \
      --accept-behavioral-analysis-not-run \
      >"${TEMPORARY_ROOT}/${refusal_case}.stdout" \
      2>"${TEMPORARY_ROOT}/${refusal_case}.stderr"; then
      fail 'install unexpectedly accepted a missing --yes acknowledgement'
    fi
    /usr/bin/grep -Fq 'refusing installation without explicit confirmation' \
      "${TEMPORARY_ROOT}/${refusal_case}.stderr" ||
      fail 'missing --yes did not reach the expected fail-closed gate'
  else
    if run_a_quo --store "${SENTINEL_ROOT}/personas.sqlite3" \
      omarchy install "${PACKAGE_V1}" --proof "${PROOF_V1}" \
      --plugins-directory "${SENTINEL_ROOT}/plugins" --yes \
      >"${TEMPORARY_ROOT}/${refusal_case}.stdout" \
      2>"${TEMPORARY_ROOT}/${refusal_case}.stderr"; then
      fail 'install unexpectedly accepted a missing analysis acknowledgement'
    fi
    /usr/bin/grep -Fq 'behavioural analysis did not run' \
      "${TEMPORARY_ROOT}/${refusal_case}.stderr" ||
      fail 'missing analysis acknowledgement did not reach the expected fail-closed gate'
  fi
  if [[ -e "${SENTINEL_ROOT}" || -L "${SENTINEL_ROOT}" ]]; then
    fail "${refusal_case} touched its absent store or plugin-directory sentinel"
  fi
done

readonly REFERENCE_BEFORE="${TEMPORARY_ROOT}/reference-before.json"
readonly REFERENCE_AFTER_INSTALL="${TEMPORARY_ROOT}/reference-after-install.json"
readonly REFERENCE_AFTER_UPDATE="${TEMPORARY_ROOT}/reference-after-update.json"
readonly REFERENCE_AFTER_DOWNGRADE="${TEMPORARY_ROOT}/reference-after-downgrade.json"
readonly REFERENCE_AFTER_UNINSTALL="${TEMPORARY_ROOT}/reference-after-uninstall.json"
run_a_quo omarchy observe-reference "${PLUGIN_ID}" \
  --plugins-directory "${PLUGINS_DIRECTORY}" --json >"${REFERENCE_BEFORE}"
assert_reference_observation "${REFERENCE_BEFORE}"

readonly INSTALL_JSON="${TEMPORARY_ROOT}/install.json"
run_a_quo --store "${PERSONA_STORE}" omarchy install "${PACKAGE_V1}" \
  --proof "${PROOF_V1}" --plugins-directory "${PLUGINS_DIRECTORY}" \
  --yes --accept-behavioral-analysis-not-run --json >"${INSTALL_JSON}"
assert_lifecycle_outcome "${INSTALL_JSON}" install
/usr/bin/jq -e --arg version "${VERSION_V1}" '
  .version == $version and
  .omarchy_manifest_validation == "passed_pinned_root_observation_not_content_continuous" and
  .staging_retained == true
' "${INSTALL_JSON}" >/dev/null || fail 'install outcome did not describe the bounded fresh-install contract'
RETAINED_INSTALL_STAGING="$(/usr/bin/jq -er '.retained_staging' "${INSTALL_JSON}")"
readonly RETAINED_INSTALL_STAGING
require_direct_retained_directory \
  "${RETAINED_INSTALL_STAGING}" '.a-quo-install-' 'retained install staging'
require_safe_user_file \
  "${RETAINED_INSTALL_STAGING}/package.tar.zst" '600' 'retained install package'
[[ "$(sha256_file "${RETAINED_INSTALL_STAGING}/package.tar.zst")" == \
  "${PACKAGE_V1_EXPECTED_SHA256}" ]] ||
  fail 'retained install staging does not contain the exact v1 package'
require_canonical_retained_directory "${LIVE_TARGET}" 'installed v1 target'
require_real_regular_file "${LIVE_TARGET}/manifest.json" 'installed v1 manifest'
INSTALLED_MANIFEST_V1_SHA256="$(sha256_file "${LIVE_TARGET}/manifest.json")"
readonly INSTALLED_MANIFEST_V1_SHA256
[[ "${INSTALLED_MANIFEST_V1_SHA256}" == "${PACKAGE_V1_MANIFEST_SHA256}" ]] ||
  fail 'installed v1 manifest differs from the inspected package manifest'
assert_install_receipt \
  "${LIVE_TARGET}" "${VERSION_V1}" "${PACKAGE_V1_EXPECTED_SHA256}" 'installed v1'
run_a_quo omarchy observe-reference "${PLUGIN_ID}" \
  --plugins-directory "${PLUGINS_DIRECTORY}" --json >"${REFERENCE_AFTER_INSTALL}"
assert_reference_observation "${REFERENCE_AFTER_INSTALL}"

readonly UPDATE_JSON="${TEMPORARY_ROOT}/update.json"
run_a_quo --store "${PERSONA_STORE}" omarchy update "${PACKAGE_V2}" \
  --proof "${PROOF_V2}" --plugins-directory "${PLUGINS_DIRECTORY}" \
  --yes --accept-behavioral-analysis-not-run --json >"${UPDATE_JSON}"
assert_lifecycle_outcome "${UPDATE_JSON}" update
/usr/bin/jq -e --arg previous "${VERSION_V1}" --arg version "${VERSION_V2}" '
  .previous_version == $previous and .version == $version and
  .publisher_continuity == "same_local_persona" and
  .omarchy_manifest_validation == "passed_path_observation_not_continuous" and
  .atomic_exchange == true and .recovery_retained == true
' "${UPDATE_JSON}" >/dev/null || fail 'update outcome did not describe the bounded same-persona contract'
PREVIOUS_RELEASE_RECOVERY="$(/usr/bin/jq -er '.previous_release_recovery' "${UPDATE_JSON}")"
readonly PREVIOUS_RELEASE_RECOVERY
require_update_recovery_directory \
  "${PREVIOUS_RELEASE_RECOVERY}" 'previous-release recovery'
require_real_regular_file "${PREVIOUS_RELEASE_RECOVERY}/manifest.json" \
  'previous-release recovery manifest'
[[ "$(sha256_file "${PREVIOUS_RELEASE_RECOVERY}/manifest.json")" == \
  "${PACKAGE_V1_MANIFEST_SHA256}" ]] ||
  fail 'previous-release recovery does not contain the exact v1 manifest'
assert_install_receipt \
  "${PREVIOUS_RELEASE_RECOVERY}" "${VERSION_V1}" "${PACKAGE_V1_EXPECTED_SHA256}" \
  'previous-release recovery'
require_canonical_retained_directory "${LIVE_TARGET}" 'installed v2 target'
require_real_regular_file "${LIVE_TARGET}/manifest.json" 'installed v2 manifest'
INSTALLED_MANIFEST_V2_SHA256="$(sha256_file "${LIVE_TARGET}/manifest.json")"
readonly INSTALLED_MANIFEST_V2_SHA256
[[ "${INSTALLED_MANIFEST_V2_SHA256}" == "${PACKAGE_V2_MANIFEST_SHA256}" ]] ||
  fail 'installed v2 manifest differs from the inspected package manifest'
assert_install_receipt \
  "${LIVE_TARGET}" "${VERSION_V2}" "${PACKAGE_V2_EXPECTED_SHA256}" 'installed v2'
run_a_quo omarchy observe-reference "${PLUGIN_ID}" \
  --plugins-directory "${PLUGINS_DIRECTORY}" --json >"${REFERENCE_AFTER_UPDATE}"
assert_reference_observation "${REFERENCE_AFTER_UPDATE}"
LIVE_TREE_BEFORE_DOWNGRADE="$(managed_tree_sha256 "${LIVE_TARGET}")"
readonly LIVE_TREE_BEFORE_DOWNGRADE

if run_a_quo --store "${PERSONA_STORE}" omarchy update "${PACKAGE_V1}" \
  --proof "${PROOF_V1}" --plugins-directory "${PLUGINS_DIRECTORY}" \
  --yes --accept-behavioral-analysis-not-run --json \
  >"${TEMPORARY_ROOT}/downgrade.stdout" 2>"${TEMPORARY_ROOT}/downgrade.stderr"; then
  fail 'the installed CLI unexpectedly accepted a downgrade'
fi
/usr/bin/grep -Fq 'is not newer than installed version' \
  "${TEMPORARY_ROOT}/downgrade.stderr" ||
  fail 'downgrade failed for an unexpected reason'
[[ "$(sha256_file "${LIVE_TARGET}/manifest.json")" == \
  "${INSTALLED_MANIFEST_V2_SHA256}" ]] || fail 'downgrade refusal changed the live v2 manifest'
[[ "$(managed_tree_sha256 "${LIVE_TARGET}")" == "${LIVE_TREE_BEFORE_DOWNGRADE}" ]] ||
  fail 'downgrade refusal changed the managed v2 tree'
run_a_quo omarchy observe-reference "${PLUGIN_ID}" \
  --plugins-directory "${PLUGINS_DIRECTORY}" --json >"${REFERENCE_AFTER_DOWNGRADE}"
assert_reference_observation "${REFERENCE_AFTER_DOWNGRADE}"

readonly UNINSTALL_JSON="${TEMPORARY_ROOT}/uninstall.json"
run_a_quo omarchy uninstall "${PLUGIN_ID}" \
  --plugins-directory "${PLUGINS_DIRECTORY}" --yes --json >"${UNINSTALL_JSON}"
assert_lifecycle_outcome "${UNINSTALL_JSON}" uninstall
/usr/bin/jq -e --arg version "${VERSION_V2}" '
  .version == $version and
  .observed_reference_state == "unreferenced_before_atomic_quarantine" and
  .atomic_quarantine == true
' "${UNINSTALL_JSON}" >/dev/null || fail 'uninstall outcome did not retain the exact managed release'
if [[ -e "${LIVE_TARGET}" || -L "${LIVE_TARGET}" ]]; then
  fail 'uninstall left an entry at the live plugin-ID path'
fi
RECOVERY_QUARANTINE="$(/usr/bin/jq -er '.recovery_quarantine' "${UNINSTALL_JSON}")"
readonly RECOVERY_QUARANTINE
require_direct_retained_directory \
  "${RECOVERY_QUARANTINE}" '.a-quo-remove-' 'uninstall recovery quarantine'
require_canonical_retained_directory \
  "${RECOVERY_QUARANTINE}/plugin" 'uninstall recovery plugin'
require_real_regular_file "${RECOVERY_QUARANTINE}/plugin/manifest.json" \
  'retained uninstall manifest'
QUARANTINED_MANIFEST_SHA256="$(
  sha256_file "${RECOVERY_QUARANTINE}/plugin/manifest.json"
)"
readonly QUARANTINED_MANIFEST_SHA256
[[ "${QUARANTINED_MANIFEST_SHA256}" == "${PACKAGE_V2_MANIFEST_SHA256}" ]] ||
  fail 'retained uninstall quarantine does not contain the exact v2 manifest'
assert_install_receipt \
  "${RECOVERY_QUARANTINE}/plugin" "${VERSION_V2}" "${PACKAGE_V2_EXPECTED_SHA256}" \
  'uninstall recovery'
run_a_quo omarchy observe-reference "${PLUGIN_ID}" \
  --plugins-directory "${PLUGINS_DIRECTORY}" --json >"${REFERENCE_AFTER_UNINSTALL}"
assert_reference_observation "${REFERENCE_AFTER_UNINSTALL}"

REFERENCE_BASELINE="$(/usr/bin/jq -cS . "${REFERENCE_BEFORE}")"
readonly REFERENCE_BASELINE
for observation in \
  "${REFERENCE_AFTER_INSTALL}" \
  "${REFERENCE_AFTER_UPDATE}" \
  "${REFERENCE_AFTER_DOWNGRADE}" \
  "${REFERENCE_AFTER_UNINSTALL}"; do
  [[ "$(/usr/bin/jq -cS . "${observation}")" == "${REFERENCE_BASELINE}" ]] ||
    fail 'persisted Omarchy reference state or raw configuration digest changed during the lifecycle'
done

run_a_quo --store "${PERSONA_STORE}" persona key-unbind \
  --fingerprint "${KEY_FINGERPRINT}" >"${TEMPORARY_ROOT}/key-unbind.log"

EVIDENCE_JSON="$(
  /usr/bin/jq -n \
  --arg schema 'urn:a-quo:evidence:installed-omarchy-core-lifecycle:v1' \
  --arg account "${EVALUATOR_ACCOUNT}" \
  --arg omarchy_query "${OBSERVED_OMARCHY_QUERY}" \
  --arg a_quo_query "${INSTALLED_A_QUO_QUERY}" \
  --arg a_quo_sha256 "${INSTALLED_A_QUO_SHA256}" \
  --arg plugin_id "${PLUGIN_ID}" \
  --arg v1 "${VERSION_V1}" \
  --arg v2 "${VERSION_V2}" \
  --arg v1_package_sha256 "${PACKAGE_V1_EXPECTED_SHA256}" \
  --arg v2_package_sha256 "${PACKAGE_V2_EXPECTED_SHA256}" \
  --arg v1_manifest_sha256 "${PACKAGE_V1_MANIFEST_SHA256}" \
  --arg v2_manifest_sha256 "${PACKAGE_V2_MANIFEST_SHA256}" \
  --arg v2_tree_sha256_before_downgrade "${LIVE_TREE_BEFORE_DOWNGRADE}" \
  --arg persona_store "${PERSONA_STORE}" \
  --slurpfile reference_before "${REFERENCE_BEFORE}" \
  --slurpfile reference_after_install "${REFERENCE_AFTER_INSTALL}" \
  --slurpfile reference_after_update "${REFERENCE_AFTER_UPDATE}" \
  --slurpfile reference_after_downgrade "${REFERENCE_AFTER_DOWNGRADE}" \
  --slurpfile reference_after_uninstall "${REFERENCE_AFTER_UNINSTALL}" \
  --slurpfile install "${INSTALL_JSON}" \
  --slurpfile update "${UPDATE_JSON}" \
  --slurpfile uninstall "${UNINSTALL_JSON}" '
  {
    schema: $schema,
    result: "passed",
    evaluator: {
      account: $account,
      disposable_marker: "verified_exact_root_owned_mode_0400",
      wayland_context: "verified_evaluator_owned_socket",
      temporary_work_cleanup: "verified_before_evidence_emission",
      clean_system_claim: "not_established_marker_only"
    },
    installed_software: {
      omarchy_package_query: $omarchy_query,
      a_quo_package_query: $a_quo_query,
      a_quo_binary_sha256: $a_quo_sha256,
      provider_registry: "empty_v1_root_owned"
    },
    subject: {
      plugin_id: $plugin_id,
      v1: {version: $v1, package_sha256: $v1_package_sha256, manifest_sha256: $v1_manifest_sha256},
      v2: {
        version: $v2,
        package_sha256: $v2_package_sha256,
        manifest_sha256: $v2_manifest_sha256,
        managed_tree_sha256_before_downgrade_refusal: $v2_tree_sha256_before_downgrade
      }
    },
    identity_and_signing: {
      persona: "self_asserted_disposable_test_publisher",
      publisher_continuity: "same_local_persona",
      direct_signatures: "verified_for_both_exact_packages",
      signing_key: "disposable_ed25519_deleted_after_unbind",
      trusted_consent: "not_run"
    },
    acknowledgement_gates: {
      missing_yes_failed_before_store_or_plugin_io: true,
      missing_behavioral_analysis_acknowledgement_failed_before_store_or_plugin_io: true
    },
    reference_observations: {
      before: $reference_before[0],
      after_install: $reference_after_install[0],
      after_update: $reference_after_update[0],
      after_downgrade_refusal: $reference_after_downgrade[0],
      after_uninstall: $reference_after_uninstall[0],
      unchanged: true,
      running_shell_application: "not_established_point_in_time_files_only"
    },
    lifecycle: {
      install: $install[0],
      update: $update[0],
      downgrade_refused: true,
      uninstall: $uninstall[0]
    },
    retained_state: {
      persona_store: $persona_store,
      install_staging: $install[0].retained_staging,
      previous_release_recovery: $update[0].previous_release_recovery,
      uninstall_recovery_quarantine: $uninstall[0].recovery_quarantine,
      automatic_purge: "not_performed"
    },
    behavioral_analysis: "not_run",
    trusted_consent: "not_run",
    plugin_safety: "not_established",
    clean_system_claim: "not_established_marker_only"
  }
'
)"
readonly EVIDENCE_JSON
if ! remove_temporary_root; then
  fail 'temporary evaluator work or the disposable signing key could not be safely removed'
fi
trap - EXIT
printf '%s\n' "${EVIDENCE_JSON}"
