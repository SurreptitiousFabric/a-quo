#!/usr/bin/env bash
# shellcheck disable=SC2016 # Exact source literals must not expand in this contract.

set -euo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
readonly EVALUATOR="${SCRIPT_DIRECTORY}/test-installed-a-quo-consent-lifecycle.sh"

[[ -f "${EVALUATOR}" && ! -L "${EVALUATOR}" ]] || {
  printf '%s\n' 'installed consent evaluator is missing or is a symlink' >&2
  exit 1
}

set +e
REFUSAL_OUTPUT="$(
  /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "${EVALUATOR}" 2>&1
)"
REFUSAL_STATUS="$?"
set -e
if [[ "${REFUSAL_STATUS}" -eq 0 || "${REFUSAL_OUTPUT}" != \
  'refusing installed consent evaluation without exact A_QUO_INSTALLED_CONSENT_LIFECYCLE_ACKNOWLEDGEMENT' ]]; then
  printf 'consent evaluator did not fail first on its exact acknowledgement: status=%s output=%q\n' \
    "${REFUSAL_STATUS}" "${REFUSAL_OUTPUT}" >&2
  exit 1
fi

active_line_of() {
  local literal="$1"
  local line
  local body
  local trimmed
  while IFS=: read -r line body; do
    trimmed="${body#"${body%%[![:space:]]*}"}"
    [[ "${trimmed}" != \#* ]] || continue
    printf '%s\n' "${line}"
    return 0
  done < <(/usr/bin/grep -Fn -- "${literal}" "${EVALUATOR}")
  return 1
}

last_active_line_of() {
  local literal="$1"
  local line
  local body
  local trimmed
  local last=''
  while IFS=: read -r line body; do
    trimmed="${body#"${body%%[![:space:]]*}"}"
    [[ "${trimmed}" != \#* ]] || continue
    last="${line}"
  done < <(/usr/bin/grep -Fn -- "${literal}" "${EVALUATOR}")
  [[ -n "${last}" ]] || return 1
  printf '%s\n' "${last}"
}

FIRST_MUTATION_LINE="$(active_line_of \
  'TEMPORARY_ROOT="$(run_as_evaluator /usr/bin/mktemp -d')" || {
  printf '%s\n' 'installed consent evaluator has no recognized first mutation boundary' >&2
  exit 1
}
readonly FIRST_MUTATION_LINE

assert_preflight() {
  local label="$1"
  local literal="$2"
  local line
  line="$(active_line_of "${literal}")" || {
    printf 'installed consent evaluator lacks active preflight guard: %s\n' "${label}" >&2
    exit 1
  }
  if ((line >= FIRST_MUTATION_LINE)); then
    printf 'installed consent evaluator runs preflight guard after mutation boundary: %s\n' \
      "${label}" >&2
    exit 1
  fi
}

assert_preflight acknowledgement \
  'A_QUO_INSTALLED_CONSENT_LIFECYCLE_ACKNOWLEDGEMENT:-'
assert_preflight root 'if [[ "${EUID}" -ne 0 ]]'
assert_preflight marker-file 'require_real_regular_file "${DISPOSABLE_MARKER}"'
assert_preflight marker-mode "'0:0 400 regular file'"
assert_preflight marker-bytes 'if ! /usr/bin/cmp -s -- "${DISPOSABLE_MARKER}" <('
assert_preflight evaluator-account \
  'ACCOUNT_RECORD="$(/usr/bin/getent passwd "${EVALUATOR_ACCOUNT}")"'
assert_preflight evaluator-home 'require_safe_user_directory "${EVALUATOR_HOME}"'
assert_preflight cross-uid-account \
  'CROSS_UID_RECORD="$(/usr/bin/getent passwd "${CROSS_UID_ACCOUNT}")"'
assert_preflight a-quo-package-pin \
  '[[ "${OBSERVED_A_QUO_QUERY}" == "${EXPECTED_A_QUO_QUERY}" ]]'
assert_preflight omarchy-package-pin \
  '[[ "${OBSERVED_OMARCHY_QUERY}" == "${EXPECTED_OMARCHY_QUERY}" ]]'
assert_preflight package-integrity '/usr/bin/pacman -Qkk a-quo'
assert_preflight installed-cli-path 'require_safe_root_path "${A_QUO}" executable'
assert_preflight installed-daemon-path 'require_safe_root_path "${A_QUO_DAEMON}" executable'
assert_preflight installed-helper-path 'require_safe_root_path "${A_QUO_CONSENT}" executable'
assert_preflight installed-unit-path 'require_safe_root_path "${SERVICE_UNIT}" regular'
assert_preflight empty-registry-path 'require_safe_root_path "${PROVIDER_REGISTRY}" regular'
assert_preflight trusted-font-path 'require_safe_root_path "${TRUSTED_FONT}" regular'
assert_preflight package-owner \
  '[[ "$(/usr/bin/pacman -Qoq -- "${package_path}")" == a-quo ]]'
assert_preflight font-package-integrity '/usr/bin/pacman -Qkk "${FONT_PACKAGE}"'
assert_preflight font-digest 'FONT_SHA256_BEFORE="$(sha256_file "${TRUSTED_FONT}")"'
assert_preflight empty-registry-bytes 'if ! /usr/bin/cmp -s -- "${PROVIDER_REGISTRY}" <('
assert_preflight wayland-runtime 'require_safe_user_directory "${EVALUATOR_RUNTIME_DIRECTORY}"'
assert_preflight wayland-socket 'if [[ -L "${WAYLAND_SOCKET}" || ! -S "${WAYLAND_SOCKET}"'
assert_preflight manager-environment-snapshot \
  'MANAGER_ENVIRONMENT="$(run_systemctl show-environment)"'
assert_preflight manager-environment-bound \
  'user-manager environment exceeds the evaluator byte or line bound'
assert_preflight manager-wayland \
  'user manager lacks the exact Wayland display; evaluator will not import or change it'
assert_preflight manager-runtime \
  'user manager lacks the exact runtime directory; evaluator will not import or change it'
assert_preflight manager-home \
  'user manager lacks the exact evaluator home; evaluator will not import or change it'
assert_preflight manager-data-home \
  'user manager has a divergent XDG_DATA_HOME; use the documented service drop-in instead'
assert_preflight manager-config-home \
  'user manager has a divergent XDG_CONFIG_HOME; enablement state would escape the evaluator boundary'
assert_preflight manager-loader-env 'user manager contains a loader-injection variable'
assert_preflight effective-fragment \
  'effective user service does not use the installed unit fragment'
assert_preflight no-drop-ins \
  'user service has drop-ins; the stock installed contract cannot be evaluated'
assert_preflight current-unit-cache 'NeedDaemonReload'
assert_preflight effective-command 'EFFECTIVE_EXEC_START='
assert_preflight effective-control-group 'KillMode'
assert_preflight initially-disabled \
  'installed user service must initially be disabled'
assert_preflight initially-inactive \
  'installed user service must initially be inactive'
assert_preflight absent-runtime \
  'A Quo runtime directory must be absent before the one-shot evaluator'
assert_preflight absent-store \
  'default evaluator persona state must be absent before the one-shot run'
assert_preflight private-state-parent \
  'for state_parent in "${EVALUATOR_HOME}/.local" "${EVALUATOR_HOME}/.local/share"'
assert_preflight private-service-parents "for service_parent in \\"
assert_preflight empty-enablement \
  'evaluator service-enable directory must initially be empty'
assert_preflight enablement-directory-identity \
  'USER_ENABLE_DIRECTORY_IDENTITY="$(/usr/bin/stat -c'
assert_preflight artifact-path 'require_real_regular_file "${ARTIFACT_SOURCE}"'
assert_preflight artifact-size \
  'signing artifact must be between 1 byte and 64 MiB for this evaluator'
assert_preflight artifact-canonical \
  'signing artifact input must already be canonical and contain no symlink component'
assert_preflight artifact-digest \
  'signing artifact input does not match its caller-supplied SHA-256 pin'
assert_preflight evaluator-artifact-read \
  'evaluator account observed different signing artifact bytes'
assert_preflight no-existing-daemon \
  'an installed A Quo daemon is already running before evaluation'

ACK_LINE="$(active_line_of \
  'A_QUO_INSTALLED_CONSENT_LIFECYCLE_ACKNOWLEDGEMENT:-')"
ROOT_LINE="$(active_line_of 'if [[ "${EUID}" -ne 0 ]]')"
MARKER_LINE="$(active_line_of 'require_real_regular_file "${DISPOSABLE_MARKER}"')"
readonly ACK_LINE ROOT_LINE MARKER_LINE
if ((ACK_LINE >= ROOT_LINE || ROOT_LINE >= MARKER_LINE || \
  MARKER_LINE >= FIRST_MUTATION_LINE)); then
  printf '%s\n' 'acknowledgement/root/marker/mutation gates are not in fail-first order' >&2
  exit 1
fi

for required_literal in \
  "schema=a-quo-disposable-omarchy-evaluator-v1" \
  "account=a-quo-evaluator" \
  "readonly EVALUATOR_HOME='/home/a-quo-evaluator'" \
  "readonly A_QUO='/usr/bin/a-quo'" \
  "readonly A_QUO_DAEMON='/usr/bin/a-quo-daemon'" \
  "readonly A_QUO_CONSENT='/usr/lib/a-quo/a-quo-consent'" \
  "readonly SERVICE_UNIT='/usr/lib/systemd/user/a-quo-daemon.service'" \
  'systemctl --user --no-pager' \
  'startup with the store absent did not end in an exact exit-code failure' \
  'startup with the store absent did not record the daemon fail-closed status' \
  'missing-store service failure left a consent socket entry' \
  'system does not have exactly one installed daemon under the evaluator UID' \
  'packaged daemon lacks the exact evaluator home' \
  'packaged daemon lacks the exact runtime directory' \
  'packaged daemon lacks the exact Wayland display' \
  'packaged daemon inherited a divergent data home' \
  'packaged daemon inherited a divergent config home' \
  'explicit service enablement did not create the sole expected installed-unit link' \
  'cross-UID probe account could not execute the control command' \
  'cross-UID socket probe failed for a reason other than private-directory denial' \
  '/usr/bin/setsid --wait /usr/bin/runuser' \
  '/usr/bin/bash -c' \
  'REQUEST_CLEANUP_UNCERTAIN=true' \
  'request-sign "${ARTIFACT}"' \
  'request process group retained a descendant after its leader exited' \
  '/usr/bin/kill -TERM -- "-${REQUEST_PGID}"' \
  '/usr/bin/kill -KILL -- "-${REQUEST_PGID}"' \
  '"${REQUEST_PGID}:${REQUEST_PGID}:${REQUEST_STARTTIME}:"[!Z]' \
  '"${request_cleanup_status}" -eq 0' \
  '"${service_cleanup_status}" -eq 0' \
  'consent helper is not a direct daemon child' \
  'DBUS_SESSION_BUS_ADDRESS|DISPLAY|PATH|SSH_AUTH_SOCK|SSH_ASKPASS|LD_PRELOAD|LD_LIBRARY_PATH' \
  'DECLINE TEST: helper inspection passed; use the real A Quo window to decline now' \
  'APPROVAL TEST: helper inspection passed; compare digest' \
  'declined request created a proof path' \
  'approved proof unexpectedly verified altered artifact bytes' \
  'ordinary restart reused the prior daemon generation' \
  'forced daemon death did not settle and remove its runtime directory' \
  'forced-death restart reused the prior daemon generation' \
  'final service disable did not restore the exact empty enablement directory' \
  'FONT_SHA256_AFTER="$(sha256_file "${TRUSTED_FONT}")"' \
  'evaluator_owned_store_and_work_roots_cleanup: "verified_before_evidence_emission"' \
  'input_origin: "not_machine_verifiable"' \
  'peer_credential_rejection: "not_exercised_beyond_filesystem_denial"' \
  'secure_attention: "not_established"' \
  'accessibility: "not_evaluated"' \
  'behavioral_analysis: "not_run"' \
  'omarchy_plugin_lifecycle: "not_run"' \
  'plugin_safety: "not_established"' \
  'clean_system_claim: "not_established_marker_only"'; do
  active_line_of "${required_literal}" >/dev/null || {
    printf 'installed consent evaluator is missing active contract literal: %s\n' \
      "${required_literal}" >&2
    exit 1
  }
done

if /usr/bin/grep -Eiq -- \
  '(cargo run|mise exec|/target/|auto.?approve|test.?approver|wtype|ydotool|xdotool|dotool|busctl|gdbus|dbus-send|notify-send|import-environment|set-environment)' \
  "${EVALUATOR}"; then
  printf '%s\n' \
    'consent evaluator contains a build-tree, approval-bypass, UI-injection, bus-authority, or environment-mutation path' >&2
  exit 1
fi
if /usr/bin/grep -Eq -- 'show-environment[[:space:]]*\|' "${EVALUATOR}"; then
  printf '%s\n' 'consent evaluator streams manager environment into an early-exit consumer' >&2
  exit 1
fi

if /usr/bin/grep -Fq -- '/usr/bin/rm -rf' "${EVALUATOR}"; then
  printf '%s\n' 'consent evaluator contains a recursive deletion path' >&2
  exit 1
fi
if /usr/bin/grep -Eq -- '^[[:space:]]*/usr/bin/rm[[:space:]]+-' "${EVALUATOR}"; then
  printf '%s\n' 'consent evaluator contains a root-privileged file-removal command' >&2
  exit 1
fi
if /usr/bin/grep -Eq -- \
  '(^|[[:space:]])[0-9]*>>?"?\$\{TEMPORARY_ROOT\}' "${EVALUATOR}"; then
  printf '%s\n' 'consent evaluator contains a root-shell redirection into evaluator state' >&2
  exit 1
fi
if [[ "$(/usr/bin/grep -Fc "/usr/bin/rmdir -- \"\${DEFAULT_STORE_ROOT}\"" \
  "${EVALUATOR}")" -ne 1 || \
  "$(/usr/bin/grep -Fc "/usr/bin/rmdir -- \"\${TEMPORARY_ROOT}\"" \
    "${EVALUATOR}")" -ne 1 ]]; then
  printf '%s\n' 'consent evaluator lacks its two identity-checked non-recursive directory removals' >&2
  exit 1
fi

if /usr/bin/grep -Eq -- \
  '(mv|cp|install|chmod|chown|rm)[[:space:]].*A_QUO_CONSENT' "${EVALUATOR}"; then
  printf '%s\n' 'consent evaluator attempts to mutate the installed trusted helper' >&2
  exit 1
fi

STORE_CLEANUP_LINE="$(last_active_line_of 'if ! remove_disposable_store; then')"
WORK_CLEANUP_LINE="$(last_active_line_of 'if ! remove_temporary_root; then')"
TRAP_DISABLE_LINE="$(last_active_line_of 'trap - EXIT INT TERM HUP')"
EVIDENCE_OUTPUT_LINE="$(last_active_line_of "printf '%s\\n' \"\${EVIDENCE_JSON}\"")"
readonly STORE_CLEANUP_LINE WORK_CLEANUP_LINE TRAP_DISABLE_LINE EVIDENCE_OUTPUT_LINE
if ((STORE_CLEANUP_LINE >= WORK_CLEANUP_LINE || \
  WORK_CLEANUP_LINE >= TRAP_DISABLE_LINE || \
  TRAP_DISABLE_LINE >= EVIDENCE_OUTPUT_LINE)); then
  printf '%s\n' 'evidence can be emitted before explicit cleanup and trap retirement' >&2
  exit 1
fi

printf '%s\n' 'installed A Quo consent lifecycle evaluator passed its non-mutating contract checks'
