#!/usr/bin/env bash
# shellcheck disable=SC2016 # Exact evaluator source literals must not expand here.

set -euo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
readonly EVALUATOR="${SCRIPT_DIRECTORY}/test-installed-a-quo-consent-lifecycle.sh"

[[ -f "${EVALUATOR}" && ! -L "${EVALUATOR}" ]] || {
  printf '%s\n' 'installed consent evaluator is missing or is a symlink' >&2
  exit 1
}

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

source_section_sha256() {
  local start_line="$1"
  local end_line="$2"
  local digest
  [[ "$(/usr/bin/grep -Fxc -- "${start_line}" "${EVALUATOR}")" -eq 1 && \
    "$(/usr/bin/grep -Fxc -- "${end_line}" "${EVALUATOR}")" -eq 1 ]] || return 1
  digest="$({
    /usr/bin/awk -v start="${start_line}" -v end="${end_line}" '
      $0 == start { copying = 1 }
      copying && $0 == end { ended = 1; exit }
      copying { print }
      END { if (!copying || !ended) exit 1 }
    ' "${EVALUATOR}" | /usr/bin/sha256sum
  })" || return 1
  printf '%s\n' "${digest%% *}"
}

require_source_section_sha256() {
  local label="$1"
  local start_line="$2"
  local end_line="$3"
  local expected="$4"
  local observed
  observed="$(source_section_sha256 "${start_line}" "${end_line}")" || {
    printf 'installed consent handoff section is not uniquely bounded: %s\n' \
      "${label}" >&2
    exit 1
  }
  [[ "${observed}" == "${expected}" ]] || {
    printf 'installed consent handoff security section changed: %s\n' \
      "${label}" >&2
    exit 1
  }
}

# These whole-function pins reject an inserted early success, including a
# helper body reduced to `return 0`, until the contract is deliberately updated.
require_source_section_sha256 retained-store-validation \
  'validate_retained_store() {' 'print_handoff_manifest() {' \
  1d140eaeafc2c6dabf744c313298bde8420c82b897a579a35752d8eba048d184
require_source_section_sha256 handoff-inventory-validation \
  'validate_handoff_inventory() {' 'create_handoff_outputs() {' \
  398bdc624afc358964e27bf0f01e06ccf1827e6700211d83cb48a0da0f2ff06a
require_source_section_sha256 handoff-publication \
  'create_handoff_outputs() {' 'remove_temporary_root() {' \
  6bfcf3d493588202b301ea5ad28bc44969f72d5b4ac01ad8ec708f91d9b2d64b

FIRST_MUTATION_LINE="$(active_line_of \
  'TEMPORARY_ROOT="$(run_as_evaluator /usr/bin/mktemp -d')" || {
  printf '%s\n' 'installed consent evaluator lacks its mutation boundary' >&2
  exit 1
}
readonly FIRST_MUTATION_LINE

for preflight_literal in \
  'A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT+x' \
  'handoff root must be the exact joined package-lifecycle consent path' \
  'handoff root overlaps retained state, service configuration, or evaluator work paths' \
  'require_owned_nonwritable_user_directory "${HANDOFF_CURRENT_PATH}"' \
  'handoff root must already be canonical and contain no symlink component' \
  'handoff root must be evaluator-owned mode 0700' \
  'handoff root must share the evaluator-home filesystem' \
  'handoff root must be empty before evaluation' \
  'HANDOFF_ROOT_IDENTITY="$(/usr/bin/stat -c'; do
  line="$(active_line_of "${preflight_literal}")" || {
    printf 'installed consent handoff lacks preflight guard: %s\n' \
      "${preflight_literal}" >&2
    exit 1
  }
  ((line < FIRST_MUTATION_LINE)) || {
    printf 'installed consent handoff guard follows mutation boundary: %s\n' \
      "${preflight_literal}" >&2
    exit 1
  }
done

for required_literal in \
  'readonly EXPECTED_HANDOFF_ROOT="${EVALUATOR_HOME}/.local/share/a-quo-installed-package-lifecycle-v1/trusted-consent-v1"' \
  'HANDOFF_PROOF="${HANDOFF_ROOT}/proof.json"' \
  'HANDOFF_MANIFEST="${HANDOFF_ROOT}/handoff.manifest"' \
  'handoff_root_is_pinned()' \
  'clear_handoff_outputs()' \
  'validate_retained_store()' \
  'validate_handoff_inventory()' \
  'create_handoff_outputs()' \
  '/usr/bin/ln -- "${APPROVED_PROOF}" "${HANDOFF_PROOF}"' \
  '/usr/bin/ln -- "${manifest_source}" "${HANDOFF_MANIFEST}"' \
  '"${EVALUATOR_UID}:${EVALUATOR_GID} 600 regular file"' \
  'post-unbind persona store does not contain the exact public handoff state' \
  'retained_public_state_signing_locator_removed_original_disposable_key_paths_removed' \
  'same_uid_private_key_copy_or_access_excluded: false' \
  'persona_store_sha256: $handoff_store_sha256' \
  'retained public persona state changed during final handoff verification' \
  'retained public persona store bytes changed during final handoff verification' \
  'caller_pinned_omarchy_plugin_v1_package_structural_validation_deferred_to_consumer' \
  'next_evaluator: "not_run_by_this_evaluator"' \
  'omarchy_plugin_lifecycle: "not_run"' \
  'behavioral_analysis: "not_run"' \
  'plugin_safety: "not_established"'; do
  active_line_of "${required_literal}" >/dev/null || {
    printf 'installed consent handoff lacks contract literal: %s\n' \
      "${required_literal}" >&2
    exit 1
  }
done

manifest_previous=0
for manifest_literal in \
  "'format=a-quo-installed-omarchy-preconsented-handoff-v1'" \
  '"store_path=${DEFAULT_STORE}"' \
  '"artifact_sha256=${ARTIFACT_EXPECTED_SHA256}"' \
  '"artifact_size=${ARTIFACT_SIZE}"' \
  "'proof_file=proof.json'" \
  '"proof_sha256=${HANDOFF_PROOF_SHA256}"' \
  '"proof_size=${HANDOFF_PROOF_SIZE}"' \
  '"persona_id=${PERSONA_ID}"' \
  '"key_fingerprint=${KEY_FINGERPRINT}"' \
  "'trusted_consent=operator-approved-installed-daemon'" \
  "'input_origin=not-machine-verifiable'"; do
  manifest_line="$(active_line_of "${manifest_literal}")" || {
    printf 'installed consent handoff manifest lacks field: %s\n' \
      "${manifest_literal}" >&2
    exit 1
  }
  ((manifest_line > manifest_previous)) || {
    printf '%s\n' 'installed consent handoff manifest field order changed' >&2
    exit 1
  }
  manifest_previous="${manifest_line}"
done

[[ "$(/usr/bin/grep -Fc -- 'request-sign "${ARTIFACT}"' "${EVALUATOR}")" -eq 1 ]] || {
  printf '%s\n' 'installed consent evaluator must retain exactly one daemon request-sign route' >&2
  exit 1
}
if /usr/bin/grep -Eq -- \
  '"\$\{A_QUO\}"[[:space:]]+(sign|sign-with|sign-direct)([[:space:]]|$)' \
  "${EVALUATOR}"; then
  printf '%s\n' 'installed consent handoff introduced a direct signing route' >&2
  exit 1
fi

UNBIND_LINE="$(last_active_line_of \
  'run_a_quo persona key-unbind --fingerprint "${KEY_FINGERPRINT}"')"
KEY_DELETE_LINE="$(last_active_line_of \
  'run_as_evaluator /usr/bin/rm -f -- "${PRIVATE_KEY}" "${PRIVATE_KEY}.pub"')"
STORE_VALIDATE_LINE="$(active_line_of 'validate_retained_store ||')"
CREATE_HANDOFF_LINE="$(last_active_line_of 'create_handoff_outputs ||')"
WORK_CLEANUP_LINE="$(last_active_line_of 'if ! remove_temporary_root; then')"
FINAL_VERIFY_LINE="$(last_active_line_of \
  "fail 'retained handoff proof does not verify for the caller-pinned artifact'")"
FINAL_STORE_RECHECK_LINE="$(last_active_line_of \
  "fail 'retained public persona store bytes changed during final handoff verification'")"
FINAL_HANDOFF_LINE="$(last_active_line_of 'validate_handoff_inventory 1 ||')"
TRAP_DISABLE_LINE="$(last_active_line_of 'trap - EXIT INT TERM HUP')"
readonly UNBIND_LINE KEY_DELETE_LINE STORE_VALIDATE_LINE CREATE_HANDOFF_LINE
readonly WORK_CLEANUP_LINE FINAL_VERIFY_LINE FINAL_STORE_RECHECK_LINE
readonly FINAL_HANDOFF_LINE TRAP_DISABLE_LINE
if ((UNBIND_LINE >= KEY_DELETE_LINE || KEY_DELETE_LINE >= STORE_VALIDATE_LINE || \
  STORE_VALIDATE_LINE >= CREATE_HANDOFF_LINE || \
  CREATE_HANDOFF_LINE >= WORK_CLEANUP_LINE || \
  WORK_CLEANUP_LINE >= FINAL_VERIFY_LINE || \
  FINAL_VERIFY_LINE >= FINAL_STORE_RECHECK_LINE || \
  FINAL_STORE_RECHECK_LINE >= FINAL_HANDOFF_LINE || \
  FINAL_HANDOFF_LINE >= TRAP_DISABLE_LINE)); then
  printf '%s\n' 'installed consent handoff lifecycle ordering is unsafe' >&2
  exit 1
fi

CLEAR_HANDOFF_LINE="$(active_line_of 'clear_handoff_outputs || handoff_cleanup_status=1')"
TRAP_STORE_CLEANUP_LINE="$(active_line_of 'remove_disposable_store || cleanup_status=1')"
readonly CLEAR_HANDOFF_LINE TRAP_STORE_CLEANUP_LINE
if ((CLEAR_HANDOFF_LINE >= TRAP_STORE_CLEANUP_LINE)); then
  printf '%s\n' 'partial handoff cleanup does not precede retained-store cleanup' >&2
  exit 1
fi

printf '%s\n' 'installed A Quo consent handoff passed its non-mutating contract checks'
