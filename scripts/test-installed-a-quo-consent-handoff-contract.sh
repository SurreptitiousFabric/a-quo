#!/usr/bin/env bash
# shellcheck disable=SC2016,SC1003 # Exact source literals include trailing backslashes.

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
require_source_section_sha256 handoff-manifest \
  'print_handoff_manifest() {' 'validate_handoff_inventory() {' \
  80dd4948644e9240e4ae9e564020757a6f804dd25b9e67da52e59aa723f705bd
require_source_section_sha256 handoff-inventory-validation \
  'validate_handoff_inventory() {' 'create_handoff_outputs() {' \
  1f62982b2fbe697787d0103498410e531b64fc85a41bd1cb73a8df4cdf4fde9a
require_source_section_sha256 handoff-publication \
  'create_handoff_outputs() {' 'remove_temporary_root() {' \
  f374dcab80fec677966627ebbaace6bdaaab87cdb6ebc0b4ccea61b431641627
require_source_section_sha256 installed-daemon-request-routing \
  'start_sign_request() {' 'finish_sign_request() {' \
  97a0e2db56b08eb9e4286d950acba1d7136dcec2a11c56231e7b48ec9fe24042
require_source_section_sha256 joined-v2-approval-and-tamper-checks \
  "APPROVED_PROOF_V2=''" 'run_systemctl stop --no-block "${SERVICE_NAME}"' \
  caf86f22554e1b6ca26fbed902ca177650f108495ffe0c86644507452a688717

FIRST_MUTATION_LINE="$(active_line_of \
  'TEMPORARY_ROOT="$(run_as_evaluator /usr/bin/mktemp -d')" || {
  printf '%s\n' 'installed consent evaluator lacks its mutation boundary' >&2
  exit 1
}
readonly FIRST_MUTATION_LINE

for preflight_literal in \
  'A_QUO_EVALUATION_PROFILE_ID' \
  'A_QUO_EVALUATION_PROFILE_SHA256' \
  'A_QUO_EVALUATION_TARGET_KIND' \
  'A_QUO_EVALUATION_ARCHITECTURE' \
  'A_QUO_EVALUATION_EVIDENCE_NAMESPACE' \
  'a-quo-omarchy4-aarch64-dec29fa-v2|3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6d|virtual-reference-target|aarch64|phase-a-aarch64-dec29fa' \
  'evaluation target binding is not the exact AArch64 reference profile tuple' \
  'A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT+x' \
  'handoff root must be the exact joined package-lifecycle consent path' \
  'handoff root overlaps retained state, service configuration, or evaluator work paths' \
  'require_owned_nonwritable_user_directory "${HANDOFF_CURRENT_PATH}"' \
  'handoff root must already be canonical and contain no symlink component' \
  'handoff root must be evaluator-owned mode 0700' \
  'handoff root must share the evaluator-home filesystem' \
  'handoff root must be empty before evaluation' \
  'HANDOFF_ROOT_IDENTITY="$(/usr/bin/stat -c' \
  'require_environment A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2' \
  'require_environment A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256' \
  'A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256 must be lowercase SHA-256' \
  'v2 signing artifact input must already be canonical and contain no symlink component' \
  'v2 signing artifact must be distinct from the v1 signing artifact' \
  'v2 signing artifact input does not match its caller-supplied SHA-256 pin' \
  'evaluator account observed different v2 signing artifact bytes'; do
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
  'target_profile: {' \
  'profile_id: $profile_id' \
  'profile_sha256: $profile_sha256' \
  'binding_role: "package-target-policy"' \
  'target_kind: $target_kind' \
  'architecture: $architecture' \
  'evidence_namespace: $evidence_namespace' \
  'cross_profile_evidence_accepted: false' \
  'aarch64_gate_satisfied_by_x86_64: false' \
  'readonly EXPECTED_HANDOFF_ROOT="${EVALUATOR_HOME}/.local/share/a-quo-installed-package-lifecycle-v1/trusted-consent-v2"' \
  'HANDOFF_PROOF_V1="${HANDOFF_ROOT}/proof-v1.json"' \
  'HANDOFF_PROOF_V2="${HANDOFF_ROOT}/proof-v2.json"' \
  'HANDOFF_MANIFEST="${HANDOFF_ROOT}/handoff.manifest"' \
  'handoff_root_is_pinned()' \
  'clear_handoff_outputs()' \
  'validate_retained_store()' \
  'validate_handoff_inventory()' \
  'create_handoff_outputs()' \
  '"${ARTIFACT_V2_SOURCE}" "${ARTIFACT_V2}"' \
  '/usr/bin/ln -- "${APPROVED_PROOF_V1}" "${HANDOFF_PROOF_V1}"' \
  '/usr/bin/ln -- "${APPROVED_PROOF_V2}" "${HANDOFF_PROOF_V2}"' \
  '/usr/bin/ln -- "${manifest_source}" "${HANDOFF_MANIFEST}"' \
  '"${EVALUATOR_UID}:${EVALUATOR_GID} 600 regular file"' \
  'start_sign_request()' \
  '  start_sign_request \' \
  '    "${ARTIFACT_V2}" \' \
  'request-sign "${ARTIFACT}"' \
  'request-sign artifact is not an exact authenticated evaluator snapshot' \
  'DECLINE TEST: helper inspection passed; use the real A Quo window to decline now' \
  'A Quo evaluator: APPROVE V1 only after comparing the exact digest' \
  'A Quo evaluator: APPROVE V2 only after comparing the exact digest' \
  'approved v1 proof does not verify for the exact artifact and expected key' \
  'approved v2 proof does not verify for the exact artifact and expected key' \
  'approved proof unexpectedly verified altered artifact bytes' \
  'approved v2 proof unexpectedly verified altered artifact bytes' \
  'post-unbind persona store does not contain the exact public handoff state' \
  'approved v1 proof did not verify after the signer reference was removed' \
  'approved v2 proof did not verify after the signer reference was removed' \
  'retained_public_state_signing_locator_removed_original_disposable_key_paths_removed' \
  'same_uid_private_key_copy_or_access_excluded: false' \
  'persona_store_sha256: $handoff_store_sha256' \
  'retained public persona state changed during final handoff verification' \
  'retained public persona store bytes changed during final handoff verification' \
  'caller_pinned_omarchy_plugin_v1_package_structural_validation_deferred_to_consumer' \
  'caller_pinned_omarchy_plugin_v2_package_structural_validation_deferred_to_consumer' \
  'proof_v1_sha256: $handoff_proof_v1_sha256' \
  'proof_v2_sha256: $handoff_proof_v2_sha256' \
  'decline_v1: "no_proof_returned"' \
  'approval_v1: "proof_returned_and_verified"' \
  'approval_v2: "proof_returned_and_verified"' \
  'artifact_v1_sha256: $artifact_sha256' \
  'artifact_v2_sha256: $artifact_v2_sha256' \
  'altered_bytes_v1: "verification_refused"' \
  'altered_bytes_v2: "verification_refused"' \
  'urn:a-quo:evidence:installed-consent-lifecycle:v2' \
  '-printf . | /usr/bin/wc -c)" -eq 3' \
  '"$(/usr/bin/wc -l <"${manifest_source}")" -eq 17' \
  'input_origin: "not_machine_verifiable"' \
  'secure_attention: "not_established"' \
  'next_evaluator: "not_run_by_this_evaluator"' \
  'omarchy_plugin_lifecycle: "not_run"' \
  'behavioral_analysis: "not_run"' \
  'plugin_safety: "not_established"' \
  'clean_system_claim: "not_established_marker_only"'; do
  active_line_of "${required_literal}" >/dev/null || {
    printf 'installed consent handoff lacks contract literal: %s\n' \
      "${required_literal}" >&2
    exit 1
  }
done

manifest_previous=0
for manifest_literal in \
  "'format=a-quo-installed-omarchy-preconsented-handoff-v2'" \
  '"store_path=${DEFAULT_STORE}"' \
  '"artifact_v1_sha256=${ARTIFACT_EXPECTED_SHA256}"' \
  '"artifact_v1_size=${ARTIFACT_SIZE}"' \
  "'proof_v1_file=proof-v1.json'" \
  '"proof_v1_sha256=${HANDOFF_PROOF_V1_SHA256}"' \
  '"proof_v1_size=${HANDOFF_PROOF_V1_SIZE}"' \
  '"artifact_v2_sha256=${ARTIFACT_V2_EXPECTED_SHA256}"' \
  '"artifact_v2_size=${ARTIFACT_V2_SIZE}"' \
  "'proof_v2_file=proof-v2.json'" \
  '"proof_v2_sha256=${HANDOFF_PROOF_V2_SHA256}"' \
  '"proof_v2_size=${HANDOFF_PROOF_V2_SIZE}"' \
  '"persona_id=${PERSONA_ID}"' \
  '"key_fingerprint=${KEY_FINGERPRINT}"' \
  "'trusted_consent_v1=operator-approved-installed-daemon'" \
  "'trusted_consent_v2=operator-approved-installed-daemon'" \
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
DECLINE_LINE="$(active_line_of \
  'A Quo evaluator: DECLINE this exact request')"
APPROVE_V1_LINE="$(active_line_of \
  'A Quo evaluator: APPROVE V1 only after comparing the exact digest')"
APPROVE_V2_LINE="$(active_line_of \
  'A Quo evaluator: APPROVE V2 only after comparing the exact digest')"
FINAL_SERVICE_STOP_LINE="$(last_active_line_of \
  'run_systemctl stop --no-block "${SERVICE_NAME}"')"
STORE_VALIDATE_LINE="$(active_line_of 'validate_retained_store ||')"
CREATE_HANDOFF_LINE="$(last_active_line_of 'create_handoff_outputs ||')"
WORK_CLEANUP_LINE="$(last_active_line_of 'if ! remove_temporary_root; then')"
FINAL_VERIFY_V1_LINE="$(last_active_line_of \
  "fail 'retained v1 handoff proof does not verify for the caller-pinned v1 artifact'")"
FINAL_VERIFY_V2_LINE="$(last_active_line_of \
  "fail 'retained v2 handoff proof does not verify for the caller-pinned v2 artifact'")"
FINAL_STORE_RECHECK_LINE="$(last_active_line_of \
  "fail 'retained public persona store bytes changed during final handoff verification'")"
FINAL_HANDOFF_LINE="$(last_active_line_of 'validate_handoff_inventory 1 ||')"
TRAP_DISABLE_LINE="$(last_active_line_of 'trap - EXIT INT TERM HUP')"
readonly DECLINE_LINE APPROVE_V1_LINE APPROVE_V2_LINE FINAL_SERVICE_STOP_LINE
readonly UNBIND_LINE KEY_DELETE_LINE STORE_VALIDATE_LINE CREATE_HANDOFF_LINE
readonly WORK_CLEANUP_LINE FINAL_VERIFY_V1_LINE FINAL_VERIFY_V2_LINE FINAL_STORE_RECHECK_LINE
readonly FINAL_HANDOFF_LINE TRAP_DISABLE_LINE
if ((DECLINE_LINE >= APPROVE_V1_LINE || APPROVE_V1_LINE >= APPROVE_V2_LINE || \
  APPROVE_V2_LINE >= FINAL_SERVICE_STOP_LINE || \
  FINAL_SERVICE_STOP_LINE >= UNBIND_LINE || \
  UNBIND_LINE >= KEY_DELETE_LINE || KEY_DELETE_LINE >= STORE_VALIDATE_LINE || \
  STORE_VALIDATE_LINE >= CREATE_HANDOFF_LINE || \
  CREATE_HANDOFF_LINE >= WORK_CLEANUP_LINE || \
  WORK_CLEANUP_LINE >= FINAL_VERIFY_V1_LINE || \
  FINAL_VERIFY_V1_LINE >= FINAL_VERIFY_V2_LINE || \
  FINAL_VERIFY_V2_LINE >= FINAL_STORE_RECHECK_LINE || \
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

if [[ "${A_QUO_CONSENT_HANDOFF_CONTRACT_MUTANT_CHILD:-0}" != 1 ]]; then
  MUTANT_ROOT="$(/usr/bin/mktemp -d \
    /tmp/a-quo-consent-handoff-contract.XXXXXX)"
  readonly MUTANT_ROOT
  MUTANT_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- \
    "${MUTANT_ROOT}")"
  readonly MUTANT_ROOT_IDENTITY
  readonly MUTANT_EVALUATOR="${MUTANT_ROOT}/test-installed-a-quo-consent-lifecycle.sh"
  readonly MUTANT_CONTRACT="${MUTANT_ROOT}/test-installed-a-quo-consent-handoff-contract.sh"
  /usr/bin/install -m 0700 -- "$0" "${MUTANT_CONTRACT}"

  remove_mutant_root() {
    [[ "${MUTANT_ROOT}" == /tmp/a-quo-consent-handoff-contract.* && \
      -d "${MUTANT_ROOT}" && ! -L "${MUTANT_ROOT}" && \
      "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "${MUTANT_ROOT}")" == \
        "${MUTANT_ROOT_IDENTITY}" ]] || return 1
    /usr/bin/rm -rf -- "${MUTANT_ROOT}"
  }
  trap 'remove_mutant_root || exit 1' EXIT

  assert_mutant_rejected() {
    local label="$1"
    local next_evaluator="$2"
    local output
    local status
    /usr/bin/install -m 0700 -- "${next_evaluator}" "${MUTANT_EVALUATOR}"
    /usr/bin/bash -n "${MUTANT_EVALUATOR}" || {
      printf 'installed consent handoff source mutant is not syntactically valid: %s\n' \
        "${label}" >&2
      exit 1
    }
    set +e
    output="$(
      /usr/bin/env -i PATH=/usr/bin:/bin \
        A_QUO_CONSENT_HANDOFF_CONTRACT_MUTANT_CHILD=1 \
        /usr/bin/bash "${MUTANT_CONTRACT}" 2>&1
    )"
    status="$?"
    set -e
    if [[ "${status}" -eq 0 ]]; then
      printf 'installed consent handoff contract accepted hostile mutant %s: %s\n' \
        "${label}" "${output}" >&2
      exit 1
    fi
  }

  reject_source_mutant() {
    local label="$1"
    local old_line="$2"
    local new_line="$3"
    local next_evaluator="${MUTANT_ROOT}/evaluator.next"
    [[ "$(/usr/bin/grep -Fxc -- "${old_line}" "${EVALUATOR}")" -eq 1 ]] || {
      printf 'installed consent handoff source mutation seam is not unique: %s\n' \
        "${label}" >&2
      exit 1
    }
    /usr/bin/env OLD_LINE="${old_line}" NEW_LINE="${new_line}" /usr/bin/awk '
      $0 == ENVIRON["OLD_LINE"] && replaced == 0 {
        print ENVIRON["NEW_LINE"]
        replaced = 1
        next
      }
      { print }
      END { if (replaced != 1) exit 1 }
    ' "${EVALUATOR}" >"${next_evaluator}" || {
      printf 'installed consent handoff source mutant could not be built: %s\n' \
        "${label}" >&2
      exit 1
    }
    assert_mutant_rejected "${label}" "${next_evaluator}"
  }

  reject_adjacent_field_swap() {
    local label="$1"
    local first_line="$2"
    local second_line="$3"
    local next_evaluator="${MUTANT_ROOT}/evaluator.next"
    [[ "$(/usr/bin/grep -Fxc -- "${first_line}" "${EVALUATOR}")" -eq 1 && \
      "$(/usr/bin/grep -Fxc -- "${second_line}" "${EVALUATOR}")" -eq 1 ]] || {
      printf 'installed consent handoff field-swap seam is not unique: %s\n' \
        "${label}" >&2
      exit 1
    }
    /usr/bin/env FIRST_LINE="${first_line}" SECOND_LINE="${second_line}" \
      /usr/bin/awk '
        $0 == ENVIRON["FIRST_LINE"] && held == "" {
          held = $0
          next
        }
        held != "" {
          if ($0 != ENVIRON["SECOND_LINE"]) exit 1
          print $0
          print held
          held = ""
          swapped = 1
          next
        }
        { print }
        END { if (held != "" || swapped != 1) exit 1 }
      ' "${EVALUATOR}" >"${next_evaluator}" || {
        printf 'installed consent handoff field-order mutant could not be built: %s\n' \
          "${label}" >&2
        exit 1
      }
    assert_mutant_rejected "${label}" "${next_evaluator}"
  }

  reject_source_mutant second-artifact-substitution \
    '    "${ARTIFACT_V2_SOURCE}" "${ARTIFACT_V2}"' \
    '    "${ARTIFACT_SOURCE}" "${ARTIFACT_V2}"'
  reject_source_mutant missing-v2-approval \
    '  start_sign_request \' \
    '  /usr/bin/true \'
  reject_source_mutant swapped-v2-approval-artifact \
    '    "${ARTIFACT_V2}" \' \
    '    "${ARTIFACT_V1}" \'
  reject_source_mutant missing-v2-proof-publication \
    '  run_as_evaluator /usr/bin/ln -- "${APPROVED_PROOF_V2}" "${HANDOFF_PROOF_V2}" || return 1' \
    '  /usr/bin/true || return 1'
  reject_source_mutant swapped-v2-proof-publication \
    '  run_as_evaluator /usr/bin/ln -- "${APPROVED_PROOF_V2}" "${HANDOFF_PROOF_V2}" || return 1' \
    '  run_as_evaluator /usr/bin/ln -- "${APPROVED_PROOF_V1}" "${HANDOFF_PROOF_V2}" || return 1'
  reject_source_mutant handoff-inventory-count \
    '    -printf . | /usr/bin/wc -c)" -eq 3 ]] || return 1' \
    '    -printf . | /usr/bin/wc -c)" -eq 2 ]] || return 1'
  reject_adjacent_field_swap handoff-manifest-field-order \
    '    "artifact_v1_size=${ARTIFACT_SIZE}" \' \
    "    'proof_v1_file=proof-v1.json' \\"

  trap - EXIT
  remove_mutant_root || {
    printf '%s\n' 'installed consent handoff mutant root cleanup failed' >&2
    exit 1
  }
fi

printf '%s\n' 'installed A Quo consent handoff passed its non-mutating contract checks'
