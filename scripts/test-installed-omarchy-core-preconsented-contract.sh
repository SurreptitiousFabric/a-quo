#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract literals must not expand in this checker.

set -euo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
readonly EVALUATOR="${SCRIPT_DIRECTORY}/test-installed-omarchy-core-lifecycle.sh"

fail() {
  printf 'installed preconsented core contract failed: %s\n' "$1" >&2
  exit 1
}

first_active_line_of() {
  local source="$1"
  local literal="$2"
  local line
  local body
  local trimmed
  while IFS=: read -r line body; do
    trimmed="${body#"${body%%[![:space:]]*}"}"
    [[ "${trimmed}" != \#* ]] || continue
    printf '%s\n' "${line}"
    return 0
  done < <(/usr/bin/grep -Fn -- "${literal}" "${source}")
  return 1
}

last_active_line_of() {
  local source="$1"
  local literal="$2"
  local line
  local body
  local trimmed
  local last=''
  while IFS=: read -r line body; do
    trimmed="${body#"${body%%[![:space:]]*}"}"
    [[ "${trimmed}" != \#* ]] || continue
    last="${line}"
  done < <(/usr/bin/grep -Fn -- "${literal}" "${source}")
  [[ -n "${last}" ]] || return 1
  printf '%s\n' "${last}"
}

active_line_in_range() {
  local source="$1"
  local literal="$2"
  local first="$3"
  local last="$4"
  local line
  local body
  local trimmed
  while IFS=: read -r line body; do
    ((line >= first && line <= last)) || continue
    trimmed="${body#"${body%%[![:space:]]*}"}"
    [[ "${trimmed}" != \#* ]] || continue
    printf '%s\n' "${line}"
    return 0
  done < <(/usr/bin/grep -Fn -- "${literal}" "${source}")
  return 1
}

require_literal() {
  local source="$1"
  local literal="$2"
  /usr/bin/grep -Fq -- "${literal}" "${source}" || {
    printf 'missing source contract literal: %s\n' "${literal}" >&2
    return 1
  }
}

source_section_sha256() {
  local source="$1"
  local start_line="$2"
  local end_line="$3"
  local digest
  [[ "$(/usr/bin/grep -Fxc -- "${start_line}" "${source}")" -eq 1 && \
    "$(/usr/bin/grep -Fxc -- "${end_line}" "${source}")" -eq 1 ]] || return 1
  digest="$({
    /usr/bin/awk -v start="${start_line}" -v end="${end_line}" '
      $0 == start { copying = 1 }
      copying && $0 == end { ended = 1; exit }
      copying { print }
      END { if (!copying || !ended) exit 1 }
    ' "${source}" | /usr/bin/sha256sum
  })" || return 1
  printf '%s\n' "${digest%% *}"
}

validate_source() {
  local source="$1"
  [[ -f "${source}" && ! -L "${source}" ]] || return 1

  # Whole-function pins make an inserted early success—including replacing a
  # critical body with `return 0`—fail every hostile-mutant validation.
  [[ "$(source_section_sha256 "${source}" \
      'parse_preconsented_handoff() {' \
      'readonly HANDOFF_MANIFEST HANDOFF_PROOF_SOURCE HANDOFF_ROOT_IDENTITY')" == \
    7ac7afd5c2a06f9dc81a70f4fdc70362a21b39a5e55cecc55d5a561d363e008c ]] || return 1
  [[ "$(source_section_sha256 "${source}" \
      'snapshot_preconsented_proof() {' 'recheck_preconsented_handoff() {')" == \
    bd4a8d28744dbd6f1681df263026ee33a7412363560842c89353033adadea5e6 ]] || return 1
  [[ "$(source_section_sha256 "${source}" \
      'recheck_preconsented_handoff() {' 'assert_install_acknowledgement_gates() {')" == \
    1588c78cd1aa80aa5e6500ef67de63e843ddb70f23851d22c0be8524f21f0822 ]] || return 1

  local begin_count
  local end_count
  local begin_line
  local end_line
  begin_count="$(/usr/bin/grep -Fxc -- '# PRECONSENTED_JOINED_MODE_BEGIN' "${source}")"
  end_count="$(/usr/bin/grep -Fxc -- '# PRECONSENTED_JOINED_MODE_END' "${source}")"
  [[ "${begin_count}" -eq 1 && "${end_count}" -eq 1 ]] || return 1
  begin_line="$(/usr/bin/grep -Fn -- '# PRECONSENTED_JOINED_MODE_BEGIN' "${source}")"
  end_line="$(/usr/bin/grep -Fn -- '# PRECONSENTED_JOINED_MODE_END' "${source}")"
  begin_line="${begin_line%%:*}"
  end_line="${end_line%%:*}"
  ((begin_line < end_line)) || return 1

  local joined
  joined="$(/usr/bin/sed -n "${begin_line},${end_line}p" "${source}")"
  for joined_literal in \
    'run_preconsented_lifecycle()' \
    'snapshot_package "${PACKAGE_V1_SOURCE}" "${PACKAGE_V1_EXPECTED_SHA256}" "${package_v1}"' \
    'snapshot_preconsented_proof "${proof_v1}"' \
    'verify "${package_v1}"' \
    '--proof "${proof_v1}"' \
    'assert_install_acknowledgement_gates "${package_v1}" "${proof_v1}"' \
    'recheck_preconsented_handoff' \
    'mode: "preconsented_joined_v1_install_only"' \
    'signing_operations_this_core_invocation: "none"' \
    'private_key_access_this_core_invocation: "none"' \
    'trusted_consent: "not_established_by_core_alone"' \
    'reported_signing_consent: "operator_approved_installed_daemon_proof_consumed"' \
    'installation_trusted_consent: "not_run_preexisting_proof_only"' \
    'behavioral_analysis: "not_run"' \
    'plugin_safety: "not_established"' \
    'source_to_binary_provenance: "not_established"' \
    'clean_system_claim: "not_established_marker_only"' \
    'update: "not_run"' \
    'downgrade: "not_run"' \
    'uninstall: "not_run"' \
    'handoff_origin_authentication: "not_established_same_uid_directory"' \
    'persona_store_sha256: $persona_store_sha256' \
    'operator_input_origin: "not_machine_verifiable"' \
    'secure_attention: "not_established"'; do
    [[ "${joined}" == *"${joined_literal}"* ]] || return 1
  done

  [[ "$(/usr/bin/grep -Fc -- 'PACKAGE_V1_SOURCE' <<<"${joined}")" -eq 1 ]] || return 1
  [[ "$(/usr/bin/grep -Fc -- 'snapshot_preconsented_proof "${proof_v1}"' \
    <<<"${joined}")" -eq 1 ]] || return 1
  [[ "$(/usr/bin/grep -Fc -- 'recheck_preconsented_handoff' <<<"${joined}")" -eq 1 ]] ||
    return 1
  [[ "${joined}" != *'HANDOFF_PROOF_SOURCE'* ]] || return 1

  local joined_flat="${joined//$'\n'/ }"
  if /usr/bin/grep -Eq -- \
    '(^|[[:space:]])(sign|request-sign|ssh-keygen)([[:space:]]|$)|persona[[:space:]]+(create|key-add|key-bind|key-unbind)([[:space:]]|$)' \
    <<<"${joined_flat}"; then
    return 1
  fi

  local snapshot_package_line
  local snapshot_proof_line
  local verify_line
  local inspect_line
  local gates_line
  local install_line
  local recheck_line
  local evidence_line
  local cleanup_line
  local trap_retire_line
  local output_line
  snapshot_package_line="$(active_line_in_range "${source}" \
    'snapshot_package "${PACKAGE_V1_SOURCE}"' "${begin_line}" "${end_line}")" || return 1
  snapshot_proof_line="$(active_line_in_range "${source}" \
    'snapshot_preconsented_proof "${proof_v1}"' "${begin_line}" "${end_line}")" || return 1
  verify_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" verify "${package_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  inspect_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" omarchy inspect "${package_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  gates_line="$(active_line_in_range "${source}" \
    'assert_install_acknowledgement_gates "${package_v1}" "${proof_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  install_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" omarchy install "${package_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  recheck_line="$(active_line_in_range "${source}" 'recheck_preconsented_handoff' \
    "${begin_line}" "${end_line}")" || return 1
  evidence_line="$(active_line_in_range "${source}" 'evidence_json="$(' \
    "${begin_line}" "${end_line}")" || return 1
  cleanup_line="$(active_line_in_range "${source}" 'if ! remove_temporary_root; then' \
    "${begin_line}" "${end_line}")" || return 1
  trap_retire_line="$(active_line_in_range "${source}" 'trap - EXIT' \
    "${begin_line}" "${end_line}")" || return 1
  output_line="$(active_line_in_range "${source}" \
    'printf '\''%s\n'\'' "${evidence_json}"' "${begin_line}" "${end_line}")" || return 1
  if ((snapshot_package_line >= snapshot_proof_line || \
    snapshot_proof_line >= verify_line || verify_line >= inspect_line || \
    inspect_line >= gates_line || gates_line >= install_line || \
    install_line >= recheck_line || recheck_line >= evidence_line || \
    evidence_line >= cleanup_line || cleanup_line >= trap_retire_line || \
    trap_retire_line >= output_line)); then
    return 1
  fi

  for global_literal in \
    'readonly EXPECTED_PRECONSENTED_HANDOFF_ROOT="${EVALUATOR_HOME}/.local/share/a-quo-installed-package-lifecycle-v1/trusted-consent-v1"' \
    'A_QUO_INSTALLED_OMARCHY_PRECONSENTED_HANDOFF_ROOT' \
    'preconsented handoff root differs from the exact joined-lifecycle path' \
    'preconsented handoff root must be evaluator-owned mode 0700' \
    "\$'handoff.manifest\\nproof.json'" \
    'preconsented handoff manifest must contain exactly eleven fields' \
    'preconsented handoff manifest contains a control, carriage-return, NUL, or non-ASCII byte' \
    'preconsented handoff manifest must end with one LF byte' \
    'preconsented handoff proof identity changed before snapshot' \
    'private preconsented proof snapshot differs from the handoff digest' \
    'preconsented handoff proof changed while its private snapshot was created' \
    'preconsented handoff root identity changed during the core evaluation' \
    'preconsented handoff manifest changed during the core evaluation' \
    'preconsented handoff proof changed during the core evaluation' \
    'preconsented default persona store changed during the core evaluation' \
    'for refusal_case in missing-yes missing-analysis-acknowledgement' \
    'preconsented ${refusal_case} touched its absent store or plugin-directory sentinel' \
    'missing_yes_failed_before_store_or_plugin_io: true' \
    'missing_behavioral_analysis_acknowledgement_failed_before_store_or_plugin_io: true'; do
    require_literal "${source}" "${global_literal}" || return 1
  done

  local manifest_previous=0
  local manifest_line
  for manifest_literal in \
    "\"\${lines[0]}\" == 'format=a-quo-installed-omarchy-preconsented-handoff-v1'" \
    '"${lines[1]}" == "store_path=${DEFAULT_PERSONA_STORE}"' \
    '"${lines[2]}" =~ ^artifact_sha256=([0-9a-f]{64})$' \
    '"${lines[3]}" =~ ^artifact_size=([1-9][0-9]{0,7})$' \
    "\"\${lines[4]}\" == 'proof_file=proof.json'" \
    '"${lines[5]}" =~ ^proof_sha256=([0-9a-f]{64})$' \
    '"${lines[6]}" =~ ^proof_size=([1-9][0-9]{0,6})$' \
    '"${lines[7]}" =~ ^persona_id=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$' \
    '"${lines[8]}" =~ ^key_fingerprint=(SHA256:[A-Za-z0-9+/]{43})$' \
    "\"\${lines[9]}\" == 'trusted_consent=operator-approved-installed-daemon'" \
    "\"\${lines[10]}\" == 'input_origin=not-machine-verifiable'"; do
    manifest_line="$(first_active_line_of "${source}" "${manifest_literal}")" || return 1
    ((manifest_line > manifest_previous)) || return 1
    manifest_previous="${manifest_line}"
  done

  local mutation_line
  local parse_line
  local default_store_line
  local handoff_mode_line
  mutation_line="$(first_active_line_of "${source}" \
    'TEMPORARY_ROOT="$(/usr/bin/mktemp -d')" || return 1
  parse_line="$(last_active_line_of "${source}" 'parse_preconsented_handoff')" || return 1
  default_store_line="$(first_active_line_of "${source}" \
    'require_real_regular_file "${DEFAULT_PERSONA_STORE}"')" || return 1
  handoff_mode_line="$(first_active_line_of "${source}" \
    'if [[ -v A_QUO_INSTALLED_OMARCHY_PRECONSENTED_HANDOFF_ROOT ]]')" || return 1
  if ((handoff_mode_line >= default_store_line || default_store_line >= parse_line || \
    parse_line >= mutation_line)); then
    return 1
  fi

  local branch_line
  local call_line
  local exit_line
  local legacy_line
  branch_line="$(last_active_line_of "${source}" 'if "${PRECONSENTED_MODE}"; then')" ||
    return 1
  call_line="$(last_active_line_of "${source}" 'run_preconsented_lifecycle')" || return 1
  exit_line="$(first_active_line_of "${source}" 'exit 0')" || return 1
  legacy_line="$(first_active_line_of "${source}" \
    'readonly PACKAGE_V1="${TEMPORARY_ROOT}/package-v1.tar.zst"')" || return 1
  [[ "$(( $(/usr/bin/grep -Fc -- 'run_preconsented_lifecycle' "${source}") ))" -eq 2 ]] ||
    return 1
  if ((end_line >= branch_line || branch_line >= call_line || call_line >= exit_line || \
    exit_line >= legacy_line)); then
    return 1
  fi
}

[[ -f "${EVALUATOR}" && ! -L "${EVALUATOR}" ]] ||
  fail 'installed core evaluator is missing or is a symlink'
validate_source "${EVALUATOR}" || fail 'current joined evaluator violates its source contract'

MUTANT_ROOT="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/a-quo-core-preconsented-contract.XXXXXX")"
readonly MUTANT_ROOT
cleanup() {
  local status="$?"
  trap - EXIT
  /usr/bin/rm -rf -- "${MUTANT_ROOT}"
  exit "${status}"
}
trap cleanup EXIT

reject_mutant() {
  local name="$1"
  local expression="$2"
  local mutant="${MUTANT_ROOT}/${name}.sh"
  /usr/bin/sed -e "${expression}" "${EVALUATOR}" >"${mutant}"
  /usr/bin/cmp -s -- "${EVALUATOR}" "${mutant}" &&
    fail "source mutant did not change the evaluator: ${name}"
  if validate_source "${mutant}" >/dev/null 2>&1; then
    fail "source contract accepted hostile mutant: ${name}"
  fi
}

reject_mutant direct-sign-substitution \
  's|--store "${PERSONA_STORE}" verify "${package_v1}"|--store "${PERSONA_STORE}" sign "${package_v1}"|'
reject_mutant missing-package-snapshot \
  '/^[[:space:]]*snapshot_package "${PACKAGE_V1_SOURCE}" "${PACKAGE_V1_EXPECTED_SHA256}" "${package_v1}"$/d'
reject_mutant missing-proof-snapshot \
  '/^[[:space:]]*snapshot_preconsented_proof "${proof_v1}"$/d'
reject_mutant missing-handoff-recheck \
  '/^[[:space:]]*recheck_preconsented_handoff$/d'
reject_mutant parse-handoff-early-success \
  's|^parse_preconsented_handoff() {$|&\n  return 0 # hostile mutant bypasses handoff parsing|'
reject_mutant proof-snapshot-early-success \
  's|^snapshot_preconsented_proof() {$|&\n  return 0 # hostile mutant bypasses proof snapshotting|'
reject_mutant handoff-recheck-early-success \
  's|^recheck_preconsented_handoff() {$|&\n  return 0 # hostile mutant bypasses final handoff checks|'
reject_mutant false-plugin-safety \
  's|plugin_safety: "not_established"|plugin_safety: "established"|g'
reject_mutant false-behavioral-analysis \
  's|behavioral_analysis: "not_run"|behavioral_analysis: "passed"|g'
reject_mutant false-installation-consent \
  's|installation_trusted_consent: "not_run_preexisting_proof_only"|installation_trusted_consent: "performed"|g'
reject_mutant joined-fallthrough '/^[[:space:]]*exit 0$/d'

trap - EXIT
/usr/bin/rm -rf -- "${MUTANT_ROOT}"
printf '%s\n' 'installed Omarchy core preconsented branch passed its non-mutating contract checks'
