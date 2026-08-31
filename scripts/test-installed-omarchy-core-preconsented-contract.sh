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
      'readonly HANDOFF_MANIFEST HANDOFF_PROOF_V1_SOURCE HANDOFF_PROOF_V2_SOURCE')" == \
    1bb395188f731a967e82dd86b412322110f01e851f05c4896cad3e4f08f97947 ]] || return 1
  [[ "$(source_section_sha256 "${source}" \
      'snapshot_preconsented_proof() {' 'recheck_preconsented_handoff() {')" == \
    91f09f4c686a43bf643aaa2cd5db30398b163c7f24ceafb017cb7bbe5db22540 ]] || return 1
  [[ "$(source_section_sha256 "${source}" \
      'recheck_preconsented_handoff() {' 'assert_install_acknowledgement_gates() {')" == \
    58faf8c8352fb9a7fd1f8eb13e488b13ca4890487a3016f1a09d5d3534a5dea1 ]] || return 1
  [[ "$(source_section_sha256 "${source}" \
      'run_preconsented_lifecycle() {' '# PRECONSENTED_JOINED_MODE_END')" == \
    645b4939b16352dfa33e20e7a3c28b2532f75378421848f79d03d090a2546873 ]] || return 1

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
    'snapshot_package "${PACKAGE_V2_SOURCE}" "${PACKAGE_V2_EXPECTED_SHA256}" "${package_v2}"' \
    '"${HANDOFF_PROOF_V1_SIZE}" "${HANDOFF_PROOF_V1_SHA256}" "${proof_v1}" '\''v1'\''' \
    '"${HANDOFF_PROOF_V2_SIZE}" "${HANDOFF_PROOF_V2_SHA256}" "${proof_v2}" '\''v2'\''' \
    'verify "${package_v1}"' \
    'verify "${package_v2}"' \
    '--proof "${proof_v1}"' \
    '--proof "${proof_v2}"' \
    'omarchy inspect "${package_v1}"' \
    'omarchy inspect "${package_v2}"' \
    'assert_install_acknowledgement_gates "${package_v1}" "${proof_v1}"' \
    'omarchy install "${package_v1}"' \
    'omarchy update "${package_v2}"' \
    'omarchy update "${package_v1}"' \
    'omarchy uninstall "${PLUGIN_ID}"' \
    'recheck_preconsented_handoff' \
    "--arg schema 'urn:a-quo:evidence:installed-omarchy-core-lifecycle:v2'" \
    'mode: "preconsented_joined_v2_lifecycle"' \
    'inspect_v1: "passed_exact_v1_package_proof_and_active_local_publisher"' \
    'inspect_v2: "passed_exact_v2_package_proof_and_active_local_publisher"' \
    'managed_tree_sha256_before_update: $v1_tree_sha256_before_update' \
    'managed_tree_sha256_before_uninstall: $v2_tree_sha256_before_uninstall' \
    'previous_release_recovery_full_tree_match: true' \
    'downgrade_refused: true' \
    'downgrade_final_managed_tree_unchanged: true' \
    'uninstall_quarantine_full_tree_match: true' \
    'previous_release_recovery: $previous_release_recovery' \
    'previous_release_recovery_managed_tree_sha256: $v1_recovery_tree_sha256' \
    'uninstall_recovery_quarantine: $uninstall_recovery_quarantine' \
    'uninstall_recovery_quarantine_managed_tree_sha256: $v2_quarantine_tree_sha256' \
    'signing_operations_this_core_invocation: "none"' \
    'private_key_access_this_core_invocation: "none"' \
    'trusted_consent: "not_established_by_core_alone"' \
    'reported_signing_consent: "operator_approved_installed_daemon_proofs_consumed"' \
    'installation_trusted_consent: "not_established_cli_acknowledgements_only"' \
    'behavioral_analysis: "not_run"' \
    'plugin_safety: "not_established"' \
    'source_to_binary_provenance: "not_established"' \
    'clean_system_claim: "not_established_marker_only"' \
    'handoff_origin_authentication: "not_established_same_uid_directory"' \
    'persona_store_sha256: $persona_store_sha256' \
    'operator_input_origin: "not_machine_verifiable"' \
    'secure_attention: "not_established"'; do
    [[ "${joined}" == *"${joined_literal}"* ]] || return 1
  done

  [[ "$(/usr/bin/grep -Fc -- 'PACKAGE_V1_SOURCE' <<<"${joined}")" -eq 1 ]] || return 1
  [[ "$(/usr/bin/grep -Fc -- 'PACKAGE_V2_SOURCE' <<<"${joined}")" -eq 1 ]] || return 1
  [[ "$(/usr/bin/grep -Fc -- 'snapshot_preconsented_proof' <<<"${joined}")" -eq 2 ]] ||
    return 1
  [[ "$(/usr/bin/grep -Fc -- 'HANDOFF_PROOF_V1_SOURCE' <<<"${joined}")" -eq 1 ]] ||
    return 1
  [[ "$(/usr/bin/grep -Fc -- 'HANDOFF_PROOF_V2_SOURCE' <<<"${joined}")" -eq 1 ]] ||
    return 1
  [[ "$(/usr/bin/grep -Fc -- 'recheck_preconsented_handoff' <<<"${joined}")" -eq 1 ]] ||
    return 1
  [[ "${joined}" != *'HANDOFF_PROOF_SOURCE'* ]] || return 1
  [[ "${joined}" != *'PRIVATE_KEY'* ]] || return 1

  local joined_flat="${joined//$'\n'/ }"
  if /usr/bin/grep -Eq -- \
    '(^|[[:space:]])(sign|request-sign|ssh-keygen)([[:space:]]|$)|persona[[:space:]]+(create|key-add|key-bind|key-unbind)([[:space:]]|$)' \
    <<<"${joined_flat}"; then
    return 1
  fi

  local snapshot_package_v1_line
  local snapshot_package_v2_line
  local snapshot_proof_v1_line
  local snapshot_proof_v2_line
  local verify_v1_line
  local verify_v2_line
  local inspect_v1_line
  local inspect_v2_line
  local gates_line
  local install_line
  local v1_tree_capture_line
  local update_line
  local v1_recovery_tree_match_line
  local v2_downgrade_tree_capture_line
  local downgrade_line
  local v2_uninstall_tree_capture_line
  local uninstall_line
  local v2_quarantine_tree_match_line
  local recheck_line
  local evidence_line
  local cleanup_line
  local trap_retire_line
  local output_line
  snapshot_package_v1_line="$(active_line_in_range "${source}" \
    'snapshot_package "${PACKAGE_V1_SOURCE}"' "${begin_line}" "${end_line}")" || return 1
  snapshot_package_v2_line="$(active_line_in_range "${source}" \
    'snapshot_package "${PACKAGE_V2_SOURCE}"' "${begin_line}" "${end_line}")" || return 1
  snapshot_proof_v1_line="$(active_line_in_range "${source}" \
    '"${HANDOFF_PROOF_V1_SIZE}" "${HANDOFF_PROOF_V1_SHA256}" "${proof_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  snapshot_proof_v2_line="$(active_line_in_range "${source}" \
    '"${HANDOFF_PROOF_V2_SIZE}" "${HANDOFF_PROOF_V2_SHA256}" "${proof_v2}"' \
    "${begin_line}" "${end_line}")" || return 1
  verify_v1_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" verify "${package_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  verify_v2_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" verify "${package_v2}"' \
    "${begin_line}" "${end_line}")" || return 1
  inspect_v1_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" omarchy inspect "${package_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  inspect_v2_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" omarchy inspect "${package_v2}"' \
    "${begin_line}" "${end_line}")" || return 1
  gates_line="$(active_line_in_range "${source}" \
    'assert_install_acknowledgement_gates "${package_v1}" "${proof_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  install_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" omarchy install "${package_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  v1_tree_capture_line="$(active_line_in_range "${source}" \
    'live_tree_v1_before_update="$(managed_tree_sha256 "${LIVE_TARGET}")"' \
    "${begin_line}" "${end_line}")" || return 1
  update_line="$(active_line_in_range "${source}" \
    'run_a_quo --store "${PERSONA_STORE}" omarchy update "${package_v2}"' \
    "${begin_line}" "${end_line}")" || return 1
  v1_recovery_tree_match_line="$(active_line_in_range "${source}" \
    '[[ "${previous_release_recovery_tree_sha256}" == "${live_tree_v1_before_update}" ]]' \
    "${begin_line}" "${end_line}")" || return 1
  v2_downgrade_tree_capture_line="$(active_line_in_range "${source}" \
    'live_tree_v2_before_downgrade="$(managed_tree_sha256 "${LIVE_TARGET}")"' \
    "${begin_line}" "${end_line}")" || return 1
  downgrade_line="$(active_line_in_range "${source}" \
    'if run_a_quo --store "${PERSONA_STORE}" omarchy update "${package_v1}"' \
    "${begin_line}" "${end_line}")" || return 1
  v2_uninstall_tree_capture_line="$(active_line_in_range "${source}" \
    'live_tree_v2_before_uninstall="$(managed_tree_sha256 "${LIVE_TARGET}")"' \
    "${begin_line}" "${end_line}")" || return 1
  uninstall_line="$(active_line_in_range "${source}" \
    'run_a_quo omarchy uninstall "${PLUGIN_ID}"' \
    "${begin_line}" "${end_line}")" || return 1
  v2_quarantine_tree_match_line="$(active_line_in_range "${source}" \
    '[[ "${uninstall_recovery_tree_sha256}" == "${live_tree_v2_before_uninstall}" ]]' \
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
  if ((snapshot_package_v1_line >= snapshot_package_v2_line || \
    snapshot_package_v2_line >= snapshot_proof_v1_line || \
    snapshot_proof_v1_line >= snapshot_proof_v2_line || \
    snapshot_proof_v2_line >= verify_v1_line || verify_v1_line >= verify_v2_line || \
    verify_v2_line >= inspect_v1_line || inspect_v1_line >= inspect_v2_line || \
    inspect_v2_line >= gates_line || gates_line >= install_line || \
    install_line >= v1_tree_capture_line || v1_tree_capture_line >= update_line || \
    update_line >= v1_recovery_tree_match_line || \
    v1_recovery_tree_match_line >= v2_downgrade_tree_capture_line || \
    v2_downgrade_tree_capture_line >= downgrade_line || \
    downgrade_line >= v2_uninstall_tree_capture_line || \
    v2_uninstall_tree_capture_line >= uninstall_line || \
    uninstall_line >= v2_quarantine_tree_match_line || \
    v2_quarantine_tree_match_line >= recheck_line || \
    recheck_line >= evidence_line || \
    evidence_line >= cleanup_line || cleanup_line >= trap_retire_line || \
    trap_retire_line >= output_line)); then
    return 1
  fi

  for global_literal in \
    'readonly EXPECTED_PRECONSENTED_HANDOFF_ROOT="${EVALUATOR_HOME}/.local/share/a-quo-installed-package-lifecycle-v1/trusted-consent-v2"' \
    'A_QUO_INSTALLED_OMARCHY_PRECONSENTED_HANDOFF_ROOT' \
    'require_environment A_QUO_EVALUATOR_PACKAGE_V2' \
    'require_environment A_QUO_EVALUATOR_PACKAGE_V2_SHA256' \
    'preconsented handoff root differs from the exact joined-lifecycle path' \
    'preconsented handoff root must be evaluator-owned mode 0700' \
    "\$'handoff.manifest\\nproof-v1.json\\nproof-v2.json'" \
    'preconsented handoff manifest must contain exactly seventeen fields' \
    'preconsented handoff manifest contains a control, carriage-return, NUL, or non-ASCII byte' \
    'preconsented handoff manifest must end with one LF byte' \
    'preconsented v1 and v2 proofs must be distinct exact bytes' \
    'preconsented ${label} handoff proof identity changed before snapshot' \
    'private preconsented ${label} proof snapshot differs from the handoff digest' \
    'preconsented ${label} handoff proof changed while its private snapshot was created' \
    'preconsented handoff root identity changed during the core evaluation' \
    'preconsented handoff manifest changed during the core evaluation' \
    'preconsented v1 handoff proof changed during the core evaluation' \
    'preconsented v2 handoff proof changed during the core evaluation' \
    'preconsented default persona store changed during the core evaluation' \
    'preconsented update did not establish the strictly newer same-persona contract' \
    '.publisher_continuity == "same_local_persona"' \
    'preconsented previous-release recovery differs from the full installed v1 tree' \
    'preconsented downgrade refusal changed the managed v2 tree' \
    'preconsented live v2 tree changed between downgrade refusal and uninstall' \
    'preconsented uninstall quarantine does not contain the exact v2 manifest' \
    'preconsented uninstall quarantine differs from the full pre-uninstall v2 tree' \
    'for refusal_case in missing-yes missing-analysis-acknowledgement' \
    'preconsented ${refusal_case} touched its absent store or plugin-directory sentinel' \
    'missing_yes_failed_before_store_or_plugin_io: true' \
    'missing_behavioral_analysis_acknowledgement_failed_before_store_or_plugin_io: true'; do
    require_literal "${source}" "${global_literal}" || return 1
  done

  local manifest_previous=0
  local manifest_line
  for manifest_literal in \
    "\"\${lines[0]}\" == 'format=a-quo-installed-omarchy-preconsented-handoff-v2'" \
    '"${lines[1]}" == "store_path=${DEFAULT_PERSONA_STORE}"' \
    '"${lines[2]}" =~ ^artifact_v1_sha256=([0-9a-f]{64})$' \
    '"${lines[3]}" =~ ^artifact_v1_size=([1-9][0-9]{0,7})$' \
    "\"\${lines[4]}\" == 'proof_v1_file=proof-v1.json'" \
    '"${lines[5]}" =~ ^proof_v1_sha256=([0-9a-f]{64})$' \
    '"${lines[6]}" =~ ^proof_v1_size=([1-9][0-9]{0,6})$' \
    '"${lines[7]}" =~ ^artifact_v2_sha256=([0-9a-f]{64})$' \
    '"${lines[8]}" =~ ^artifact_v2_size=([1-9][0-9]{0,7})$' \
    "\"\${lines[9]}\" == 'proof_v2_file=proof-v2.json'" \
    '"${lines[10]}" =~ ^proof_v2_sha256=([0-9a-f]{64})$' \
    '"${lines[11]}" =~ ^proof_v2_size=([1-9][0-9]{0,6})$' \
    '"${lines[12]}" =~ ^persona_id=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$' \
    '"${lines[13]}" =~ ^key_fingerprint=(SHA256:[A-Za-z0-9+/]{43})$' \
    "\"\${lines[14]}\" == 'trusted_consent_v1=operator-approved-installed-daemon'" \
    "\"\${lines[15]}\" == 'trusted_consent_v2=operator-approved-installed-daemon'" \
    "\"\${lines[16]}\" == 'input_origin=not-machine-verifiable'"; do
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
  shift
  local mutant="${MUTANT_ROOT}/${name}.sh"
  local expression
  local -a sed_arguments=()
  for expression in "$@"; do
    sed_arguments+=(-e "${expression}")
  done
  /usr/bin/sed "${sed_arguments[@]}" "${EVALUATOR}" >"${mutant}"
  /usr/bin/cmp -s -- "${EVALUATOR}" "${mutant}" &&
    fail "source mutant did not change the evaluator: ${name}"
  if validate_source "${mutant}" >/dev/null 2>&1; then
    fail "source contract accepted hostile mutant: ${name}"
  fi
}

reject_mutant direct-sign-v1-substitution \
  's|--store "${PERSONA_STORE}" verify "${package_v1}"|--store "${PERSONA_STORE}" sign "${package_v1}"|'
reject_mutant direct-sign-v2-substitution \
  's|--store "${PERSONA_STORE}" verify "${package_v2}"|--store "${PERSONA_STORE}" sign "${package_v2}"|'
reject_mutant direct-request-sign-substitution \
  's|--store "${PERSONA_STORE}" verify "${package_v2}"|--store "${PERSONA_STORE}" request-sign "${package_v2}"|'
reject_mutant missing-v1-package-snapshot \
  '/^[[:space:]]*snapshot_package "${PACKAGE_V1_SOURCE}" "${PACKAGE_V1_EXPECTED_SHA256}" "${package_v1}"$/d'
reject_mutant missing-v2-package-snapshot \
  '/^[[:space:]]*snapshot_package "${PACKAGE_V2_SOURCE}" "${PACKAGE_V2_EXPECTED_SHA256}" "${package_v2}"$/d'
reject_mutant v2-package-source-substitution \
  's|snapshot_package "${PACKAGE_V2_SOURCE}" "${PACKAGE_V2_EXPECTED_SHA256}" "${package_v2}"|snapshot_package "${PACKAGE_V1_SOURCE}" "${PACKAGE_V1_EXPECTED_SHA256}" "${package_v2}"|'
reject_mutant missing-v1-proof-snapshot \
  '/^[[:space:]]*"${HANDOFF_PROOF_V1_SOURCE}" "${HANDOFF_PROOF_V1_IDENTITY}"/d'
reject_mutant missing-v2-proof-snapshot \
  '/^[[:space:]]*"${HANDOFF_PROOF_V2_SOURCE}" "${HANDOFF_PROOF_V2_IDENTITY}"/d'
reject_mutant v2-proof-source-substitution \
  '/^[[:space:]]*"${HANDOFF_PROOF_V2_SOURCE}" "${HANDOFF_PROOF_V2_IDENTITY}"/s/HANDOFF_PROOF_V2/HANDOFF_PROOF_V1/g'
reject_mutant v2-verification-package-swap \
  's|verify "${package_v2}"|verify "${package_v1}"|'
reject_mutant v2-verification-proof-swap \
  's|--proof "${proof_v2}" --json >"${verify_v2}"|--proof "${proof_v1}" --json >"${verify_v2}"|'
reject_mutant v2-inspection-proof-swap \
  's|--proof "${proof_v2}" --json >"${inspection_v2}"|--proof "${proof_v1}" --json >"${inspection_v2}"|'
reject_mutant proof-digest-distinctness-inversion \
  's|"${HANDOFF_PROOF_V1_SHA256}" != "${HANDOFF_PROOF_V2_SHA256}"|"${HANDOFF_PROOF_V1_SHA256}" == "${HANDOFF_PROOF_V2_SHA256}"|'
reject_mutant missing-handoff-recheck \
  '/^[[:space:]]*recheck_preconsented_handoff$/d'
reject_mutant parse-handoff-early-success \
  's|^parse_preconsented_handoff() {$|&\n  return 0 # hostile mutant bypasses handoff parsing|'
reject_mutant proof-snapshot-early-success \
  's|^snapshot_preconsented_proof() {$|&\n  return 0 # hostile mutant bypasses proof snapshotting|'
reject_mutant handoff-recheck-early-success \
  's|^recheck_preconsented_handoff() {$|&\n  return 0 # hostile mutant bypasses final handoff checks|'
reject_mutant joined-lifecycle-early-success \
  's|^run_preconsented_lifecycle() {$|&\n  return 0 # hostile mutant bypasses the joined lifecycle|'
reject_mutant missing-v2-inspection \
  '/^[[:space:]]*run_a_quo --store "${PERSONA_STORE}" omarchy inspect "${package_v2}"/d'
reject_mutant missing-install-step \
  '/^[[:space:]]*run_a_quo --store "${PERSONA_STORE}" omarchy install "${package_v1}"/d'
reject_mutant missing-v1-tree-capture \
  '/^[[:space:]]*live_tree_v1_before_update="$(managed_tree_sha256 "${LIVE_TARGET}")"$/d'
reject_mutant missing-update-step \
  '/^[[:space:]]*run_a_quo --store "${PERSONA_STORE}" omarchy update "${package_v2}"/d'
reject_mutant missing-strictly-newer-update-outcome \
  '/^[[:space:]]*\.previous_version == \$previous and \.version == \$version and$/d'
reject_mutant v1-recovery-tree-source-substitution \
  's|managed_tree_sha256 "${previous_release_recovery}"|managed_tree_sha256 "${LIVE_TARGET}"|'
reject_mutant missing-v1-recovery-tree-match \
  '/^[[:space:]]*\[\[ "${previous_release_recovery_tree_sha256}" == "${live_tree_v1_before_update}" \]\] ||$/d'
reject_mutant missing-downgrade-refusal-step \
  '/^[[:space:]]*if run_a_quo --store "${PERSONA_STORE}" omarchy update "${package_v1}"/d'
reject_mutant missing-v2-pre-uninstall-tree-capture \
  '/^[[:space:]]*live_tree_v2_before_uninstall="$(managed_tree_sha256 "${LIVE_TARGET}")"$/d'
reject_mutant missing-uninstall-step \
  '/^[[:space:]]*run_a_quo omarchy uninstall "${PLUGIN_ID}"/d'
reject_mutant v2-quarantine-tree-source-substitution \
  's|managed_tree_sha256 "${recovery_quarantine}/plugin"|managed_tree_sha256 "${previous_release_recovery}"|'
reject_mutant missing-v2-quarantine-tree-match \
  '/^[[:space:]]*\[\[ "${uninstall_recovery_tree_sha256}" == "${live_tree_v2_before_uninstall}" \]\] ||$/d'
reject_mutant lifecycle-install-update-order \
  '/^[[:space:]]*run_a_quo --store "${PERSONA_STORE}" omarchy install "${package_v1}"/s|omarchy install "${package_v1}"|omarchy __joined_order_swap__ "${package_v1}"|' \
  '/^[[:space:]]*run_a_quo --store "${PERSONA_STORE}" omarchy update "${package_v2}"/s|omarchy update "${package_v2}"|omarchy install "${package_v1}"|' \
  's|omarchy __joined_order_swap__ "${package_v1}"|omarchy update "${package_v2}"|'
reject_mutant false-plugin-safety \
  's|plugin_safety: "not_established"|plugin_safety: "established"|g'
reject_mutant false-behavioral-analysis \
  's|behavioral_analysis: "not_run"|behavioral_analysis: "passed"|g'
reject_mutant false-core-trusted-consent \
  's|trusted_consent: "not_established_by_core_alone"|trusted_consent: "established_by_core"|g'
reject_mutant false-reported-signing-consent \
  's|reported_signing_consent: "operator_approved_installed_daemon_proofs_consumed"|reported_signing_consent: "established_by_core"|g'
reject_mutant false-installation-consent \
  's|installation_trusted_consent: "not_established_cli_acknowledgements_only"|installation_trusted_consent: "established"|g'
reject_mutant false-downgrade-no-mutation-claim \
  's|downgrade_final_managed_tree_unchanged: true|downgrade_live_mutation: false|g'
reject_mutant joined-schema-downgrade \
  's|urn:a-quo:evidence:installed-omarchy-core-lifecycle:v2|urn:a-quo:evidence:installed-omarchy-core-lifecycle:v1|g'
reject_mutant joined-fallthrough '/^[[:space:]]*exit 0$/d'

trap - EXIT
/usr/bin/rm -rf -- "${MUTANT_ROOT}"
printf '%s\n' 'installed Omarchy core preconsented branch passed its non-mutating contract checks'
