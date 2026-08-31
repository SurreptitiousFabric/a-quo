#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
readonly EVALUATOR="${SCRIPT_DIRECTORY}/test-installed-omarchy-core-lifecycle.sh"

[[ -f "${EVALUATOR}" && ! -L "${EVALUATOR}" ]] || {
  printf '%s\n' 'installed lifecycle evaluator is missing or is a symlink' >&2
  exit 1
}

set +e
REFUSAL_OUTPUT="$(
  /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "${EVALUATOR}" 2>&1
)"
REFUSAL_STATUS="$?"
set -e
if [[ "${REFUSAL_STATUS}" -eq 0 || "${REFUSAL_OUTPUT}" != \
  'refusing installed lifecycle evaluation without exact A_QUO_INSTALLED_OMARCHY_CORE_LIFECYCLE_ACKNOWLEDGEMENT' ]]; then
  printf 'evaluator did not fail first on its exact acknowledgement: status=%s output=%q\n' \
    "${REFUSAL_STATUS}" "${REFUSAL_OUTPUT}" >&2
  exit 1
fi

ACK_LINE="$(/usr/bin/grep -n -m1 'A_QUO_INSTALLED_OMARCHY_CORE_LIFECYCLE_ACKNOWLEDGEMENT:-' \
  "${EVALUATOR}")"
ROOT_LINE="$(/usr/bin/grep -Fn -m1 "if [[ \"\${EUID}\" -ne 0 ]]" "${EVALUATOR}")"
MARKER_LINE="$(/usr/bin/grep -Fn -m1 "require_real_regular_file \"\${DISPOSABLE_MARKER}\"" \
  "${EVALUATOR}")"
ACK_LINE="${ACK_LINE%%:*}"
ROOT_LINE="${ROOT_LINE%%:*}"
MARKER_LINE="${MARKER_LINE%%:*}"
readonly ACK_LINE ROOT_LINE MARKER_LINE
if (( ACK_LINE >= ROOT_LINE || ROOT_LINE >= MARKER_LINE )); then
  printf '%s\n' 'acknowledgement/root/marker gates are not in fail-first order' >&2
  exit 1
fi

for required_literal in \
  "schema=a-quo-disposable-omarchy-evaluator-v1" \
  "account=a-quo-evaluator" \
  "'0:0 400 regular file'" \
  "readonly EVALUATOR_HOME='/home/a-quo-evaluator'" \
  'A_QUO_EXPECTED_OMARCHY_PACKAGE_QUERY' \
  "if [[ ! \"\${EXPECTED_OMARCHY_QUERY}\" =~ ^omarchy(-dev)?[[:space:]][^[:space:]]+$ ]]; then" \
  "readonly EXPECTED_OMARCHY_PACKAGE=\"\${EXPECTED_OMARCHY_QUERY%%[[:space:]]*}\"" \
  "/usr/bin/pacman -Q -- \"\${EXPECTED_OMARCHY_PACKAGE}\"" \
  "'derived Omarchy package name is outside the closed supported set'" \
  'A_QUO_EVALUATOR_PACKAGE_V1_SHA256' \
  'A_QUO_EVALUATOR_PACKAGE_V2_SHA256' \
  'A_QUO_EVALUATOR_WAYLAND_DISPLAY' \
  '/usr/bin/a-quo' \
  'pacman -Qoq' \
  '/usr/share/a-quo/provider-registry-v1.json' \
  'omarchy observe-reference' \
  'keys == ["plugin_id", "shell_config_sha256", "shell_config_source", "state"]' \
  '--accept-behavioral-analysis-not-run' \
  '.behavioral_analysis == "not_run"' \
  '.trusted_consent == "not_run"' \
  '.runtime_safety == "not_evaluated"' \
  'plugin_safety: "not_established"' \
  'temporary_work_cleanup: "verified_before_evidence_emission"' \
  'clean_system_claim: "not_established_marker_only"'; do
  /usr/bin/grep -Fq -- "${required_literal}" "${EVALUATOR}" || {
    printf 'installed lifecycle evaluator is missing contract literal: %s\n' \
      "${required_literal}" >&2
    exit 1
  }
done

if /usr/bin/grep -Fq -- '/usr/bin/pacman -Q omarchy' "${EVALUATOR}"; then
  printf '%s\n' 'evaluator hardcodes the non-dev Omarchy package query' >&2
  exit 1
fi

for supported_query in \
  'omarchy 4.0.0-1' \
  'omarchy-dev 4.0.0.r6589.gdec29fa-1'; do
  if [[ ! "${supported_query}" =~ ^omarchy(-dev)?[[:space:]][^[:space:]]+$ ]]; then
    printf 'contract fixture is not accepted as a supported Omarchy query: %s\n' \
      "${supported_query}" >&2
    exit 1
  fi
  supported_package="${supported_query%%[[:space:]]*}"
  if [[ "${supported_package}" != omarchy && "${supported_package}" != omarchy-dev ]]; then
    printf 'contract fixture derived an unsupported Omarchy package: %s\n' \
      "${supported_package}" >&2
    exit 1
  fi
done

for unsupported_query in \
  'omarchy' \
  'omarchy-beta 4.0.0-1' \
  'omarchy-dev 4.0.0-1 trailing' \
  'omarchy;printf 4.0.0-1'; do
  if [[ "${unsupported_query}" =~ ^omarchy(-dev)?[[:space:]][^[:space:]]+$ ]]; then
    printf 'contract fixture unexpectedly accepts an unsupported Omarchy query: %s\n' \
      "${unsupported_query}" >&2
    exit 1
  fi
done

if /usr/bin/grep -Eq -- \
  '(cargo run|mise exec|omarchy (enable|disable)|shell\.json.*(>|tee)|DBUS_SESSION_BUS_ADDRESS)' \
  "${EVALUATOR}"; then
  printf '%s\n' 'evaluator contains a forbidden build-tree, enablement, config-write, or D-Bus path' >&2
  exit 1
fi

if [[ "$(/usr/bin/grep -Ec '/usr/bin/rm -rf -- "\$\{TEMPORARY_ROOT\}"' \
  "${EVALUATOR}")" -ne 1 ]]; then
  printf '%s\n' 'evaluator must have exactly one guarded recursive cleanup target' >&2
  exit 1
fi
if [[ "$(/usr/bin/grep -Ec 'SENTINEL_ROOT=.*/no-io-' "${EVALUATOR}")" -ne 1 || \
  "$(/usr/bin/grep -Ec 'touched its absent store or plugin-directory sentinel' \
    "${EVALUATOR}")" -ne 1 ]]; then
  printf '%s\n' 'evaluator does not retain the two fail-before-I/O sentinel checks' >&2
  exit 1
fi

printf '%s\n' 'installed Omarchy core lifecycle evaluator passed its non-mutating contract checks'
