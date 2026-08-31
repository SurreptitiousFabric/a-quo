#!/usr/bin/env bash
# shellcheck disable=SC2016 # This contract intentionally matches exact source literals.

set -euo pipefail
export LC_ALL=C

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
readonly EVALUATOR_SOURCE="${SCRIPT_DIRECTORY}/test-installed-a-quo-package-lifecycle.sh"

fail_contract() {
  printf 'installed package lifecycle contract failed: %s\n' "$1" >&2
  exit 1
}

[[ -f "${EVALUATOR_SOURCE}" && ! -L "${EVALUATOR_SOURCE}" ]] ||
  fail_contract 'armed evaluator is missing or is a symlink'

# Inspect and invoke only one private byte snapshot. The exact acknowledgement
# prefix is validated before the snapshot is ever executed.
CONTRACT_ROOT="$(/usr/bin/mktemp -d /tmp/a-quo-package-lifecycle-contract.XXXXXX)"
readonly CONTRACT_ROOT
CONTRACT_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "${CONTRACT_ROOT}")"
readonly CONTRACT_ROOT_IDENTITY

remove_contract_root() {
  [[ "${CONTRACT_ROOT}" == /tmp/a-quo-package-lifecycle-contract.* && \
    -d "${CONTRACT_ROOT}" && ! -L "${CONTRACT_ROOT}" && \
    "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "${CONTRACT_ROOT}")" == \
      "${CONTRACT_ROOT_IDENTITY}" ]] || return 1
  /usr/bin/rm -rf -- "${CONTRACT_ROOT}"
}
trap 'remove_contract_root || exit 1' EXIT

readonly EVALUATOR="${CONTRACT_ROOT}/test-installed-a-quo-package-lifecycle.sh"
/usr/bin/install -m 0700 -- "${EVALUATOR_SOURCE}" "${EVALUATOR}"
/usr/bin/cmp -s -- "${EVALUATOR_SOURCE}" "${EVALUATOR}" ||
  fail_contract 'private evaluator snapshot differs from its source'
/usr/bin/bash -n "${EVALUATOR}" || fail_contract 'private evaluator snapshot has invalid syntax'
if ! /usr/bin/diff -u --label expected-acknowledgement-prefix \
  --label observed-acknowledgement-prefix - \
  <(/usr/bin/sed -n '1,19p' "${EVALUATOR}") >/dev/null <<'ACKNOWLEDGEMENT_PREFIX'
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
ACKNOWLEDGEMENT_PREFIX
then
  fail_contract 'armed evaluator acknowledgement prefix differs from the closed fail-first form'
fi

# This sole evaluator invocation is the already validated private snapshot with
# its acknowledgement absent. It exits before root or external-state checks.
set +e
REFUSAL_OUTPUT="$(
  /usr/bin/env -i PATH=/usr/bin:/bin \
    /usr/bin/bash --noprofile --norc "${EVALUATOR}" 2>&1
)"
REFUSAL_STATUS="$?"
set -e
readonly REFUSAL_OUTPUT REFUSAL_STATUS
if [[ "${REFUSAL_STATUS}" -eq 0 || "${REFUSAL_OUTPUT}" != \
  'refusing installed package lifecycle without exact A_QUO_INSTALLED_PACKAGE_LIFECYCLE_ACKNOWLEDGEMENT' ]]; then
  printf 'armed evaluator did not fail first on its exact acknowledgement: status=%s output=%q\n' \
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

line_or_fail() {
  local label="$1"
  local literal="$2"
  local line
  line="$(active_line_of "${literal}")" ||
    fail_contract "armed evaluator lacks active contract point: ${label}"
  printf '%s\n' "${line}"
}

exact_command_line_of() {
  local command="$1"
  /usr/bin/awk -v expected="${command}" '
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      sub(/[[:space:]]*$/, "", line)
      if (line == expected) {
        print NR
        exit
      }
    }
  ' "${EVALUATOR}"
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
  observed="$(source_section_sha256 "${start_line}" "${end_line}")" ||
    fail_contract "security-critical source section is not uniquely bounded: ${label}"
  [[ "${observed}" == "${expected}" ]] ||
    fail_contract "security-critical source section changed: ${label}"
}

# Literal/order checks below aid diagnosis. These whole-section hashes are the
# reachability regression boundary for the critical package and transition
# functions: an inserted early success must force explicit contract review.
require_source_section_sha256 safe-root-chain \
  'require_safe_root_chain() {' 'require_bounded_safe_root_tree() {' \
  5e3646fd03adbce7d317fc275b7364e0d1458c811c72c0230a25df1a9ca03309
require_source_section_sha256 root-package-input \
  'require_root_package_input() {' 'require_safe_evaluator_directory() {' \
  2cfc5e693e656f5da3dd71e3b5d8e1340a9d9339d12e8077adb447fb1d4b5e75
require_source_section_sha256 exact-package-absence \
  'assert_a_quo_package_absent() {' 'if (( EUID != 0 )); then' \
  143e6f36f17cdd964d8eed23da1ae0963213ca6e700ddcfbdc11a229a58f6367
require_source_section_sha256 static-input-rebinding \
  'assert_static_inputs() {' \
  "assert_static_inputs 'before any package or user-state mutation'" \
  3245c9e33a7512a95980775276039dcc7dba85fef35042ccf54e1e27fa8603b2
require_source_section_sha256 service-state-boundary \
  'assert_no_enablement_or_process() {' 'assert_service_disabled() {' \
  2d6ece4de9164ce03c5e0e2c6b56c44d469360b7ebea0891016a9a6bdea8bc8c
require_source_section_sha256 absent-transition-boundary \
  'assert_absent_transition_boundary() {' 'assert_installed_transition_boundary() {' \
  03abdfbaf100596df1a539324b62449414fff2f3946670f9781d55ffed18027f
require_source_section_sha256 installed-transition-boundary \
  'assert_installed_transition_boundary() {' 'assert_installed_package() {' \
  22dd7452fa4a7db81c9c7f7094469770b54f48465b605a757249fc9886c9a6f5
require_source_section_sha256 installed-package-verification \
  'assert_installed_package() {' 'assert_consent_to_core_binding() {' \
  ba392324a2c52539f8186fdb71b6d2fef7608437044d19fcc76b91acbeb0a16a
require_source_section_sha256 consent-to-core-binding \
  'assert_consent_to_core_binding() {' 'CURRENT_STAGE=install-old' \
  ef2df18326bf3bc5a5cf125635519b4ad9256e86aaf722e04efc103714ad4428

BRIDGE_LOCK_LINE="$(line_or_fail bridge-lock 'exec 9<>"${BRIDGE_LOCK}"')"
FIRST_PERSISTENT_SEED_LINE="$(line_or_fail persistent-state-seed \
  'MUTATION_STARTED=true')"
FIRST_PACMAN_MUTATION_LINE="$(line_or_fail first-pacman-mutation \
  'run_pacman_transaction -U -- "${OLD_PACKAGE_SNAPSHOT}"')"
readonly BRIDGE_LOCK_LINE FIRST_PERSISTENT_SEED_LINE FIRST_PACMAN_MUTATION_LINE
if ((BRIDGE_LOCK_LINE >= FIRST_PERSISTENT_SEED_LINE ||
  FIRST_PERSISTENT_SEED_LINE >= FIRST_PACMAN_MUTATION_LINE)); then
  fail_contract 'bridge lock, persistent seed, and first pacman mutation are out of order'
fi

assert_before_seed() {
  local label="$1"
  local literal="$2"
  local line
  line="$(line_or_fail "${label}" "${literal}")"
  if ((line >= FIRST_PERSISTENT_SEED_LINE || line >= FIRST_PACMAN_MUTATION_LINE)); then
    fail_contract "gate occurs after persistent seed or first pacman mutation: ${label}"
  fi
}

# Target authorization and identity.
assert_before_seed acknowledgement \
  'A_QUO_INSTALLED_PACKAGE_LIFECYCLE_ACKNOWLEDGEMENT:-'
assert_before_seed root 'if (( EUID != 0 )); then'
assert_before_seed marker-file \
  'require_real_regular_file "${DISPOSABLE_MARKER}"'
assert_before_seed marker-safe-chain \
  'require_safe_root_chain "${DISPOSABLE_MARKER}"'
assert_before_seed marker-mode "'0:0:400:regular file'"
assert_before_seed marker-bytes '/usr/bin/cmp -s -- "${DISPOSABLE_MARKER}" <('
assert_before_seed evaluator-account \
  'ACCOUNT_RECORD="$(/usr/bin/getent passwd "${EVALUATOR_ACCOUNT}")"'
assert_before_seed evaluator-home 'require_safe_evaluator_directory "${EVALUATOR_HOME}"'
assert_before_seed optional-state-parent-preflight \
  'if [[ -e "${optional_evaluator_directory}" || -L "${optional_evaluator_directory}" ]]; then'

# Caller pins, local target state, and package inputs.
assert_before_seed required-package-inputs 'A_QUO_PACKAGE_LIFECYCLE_OLD_PACKAGE'
assert_before_seed required-v2-fixture-inputs 'A_QUO_EVALUATOR_PACKAGE_V2'
assert_before_seed package-digest-format \
  '[[ "${digest}" =~ ^[0-9a-f]{64}$ ]]'
assert_before_seed distinct-package-bytes \
  '[[ "${OLD_PACKAGE_EXPECTED_SHA256}" != "${NEW_PACKAGE_EXPECTED_SHA256}" ]]'
assert_before_seed distinct-plugin-fixture-bytes \
  '[[ "${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}" !='
assert_before_seed full-source-commits \
  '[[ "${commit}" =~ ^[0-9a-f]{40}$ ]]'
assert_before_seed exact-package-queries \
  '[[ "${OLD_PACKAGE_QUERY}" =~ ^a-quo[[:space:]][^[:space:]]+$'
assert_before_seed forward-version-order \
  '(( $(/usr/bin/vercmp "${NEW_PACKAGE_VERSION}" "${OLD_PACKAGE_VERSION}") > 0 ))'
assert_before_seed exact-omarchy-query \
  '[[ "${EXPECTED_OMARCHY_QUERY}" =~ ^omarchy(-dev)?[[:space:]][^[:space:]]+$ ]]'
assert_before_seed installed-omarchy-pin \
  '[[ "$(/usr/bin/pacman -Q -- "${EXPECTED_OMARCHY_PACKAGE}")" =='
assert_before_seed pacman-binary-safe-chain \
  'require_safe_root_chain "${PACMAN_BINARY}" '\''Pacman binary'\'''
assert_before_seed pacman-binary-hash \
  'PACMAN_BINARY_SHA256="$(sha256_file "${PACMAN_BINARY}")"'
assert_before_seed pacman-owning-package \
  '[[ "$(/usr/bin/pacman -Qoq -- "${PACMAN_BINARY}")" == pacman ]]'
assert_before_seed pacman-package-integrity \
  '/usr/bin/pacman -Qkk pacman'
assert_before_seed old-root-package-input \
  'require_root_package_input "${OLD_PACKAGE_SOURCE}"'
assert_before_seed new-root-package-input \
  'require_root_package_input "${NEW_PACKAGE_SOURCE}"'
assert_before_seed fixture-v1-root-package-input \
  'require_root_package_input "${A_QUO_EVALUATOR_PACKAGE_V1}"'
assert_before_seed fixture-v2-root-package-input \
  'require_root_package_input "${A_QUO_EVALUATOR_PACKAGE_V2}"'
assert_before_seed wayland-socket \
  '[[ -S "${WAYLAND_SOCKET}" && ! -L "${WAYLAND_SOCKET}"'
assert_before_seed absent-persona \
  'fail '\''installed-core persona root must be absent before package mutation'\'''
assert_before_seed absent-plugin \
  'fail '\''installed-core plugin target must be absent before package mutation'\'''
assert_before_seed absent-evidence-root \
  'fail '\''package-lifecycle evidence root must be absent before this one-shot run'\'''
assert_before_seed initially-uninstalled \
  'assert_a_quo_package_absent '\''before preflight'\'''
assert_before_seed exact-not-found \
  '"${query_output}" == "error: package '\''a-quo'\'' was not found"'
assert_before_seed local-pacman-database-integrity \
  '/usr/bin/pacman -Dk >/dev/null'
assert_before_seed no-stray-local-database-entry \
  '-name '\''a-quo-*'\'' -print -quit'
PREFLIGHT_DAEMON_LINE="$(exact_command_line_of 'assert_no_daemon_process')"
readonly PREFLIGHT_DAEMON_LINE
[[ -n "${PREFLIGHT_DAEMON_LINE}" ]] ||
  fail_contract 'armed evaluator lacks its exact preflight daemon check'
if ((PREFLIGHT_DAEMON_LINE >= FIRST_PERSISTENT_SEED_LINE)); then
  fail_contract 'daemon preflight occurs after persistent state is seeded'
fi
[[ "$(/usr/bin/grep -Ec '^[[:space:]]*assert_no_daemon_process[[:space:]]*$' \
  "${EVALUATOR}")" -eq 2 ]] ||
  fail_contract 'daemon absence must be checked once in preflight and once by lifecycle state checks'
assert_before_seed no-unmanaged-package-leaf \
  'fail "an A Quo package leaf exists ${stage}: ${package_leaf}"'
assert_before_seed initial-pacman-lock-absence \
  'fail '\''pacman database lock exists before the package lifecycle'\'''
assert_before_seed initial-service-disablement \
  'fail '\''A Quo user service is enabled before package installation'\'''
assert_before_seed initial-user-unit-absence \
  'fail '\''A Quo user unit is not exactly absent and disabled before package installation'\'''
assert_before_seed evaluator-enable-preflight \
  '/usr/bin/systemctl --user --no-pager is-enabled a-quo-daemon.service'
assert_before_seed global-enable-preflight \
  '/usr/bin/systemctl --global --no-pager is-enabled a-quo-daemon.service'

# Committed harness policy, bounded snapshots, package metadata, and network
# isolation must all be established before user state is seeded.
assert_before_seed source-checkout-safe-chain \
  'require_safe_root_chain "${REPOSITORY_ROOT}" '\''source checkout'\'''
assert_before_seed canonical-executing-bridge \
  'fail '\''package lifecycle bridge is not executing from its canonical repository path'\'''
assert_before_seed executing-bridge-safe-chain \
  'require_safe_root_chain "${EXECUTING_BRIDGE_PATH}" '\''executing package lifecycle bridge'\'''
assert_before_seed git-config-isolation 'export GIT_CONFIG_GLOBAL=/dev/null'
assert_before_seed git-system-config-isolation 'export GIT_CONFIG_NOSYSTEM=1'
assert_before_seed no-optional-git-locks 'export GIT_OPTIONAL_LOCKS=0'
assert_before_seed bounded-root-owned-git-metadata \
  'require_bounded_safe_root_tree "${REPOSITORY_ROOT}/.git"'
assert_before_seed verifier-harness-presence \
  '"${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh"'
assert_before_seed consent-harness-presence \
  '"${SCRIPT_DIRECTORY}/test-installed-a-quo-consent-lifecycle.sh"'
assert_before_seed core-harness-presence \
  '"${SCRIPT_DIRECTORY}/test-installed-omarchy-core-lifecycle.sh"'
assert_before_seed consent-policy-digest \
  'COMMITTED_CONSENT_EVALUATOR_SHA256="$({'
assert_before_seed no-shallow-history \
  'rev-parse --is-shallow-repository'
assert_before_seed no-grafts \
  'fail '\''source checkout contains a legacy graft file'\'''
assert_before_seed standalone-checkout \
  'fail '\''source checkout must be one standalone checkout, not a linked worktree'\'''
assert_before_seed no-alternate-object-store \
  'fail '\''source checkout uses an alternate Git object store'\'''
assert_before_seed no-partial-clone \
  'fail '\''source checkout has partial-clone or promisor configuration'\'''
assert_before_seed no-replacement-refs \
  '[[ -z "${REPLACEMENT_REF}" ]]'
assert_before_seed tracked-executable-bridge \
  'fail '\''package lifecycle bridge is not one tracked executable blob at HEAD'\'''
assert_before_seed bounded-tracked-files \
  'fail '\''source checkout tracked-file count is empty or outside the closed bound'\'''
assert_before_seed immutable-tracked-files \
  ''\''source checkout tracked file'\'''
assert_before_seed clean-checkout \
  'fail '\''source checkout must be clean before package mutation'\'''
assert_before_seed source-ancestry \
  'fail '\''old A Quo source commit is not an ancestor of new source commit'\'''
assert_before_seed committed-bridge-digest \
  'COMMITTED_BRIDGE_SHA256="$({'
assert_before_seed live-bridge-policy-binding \
  'fail '\''executing package lifecycle bridge differs from current committed policy'\'''
[[ "$(/usr/bin/grep -Fc -- \
    '"$(sha256_file "${EXECUTING_BRIDGE_PATH}")" ==' "${EVALUATOR}")" -eq 1 && \
  "$(/usr/bin/grep -Fxc -- \
    '[[ "${EXECUTING_BRIDGE_SHA256}" == "${COMMITTED_BRIDGE_SHA256}" ]] ||' \
    "${EVALUATOR}")" -eq 1 ]] ||
  fail_contract 'initial and repeated executing-bridge byte bindings are both required'
assert_before_seed committed-policy-digests \
  'fail '\''working package verifier, consent evaluator, or installed-core evaluator differs from current committed policy'\'''
assert_before_seed network-namespace-probe \
  '/usr/bin/unshare --net -- /usr/bin/true'
assert_before_seed old-bounded-snapshot \
  'snapshot_package "${OLD_PACKAGE_SOURCE}" "${OLD_PACKAGE_EXPECTED_SHA256}"'
assert_before_seed new-bounded-snapshot \
  'snapshot_package "${NEW_PACKAGE_SOURCE}" "${NEW_PACKAGE_EXPECTED_SHA256}"'
assert_before_seed private-harness-digest \
  'fail '\''private committed evaluator snapshots do not match their expected hashes'\'''
assert_before_seed old-package-verifier \
  '"${COMMITTED_VERIFIER}" "${OLD_PACKAGE_SNAPSHOT}" "${OLD_SOURCE_COMMIT}"'
assert_before_seed new-package-verifier \
  '"${COMMITTED_VERIFIER}" "${NEW_PACKAGE_SNAPSHOT}" "${NEW_SOURCE_COMMIT}"'
assert_before_seed explicit-aarch64-profile \
  'readonly EVALUATION_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"'
assert_before_seed verifier-receipt-package-binding \
  'package verifier receipt does not identify its exact package snapshot'
assert_before_seed old-verifier-target-binding \
  'old package verifier receipt is missing, duplicated, reordered, or cross-profile'
assert_before_seed new-verifier-target-binding \
  'new package verifier receipt is missing, duplicated, reordered, or cross-profile'
assert_before_seed cross-version-target-binding \
  'old and new package verifier receipts bind different target profiles'
assert_before_seed exact-profile-id \
  'profile_id=${EVALUATION_PROFILE_ID}'
assert_before_seed exact-profile-digest \
  'profile_sha256=${EVALUATION_PROFILE_SHA256}'
assert_before_seed exact-target-architecture \
  'architecture=${EVALUATION_ARCHITECTURE}'
assert_before_seed exact-evidence-namespace \
  'evidence_namespace=${EVALUATION_EVIDENCE_NAMESPACE}'
assert_before_seed cross-profile-nonclaim \
  "'cross_profile_evidence_accepted=false'"
assert_before_seed aarch64-independence-nonclaim \
  "'aarch64_gate_satisfied_by_x86_64=false'"
assert_before_seed old-version-binding \
  'fail '\''old package query disagrees with verified package metadata'\'''
assert_before_seed new-version-binding \
  'fail '\''new package query disagrees with verified package metadata'\'''
assert_before_seed no-archive-install-or-backup-metadata \
  'if /usr/bin/grep -Eq '\''^(backup|install) = '\'' "${output}"; then'
assert_before_seed old-dependencies-local \
  '/usr/bin/pacman -T -- "${OLD_DEPENDENCIES[@]}"'
assert_before_seed new-dependencies-local \
  '/usr/bin/pacman -T -- "${NEW_DEPENDENCIES[@]}"'
assert_before_seed pacman-config-safe-chain \
  'require_safe_root_chain /etc/pacman.conf'
assert_before_seed pacman-include-bound \
  'fail '\''target pacman Include set is empty or outside the closed count bound'\'''
assert_before_seed pacman-include-safe-chain \
  'require_safe_root_chain "${pacman_include_file}" '\''target pacman Include'\'''
assert_before_seed no-nested-pacman-includes \
  'fail '\''nested target pacman Include directives are unsupported'\'''
assert_before_seed effective-hook-directories \
  'mapfile -t CONFIGURED_HOOK_DIRECTORIES < <(/usr/bin/pacman-conf HookDir)'
assert_before_seed absent-hook-parent-safe-chain \
  ''\''absent effective pacman hook directory parent'\'''
assert_before_seed pacman-repository-inventory \
  'mapfile -t PACMAN_REPOSITORIES < <(/usr/bin/pacman-conf --repo-list)'
assert_before_seed pacman-repository-count-bound \
  'fail '\''configured pacman repository count is empty or outside the closed bound'\'''
assert_before_seed effective-pacman-config-snapshot \
  'write_effective_pacman_config "${PACMAN_EFFECTIVE_CONFIG}"'
assert_before_seed effective-hook-inventory-snapshot \
  'write_hook_inventory "${PACMAN_HOOK_INVENTORY}"'
assert_before_seed effective-pacman-policy-digests \
  'PACMAN_EFFECTIVE_CONFIG_SHA256="$(sha256_file "${PACMAN_EFFECTIVE_CONFIG}")"'
assert_before_seed pacman-binary-recheck \
  '"$(sha256_file "${PACMAN_BINARY}")" == "${PACMAN_BINARY_SHA256}"'
assert_before_seed pacman-package-query-recheck \
  '"$(/usr/bin/pacman -Q pacman)" == "${PACMAN_PACKAGE_QUERY}"'
assert_before_seed final-static-input-check \
  'assert_static_inputs '\''before any package or user-state mutation'\'''
assert_before_seed repeated-bridge-policy-binding \
  'fail "executing package lifecycle bridge changed ${stage}"'
assert_before_seed preprovisioned-lock-directory \
  'fail '\''pre-provisioned package lifecycle bridge lock directory is unsafe or absent'\'''
assert_before_seed preprovisioned-lock-file \
  'fail '\''pre-provisioned package lifecycle bridge lock is unsafe'\'''

ACK_LINE="$(line_or_fail acknowledgement-order \
  'A_QUO_INSTALLED_PACKAGE_LIFECYCLE_ACKNOWLEDGEMENT:-')"
ROOT_LINE="$(line_or_fail root-order 'if (( EUID != 0 )); then')"
MARKER_LINE="$(line_or_fail marker-order \
  'require_real_regular_file "${DISPOSABLE_MARKER}"')"
NETWORK_GATE_LINE="$(line_or_fail network-order \
  '/usr/bin/unshare --net -- /usr/bin/true')"
readonly ACK_LINE ROOT_LINE MARKER_LINE NETWORK_GATE_LINE
if ((ACK_LINE >= ROOT_LINE || ROOT_LINE >= MARKER_LINE ||
  MARKER_LINE >= NETWORK_GATE_LINE || NETWORK_GATE_LINE >= FIRST_PERSISTENT_SEED_LINE)); then
  fail_contract 'acknowledgement/root/marker/network/seed gates are not fail-first ordered'
fi

STATE_DIRECTORY_CREATE_LINE="$(line_or_fail evaluator-state-directory-creation \
  '/usr/bin/install -d -m 0700 -- "${evaluator_state_parent}"')"
STATE_SENTINEL_CREATE_LINE="$(line_or_fail evaluator-state-sentinel-creation \
  'oflag=excl,nofollow status=none')"
readonly STATE_DIRECTORY_CREATE_LINE STATE_SENTINEL_CREATE_LINE
if ! ((FIRST_PERSISTENT_SEED_LINE < STATE_DIRECTORY_CREATE_LINE &&
  STATE_DIRECTORY_CREATE_LINE < STATE_SENTINEL_CREATE_LINE &&
  STATE_SENTINEL_CREATE_LINE < FIRST_PACMAN_MUTATION_LINE)); then
  fail_contract 'evaluator-privileged state creation is outside the persistent seed boundary'
fi
line_or_fail evaluator-state-creator \
  '/usr/bin/runuser -u "${EVALUATOR_ACCOUNT}" --' >/dev/null

# Every package mutation goes through the same no-network pacman wrapper.
line_or_fail pacman-network-wrapper \
  '/usr/bin/unshare --net -- /usr/bin/pacman --noconfirm "$@"' >/dev/null
INSTALLED_SERVICE_CHECK_LINE="$(exact_command_line_of 'assert_service_disabled')"
readonly INSTALLED_SERVICE_CHECK_LINE
[[ -n "${INSTALLED_SERVICE_CHECK_LINE}" ]] ||
  fail_contract 'installed-package verification omits its exact disabled-service check'
mapfile -t TRANSACTION_MARKERS < <(
  /usr/bin/awk '/^[[:space:]]*run_pacman_transaction -[UR] / {print NR ":" $0}' \
    "${EVALUATOR}"
)
[[ "${#TRANSACTION_MARKERS[@]}" -eq 4 ]] ||
  fail_contract 'armed evaluator must contain exactly four package mutations'
for transaction_index in 0 1 2 3; do
  TRANSACTION_MARKERS[transaction_index]="${TRANSACTION_MARKERS[transaction_index]#*:}"
  TRANSACTION_MARKERS[transaction_index]="${TRANSACTION_MARKERS[transaction_index]#"${TRANSACTION_MARKERS[transaction_index]%%[![:space:]]*}"}"
done
readonly TRANSACTION_MARKERS
[[ "${TRANSACTION_MARKERS[0]}" == \
    'run_pacman_transaction -U -- "${OLD_PACKAGE_SNAPSHOT}"' &&
  "${TRANSACTION_MARKERS[1]}" == \
    'run_pacman_transaction -U -- "${NEW_PACKAGE_SNAPSHOT}"' &&
  "${TRANSACTION_MARKERS[2]}" == 'run_pacman_transaction -R -- a-quo' &&
  "${TRANSACTION_MARKERS[3]}" == \
    'run_pacman_transaction -U -- "${NEW_PACKAGE_SNAPSHOT}"' ]] ||
  fail_contract 'package mutations differ from install-old/upgrade/remove/reinstall'

INSTALL_LINE="$(line_or_fail install-old \
  'run_pacman_transaction -U -- "${OLD_PACKAGE_SNAPSHOT}"')"
INSTALL_BOUNDARY_LINE="$(line_or_fail install-old-boundary \
  'assert_absent_transition_boundary '\''immediately before old-package installation'\''')"
VERIFY_OLD_LINE="$(line_or_fail verify-old \
  'assert_installed_package "${OLD_PACKAGE_QUERY}" "${OLD_PACKAGE_SNAPSHOT}" old-install old')"
UPGRADE_LINE="$(line_or_fail upgrade-new \
  'run_pacman_transaction -U -- "${NEW_PACKAGE_SNAPSHOT}"')"
UPGRADE_BOUNDARY_LINE="$(line_or_fail upgrade-new-boundary \
  'assert_installed_transition_boundary "${OLD_PACKAGE_QUERY}"')"
VERIFY_UPGRADE_LINE="$(line_or_fail verify-upgrade \
  'assert_installed_package "${NEW_PACKAGE_QUERY}" "${NEW_PACKAGE_SNAPSHOT}" new-upgrade new')"
CONSENT_STAGE_LINE="$(line_or_fail consent-stage 'CURRENT_STAGE=installed-trusted-consent-v1-v2')"
CONSENT_ENV_LINE="$(line_or_fail sanitized-consent-environment \
  'A_QUO_INSTALLED_CONSENT_LIFECYCLE_ACKNOWLEDGEMENT=I-understand-this-runs-real-a-quo-consent-on-the-disposable-evaluator-account')"
CONSENT_HANDOFF_ENV_LINE="$(line_or_fail exact-consent-handoff \
  'A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT="${CONSENT_HANDOFF_ROOT}"')"
CONSENT_PROFILE_ENV_LINE="$(line_or_fail exact-consent-profile-binding \
  'A_QUO_EVALUATION_PROFILE_ID="${EVALUATION_PROFILE_ID}"')"
CONSENT_PROFILE_NAMESPACE_ENV_LINE="$(line_or_fail exact-consent-profile-namespace \
  'A_QUO_EVALUATION_EVIDENCE_NAMESPACE="${EVALUATION_EVIDENCE_NAMESPACE}"')"
CONSENT_V2_ARTIFACT_ENV_LINE="$(line_or_fail exact-consent-v2-artifact \
  'A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2="${A_QUO_EVALUATOR_PACKAGE_V2}"')"
CONSENT_V2_DIGEST_ENV_LINE="$(line_or_fail exact-consent-v2-artifact-digest \
  'A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256="${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}"')"
CONSENT_RUN_LINE="$(line_or_fail network-isolated-committed-consent-run \
  '/usr/bin/unshare --net -- "${COMMITTED_CONSENT_EVALUATOR}" >"${CONSENT_EVIDENCE}"')"
CONSENT_VERIFY_LINE="$(line_or_fail consent-evidence-verification \
  'fail '\''installed-consent evaluator returned invalid or overstated evidence'\''')"
POST_CONSENT_VERIFY_LINE="$(line_or_fail post-consent-installed-package-verification \
  'post-installed-consent new')"
CORE_STAGE_LINE="$(line_or_fail core-stage 'CURRENT_STAGE=installed-preconsented-core-v2-lifecycle')"
CORE_ENV_LINE="$(line_or_fail sanitized-core-environment \
  'A_QUO_INSTALLED_OMARCHY_CORE_LIFECYCLE_ACKNOWLEDGEMENT=I-understand-this-mutates-the-disposable-a-quo-evaluator-account')"
CORE_HANDOFF_ENV_LINE="$(line_or_fail exact-core-handoff \
  'A_QUO_INSTALLED_OMARCHY_PRECONSENTED_HANDOFF_ROOT="${CONSENT_HANDOFF_ROOT}"')"
CORE_PROFILE_ENV_LINE="$(last_active_line_of \
  'A_QUO_EVALUATION_PROFILE_ID="${EVALUATION_PROFILE_ID}"')" ||
  fail_contract 'armed evaluator lacks exact core profile binding'
CORE_PROFILE_NAMESPACE_ENV_LINE="$(last_active_line_of \
  'A_QUO_EVALUATION_EVIDENCE_NAMESPACE="${EVALUATION_EVIDENCE_NAMESPACE}"')" ||
  fail_contract 'armed evaluator lacks exact core profile namespace'
CORE_V2_PACKAGE_ENV_LINE="$(line_or_fail exact-core-v2-package \
  'A_QUO_EVALUATOR_PACKAGE_V2="${A_QUO_EVALUATOR_PACKAGE_V2}"')"
CORE_V2_DIGEST_ENV_LINE="$(line_or_fail exact-core-v2-package-digest \
  'A_QUO_EVALUATOR_PACKAGE_V2_SHA256="${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}"')"
CORE_RUN_LINE="$(line_or_fail network-isolated-committed-core-run \
  '/usr/bin/unshare --net -- "${COMMITTED_CORE_EVALUATOR}" >"${CORE_EVIDENCE}"')"
CORE_VERIFY_LINE="$(line_or_fail core-evidence-verification \
  'fail '\''installed-core evaluator returned invalid or overstated evidence'\''')"
BINDING_STAGE_LINE="$(line_or_fail consent-core-binding-stage \
  'CURRENT_STAGE=validate-consent-to-core-binding')"
BINDING_LINE="$(line_or_fail consent-core-binding \
  'assert_consent_to_core_binding "${CONSENT_EVIDENCE}" "${CORE_EVIDENCE}"')"
POST_CORE_VERIFY_LINE="$(line_or_fail post-core-installed-package-verification \
  'post-installed-preconsented-core new')"
RETAINED_BEFORE_LINE="$(line_or_fail retained-state-before-remove \
  'retained_state_manifest "${RETAINED_BEFORE_REMOVE}"')"
REMOVE_LINE="$(line_or_fail remove-package 'run_pacman_transaction -R -- a-quo')"
REMOVE_BOUNDARY_LINE="$(line_or_fail remove-package-boundary \
  'assert_installed_transition_boundary "${NEW_PACKAGE_QUERY}"')"
ABSENCE_LINE="$(line_or_fail verify-package-absence \
  'assert_a_quo_package_absent '\''after package removal'\''')"
REMOVAL_STATE_LINE="$(line_or_fail verify-state-after-remove \
  'retained_state_manifest "${RETAINED_AFTER_REMOVE}"')"
REMOVAL_COMPARE_LINE="$(line_or_fail compare-state-after-remove \
  '/usr/bin/cmp -s -- "${RETAINED_BEFORE_REMOVE}" "${RETAINED_AFTER_REMOVE}"')"
REMOVAL_SERVICE_LINE="$(last_active_line_of 'assert_no_enablement_or_process absent')" ||
  fail_contract 'armed evaluator lacks post-removal service-state verification'
REINSTALL_LINE="$(last_active_line_of \
  'run_pacman_transaction -U -- "${NEW_PACKAGE_SNAPSHOT}"')" ||
  fail_contract 'armed evaluator lacks new-package reinstall'
REINSTALL_BOUNDARY_LINE="$(last_active_line_of \
  'assert_absent_transition_boundary '\''immediately before new-package reinstall'\''')" ||
  fail_contract 'armed evaluator lacks new-package reinstall boundary'
VERIFY_REINSTALL_LINE="$(last_active_line_of \
  'assert_installed_package "${NEW_PACKAGE_QUERY}" "${NEW_PACKAGE_SNAPSHOT}" new-reinstall new')" ||
  fail_contract 'armed evaluator lacks reinstall verification'
REINSTALL_STATE_LINE="$(line_or_fail retained-state-after-reinstall \
  'retained_state_manifest "${RETAINED_AFTER_REINSTALL}"')"
REINSTALL_COMPARE_LINE="$(line_or_fail compare-state-after-reinstall \
  '/usr/bin/cmp -s -- "${RETAINED_BEFORE_REMOVE}" "${RETAINED_AFTER_REINSTALL}"')"
readonly INSTALL_LINE INSTALL_BOUNDARY_LINE VERIFY_OLD_LINE
readonly UPGRADE_LINE UPGRADE_BOUNDARY_LINE VERIFY_UPGRADE_LINE
readonly CONSENT_STAGE_LINE CONSENT_ENV_LINE CONSENT_RUN_LINE CONSENT_VERIFY_LINE
readonly CONSENT_HANDOFF_ENV_LINE POST_CONSENT_VERIFY_LINE
readonly CONSENT_PROFILE_ENV_LINE CONSENT_PROFILE_NAMESPACE_ENV_LINE
readonly CONSENT_V2_ARTIFACT_ENV_LINE CONSENT_V2_DIGEST_ENV_LINE
readonly CORE_STAGE_LINE CORE_ENV_LINE CORE_HANDOFF_ENV_LINE CORE_RUN_LINE
readonly CORE_PROFILE_ENV_LINE CORE_PROFILE_NAMESPACE_ENV_LINE
readonly CORE_V2_PACKAGE_ENV_LINE CORE_V2_DIGEST_ENV_LINE
readonly CORE_VERIFY_LINE BINDING_STAGE_LINE BINDING_LINE POST_CORE_VERIFY_LINE
readonly RETAINED_BEFORE_LINE REMOVE_LINE REMOVE_BOUNDARY_LINE ABSENCE_LINE REMOVAL_STATE_LINE
readonly REMOVAL_COMPARE_LINE REMOVAL_SERVICE_LINE REINSTALL_LINE REINSTALL_BOUNDARY_LINE
readonly VERIFY_REINSTALL_LINE
readonly REINSTALL_STATE_LINE REINSTALL_COMPARE_LINE

for profile_environment_name in \
  A_QUO_EVALUATION_PROFILE_ID \
  A_QUO_EVALUATION_PROFILE_SHA256 \
  A_QUO_EVALUATION_TARGET_KIND \
  A_QUO_EVALUATION_ARCHITECTURE \
  A_QUO_EVALUATION_EVIDENCE_NAMESPACE; do
  [[ "$(/usr/bin/grep -Fc -- "${profile_environment_name}=" "${EVALUATOR}")" -eq 2 ]] ||
    fail_contract "profile environment binding is missing or duplicated: ${profile_environment_name}"
done

if ((INSTALLED_SERVICE_CHECK_LINE >= INSTALL_LINE)); then
  fail_contract 'disabled-service check is not part of installed-package verification'
fi

if ! ((INSTALL_BOUNDARY_LINE < INSTALL_LINE &&
  INSTALL_LINE - INSTALL_BOUNDARY_LINE <= 2 &&
  INSTALL_LINE < VERIFY_OLD_LINE &&
  VERIFY_OLD_LINE < UPGRADE_BOUNDARY_LINE &&
  UPGRADE_BOUNDARY_LINE < UPGRADE_LINE &&
  UPGRADE_LINE - UPGRADE_BOUNDARY_LINE <= 3 &&
  UPGRADE_LINE < VERIFY_UPGRADE_LINE &&
  VERIFY_UPGRADE_LINE < CONSENT_STAGE_LINE &&
  CONSENT_STAGE_LINE < CONSENT_ENV_LINE &&
  CONSENT_ENV_LINE < CONSENT_HANDOFF_ENV_LINE &&
  CONSENT_HANDOFF_ENV_LINE < CONSENT_PROFILE_ENV_LINE &&
  CONSENT_PROFILE_ENV_LINE < CONSENT_PROFILE_NAMESPACE_ENV_LINE &&
  CONSENT_PROFILE_NAMESPACE_ENV_LINE < CONSENT_V2_ARTIFACT_ENV_LINE &&
  CONSENT_V2_ARTIFACT_ENV_LINE < CONSENT_V2_DIGEST_ENV_LINE &&
  CONSENT_V2_DIGEST_ENV_LINE < CONSENT_RUN_LINE &&
  CONSENT_RUN_LINE < CONSENT_VERIFY_LINE &&
  CONSENT_VERIFY_LINE < POST_CONSENT_VERIFY_LINE &&
  POST_CONSENT_VERIFY_LINE < CORE_STAGE_LINE &&
  CORE_STAGE_LINE < CORE_ENV_LINE &&
  CORE_ENV_LINE < CORE_HANDOFF_ENV_LINE &&
  CORE_HANDOFF_ENV_LINE < CORE_PROFILE_ENV_LINE &&
  CORE_PROFILE_ENV_LINE < CORE_PROFILE_NAMESPACE_ENV_LINE &&
  CORE_PROFILE_NAMESPACE_ENV_LINE < CORE_V2_PACKAGE_ENV_LINE &&
  CORE_V2_PACKAGE_ENV_LINE < CORE_V2_DIGEST_ENV_LINE &&
  CORE_V2_DIGEST_ENV_LINE < CORE_RUN_LINE &&
  CORE_RUN_LINE < CORE_VERIFY_LINE &&
  CORE_VERIFY_LINE < BINDING_STAGE_LINE &&
  BINDING_STAGE_LINE < BINDING_LINE &&
  BINDING_LINE < POST_CORE_VERIFY_LINE &&
  POST_CORE_VERIFY_LINE < RETAINED_BEFORE_LINE &&
  RETAINED_BEFORE_LINE < REMOVE_BOUNDARY_LINE &&
  REMOVE_BOUNDARY_LINE < REMOVE_LINE &&
  REMOVE_LINE - REMOVE_BOUNDARY_LINE <= 3 &&
  REMOVE_LINE < ABSENCE_LINE &&
  ABSENCE_LINE < REMOVAL_SERVICE_LINE &&
  REMOVAL_SERVICE_LINE < REMOVAL_STATE_LINE &&
  REMOVAL_STATE_LINE < REMOVAL_COMPARE_LINE &&
  REMOVAL_COMPARE_LINE < REINSTALL_BOUNDARY_LINE &&
  REINSTALL_BOUNDARY_LINE < REINSTALL_LINE &&
  REINSTALL_LINE - REINSTALL_BOUNDARY_LINE <= 2 &&
  REINSTALL_LINE < VERIFY_REINSTALL_LINE &&
  VERIFY_REINSTALL_LINE < REINSTALL_STATE_LINE &&
  REINSTALL_STATE_LINE < REINSTALL_COMPARE_LINE)); then
  fail_contract 'installed package lifecycle transition or verification order drifted'
fi

for verification_literal in \
  '/usr/bin/pacman -Qkk a-quo' \
  '/usr/bin/pacman -Qlq a-quo' \
  'fail "registered package inventory differs ${stage}"' \
  '/usr/bin/cmp -s -- "${extracted}/${relative}" "/${relative}"' \
  '"0:0:${mode}:regular file"' \
  'fail "declared dependencies are not satisfied ${stage}"' \
  'fail "optional reviewer registry is not empty ${stage}"' \
  'assert_preservation_sentinel "${stage}"'; do
  line_or_fail installed-verification-body "${verification_literal}" >/dev/null
done
[[ "$(/usr/bin/grep -Fc -- '! -e "${package_leaf}.pacsave"' \
  "${EVALUATOR}")" -eq 1 ]] ||
  fail_contract 'the shared exact-absence gate must reject package pacsave leaves'
[[ "$(/usr/bin/grep -Ec \
  '^[[:space:]]*assert_absent_transition_boundary([[:space:]]|$)' \
  "${EVALUATOR}")" -eq 2 && \
  "$(/usr/bin/grep -Ec \
  '^[[:space:]]*assert_installed_transition_boundary([[:space:]]|$)' \
  "${EVALUATOR}")" -eq 2 ]] ||
  fail_contract 'all four Pacman mutations must have explicit transition-state boundaries'
for boundary_literal in \
  'assert_a_quo_package_absent "${stage}"' \
  'assert_no_enablement_or_process absent' \
  '/usr/bin/pacman -Qkk a-quo' \
  'assert_service_disabled' \
  'fail "Pacman database lock exists ${stage}"'; do
  line_or_fail transition-boundary-body "${boundary_literal}" >/dev/null
done
for service_literal in \
  'run_evaluator_systemctl is-enabled a-quo-daemon.service' \
  'run_global_systemctl is-enabled a-quo-daemon.service' \
  '"${EVALUATOR_RUNTIME_DIRECTORY}/systemd/user"' \
  'expected_enabled_output=disabled' \
  'expected_enabled_output=not-found'; do
  line_or_fail sampled-service-boundary "${service_literal}" >/dev/null
done

# Reject dependency/signature bypasses, network acquisition, service mutation,
# scanner scope creep, direct generic D-Bus tooling, and session-bus injection.
ACTIVE_SOURCE="$(
  /usr/bin/awk '{line=$0; sub(/^[[:space:]]*/, "", line); if (line !~ /^#/) print $0}' \
    "${EVALUATOR}"
)"
readonly ACTIVE_SOURCE
if /usr/bin/grep -Eq -- \
  '^[[:space:]]*(return|exit)([[:space:]]+0)?([[:space:]]*(;|#).*)?[[:space:]]*$' \
  <<<"${ACTIVE_SOURCE}"; then
  fail_contract 'armed evaluator contains a bare or zero-status early-success exit'
fi
if /usr/bin/grep -Eq -- \
  '(^|[[:space:]])(--assume-installed|--cachedir|--config|--dbonly|--dbpath|--gpgdir|--hookdir|--logfile|--needed|--nodeps|--nosave|--noscriptlet|--overwrite|--root|--sysroot)([=[:space:]]|$)|run_pacman_transaction[[:space:]]+(-Rns|-Rdd|-S[^[:space:]]*|--remove|--sync|--upgrade)([[:space:]]|$)|/usr/bin/pacman.*[[:space:]](-U|-R|-Rns|-Rdd|-S[^[:space:]]*|--remove|--sync|--upgrade)([[:space:]]|$)|/usr/bin/pacman.*[[:space:]]-d(d)?([[:space:]]|$)|SigLevel[[:space:]]*=[[:space:]]*Never' \
  <<<"${ACTIVE_SOURCE}"; then
  fail_contract 'armed evaluator contains a dependency, overwrite, scriptlet, signature, or repository bypass'
fi
[[ "$(/usr/bin/grep -Ec \
  '^[[:space:]]*run_pacman_transaction(\(\)[[:space:]]*\{|[[:space:]]+-[UR][[:space:]])' \
  "${EVALUATOR}")" -eq 5 ]] ||
  fail_contract 'Pacman transaction wrapper must have one definition and four direct calls'
if /usr/bin/grep -Eq -- \
  '(mkdir|install|chown|chmod).*(BRIDGE_LOCK|package lifecycle bridge lock)|(^|[[:space:]]):[[:space:]]*>"?\$\{BRIDGE_LOCK\}"?' \
  <<<"${ACTIVE_SOURCE}"; then
  fail_contract 'armed evaluator creates or rewrites pre-provisioned bridge coordination state'
fi
if /usr/bin/grep -Eq -- \
  '/usr/bin/systemctl.*[[:space:]](enable|disable|start|stop|restart|preset|preset-all)([[:space:]]|$)|run_[[:alnum:]_]*systemctl[[:space:]]+(enable|disable|start|stop|restart|preset|preset-all)([[:space:]]|$)|(^|[[:space:]])omarchy[[:space:]]+(enable|disable)([[:space:]]|$)' \
  <<<"${ACTIVE_SOURCE}"; then
  fail_contract 'armed evaluator contains a service or Omarchy enablement mutation'
fi
if /usr/bin/grep -Eiq -- \
  '(^|[^[:alnum:]_])(curl|wget)([^[:alnum:]_]|$)|plug[[:space:]_-]*(and|&)[[:space:]_-]*prejudice|scanner|scan-installed|DBUS_SESSION_BUS_ADDRESS|(^|[^[:alnum:]_])(busctl|gdbus|dbus-send)([^[:alnum:]_]|$)' \
  <<<"${ACTIVE_SOURCE}"; then
  fail_contract 'armed evaluator contains network acquisition, scanner, direct generic D-Bus tooling, or session-bus injection'
fi

# Failure handling may observe package state but must never attempt a reversal.
CLEANUP_START_LINE="$(line_or_fail cleanup-function 'cleanup() {')"
CLEANUP_TRAP_LINE="$(line_or_fail cleanup-trap 'trap cleanup EXIT')"
readonly CLEANUP_START_LINE CLEANUP_TRAP_LINE
CLEANUP_BODY="$(
  /usr/bin/sed -n "${CLEANUP_START_LINE},${CLEANUP_TRAP_LINE}p" "${EVALUATOR}"
)"
readonly CLEANUP_BODY
if /usr/bin/grep -Eq -- \
  'run_pacman_transaction|/usr/bin/pacman[[:space:]].*-[URSD]|/usr/bin/systemctl.*[[:space:]](enable|disable|start|stop|restart|preset)' \
  <<<"${CLEANUP_BODY}"; then
  fail_contract 'failure cleanup contains an automatic package or service reversal'
fi
if /usr/bin/grep -Eq -- \
  '(/usr/bin/)?(rm|unlink|truncate).*(PACMAN_LOCK|/var/lib/pacman/db\.lck)|(PACMAN_LOCK|/var/lib/pacman/db\.lck).*(rm|unlink|truncate)' \
  <<<"${ACTIVE_SOURCE}"; then
  fail_contract 'armed evaluator can delete or truncate the pacman database lock'
fi
if /usr/bin/grep -Eq -- \
  '(^|[^<])>[[:space:]]*"?\$\{PACMAN_LOCK\}"?|(^|[^<])>[[:space:]]*/var/lib/pacman/db\.lck' \
  <<<"${ACTIVE_SOURCE}"; then
  fail_contract 'armed evaluator can overwrite the pacman database lock'
fi
for failure_literal in \
  'package lifecycle stopped without automatic reversal:' \
  'automatic_reversal_on_failure: false'; do
  line_or_fail failure-nonreversal "${failure_literal}" >/dev/null
done

[[ "$(/usr/bin/grep -Fc -- '/usr/bin/rm -rf -- "${TEMPORARY_ROOT}"' \
  "${EVALUATOR}")" -eq 1 ]] ||
  fail_contract 'armed evaluator must have one exact identity-checked recursive cleanup target'
line_or_fail cleanup-prefix-guard \
  '[[ "${TEMPORARY_ROOT}" == /var/tmp/a-quo-installed-package-lifecycle.* ]]' >/dev/null
line_or_fail cleanup-identity-guard \
  '"${TEMPORARY_ROOT_IDENTITY}:0:0:700"' >/dev/null

EVIDENCE_BUILD_LINE="$(line_or_fail evidence-build 'EVIDENCE_JSON="$({')"
SUCCESS_CLEANUP_LINE="$(last_active_line_of 'if ! remove_temporary_root; then')" ||
  fail_contract 'armed evaluator lacks explicit success cleanup'
TRAP_RETIRE_LINE="$(last_active_line_of 'trap - EXIT')" ||
  fail_contract 'armed evaluator does not retire its cleanup trap'
EVIDENCE_OUTPUT_LINE="$(last_active_line_of 'printf '\''%s\n'\'' "${EVIDENCE_JSON}"')" ||
  fail_contract 'armed evaluator lacks final evidence emission'
readonly EVIDENCE_BUILD_LINE SUCCESS_CLEANUP_LINE TRAP_RETIRE_LINE EVIDENCE_OUTPUT_LINE
if ! ((EVIDENCE_BUILD_LINE < SUCCESS_CLEANUP_LINE &&
  SUCCESS_CLEANUP_LINE < TRAP_RETIRE_LINE &&
  TRAP_RETIRE_LINE < EVIDENCE_OUTPUT_LINE)); then
  fail_contract 'success evidence can be emitted before cleanup and trap retirement'
fi

for required_literal in \
  'target_profile: {' \
  'profile_id: $profile_id' \
  'profile_sha256: $profile_sha256' \
  'binding_role: "package-target-policy"' \
  'target_kind: $target_kind' \
  'architecture: $architecture' \
  'evidence_namespace: $evidence_namespace' \
  'old_and_new_verifier_receipts_match: true' \
  'cross_profile_evidence_accepted: false' \
  'aarch64_gate_satisfied_by_x86_64: false' \
  '"trusted_signing_consent_for_plugin_v1",' \
  '"trusted_signing_consent_for_plugin_v2",' \
  '"inspect_plugin_v1_and_v2",' \
  '"install_plugin_v1",' \
  '"update_plugin_v2",' \
  '"refuse_plugin_v1_downgrade_with_final_managed_tree_unchanged",' \
  '"uninstall_plugin_v2_to_retained_quarantine",' \
  '.handoff.format == "a-quo-installed-omarchy-preconsented-handoff-v2"' \
  '.consent.approval_v2 == "proof_returned_and_verified"' \
  '.schema == "urn:a-quo:evidence:installed-omarchy-core-lifecycle:v2"' \
  '.mode == "preconsented_joined_v2_lifecycle"' \
  '.subject.v2.package_sha256 == $expected_v2_sha256' \
  '$c.handoff.proof_v2_sha256 == $k.subject.v2.proof_sha256' \
  '.lifecycle.previous_release_recovery_full_tree_match == true' \
  '.lifecycle.downgrade_refused == true' \
  '.lifecycle.downgrade_final_managed_tree_unchanged == true' \
  '.lifecycle.uninstall_quarantine_full_tree_match == true' \
  '.retained_state.previous_release_recovery_managed_tree_sha256 ==' \
  '.subject.v1.managed_tree_sha256_before_update' \
  '.subject.v2.managed_tree_sha256_before_downgrade_refusal ==' \
  '.retained_state.uninstall_recovery_quarantine_managed_tree_sha256 ==' \
  '.subject.v2.managed_tree_sha256_before_uninstall' \
  '.signing_operations_this_core_invocation == "none"' \
  '.private_key_access_this_core_invocation == "none"' \
  '.trusted_consent == "not_established_by_core_alone"' \
  '.reported_signing_consent == "operator_approved_installed_daemon_proofs_consumed"' \
  '.installation_trusted_consent == "not_established_cli_acknowledgements_only"' \
  'consent_to_core_handoff_binding:' \
  '"verified_exact_v1_v2_packages_proofs_manifest_persona_fingerprint_and_store"' \
  'retained_user_state_preserved_across_remove_reinstall: true' \
  'real_root_package_lifecycle_tested: true' \
  'package_dependencies_satisfied_locally: true' \
  'package_query: $pacman_package_query' \
  'binary_sha256: $pacman_binary_sha256' \
  'runtime_dependency_identity_pinned: false' \
  'local_package_transactions_requested: true' \
  'repository_sync_or_dependency_acquisition_requested: false' \
  'pacman_process_trees_fresh_network_namespace: true' \
  'nested_consent_and_core_process_trees_fresh_network_namespace: true' \
  'inherited_descriptor_or_unix_socket_isolation_established: false' \
  'hook_host_service_delegation_excluded: false' \
  'whole_machine_network_silence: false' \
  'package_archive_install_script_present: false' \
  'package_backup_entries_present: false' \
  'package_archive_resource_containment_established: false' \
  'libalpm_hook_execution: "target_effective_policy_applied; exact_triggered_subset_not_independently_enumerated"' \
  'package_signatures_verified: false' \
  'source_to_binary_provenance_established: false' \
  'source_checkout_is_independently_authenticated: false' \
  'script_requested_service_start_or_enable: true' \
  'service_ever_started_or_enabled_established: true' \
  'evaluator_and_global_service_disabled_at_sampled_boundaries: true' \
  'service_inactive_at_sampled_boundaries: true' \
  'unit_absent_at_post_removal_sample: true' \
  'other_user_runtime_enablement_checked: false' \
  'live_service_tested: true' \
  'trusted_signing_consent_tested: true' \
  'trusted_installation_consent_tested: false' \
  'behavioral_analysis: "not_run"' \
  'plugin_safety: "not_established"' \
  'clean_system_claim: "not_established_disposable_marker_only"' \
  'joined_plugin_install_update_downgrade_refusal_uninstall_tested: true' \
  'a_quo_package_downgrade_refusal_tested: false' \
  'joined_plugin_downgrade_refusal_tested: true' \
  'joined_plugin_rollback_failure_tested: false' \
  'interruption_recovery_tested: false' \
  'removal_then_reinstall_is_rollback: false' \
  'unrelated_pacman_process_exclusion_established: false' \
  'retained_state_post_enumeration_bounds_applied: true' \
  'retained_state_enumeration_resource_contained: false' \
  'retained_state_same_uid_race_excluded: false' \
  'automatic_reversal_on_failure: false' \
  'temporary_work_cleanup: "verified_before_evidence_emission"'; do
  line_or_fail required-evidence-nonclaim "${required_literal}" >/dev/null
done
[[ "$(/usr/bin/grep -Fc -- '/usr/bin/jq -s -e --arg expected_query' \
  "${EVALUATOR}")" -eq 2 && \
  "$(/usr/bin/grep -Fxc -- '  length == 1 and' "${EVALUATOR}")" -eq 2 ]] ||
  fail_contract 'consent and core child outputs must each be exactly one JSON document'
line_or_fail policy-bridge-evidence \
  'policy_bridge_sha256: $policy_bridge_sha256' >/dev/null
[[ "$(/usr/bin/grep -Fc -- \
    'aarch64_gate_satisfied_by_x86_64: false' "${EVALUATOR}")" -eq 4 && \
  "$(/usr/bin/grep -Fc -- \
    'aarch64_gate_satisfied_by_x86_64: true' "${EVALUATOR}")" -eq 0 ]] ||
  fail_contract 'AArch64 evidence has a missing, duplicated, or affirmative x86_64 gate claim'

if [[ "${A_QUO_PACKAGE_LIFECYCLE_CONTRACT_MUTANT_CHILD:-0}" != 1 ]]; then
  MUTANT_ROOT="$(/usr/bin/mktemp -d /tmp/a-quo-package-lifecycle-contract.XXXXXX)"
  readonly MUTANT_ROOT
  MUTANT_ROOT_IDENTITY="$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "${MUTANT_ROOT}")"
  readonly MUTANT_ROOT_IDENTITY
  readonly MUTANT_EVALUATOR="${MUTANT_ROOT}/test-installed-a-quo-package-lifecycle.sh"
  readonly MUTANT_CONTRACT="${MUTANT_ROOT}/test-installed-a-quo-package-lifecycle-contract.sh"
  /usr/bin/install -m 0700 -- "$0" "${MUTANT_CONTRACT}"

  remove_mutant_root() {
    [[ "${MUTANT_ROOT}" == /tmp/a-quo-package-lifecycle-contract.* && \
      -d "${MUTANT_ROOT}" && ! -L "${MUTANT_ROOT}" && \
      "$(/usr/bin/stat -c '%d:%i:%u:%g:%a' -- "${MUTANT_ROOT}")" == \
        "${MUTANT_ROOT_IDENTITY}" ]] || return 1
    /usr/bin/rm -rf -- "${MUTANT_ROOT}"
  }
  trap 'remove_mutant_root && remove_contract_root || exit 1' EXIT

  reject_source_mutant() {
    local label="$1"
    local old_line="$2"
    local new_line="$3"
    local expected_match_count="${4:-1}"
    local next_evaluator="${MUTANT_ROOT}/evaluator.next"
    local output
    local status
    [[ "$(/usr/bin/grep -Fxc -- "${old_line}" "${EVALUATOR}")" -eq \
      "${expected_match_count}" ]] ||
      fail_contract "source mutation seam is not unique: ${label}"
    /usr/bin/env OLD_LINE="${old_line}" NEW_LINE="${new_line}" /usr/bin/awk '
      $0 == ENVIRON["OLD_LINE"] && replaced == 0 {
        print ENVIRON["NEW_LINE"]
        replaced = 1
        next
      }
      { print }
      END { if (replaced != 1) exit 1 }
    ' "${EVALUATOR}" >"${next_evaluator}" ||
      fail_contract "source mutant could not be built: ${label}"
    /usr/bin/install -m 0700 -- "${next_evaluator}" "${MUTANT_EVALUATOR}"
    /usr/bin/bash -n "${MUTANT_EVALUATOR}" ||
      fail_contract "source mutant is not syntactically valid: ${label}"
    set +e
    output="$(
      /usr/bin/env -i PATH=/usr/bin:/bin \
        A_QUO_PACKAGE_LIFECYCLE_CONTRACT_MUTANT_CHILD=1 \
        /usr/bin/bash "${MUTANT_CONTRACT}" 2>&1
    )"
    status="$?"
    set -e
    [[ "${status}" -ne 0 && \
      "${output}" == installed\ package\ lifecycle\ contract\ failed:* ]] ||
      fail_contract "source mutant was not rejected by the child contract: ${label}"
  }

  reject_source_mutant transition-boundary \
    "assert_absent_transition_boundary 'immediately before old-package installation'" \
    ': # hostile mutant removed the install transition boundary'
  reject_source_mutant x86-profile-substitution \
    'readonly EVALUATION_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"' \
    'readonly EVALUATION_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-physical-v1.profile"'
  reject_source_mutant pacman-policy-bypass \
    '    /usr/bin/unshare --net -- /usr/bin/pacman --noconfirm "$@"' \
    '    /usr/bin/unshare --net -- /usr/bin/pacman --noconfirm --nodeps "$@"'
  reject_source_mutant service-mutation \
    '  assert_no_daemon_process' \
    '  /usr/bin/systemctl --global enable a-quo-daemon.service'
  reject_source_mutant automatic-package-reversal \
    '  local installed_query=absent' \
    '  run_pacman_transaction -U -- "${OLD_PACKAGE_SNAPSHOT}"'
  reject_source_mutant false-signature-claim \
    '      package_signatures_verified: false,' \
    '      package_signatures_verified: true,'
  reject_source_mutant consent-evaluator-substitution \
    '  /usr/bin/unshare --net -- "${COMMITTED_CONSENT_EVALUATOR}" >"${CONSENT_EVIDENCE}"' \
    '  /usr/bin/unshare --net -- "${COMMITTED_CORE_EVALUATOR}" >"${CONSENT_EVIDENCE}"'
  reject_source_mutant consent-handoff-substitution \
    "  A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT=\"\${CONSENT_HANDOFF_ROOT}\" \\" \
    "  A_QUO_INSTALLED_CONSENT_HANDOFF_ROOT=/tmp/untrusted-handoff \\"
  reject_source_mutant consent-v2-artifact-substitution \
    "  A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2=\"\${A_QUO_EVALUATOR_PACKAGE_V2}\" \\" \
    "  A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2=\"\${A_QUO_EVALUATOR_PACKAGE_V1}\" \\"
  reject_source_mutant consent-v2-digest-substitution \
    "  A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256=\"\${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}\" \\" \
    "  A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2_SHA256=\"\${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}\" \\"
  reject_source_mutant consent-profile-substitution \
    "  A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2=\"\${A_QUO_EVALUATOR_PACKAGE_V2}\" \\" \
    $'  A_QUO_EVALUATION_PROFILE_ID=x86_64-hostile-mutant \\\n  A_QUO_EVALUATOR_SIGNING_ARTIFACT_V2="${A_QUO_EVALUATOR_PACKAGE_V2}" \\'
  reject_source_mutant consent-evidence-bypass \
    '  fail '\''installed-consent evaluator returned invalid or overstated evidence'\''' \
    '  : # hostile mutant accepts unvalidated consent evidence'
  reject_source_mutant core-evidence-bypass \
    '  fail '\''installed-core evaluator returned invalid or overstated evidence'\''' \
    '  : # hostile mutant accepts unvalidated core evidence'
  reject_source_mutant core-preconsented-mode-bypass \
    "  A_QUO_INSTALLED_OMARCHY_PRECONSENTED_HANDOFF_ROOT=\"\${CONSENT_HANDOFF_ROOT}\" \\" \
    "  A_QUO_UNUSED_PRECONSENTED_HANDOFF_ROOT=\"\${CONSENT_HANDOFF_ROOT}\" \\"
  reject_source_mutant core-v2-package-substitution \
    "  A_QUO_EVALUATOR_PACKAGE_V2=\"\${A_QUO_EVALUATOR_PACKAGE_V2}\" \\" \
    "  A_QUO_EVALUATOR_PACKAGE_V2=\"\${A_QUO_EVALUATOR_PACKAGE_V1}\" \\"
  reject_source_mutant core-v2-digest-substitution \
    "  A_QUO_EVALUATOR_PACKAGE_V2_SHA256=\"\${A_QUO_EVALUATOR_PACKAGE_V2_SHA256}\" \\" \
    "  A_QUO_EVALUATOR_PACKAGE_V2_SHA256=\"\${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}\" \\"
  reject_source_mutant core-architecture-substitution \
    "  A_QUO_EVALUATOR_PLUGIN_ID=\"\${A_QUO_EVALUATOR_PLUGIN_ID}\" \\" \
    $'  A_QUO_EVALUATION_ARCHITECTURE=x86_64 \\\n  A_QUO_EVALUATOR_PLUGIN_ID="${A_QUO_EVALUATOR_PLUGIN_ID}" \\'
  reject_source_mutant core-evidence-schema-downgrade \
    '    .schema == "urn:a-quo:evidence:installed-omarchy-core-lifecycle:v2" and' \
    '    .schema == "urn:a-quo:evidence:installed-omarchy-core-lifecycle:v1" and'
  reject_source_mutant proof-v2-binding-substitution \
    '      $c.handoff.proof_v2_sha256 == $k.subject.v2.proof_sha256 and' \
    '      $c.handoff.proof_v2_sha256 == $k.subject.v1.proof_sha256 and'
  reject_source_mutant nested-target-profile-binding-bypass \
    '      $c.target_profile == $k.target_profile and' \
    '      $c.target_profile != $k.target_profile and'
  reject_source_mutant downgrade-refusal-evidence-bypass \
    '    .lifecycle.downgrade_refused == true and' \
    '    .lifecycle.downgrade_refused == false and'
  reject_source_mutant v1-recovery-full-tree-evidence-bypass \
    '    .lifecycle.previous_release_recovery_full_tree_match == true and' \
    '    .lifecycle.previous_release_recovery_full_tree_match == false and'
  reject_source_mutant downgrade-final-tree-evidence-bypass \
    '    .lifecycle.downgrade_final_managed_tree_unchanged == true and' \
    '    .lifecycle.downgrade_final_managed_tree_unchanged == false and'
  reject_source_mutant v2-quarantine-full-tree-evidence-bypass \
    '    .lifecycle.uninstall_quarantine_full_tree_match == true and' \
    '    .lifecycle.uninstall_quarantine_full_tree_match == false and'
  reject_source_mutant v1-recovery-full-tree-binding-bypass \
    '    .retained_state.previous_release_recovery_managed_tree_sha256 ==' \
    '    .retained_state.previous_release_recovery_managed_tree_sha256 !='
  reject_source_mutant v2-quarantine-full-tree-binding-bypass \
    '    .retained_state.uninstall_recovery_quarantine_managed_tree_sha256 ==' \
    '    .retained_state.uninstall_recovery_quarantine_managed_tree_sha256 !='
  reject_source_mutant false-a-quo-package-downgrade-claim \
    '      a_quo_package_downgrade_refusal_tested: false,' \
    '      a_quo_package_downgrade_refusal_tested: true,'
  reject_source_mutant false-x86-satisfies-aarch64-claim \
    '        aarch64_gate_satisfied_by_x86_64: false' \
    '        aarch64_gate_satisfied_by_x86_64: true' \
    2
  reject_source_mutant false-joined-plugin-downgrade-claim \
    '      joined_plugin_downgrade_refusal_tested: true,' \
    '      joined_plugin_downgrade_refusal_tested: false,'
  reject_source_mutant false-install-consent-claim \
    '    .installation_trusted_consent == "not_established_cli_acknowledgements_only" and' \
    '    .installation_trusted_consent == "verified" and'
  reject_source_mutant false-plugin-safety-claim \
    '      plugin_safety: "not_established",' \
    '      plugin_safety: "established",'
  reject_source_mutant bridge-lock-creation \
    'exec 9<>"${BRIDGE_LOCK}"' \
    '/usr/bin/install -m 0600 /dev/null "${BRIDGE_LOCK}"'
  reject_source_mutant pacman-hash-bypass \
    'PACMAN_BINARY_SHA256="$(sha256_file "${PACMAN_BINARY}")"' \
    'PACMAN_BINARY_SHA256="$(printf '\''%064d'\'' 0)"'
  reject_source_mutant package-database-check-bypass \
    '  /usr/bin/pacman -Dk >/dev/null ||' \
    '  /usr/bin/true ||'

  PRE_ACK_SIDE_EFFECT="${MUTANT_ROOT}/unsafe-prefix-executed"
  readonly PRE_ACK_SIDE_EFFECT
  reject_source_mutant pre-ack-side-effect \
    "readonly REQUIRED_ACKNOWLEDGEMENT='I-understand-this-mutates-the-disposable-a-quo-package-evaluator'" \
    "/usr/bin/touch -- '${PRE_ACK_SIDE_EFFECT}'"$'\n'"readonly REQUIRED_ACKNOWLEDGEMENT='I-understand-this-mutates-the-disposable-a-quo-package-evaluator'"
  [[ ! -e "${PRE_ACK_SIDE_EFFECT}" && ! -L "${PRE_ACK_SIDE_EFFECT}" ]] ||
    fail_contract 'unsafe acknowledgement-prefix mutant was executed before rejection'
  reject_source_mutant static-input-early-success \
    'assert_static_inputs() {' \
    $'assert_static_inputs() {\n  return 0 # hostile mutant bypasses static-input rebinding'
  reject_source_mutant absent-boundary-early-success \
    'assert_absent_transition_boundary() {' \
    $'assert_absent_transition_boundary() {\n  return 0 # hostile mutant bypasses the absent transition boundary'
  reject_source_mutant installed-boundary-early-success \
    'assert_installed_transition_boundary() {' \
    $'assert_installed_transition_boundary() {\n  return 0 # hostile mutant bypasses the installed transition boundary'
  reject_source_mutant installed-verification-early-success \
    'assert_installed_package() {' \
    $'assert_installed_package() {\n  return 0 # hostile mutant bypasses installed-package verification'
  reject_source_mutant consent-core-binding-early-success \
    'assert_consent_to_core_binding() {' \
    $'assert_consent_to_core_binding() {\n  return 0 # hostile mutant bypasses consent-to-core binding'
  reject_source_mutant executing-bridge-hash-bypass \
    '[[ "${EXECUTING_BRIDGE_SHA256}" == "${COMMITTED_BRIDGE_SHA256}" ]] ||' \
    '[[ "${COMMITTED_BRIDGE_SHA256}" == "${COMMITTED_BRIDGE_SHA256}" ]] ||'
  reject_source_mutant indistinct-plugin-fixture-gate \
    "[[ \"\${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}\" != \\" \
    "[[ \"\${A_QUO_EVALUATOR_PACKAGE_V1_SHA256}\" == \\"

  trap 'remove_contract_root || exit 1' EXIT
  remove_mutant_root || fail_contract 'source mutation matrix cleanup failed'
fi

remove_contract_root || fail_contract 'private contract snapshot cleanup failed'
trap - EXIT
printf '%s\n' \
  'installed A Quo package lifecycle evaluator passed its non-mutating contract checks'
