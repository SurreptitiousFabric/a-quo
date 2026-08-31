#!/usr/bin/env bash
# shellcheck disable=SC2016

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
readonly EVALUATOR="${SCRIPT_DIRECTORY}/test-arch-package-upgrade-smoke.sh"

[[ -f "${EVALUATOR}" && ! -L "${EVALUATOR}" && -x "${EVALUATOR}" ]] || {
  printf '%s\n' 'package-transition evaluator is missing, non-executable, or a symlink' >&2
  exit 1
}

for required_tool in awk chmod cp env git grep install ln mkdir mkfifo \
  mktemp mv rm sed sha256sum stat tar timeout touch; do
  command -v "${required_tool}" >/dev/null || {
    printf 'package-transition contract tool is unavailable: %s\n' \
      "${required_tool}" >&2
    exit 1
  }
done

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-package-transition-contract.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

fail_contract() {
  printf 'package-transition contract failed: %s\n' "$1" >&2
  exit 1
}

assert_refused() {
  local label="$1"
  local expected="$2"
  shift 2
  local output
  local status
  set +e
  output="$(timeout 10 "$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != *"${expected}"* ]]; then
    printf 'package-transition refusal mismatch: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

assert_status() {
  local label="$1"
  local expected_status="$2"
  local expected_output="$3"
  shift 3
  local output
  local status
  set +e
  output="$(timeout 10 "$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne "${expected_status}" || \
    "${output}" != *"${expected_output}"* ]]; then
    printf 'package-transition status mismatch: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

line_number() {
  local pattern="$1"
  local line
  line="$(grep -n -m1 -F -- "${pattern}" "${EVALUATOR}")" ||
    fail_contract "missing ordered source marker: ${pattern}"
  printf '%s\n' "${line%%:*}"
}

# Usage and inherited repository state must fail before host inspection.
assert_status usage 2 \
  'usage: test-arch-package-upgrade-smoke.sh OLD_PACKAGE OLD_SHA256 OLD_SOURCE_COMMIT NEW_PACKAGE NEW_SHA256 NEW_SOURCE_COMMIT [PROFILE]' \
  "${EVALUATOR}"
for git_override in \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_CONFIG \
  GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM \
  GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_DIR GIT_GRAFT_FILE \
  GIT_INDEX_FILE GIT_NAMESPACE GIT_OBJECT_DIRECTORY \
  GIT_QUARANTINE_PATH GIT_REPLACE_REF_BASE GIT_SHALLOW_FILE GIT_WORK_TREE; do
  assert_refused "override-${git_override}" \
    "inherited Git repository override: ${git_override}" \
    env "${git_override}=contract-sentinel" \
      "${EVALUATOR}" a b c d e f
done

# Pin fail-first ordering and the boundary immediately before libalpm mutation.
root_line="$(line_number 'if (( EUID == 0 )); then')"
temporary_line="$(line_number 'TEMPORARY_ROOT="$(')"
snapshot_hash_line="$(line_number 'OLD_PACKAGE_SHA256="$(sha256sum')"
digest_match_line="$(line_number '[[ "${NEW_PACKAGE_SHA256}" == "${NEW_EXPECTED_SHA256}" ]] ||')"
version_line="$(line_number '(( $(vercmp "${NEW_PACKAGE_VERSION}" "${OLD_PACKAGE_VERSION}") > 0 ))')"
verifier_line="$(line_number '"${COMMITTED_VERIFIER}" "${NEW_PACKAGE_SNAPSHOT}" "${NEW_SOURCE_COMMIT}"')"
post_verify_line="$(line_number "assert_static_inputs_unchanged 'after exact package verification'")"
pre_mutation_line="$(line_number "assert_static_inputs_unchanged 'immediately before package-manager mutation'")"
mutation_line="$(line_number 'run_initial_fakeroot pacman -U')"
if (( root_line >= temporary_line || temporary_line >= snapshot_hash_line || \
  snapshot_hash_line >= digest_match_line || digest_match_line >= version_line || \
  version_line >= verifier_line || \
  verifier_line >= post_verify_line || post_verify_line >= pre_mutation_line || \
  pre_mutation_line >= mutation_line )); then
  fail_contract 'root/snapshot/version/verifier/recheck/mutation gates are out of order'
fi

mapfile -t transaction_markers < <(
  grep -nE '^run_(initial|saved)_fakeroot pacman -[UR] ' "${EVALUATOR}"
)
(( ${#transaction_markers[@]} == 4 )) ||
  fail_contract 'package transition must contain exactly four mutating transactions'
[[ "${transaction_markers[0]}" == *':run_initial_fakeroot pacman -U '* &&
  "${transaction_markers[1]}" == *':run_saved_fakeroot pacman -U '* &&
  "${transaction_markers[2]}" == *':run_saved_fakeroot pacman -R '* &&
  "${transaction_markers[3]}" == *':run_saved_fakeroot pacman -U '* ]] ||
  fail_contract 'package transactions are not install, upgrade, remove, reinstall'
old_assert_line="$(line_number 'assert_installed_package old-install')"
upgrade_assert_line="$(line_number 'assert_installed_package new-upgrade')"
removal_state_line="$(line_number 'assert_user_state removal')"
reinstall_assert_line="$(line_number 'assert_installed_package new-reinstall')"
final_recheck_line="$(line_number "assert_static_inputs_unchanged 'during the package transition'")"
first_transaction_line="${transaction_markers[0]%%:*}"
second_transaction_line="${transaction_markers[1]%%:*}"
third_transaction_line="${transaction_markers[2]%%:*}"
fourth_transaction_line="${transaction_markers[3]%%:*}"
if (( mutation_line != first_transaction_line ||
  first_transaction_line >= old_assert_line ||
  old_assert_line >= second_transaction_line ||
  second_transaction_line >= upgrade_assert_line ||
  upgrade_assert_line >= third_transaction_line ||
  third_transaction_line >= removal_state_line ||
  removal_state_line >= fourth_transaction_line ||
  fourth_transaction_line >= reinstall_assert_line ||
  reinstall_assert_line >= final_recheck_line )); then
  fail_contract 'install/verify/upgrade/verify/remove/state/reinstall/verify order changed'
fi

for required_literal in \
  'export GIT_NO_REPLACE_OBJECTS=1' \
  'export GIT_NO_LAZY_FETCH=1' \
  'rev-parse --is-shallow-repository' \
  'rev-parse --path-format=absolute --git-common-dir' \
  'source repository contains a legacy graft file' \
  'for-each-ref --count=1' \
  "--format='%(refname)' refs/replace" \
  'source repository replacement refs could not be inspected' \
  '-c core.fsmonitor=false' \
  'source repository cleanliness could not be inspected' \
  'source repository HEAD could not be reinspected' \
  'source repository cleanliness could not be reinspected' \
  'status --porcelain=v1 --untracked-files=normal' \
  'merge-base --is-ancestor' \
  "readonly MAXIMUM_PACKAGE_BYTES=268435456" \
  "readonly MAXIMUM_PKGINFO_BYTES=65536" \
  'caller-pinned package SHA-256 values must be lowercase hex' \
  'old package snapshot does not match its caller-pinned SHA-256' \
  'new package snapshot does not match its caller-pinned SHA-256' \
  'iflag=fullblock,nofollow,nonblock' \
  "'after exact package verification'" \
  "'immediately before package-manager mutation'" \
  'chmod 0500 -- "${COMMITTED_VERIFIER}"' \
  '"${COMMITTED_VERIFIER}" "${OLD_PACKAGE_SNAPSHOT}" "${OLD_SOURCE_COMMIT}"' \
  '"${COMMITTED_VERIFIER}" "${NEW_PACKAGE_SNAPSHOT}" "${NEW_SOURCE_COMMIT}"' \
  '"${TARGET_PROFILE}"' \
  'profile_id profile_repository_path profile_sha256 target_kind architecture' \
  'evidence_namespace output_layout build_environment cli_needed consent_needed' \
  '"Architecture = ${PACKAGE_ARCHITECTURE}"' \
  '--arch "${PACKAGE_ARCHITECTURE}"' \
  '--root "${INSTALL_ROOT}"' \
  '--dbpath "${DATABASE_PATH}"' \
  '--cachedir "${CACHE_PATH}"' \
  '--gpgdir "${GPG_PATH}"' \
  '--hookdir "${HOOK_PATH}"' \
  'SigLevel = Never' \
  'LocalFileSigLevel = Never' \
  'fakeroot --unknown-is-real -s "${FAKEROOT_STATE}" -- "$@"' \
  '-i "${FAKEROOT_STATE}" -s "${FAKEROOT_STATE}" -- "$@"' \
  'assert_user_state "${stage}"' \
  'assert_user_state removal' \
  "stat -c '%d:%i:%u:%g:%a:%h:%F:%s'" \
  "'user_state_preserved=true'" \
  "'caller_pinned_package_sha256_matched=true'" \
  "'git_lazy_fetch_disabled=true'" \
  "'package_signature_verified=false'" \
  "'package_source_to_binary_provenance_established=false'" \
  "'dependencies_resolved=false'" \
  "'scriptlets_and_hooks_executed=false'" \
  "'network_or_repository_sync_performed=false'" \
  "'real_root_ownership_tested=false'" \
  "'live_package_upgrade_tested=false'" \
  "'package_downgrade_refusal_tested=false'" \
  "'package_interruption_recovery_tested=false'" \
  "'same_uid_snapshot_substitution_resistance_tested=false'" \
  "'archive_resource_exhaustion_containment_tested=false'" \
  "'clean_system_tested=false'" \
  "'systemd_user_manager_tested=false'" \
  "'wayland_consent_tested=false'" \
  "'omarchy_integration_tested=false'" \
  "'behavioural_analysis_tested=false'" \
  "'physical_omarchy_state_changed=false'" \
  "'cross_profile_evidence_accepted=false'" \
  "'aarch64_gate_satisfied_by_x86_64=false'" \
  "'signed_does_not_mean_safe=true'"; do
  grep -Fq -- "${required_literal}" "${EVALUATOR}" ||
    fail_contract "evaluator is missing contract literal: ${required_literal}"
done

[[ "$(grep -Fc -- '--nodeps --nodeps --noscriptlet' "${EVALUATOR}")" -eq 4 ]] ||
  fail_contract 'all four local package transactions must disable dependencies and scriptlets'
[[ "$(grep -Fc 'rm -rf -- "${TEMPORARY_ROOT}"' "${EVALUATOR}")" -eq 1 ]] ||
  fail_contract 'evaluator must have one exact private temporary-root cleanup'
if grep -Eq -- \
  '^[[:space:]]*(curl|wget|gh|repo-add|mount|sudo)([[:space:]]|$)|pacman[[:space:]]+-(S|Sy|Syy)|systemctl([^\n]*)(enable|start|restart|daemon-reload)' \
  "${EVALUATOR}"; then
  fail_contract 'evaluator contains a network, repository, mount, privilege, or live-service action'
fi
if grep -Eq -- \
  'rm[[:space:]]+-rf[[:space:]]+--?[[:space:]]+("?/("|[[:space:]]|$)|"?\$\{?(HOME|REPOSITORY_ROOT|INSTALL_ROOT))' \
  "${EVALUATOR}"; then
  fail_contract 'evaluator contains a broad recursive deletion target'
fi

# Build one private synthetic source graph. OLD is an ancestor of NEW; an
# unrelated root is merged into HEAD solely so both unrelated inputs are
# reachable and the evaluator reaches its direct relationship check.
readonly SOURCE_REPOSITORY="${TEMPORARY_ROOT}/source"
readonly STUB_DIRECTORY="${TEMPORARY_ROOT}/bin"
readonly FIXTURE_DIRECTORY="${TEMPORARY_ROOT}/fixtures"
readonly VERIFIER_LOG="${TEMPORARY_ROOT}/verifier.log"
readonly PACMAN_SENTINEL="${TEMPORARY_ROOT}/pacman-mutation-attempted"
readonly VERCMP_SENTINEL="${TEMPORARY_ROOT}/vercmp-called"
readonly ARCH_MARKER="${TEMPORARY_ROOT}/arch-release"
mkdir -m 0700 -- "${SOURCE_REPOSITORY}" "${STUB_DIRECTORY}" \
  "${FIXTURE_DIRECTORY}"
mkdir -m 0700 -- "${SOURCE_REPOSITORY}/scripts"
mkdir -m 0700 -- "${SOURCE_REPOSITORY}/packaging"
mkdir -m 0700 -- "${SOURCE_REPOSITORY}/packaging/evaluation-targets"
touch "${ARCH_MARKER}"

# The production host gate remains statically pinned above. This sole
# transformation lets the remaining exact preflight run on non-Arch CI hosts.
sed 's|! -f /etc/arch-release|! -f "${A_QUO_CONTRACT_ARCH_RELEASE:-/etc/arch-release}"|' \
  "${EVALUATOR}" >"${SOURCE_REPOSITORY}/scripts/test-arch-package-upgrade-smoke.sh"
chmod 0755 -- "${SOURCE_REPOSITORY}/scripts/test-arch-package-upgrade-smoke.sh"
for helper in \
  resolve-arch-package-target.sh \
  verify-omarchy-evaluation-target-profile.sh \
  verify-omarchy-x86_64-physical-target-profile.sh; do
  install -m 0755 -- "${SCRIPT_DIRECTORY}/${helper}" \
    "${SOURCE_REPOSITORY}/scripts/${helper}"
done
for profile in \
  a-quo-omarchy4-aarch64-dec29fa-v2.profile \
  a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile; do
  install -m 0644 -- \
    "${SCRIPT_DIRECTORY}/../packaging/evaluation-targets/${profile}" \
    "${SOURCE_REPOSITORY}/packaging/evaluation-targets/${profile}"
done
[[ "$(grep -Fc 'A_QUO_CONTRACT_ARCH_RELEASE' \
  "${SOURCE_REPOSITORY}/scripts/test-arch-package-upgrade-smoke.sh")" -eq 1 ]] ||
  fail_contract 'CI host-marker adaptation did not replace exactly one operand'

apply_verifier_fixture() {
  install -m 0755 /dev/stdin \
    "${SOURCE_REPOSITORY}/scripts/verify-arch-package-skeleton.sh" <<'VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 3 ]]
package_path="$1"
source_commit="$2"
profile_path="$3"
[[ -f "${package_path}" && ! -L "${package_path}" ]]
[[ -f "${profile_path}" && ! -L "${profile_path}" ]]
[[ "$(stat -c '%a:%h:%F' -- "${package_path}")" == '400:1:regular file' ]]
pkginfo="$(bsdtar -xOf "${package_path}" .PKGINFO)"
case "$(basename -- "${profile_path}")" in
  a-quo-omarchy4-aarch64-dec29fa-v2.profile)
    expected_architecture=aarch64
    expected_profile_id=a-quo-omarchy4-aarch64-dec29fa-v2
    expected_namespace=phase-a-aarch64-dec29fa
    ;;
  a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile)
    expected_architecture=x86_64
    expected_profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1
    expected_namespace=physical-x86_64-official-omarchy-4.0.2
    ;;
  *) exit 65 ;;
esac
observed_xdata="$(sed -n 's/^xdata = //p' <<<"${pkginfo}")"
expected_xdata="$(printf '%s\n' \
  pkgtype=pkg \
  "a-quo-profile-id=${expected_profile_id}" \
  "a-quo-evidence-namespace=${expected_namespace}")"
if [[ "$(grep -c '^arch = ' <<<"${pkginfo}")" -ne 1 ||
  "$(grep -Fxc "arch = ${expected_architecture}" <<<"${pkginfo}")" -ne 1 ||
  "${observed_xdata}" != "${expected_xdata}" ]]; then
  printf '%s\n' 'synthetic verifier rejected cross-profile package metadata' >&2
  exit 1
fi
case "${package_path}" in
  */input/old/*) label=old ;;
  */input/new/*) label=new ;;
  *) printf 'verifier did not receive a private old/new snapshot: %s\n' \
       "${package_path}" >&2; exit 66 ;;
esac
printf '%s|%s|%s|%s\n' "${label}" "$(basename -- "${package_path}")" \
  "${source_commit}" "$(basename -- "${profile_path}")" \
  >>"${A_QUO_CONTRACT_VERIFIER_LOG:?}"
case "${A_QUO_CONTRACT_VERIFIER_MODE:-success}" in
  fail)
    printf '%s\n' 'synthetic committed verifier failure' >&2
    exit 67
    ;;
  mutate-snapshot)
    if [[ "${label}" == new ]]; then
      chmod 0600 -- "${package_path}"
      printf '%s\n' mutation >>"${package_path}"
    fi
    ;;
  mutate-source)
    if [[ "${label}" == new ]]; then
      printf '%s\n' mutation >>"${A_QUO_VERIFIER_REPOSITORY_ROOT:?}/progress.txt"
    fi
    ;;
  success) ;;
  *) exit 68 ;;
esac
VERIFIER
}
apply_verifier_fixture

printf '%s\n' '/target/' >"${SOURCE_REPOSITORY}/.gitignore"
printf '%s\n' '[workspace.package]' 'version = "0.1.0"' \
  >"${SOURCE_REPOSITORY}/Cargo.toml"
git -C "${SOURCE_REPOSITORY}" init --quiet --initial-branch=main
git -C "${SOURCE_REPOSITORY}" add --all
git -C "${SOURCE_REPOSITORY}" \
  -c user.name='A Quo transition contract' \
  -c user.email='noreply@a-quo.invalid' \
  commit --quiet --message=old
OLD_COMMIT="$(git -C "${SOURCE_REPOSITORY}" rev-parse HEAD)"
readonly OLD_COMMIT
printf '%s\n' descendant >"${SOURCE_REPOSITORY}/progress.txt"
git -C "${SOURCE_REPOSITORY}" add progress.txt
git -C "${SOURCE_REPOSITORY}" \
  -c user.name='A Quo transition contract' \
  -c user.email='noreply@a-quo.invalid' \
  commit --quiet --message=new
NEW_COMMIT="$(git -C "${SOURCE_REPOSITORY}" rev-parse HEAD)"
readonly NEW_COMMIT
EMPTY_TREE="$(git -C "${SOURCE_REPOSITORY}" mktree </dev/null)"
UNRELATED_COMMIT="$(printf '%s\n' unrelated | \
  git -C "${SOURCE_REPOSITORY}" \
    -c user.name='A Quo transition contract' \
    -c user.email='noreply@a-quo.invalid' commit-tree "${EMPTY_TREE}")"
readonly EMPTY_TREE UNRELATED_COMMIT
git -C "${SOURCE_REPOSITORY}" update-ref refs/heads/unrelated \
  "${UNRELATED_COMMIT}"
git -C "${SOURCE_REPOSITORY}" \
  -c user.name='A Quo transition contract' \
  -c user.email='noreply@a-quo.invalid' \
  merge --quiet --allow-unrelated-histories --no-ff --no-edit unrelated

package_version() {
  local commit="$1"
  local count
  count="$(git -C "${SOURCE_REPOSITORY}" rev-list --count "${commit}")"
  printf '0.1.0.r%s.g%s-1\n' "${count}" "${commit:0:12}"
}
OLD_VERSION="$(package_version "${OLD_COMMIT}")"
NEW_VERSION="$(package_version "${NEW_COMMIT}")"
readonly OLD_VERSION NEW_VERSION

make_package() {
  local output="$1"
  shift
  local staging
  staging="$(mktemp -d "${TEMPORARY_ROOT}/package.XXXXXX")"
  printf '%s\n' 'pkgname = a-quo' "$@" >"${staging}/.PKGINFO"
  tar --format=ustar -cf "${output}" -C "${staging}" .PKGINFO
  rm -rf -- "${staging}"
}

readonly OLD_PACKAGE="${FIXTURE_DIRECTORY}/a-quo-${OLD_VERSION}-aarch64.pkg.tar"
readonly NEW_PACKAGE="${FIXTURE_DIRECTORY}/a-quo-${NEW_VERSION}-aarch64.pkg.tar"
make_package "${OLD_PACKAGE}" \
  "pkgver = ${OLD_VERSION}" \
  'xdata = pkgtype=pkg' \
  'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
  'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa' \
  'arch = aarch64'
make_package "${NEW_PACKAGE}" \
  "pkgver = ${NEW_VERSION}" \
  'xdata = pkgtype=pkg' \
  'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
  'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa' \
  'arch = aarch64'
file_sha256() {
  local result
  result="$(sha256sum -- "$1")"
  printf '%s\n' "${result%% *}"
}
OLD_SHA256="$(file_sha256 "${OLD_PACKAGE}")"
NEW_SHA256="$(file_sha256 "${NEW_PACKAGE}")"
readonly OLD_SHA256 NEW_SHA256
readonly CROSS_OLD_DIRECTORY="${FIXTURE_DIRECTORY}/cross-old"
readonly CROSS_NEW_DIRECTORY="${FIXTURE_DIRECTORY}/cross-new"
mkdir -m 0700 -- "${CROSS_OLD_DIRECTORY}" "${CROSS_NEW_DIRECTORY}"
CROSS_OLD_PACKAGE="${CROSS_OLD_DIRECTORY}/$(basename -- "${OLD_PACKAGE}")"
CROSS_NEW_PACKAGE="${CROSS_NEW_DIRECTORY}/$(basename -- "${NEW_PACKAGE}")"
readonly CROSS_OLD_PACKAGE CROSS_NEW_PACKAGE
make_package "${CROSS_OLD_PACKAGE}" \
  "pkgver = ${OLD_VERSION}" \
  'xdata = pkgtype=pkg' \
  'xdata = a-quo-profile-id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'xdata = a-quo-evidence-namespace=physical-x86_64-official-omarchy-4.0.2' \
  'arch = x86_64'
make_package "${CROSS_NEW_PACKAGE}" \
  "pkgver = ${NEW_VERSION}" \
  'xdata = pkgtype=pkg' \
  'xdata = a-quo-profile-id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'xdata = a-quo-evidence-namespace=physical-x86_64-official-omarchy-4.0.2' \
  'arch = x86_64'
CROSS_OLD_SHA256="$(file_sha256 "${CROSS_OLD_PACKAGE}")"
CROSS_NEW_SHA256="$(file_sha256 "${CROSS_NEW_PACKAGE}")"
readonly CROSS_OLD_SHA256 CROSS_NEW_SHA256

# Portable command shims: they provide only the host facts and archive syntax
# required to reach preflight. The first mutating pacman request exits 73.
install -m 0755 /dev/stdin "${STUB_DIRECTORY}/uname" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' aarch64
STUB
install -m 0755 /dev/stdin "${STUB_DIRECTORY}/bsdtar" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ -x /usr/bin/bsdtar ]]; then
  exec /usr/bin/bsdtar "$@"
fi
exec /usr/bin/tar "$@"
STUB
install -m 0755 /dev/stdin "${STUB_DIRECTORY}/vercmp" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' called >"${A_QUO_CONTRACT_VERCMP_SENTINEL:?}"
if [[ "${A_QUO_CONTRACT_VERCMP_MODE:-normal}" == no-progress ]]; then
  printf '%s\n' 0
elif [[ "$1" == "$2" ]]; then
  printf '%s\n' 0
elif [[ "$1" == *'.r2.'* && "$2" == *'.r1.'* ]]; then
  printf '%s\n' 1
else
  printf '%s\n' -1
fi
STUB
install -m 0755 /dev/stdin "${STUB_DIRECTORY}/pacman" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  if [[ "${argument}" == -U || "${argument}" == -R ]]; then
    printf '%s\n' attempted >"${A_QUO_CONTRACT_PACMAN_SENTINEL:?}"
    printf '%s\n' 'synthetic pacman mutation sentinel' >&2
    exit 73
  fi
done
exit 1
STUB
install -m 0755 /dev/stdin "${STUB_DIRECTORY}/fakeroot" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
while (( $# > 0 )); do
  if [[ "$1" == -- ]]; then
    shift
    break
  fi
  shift
done
[[ "${1:-}" == pacman ]]
shift
exec "${A_QUO_CONTRACT_STUB_DIRECTORY:?}/pacman" "$@"
STUB
install -m 0755 /dev/stdin "${STUB_DIRECTORY}/env" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -i ]]; then
  shift
fi
while (( $# > 0 )) && [[ "$1" == *=* ]]; do
  shift
done
case "${1:-}" in
  pacman)
    shift
    exec "${A_QUO_CONTRACT_STUB_DIRECTORY:?}/pacman" "$@"
    ;;
  fakeroot)
    shift
    exec "${A_QUO_CONTRACT_STUB_DIRECTORY:?}/fakeroot" "$@"
    ;;
  *)
    printf 'synthetic env refused unexpected command: %s\n' "${1:-missing}" >&2
    exit 69
    ;;
esac
STUB

assert_fixture_refused() {
  local label="$1"
  local expected="$2"
  local repository="$3"
  shift 3
  assert_refused "${label}" "${expected}" \
    env PATH="${STUB_DIRECTORY}:${PATH}" \
      A_QUO_CONTRACT_ARCH_RELEASE="${ARCH_MARKER}" \
      A_QUO_CONTRACT_STUB_DIRECTORY="${STUB_DIRECTORY}" \
      A_QUO_CONTRACT_VERIFIER_LOG="${VERIFIER_LOG}" \
      A_QUO_CONTRACT_PACMAN_SENTINEL="${PACMAN_SENTINEL}" \
      A_QUO_CONTRACT_VERCMP_SENTINEL="${VERCMP_SENTINEL}" \
      "${repository}/scripts/test-arch-package-upgrade-smoke.sh" "$@"
}

# File and version hostility.
ln -s -- "${OLD_PACKAGE}" "${FIXTURE_DIRECTORY}/old-symlink.pkg.tar"
mkdir -m 0700 -- "${FIXTURE_DIRECTORY}/not-a-package"
mkfifo "${FIXTURE_DIRECTORY}/package-fifo"
assert_fixture_refused symlink-package \
  'each package input must be one real regular non-symlink file' \
  "${SOURCE_REPOSITORY}" "${FIXTURE_DIRECTORY}/old-symlink.pkg.tar" \
  "${OLD_SHA256}" "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" \
  "${NEW_COMMIT}"
assert_fixture_refused directory-package \
  'each package input must be one real regular non-symlink file' \
  "${SOURCE_REPOSITORY}" "${FIXTURE_DIRECTORY}/not-a-package" \
  "${OLD_SHA256}" "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" \
  "${NEW_COMMIT}"
assert_fixture_refused fifo-package \
  'each package input must be one real regular non-symlink file' \
  "${SOURCE_REPOSITORY}" "${FIXTURE_DIRECTORY}/package-fifo" \
  "${OLD_SHA256}" "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" \
  "${NEW_COMMIT}"

readonly X86_64_PROFILE="${SOURCE_REPOSITORY}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
assert_fixture_refused x86-profile-on-aarch64-host \
  'requires its mapped architecture on an Arch-family host: expected=x86_64 observed=aarch64' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}" \
  "${X86_64_PROFILE}"

assert_fixture_refused cross-profile-old-package \
  'synthetic verifier rejected cross-profile package metadata' \
  "${SOURCE_REPOSITORY}" "${CROSS_OLD_PACKAGE}" "${CROSS_OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
assert_fixture_refused cross-profile-new-package \
  'synthetic verifier rejected cross-profile package metadata' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${CROSS_NEW_PACKAGE}" "${CROSS_NEW_SHA256}" \
  "${NEW_COMMIT}"
[[ ! -e "${PACMAN_SENTINEL}" ]] ||
  fail_contract 'cross-profile package metadata reached package-manager mutation'

assert_fixture_refused malformed-old-digest \
  'caller-pinned package SHA-256 values must be lowercase hex' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256^^}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
assert_fixture_refused malformed-new-digest \
  'caller-pinned package SHA-256 values must be lowercase hex' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" short "${NEW_COMMIT}"
assert_fixture_refused equal-digests \
  'old and new caller-pinned package SHA-256 values must be distinct' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${OLD_SHA256}" "${NEW_COMMIT}"
readonly WRONG_SHA256=0000000000000000000000000000000000000000000000000000000000000000
assert_fixture_refused wrong-old-digest \
  'old package snapshot does not match its caller-pinned SHA-256' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${WRONG_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
assert_fixture_refused wrong-new-digest \
  'new package snapshot does not match its caller-pinned SHA-256' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${WRONG_SHA256}" "${NEW_COMMIT}"

readonly MISSING_VERSION="${FIXTURE_DIRECTORY}/missing-version.pkg.tar"
readonly DUPLICATE_VERSION="${FIXTURE_DIRECTORY}/duplicate-version.pkg.tar"
readonly MALFORMED_VERSION="${FIXTURE_DIRECTORY}/malformed-version.pkg.tar"
make_package "${MISSING_VERSION}" 'pkgdesc = no version'
make_package "${DUPLICATE_VERSION}" \
  "pkgver = ${OLD_VERSION}" "pkgver = ${OLD_VERSION}"
make_package "${MALFORMED_VERSION}" "pkgver=${OLD_VERSION}"
MISSING_VERSION_SHA256="$(file_sha256 "${MISSING_VERSION}")"
DUPLICATE_VERSION_SHA256="$(file_sha256 "${DUPLICATE_VERSION}")"
MALFORMED_VERSION_SHA256="$(file_sha256 "${MALFORMED_VERSION}")"
readonly MISSING_VERSION_SHA256 DUPLICATE_VERSION_SHA256 \
  MALFORMED_VERSION_SHA256
assert_fixture_refused missing-version \
  'old .PKGINFO must contain exactly one package version' \
  "${SOURCE_REPOSITORY}" "${MISSING_VERSION}" "${MISSING_VERSION_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
assert_fixture_refused duplicate-version \
  'old .PKGINFO must contain exactly one package version' \
  "${SOURCE_REPOSITORY}" "${DUPLICATE_VERSION}" \
  "${DUPLICATE_VERSION_SHA256}" "${OLD_COMMIT}" "${NEW_PACKAGE}" \
  "${NEW_SHA256}" "${NEW_COMMIT}"
assert_fixture_refused malformed-version \
  'old .PKGINFO must contain exactly one package version' \
  "${SOURCE_REPOSITORY}" "${MALFORMED_VERSION}" \
  "${MALFORMED_VERSION_SHA256}" "${OLD_COMMIT}" "${NEW_PACKAGE}" \
  "${NEW_SHA256}" "${NEW_COMMIT}"

# Commit direction and repository-context hostility.
assert_fixture_refused malformed-commit \
  'source commits must be full lowercase Git object IDs' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT^^}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
assert_fixture_refused same-commit \
  'old and new source commits must be distinct' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${OLD_COMMIT}"
assert_fixture_refused reversed-commits \
  'old source commit is not an ancestor of new source commit' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${NEW_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${OLD_COMMIT}"
assert_fixture_refused unrelated-commits \
  'old source commit is not an ancestor of new source commit' \
  "${SOURCE_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" \
  "${UNRELATED_COMMIT}"

DIRTY_REPOSITORY="${TEMPORARY_ROOT}/dirty-source"
cp -a -- "${SOURCE_REPOSITORY}" "${DIRTY_REPOSITORY}"
printf '%s\n' dirty >>"${DIRTY_REPOSITORY}/progress.txt"
assert_fixture_refused dirty-source \
  'source repository must be clean before the package transition' \
  "${DIRTY_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"

SHALLOW_REPOSITORY="${TEMPORARY_ROOT}/shallow-source"
git clone --quiet --depth=1 "file://${SOURCE_REPOSITORY}" "${SHALLOW_REPOSITORY}"
assert_fixture_refused shallow-source \
  'source repository must contain complete non-shallow history' \
  "${SHALLOW_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"

GRAFT_REPOSITORY="${TEMPORARY_ROOT}/graft-source"
cp -a -- "${SOURCE_REPOSITORY}" "${GRAFT_REPOSITORY}"
mkdir -p -- "${GRAFT_REPOSITORY}/.git/info"
printf '%s\n' "${NEW_COMMIT} ${UNRELATED_COMMIT}" \
  >"${GRAFT_REPOSITORY}/.git/info/grafts"
assert_fixture_refused legacy-graft \
  'source repository contains a legacy graft file' \
  "${GRAFT_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"

REPLACEMENT_REPOSITORY="${TEMPORARY_ROOT}/replacement-source"
cp -a -- "${SOURCE_REPOSITORY}" "${REPLACEMENT_REPOSITORY}"
git -C "${REPLACEMENT_REPOSITORY}" replace "${OLD_COMMIT}" "${NEW_COMMIT}"
assert_fixture_refused replacement-source \
  'source repository contains replacement refs' \
  "${REPLACEMENT_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"

# A hidden worktree substitution must still differ from the committed policy.
SUBSTITUTED_REPOSITORY="${TEMPORARY_ROOT}/substituted-source"
cp -a -- "${SOURCE_REPOSITORY}" "${SUBSTITUTED_REPOSITORY}"
git -C "${SUBSTITUTED_REPOSITORY}" update-index --assume-unchanged \
  scripts/verify-arch-package-skeleton.sh
printf '%s\n' '# substituted' \
  >>"${SUBSTITUTED_REPOSITORY}/scripts/verify-arch-package-skeleton.sh"
assert_fixture_refused substituted-verifier \
  'working verifier differs from the current committed policy' \
  "${SUBSTITUTED_REPOSITORY}" "${OLD_PACKAGE}" "${OLD_SHA256}" \
  "${OLD_COMMIT}" "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"

# Verifier failures and mutation attempts must precede any package-manager
# mutation. Each case uses the exact committed verifier copied by the smoke.
rm -f -- "${VERIFIER_LOG}" "${PACMAN_SENTINEL}" "${VERCMP_SENTINEL}"
assert_status verifier-failure 67 'synthetic committed verifier failure' \
  env A_QUO_CONTRACT_VERIFIER_MODE=fail \
    PATH="${STUB_DIRECTORY}:${PATH}" \
    A_QUO_CONTRACT_ARCH_RELEASE="${ARCH_MARKER}" \
    A_QUO_CONTRACT_STUB_DIRECTORY="${STUB_DIRECTORY}" \
    A_QUO_CONTRACT_VERIFIER_LOG="${VERIFIER_LOG}" \
    A_QUO_CONTRACT_PACMAN_SENTINEL="${PACMAN_SENTINEL}" \
    A_QUO_CONTRACT_VERCMP_SENTINEL="${VERCMP_SENTINEL}" \
    "${SOURCE_REPOSITORY}/scripts/test-arch-package-upgrade-smoke.sh" \
    "${OLD_PACKAGE}" "${OLD_SHA256}" "${OLD_COMMIT}" \
    "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
[[ ! -e "${PACMAN_SENTINEL}" ]] ||
  fail_contract 'verifier failure reached package-manager mutation'

rm -f -- "${VERIFIER_LOG}" "${PACMAN_SENTINEL}" "${VERCMP_SENTINEL}"
assert_status vercmp-no-progress 1 \
  'new package version does not sort after old package version' \
  env A_QUO_CONTRACT_VERCMP_MODE=no-progress \
    PATH="${STUB_DIRECTORY}:${PATH}" \
    A_QUO_CONTRACT_ARCH_RELEASE="${ARCH_MARKER}" \
    A_QUO_CONTRACT_STUB_DIRECTORY="${STUB_DIRECTORY}" \
    A_QUO_CONTRACT_VERIFIER_LOG="${VERIFIER_LOG}" \
    A_QUO_CONTRACT_PACMAN_SENTINEL="${PACMAN_SENTINEL}" \
    A_QUO_CONTRACT_VERCMP_SENTINEL="${VERCMP_SENTINEL}" \
    "${SOURCE_REPOSITORY}/scripts/test-arch-package-upgrade-smoke.sh" \
    "${OLD_PACKAGE}" "${OLD_SHA256}" "${OLD_COMMIT}" \
    "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
[[ -f "${VERCMP_SENTINEL}" && ! -e "${PACMAN_SENTINEL}" ]] ||
  fail_contract 'non-forward vercmp result did not fail before package-manager mutation'

# Invoke the mutation modes explicitly. These calls are separate to keep
# environment provenance visible.
rm -f -- "${VERIFIER_LOG}" "${PACMAN_SENTINEL}"
assert_status snapshot-mutation-mode 1 \
  'a private package snapshot changed after exact package verification' \
  env A_QUO_CONTRACT_VERIFIER_MODE=mutate-snapshot \
    PATH="${STUB_DIRECTORY}:${PATH}" \
    A_QUO_CONTRACT_ARCH_RELEASE="${ARCH_MARKER}" \
    A_QUO_CONTRACT_STUB_DIRECTORY="${STUB_DIRECTORY}" \
    A_QUO_CONTRACT_VERIFIER_LOG="${VERIFIER_LOG}" \
    A_QUO_CONTRACT_PACMAN_SENTINEL="${PACMAN_SENTINEL}" \
    A_QUO_CONTRACT_VERCMP_SENTINEL="${VERCMP_SENTINEL}" \
    "${SOURCE_REPOSITORY}/scripts/test-arch-package-upgrade-smoke.sh" \
    "${OLD_PACKAGE}" "${OLD_SHA256}" "${OLD_COMMIT}" \
    "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
[[ ! -e "${PACMAN_SENTINEL}" ]] ||
  fail_contract 'mutated snapshot reached package-manager mutation'

rm -f -- "${VERIFIER_LOG}" "${PACMAN_SENTINEL}"
assert_status source-mutation-mode 1 \
  'source repository changed after exact package verification' \
  env A_QUO_CONTRACT_VERIFIER_MODE=mutate-source \
    PATH="${STUB_DIRECTORY}:${PATH}" \
    A_QUO_CONTRACT_ARCH_RELEASE="${ARCH_MARKER}" \
    A_QUO_CONTRACT_STUB_DIRECTORY="${STUB_DIRECTORY}" \
    A_QUO_CONTRACT_VERIFIER_LOG="${VERIFIER_LOG}" \
    A_QUO_CONTRACT_PACMAN_SENTINEL="${PACMAN_SENTINEL}" \
    A_QUO_CONTRACT_VERCMP_SENTINEL="${VERCMP_SENTINEL}" \
    "${SOURCE_REPOSITORY}/scripts/test-arch-package-upgrade-smoke.sh" \
    "${OLD_PACKAGE}" "${OLD_SHA256}" "${OLD_COMMIT}" \
    "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
[[ ! -e "${PACMAN_SENTINEL}" ]] ||
  fail_contract 'mutated source reached package-manager mutation'

# Restore the fixture source dirtied deliberately above without using a broad
# checkout/reset operation: remove exactly the appended final line.
sed '$d' "${SOURCE_REPOSITORY}/progress.txt" \
  >"${SOURCE_REPOSITORY}/progress.txt.restored"
mv -- "${SOURCE_REPOSITORY}/progress.txt.restored" \
  "${SOURCE_REPOSITORY}/progress.txt"

rm -f -- "${VERIFIER_LOG}" "${PACMAN_SENTINEL}" "${VERCMP_SENTINEL}"
assert_status preflight-sentinel 73 'synthetic pacman mutation sentinel' \
  env PATH="${STUB_DIRECTORY}:${PATH}" \
    A_QUO_CONTRACT_ARCH_RELEASE="${ARCH_MARKER}" \
    A_QUO_CONTRACT_STUB_DIRECTORY="${STUB_DIRECTORY}" \
    A_QUO_CONTRACT_VERIFIER_LOG="${VERIFIER_LOG}" \
    A_QUO_CONTRACT_PACMAN_SENTINEL="${PACMAN_SENTINEL}" \
    A_QUO_CONTRACT_VERCMP_SENTINEL="${VERCMP_SENTINEL}" \
    "${SOURCE_REPOSITORY}/scripts/test-arch-package-upgrade-smoke.sh" \
    "${OLD_PACKAGE}" "${OLD_SHA256}" "${OLD_COMMIT}" \
    "${NEW_PACKAGE}" "${NEW_SHA256}" "${NEW_COMMIT}"
[[ -f "${PACMAN_SENTINEL}" && -f "${VERCMP_SENTINEL}" ]] ||
  fail_contract 'valid preflight did not reach vercmp and the controlled pacman sentinel'
[[ "$(wc -l <"${VERIFIER_LOG}")" -eq 2 ]] ||
  fail_contract 'valid preflight did not invoke the committed verifier exactly twice'
grep -Fq -- "old|$(basename -- "${OLD_PACKAGE}")|${OLD_COMMIT}" \
  "${VERIFIER_LOG}" || fail_contract 'old verifier call lost package basename or commit'
grep -Fq -- "new|$(basename -- "${NEW_PACKAGE}")|${NEW_COMMIT}" \
  "${VERIFIER_LOG}" || fail_contract 'new verifier call lost package basename or commit'

printf '%s\n' \
  'Arch package transition smoke passed its offline hostile contract' \
  'real_pacman_invoked=false' \
  'real_root_or_system_state_mutated=false' \
  'success_path_stopped_at=controlled-first-pacman-mutation-sentinel'
