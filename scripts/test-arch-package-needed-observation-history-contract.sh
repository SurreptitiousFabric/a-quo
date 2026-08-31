#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_LAZY_FETCH=1
umask 077

fail_contract() {
  printf 'historical x86_64 NEEDED observation contract failed: %s\n' "$1" >&2
  exit 1
}

for git_environment_override in \
  GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_COMMON_DIR \
  GIT_CONFIG \
  GIT_CONFIG_COUNT \
  GIT_CONFIG_GLOBAL \
  GIT_CONFIG_NOSYSTEM \
  GIT_CONFIG_PARAMETERS \
  GIT_CONFIG_SYSTEM \
  GIT_DIR \
  GIT_GRAFT_FILE \
  GIT_INDEX_FILE \
  GIT_NAMESPACE \
  GIT_OBJECT_DIRECTORY \
  GIT_QUARANTINE_PATH \
  GIT_REPLACE_REF_BASE \
  GIT_SHALLOW_FILE \
  GIT_WORK_TREE; do
  [[ ! -v "${git_environment_override}" ]] ||
    fail_contract "inherited Git repository override: ${git_environment_override}"
done
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly HISTORICAL_COMMIT=cbbe29b6bc76949182777d7ec10dc73a219f7592

for required_tool in \
  bash chmod git id mkdir mktemp rm sha256sum shellcheck stat tar; do
  command -v "${required_tool}" >/dev/null ||
    fail_contract "required historical-contract tool is unavailable: ${required_tool}"
done

GIT_COMMON_DIRECTORY="$(
  git -C "${REPOSITORY_ROOT}" rev-parse --path-format=absolute --git-common-dir
)" || fail_contract 'Git common directory could not be inspected'
readonly GIT_COMMON_DIRECTORY
[[ -d "${GIT_COMMON_DIRECTORY}" && ! -L "${GIT_COMMON_DIRECTORY}" ]] ||
  fail_contract 'Git common directory is unavailable or unsafe'
[[ ! -e "${GIT_COMMON_DIRECTORY}/info/grafts" &&
  ! -L "${GIT_COMMON_DIRECTORY}/info/grafts" ]] ||
  fail_contract 'source checkout contains a legacy graft file'
for alternate_file in \
  "${GIT_COMMON_DIRECTORY}/objects/info/alternates" \
  "${GIT_COMMON_DIRECTORY}/objects/info/http-alternates"; do
  [[ ! -e "${alternate_file}" && ! -L "${alternate_file}" ]] ||
    fail_contract 'source checkout uses an alternate Git object store'
done
[[ "$(git -C "${REPOSITORY_ROOT}" rev-parse --is-shallow-repository)" == false ]] ||
  fail_contract 'historical contract requires complete non-shallow history'
set +e
PARTIAL_CLONE_CONFIGURATION="$(
  git -C "${REPOSITORY_ROOT}" config --local --get-regexp \
    '^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$'
)"
PARTIAL_CLONE_STATUS="$?"
set -e
readonly PARTIAL_CLONE_CONFIGURATION PARTIAL_CLONE_STATUS
[[ "${PARTIAL_CLONE_STATUS}" -eq 1 &&
  -z "${PARTIAL_CLONE_CONFIGURATION}" ]] ||
  fail_contract 'source checkout has partial-clone or promisor configuration'
[[ -z "$(git -C "${REPOSITORY_ROOT}" for-each-ref --count=1 \
  --format='%(refname)' refs/replace)" ]] ||
  fail_contract 'source checkout contains replacement refs'
SOURCE_HEAD="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)" ||
  fail_contract 'source HEAD could not be inspected'
readonly SOURCE_HEAD
git -C "${REPOSITORY_ROOT}" cat-file -e \
  "${HISTORICAL_COMMIT}^{commit}" 2>/dev/null ||
  fail_contract 'historical observation commit is unavailable'
git -C "${REPOSITORY_ROOT}" merge-base --is-ancestor \
  "${HISTORICAL_COMMIT}" "${SOURCE_HEAD}" ||
  fail_contract 'historical observation commit is not an ancestor of HEAD'

assert_historical_blob() {
  local path="$1"
  local expected_blob="$2"
  [[ "$(git -C "${REPOSITORY_ROOT}" rev-parse \
    "${HISTORICAL_COMMIT}:${path}")" == "${expected_blob}" ]] ||
    fail_contract "historical Git blob changed or is unavailable: ${path}"
}
assert_historical_blob .github/workflows/x86-package-needed-observation.yml \
  f6f27ecf466f12a80f2086b04cd2b911208b42b7
assert_historical_blob .github/workflows/x86-package-needed-observation.Dockerfile \
  b0c9710f53e85f229943108cd8914ecab2b2f082
assert_historical_blob scripts/run-x86-package-needed-observation-offline.sh \
  ac3ea60815736a7506dae1b00d1a501001d7464c
assert_historical_blob scripts/verify-x86-package-observation-container-policy.sh \
  3871aacb653ea9f2338e90ca4f76a53346b2e77b
assert_historical_blob scripts/verify-arch-package-needed-observation-bundle.sh \
  cb179a526a3943a9d176cf6db3eb51f0328a43fa
assert_historical_blob scripts/test-arch-package-needed-observation-bundle-contract.sh \
  907bb8f8991d72917bae2eeb53470ce94b7055d0

TEMPORARY_ROOT="$(mktemp -d \
  "${TMPDIR:-/tmp}/a-quo-needed-observation-history.XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_ROOT_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
  fail_contract 'temporary historical directory identity is unavailable'
readonly TEMPORARY_ROOT_IDENTITY
cleanup() {
  local exit_status="$?"
  local current_identity
  trap - EXIT
  case "${TEMPORARY_ROOT}" in
    "${TMPDIR:-/tmp}/a-quo-needed-observation-history."??????) ;;
    *) fail_contract 'unsafe historical cleanup target' ;;
  esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] ||
    fail_contract 'historical cleanup target changed type'
  current_identity="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
    fail_contract 'historical cleanup identity is unavailable'
  [[ "${current_identity}" == "${TEMPORARY_ROOT_IDENTITY}" ]] ||
    fail_contract 'historical cleanup target was substituted'
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${exit_status}"
}
trap cleanup EXIT

readonly ARCHIVE="${TEMPORARY_ROOT}/source.tar"
readonly SNAPSHOT="${TEMPORARY_ROOT}/source"
mkdir -m 0700 -- "${SNAPSHOT}"
git -C "${REPOSITORY_ROOT}" archive --format=tar \
  --output="${ARCHIVE}" "${HISTORICAL_COMMIT}"
tar --no-same-owner --no-same-permissions -xf "${ARCHIVE}" -C "${SNAPSHOT}"

file_sha256() {
  local digest
  digest="$(sha256sum -- "$1")" || return 1
  printf '%s\n' "${digest%% *}"
}
[[ "$(file_sha256 "${SNAPSHOT}/scripts/build-arch-package-skeleton.sh")" == \
  63c54347df158778bcafaa307acae49cec38e1eddf6727a1e5bf6316769d9fee ]] ||
  fail_contract 'historical builder bytes changed'
[[ "$(file_sha256 "${SNAPSHOT}/scripts/resolve-arch-package-target.sh")" == \
  60cc574be2340c94c8da353489c104ac6fc202f10b2b9d983d368852c392ffea ]] ||
  fail_contract 'historical target resolver bytes changed'
[[ "$(file_sha256 "${SNAPSHOT}/scripts/verify-arch-package-skeleton.sh")" == \
  f0427319b1d6903261903c3756d1c2bf77b261be9a298b413fe317c41d495c92 ]] ||
  fail_contract 'historical package verifier bytes changed'
[[ "$(file_sha256 "${SNAPSHOT}/scripts/verify-arch-package-needed-observation-bundle.sh")" == \
  37fbab65fe963a9f82091647d66a95de472d6212552be41988b824452815d796 ]] ||
  fail_contract 'historical bundle verifier bytes changed'
[[ "$(file_sha256 "${SNAPSHOT}/scripts/test-arch-package-needed-observation-bundle-contract.sh")" == \
  124d899f0eb327bc253e76eb547bc47245aa9011a6bd0383baaec8478611bd38 ]] ||
  fail_contract 'historical hostile contract bytes changed'

bash -n \
  "${SNAPSHOT}/scripts/build-arch-package-skeleton.sh" \
  "${SNAPSHOT}/scripts/resolve-arch-package-target.sh" \
  "${SNAPSHOT}/scripts/verify-arch-package-skeleton.sh" \
  "${SNAPSHOT}/scripts/verify-arch-package-needed-observation-bundle.sh" \
  "${SNAPSHOT}/scripts/test-arch-package-needed-observation-bundle-contract.sh" \
  "${SNAPSHOT}/scripts/run-x86-package-needed-observation-offline.sh" \
  "${SNAPSHOT}/scripts/verify-x86-package-observation-container-policy.sh"
shellcheck \
  "${SNAPSHOT}/scripts/build-arch-package-skeleton.sh" \
  "${SNAPSHOT}/scripts/resolve-arch-package-target.sh" \
  "${SNAPSHOT}/scripts/verify-arch-package-skeleton.sh" \
  "${SNAPSHOT}/scripts/verify-arch-package-needed-observation-bundle.sh" \
  "${SNAPSHOT}/scripts/test-arch-package-needed-observation-bundle-contract.sh" \
  "${SNAPSHOT}/scripts/run-x86-package-needed-observation-offline.sh" \
  "${SNAPSHOT}/scripts/verify-x86-package-observation-container-policy.sh"

HISTORICAL_OUTPUT="$(
  env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_SYSTEM -u GIT_CONFIG_NOSYSTEM \
    bash "${SNAPSHOT}/scripts/test-arch-package-needed-observation-bundle-contract.sh"
)"
readonly HISTORICAL_OUTPUT
for historical_literal in \
  'x86_64 package NEEDED observation bundle passed its offline hostile contract' \
  'contract_evidence=synthetic-control-flow-only' \
  'accepted_aarch64_default_regression=preserved' \
  'physical_intel_observation=false' \
  'physical_target_evidence=false' \
  'real_x86_64_package_evidence=false' \
  'needed_observation_accepted_as_policy=false' \
  'stage_4_completed=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  [[ "${HISTORICAL_OUTPUT}" == *"${historical_literal}"* ]] ||
    fail_contract "historical hostile suite lost receipt: ${historical_literal}"
done

printf '%s\n' \
  'exact cbbe29b6 x86_64 non-accepting observation suite passed from Git history' \
  "historical_source_commit=${HISTORICAL_COMMIT}" \
  'historical_observation_authority=none' \
  'historical_package_static_acceptance=false' \
  'live_needed_policy_source=separate-reviewed-lock' \
  'physical_target_evidence=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false'
