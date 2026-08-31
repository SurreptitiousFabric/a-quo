#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_LAZY_FETCH=1
umask 077

fail() {
  printf 'Arch package transition smoke refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s OLD_PACKAGE OLD_SHA256 OLD_SOURCE_COMMIT NEW_PACKAGE NEW_SHA256 NEW_SOURCE_COMMIT\n' \
    "${0##*/}" >&2
  exit 2
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
  if [[ -v "${git_environment_override}" ]]; then
    fail "inherited Git repository override: ${git_environment_override}"
  fi
done

[[ "$#" -eq 6 ]] || usage

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly OLD_PACKAGE_INPUT="$1"
readonly OLD_EXPECTED_SHA256="$2"
readonly OLD_SOURCE_COMMIT="$3"
readonly NEW_PACKAGE_INPUT="$4"
readonly NEW_EXPECTED_SHA256="$5"
readonly NEW_SOURCE_COMMIT="$6"
readonly MAXIMUM_PACKAGE_BYTES=268435456
readonly MAXIMUM_PKGINFO_BYTES=65536

for source_commit in "${OLD_SOURCE_COMMIT}" "${NEW_SOURCE_COMMIT}"; do
  [[ "${source_commit}" =~ ^[0-9a-f]{40}$ ]] ||
    fail 'source commits must be full lowercase Git object IDs'
done
for expected_sha256 in \
  "${OLD_EXPECTED_SHA256}" "${NEW_EXPECTED_SHA256}"; do
  [[ "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'caller-pinned package SHA-256 values must be lowercase hex'
done
[[ "${OLD_SOURCE_COMMIT}" != "${NEW_SOURCE_COMMIT}" ]] ||
  fail 'old and new source commits must be distinct'
[[ "${OLD_EXPECTED_SHA256}" != "${NEW_EXPECTED_SHA256}" ]] ||
  fail 'old and new caller-pinned package SHA-256 values must be distinct'

for package_input in "${OLD_PACKAGE_INPUT}" "${NEW_PACKAGE_INPUT}"; do
  [[ -f "${package_input}" && ! -L "${package_input}" ]] ||
    fail 'each package input must be one real regular non-symlink file'
done
OLD_PACKAGE_PATH="$(realpath -e -- "${OLD_PACKAGE_INPUT}")"
NEW_PACKAGE_PATH="$(realpath -e -- "${NEW_PACKAGE_INPUT}")"
readonly OLD_PACKAGE_PATH NEW_PACKAGE_PATH
[[ "${OLD_PACKAGE_PATH}" != "${NEW_PACKAGE_PATH}" ]] ||
  fail 'old and new package inputs must be distinct files'

if [[ "$(uname -m)" != aarch64 || ! -f /etc/arch-release ]]; then
  fail 'the package transition smoke requires a native aarch64 Arch-family host'
fi
if (( EUID == 0 )); then
  fail 'the package transition smoke must not run as real root'
fi

for required_tool in \
  awk bsdtar chmod cmp cut dd fakeroot find git grep head id mkdir mktemp \
  od pacman realpath rm sed sha256sum sort stat systemctl tail tar tr \
  vercmp wc; do
  command -v "${required_tool}" >/dev/null ||
    fail "required transition-smoke tool is unavailable: ${required_tool}"
done

GIT_COMMON_DIRECTORY="$(
  git -C "${REPOSITORY_ROOT}" rev-parse --path-format=absolute --git-common-dir
)"
readonly GIT_COMMON_DIRECTORY
[[ -d "${GIT_COMMON_DIRECTORY}" ]] ||
  fail 'source repository Git common directory is unavailable'
if [[ -e "${GIT_COMMON_DIRECTORY}/info/grafts" ||
  -L "${GIT_COMMON_DIRECTORY}/info/grafts" ]]; then
  fail 'source repository contains a legacy graft file'
fi
[[ "$(git -C "${REPOSITORY_ROOT}" rev-parse --is-shallow-repository)" == false ]] ||
  fail 'source repository must contain complete non-shallow history'
REPLACEMENT_REF="$(
  git -C "${REPOSITORY_ROOT}" for-each-ref --count=1 \
    --format='%(refname)' refs/replace
)" || fail 'source repository replacement refs could not be inspected'
readonly REPLACEMENT_REF
if [[ -n "${REPLACEMENT_REF}" ]]; then
  fail 'source repository contains replacement refs'
fi
SOURCE_HEAD="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)"
readonly SOURCE_HEAD
SOURCE_STATUS="$(
  git -C "${REPOSITORY_ROOT}" -c core.fsmonitor=false \
    status --porcelain=v1 --untracked-files=normal
)" || fail 'source repository cleanliness could not be inspected'
readonly SOURCE_STATUS
if [[ -n "${SOURCE_STATUS}" ]]; then
  fail 'source repository must be clean before the package transition'
fi
for source_commit in "${OLD_SOURCE_COMMIT}" "${NEW_SOURCE_COMMIT}"; do
  git -C "${REPOSITORY_ROOT}" cat-file -e "${source_commit}^{commit}" 2>/dev/null ||
    fail "source commit is unavailable: ${source_commit}"
  git -C "${REPOSITORY_ROOT}" merge-base --is-ancestor \
    "${source_commit}" "${SOURCE_HEAD}" ||
    fail "source commit is not reachable from current HEAD: ${source_commit}"
done
git -C "${REPOSITORY_ROOT}" merge-base --is-ancestor \
  "${OLD_SOURCE_COMMIT}" "${NEW_SOURCE_COMMIT}" ||
  fail 'old source commit is not an ancestor of new source commit'

readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh"
[[ -f "${VERIFIER}" && ! -L "${VERIFIER}" && -x "${VERIFIER}" ]] ||
  fail 'current package verifier is missing, non-executable, or a symlink'

mkdir -p -- "${REPOSITORY_ROOT}/target"
TEMPORARY_ROOT="$(
  mktemp -d "${REPOSITORY_ROOT}/target/.a-quo-package-transition.XXXXXX"
)"
readonly TEMPORARY_ROOT
cleanup() {
  local status="$?"
  trap - EXIT
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${status}"
}
trap cleanup EXIT

readonly SNAPSHOT_DIRECTORY="${TEMPORARY_ROOT}/input"
readonly OLD_SNAPSHOT_DIRECTORY="${SNAPSHOT_DIRECTORY}/old"
readonly NEW_SNAPSHOT_DIRECTORY="${SNAPSHOT_DIRECTORY}/new"
mkdir -m 0700 -- "${SNAPSHOT_DIRECTORY}" \
  "${OLD_SNAPSHOT_DIRECTORY}" "${NEW_SNAPSHOT_DIRECTORY}"

snapshot_package() {
  local label="$1"
  local input_path="$2"
  local output_path="$3"
  local metadata_before
  local metadata_after
  local snapshot_size
  metadata_before="$(stat -c '%d:%i:%s:%f:%Y:%Z' -- "${input_path}")" ||
    fail "${label} package metadata is unavailable"
  if ! dd if="${input_path}" of="${output_path}" \
    bs=1048576 count=257 iflag=fullblock,nofollow,nonblock status=none; then
    fail "${label} package could not be copied through the bounded no-follow reader"
  fi
  metadata_after="$(stat -c '%d:%i:%s:%f:%Y:%Z' -- "${input_path}")" ||
    fail "${label} package metadata disappeared after snapshot"
  [[ "${metadata_before}" == "${metadata_after}" ]] ||
    fail "${label} package changed while its private snapshot was created"
  chmod 0400 -- "${output_path}"
  snapshot_size="$(stat -c '%s' -- "${output_path}")"
  [[ "${snapshot_size}" =~ ^[1-9][0-9]*$ ]] ||
    fail "${label} package snapshot has an invalid size"
  (( snapshot_size <= MAXIMUM_PACKAGE_BYTES )) ||
    fail "${label} package exceeds the closed 256 MiB bound"
  [[ "$(stat -c '%u:%a:%h:%F' -- "${output_path}")" == \
    "$(id -u):400:1:regular file" ]] ||
    fail "${label} package snapshot is not one private singly linked regular file"
}

OLD_PACKAGE_SNAPSHOT="${OLD_SNAPSHOT_DIRECTORY}/$(basename -- "${OLD_PACKAGE_PATH}")"
NEW_PACKAGE_SNAPSHOT="${NEW_SNAPSHOT_DIRECTORY}/$(basename -- "${NEW_PACKAGE_PATH}")"
readonly OLD_PACKAGE_SNAPSHOT NEW_PACKAGE_SNAPSHOT
snapshot_package old "${OLD_PACKAGE_PATH}" "${OLD_PACKAGE_SNAPSHOT}"
snapshot_package new "${NEW_PACKAGE_PATH}" "${NEW_PACKAGE_SNAPSHOT}"
OLD_PACKAGE_SHA256="$(sha256sum -- "${OLD_PACKAGE_SNAPSHOT}" | cut -d ' ' -f 1)"
NEW_PACKAGE_SHA256="$(sha256sum -- "${NEW_PACKAGE_SNAPSHOT}" | cut -d ' ' -f 1)"
readonly OLD_PACKAGE_SHA256 NEW_PACKAGE_SHA256
[[ "${OLD_PACKAGE_SHA256}" == "${OLD_EXPECTED_SHA256}" ]] ||
  fail 'old package snapshot does not match its caller-pinned SHA-256'
[[ "${NEW_PACKAGE_SHA256}" == "${NEW_EXPECTED_SHA256}" ]] ||
  fail 'new package snapshot does not match its caller-pinned SHA-256'
[[ "${OLD_PACKAGE_SHA256}" != "${NEW_PACKAGE_SHA256}" ]] ||
  fail 'old and new package snapshots must not have the same SHA-256'

expected_package_version() {
  local source_commit="$1"
  local workspace_version
  local commit_count
  workspace_version="$(
    git -C "${REPOSITORY_ROOT}" show "${source_commit}:Cargo.toml" |
      sed -n 's/^version = "\([^"]*\)"$/\1/p' |
      head -n 1
  )"
  [[ "${workspace_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    fail "committed workspace version is invalid: ${source_commit}"
  commit_count="$(git -C "${REPOSITORY_ROOT}" rev-list --count "${source_commit}")"
  [[ "${commit_count}" =~ ^[1-9][0-9]*$ ]] ||
    fail "committed revision count is invalid: ${source_commit}"
  printf '%s.r%s.g%s-1\n' \
    "${workspace_version}" "${commit_count}" "${source_commit:0:12}"
}

read_package_version() {
  local label="$1"
  local package_snapshot="$2"
  local output_path="$3"
  local output_size
  local printable_size
  local last_byte
  local -a versions=()
  local -a extraction_status=()
  set +e
  bsdtar -xOf "${package_snapshot}" .PKGINFO |
    dd of="${output_path}" bs=$((MAXIMUM_PKGINFO_BYTES + 1)) count=1 \
      iflag=fullblock status=none
  extraction_status=("${PIPESTATUS[@]}")
  set -e
  output_size="$(stat -c '%s' -- "${output_path}")"
  if [[ ! "${output_size}" =~ ^[1-9][0-9]*$ ]] ||
    (( output_size > MAXIMUM_PKGINFO_BYTES )); then
    fail "${label} .PKGINFO is outside the closed byte bound"
  fi
  (( extraction_status[0] == 0 && extraction_status[1] == 0 )) ||
    fail "${label} package has no readable .PKGINFO"
  printable_size="$(tr -cd '\11\12\40-\176' <"${output_path}" | wc -c)"
  [[ "${printable_size}" == "${output_size}" ]] ||
    fail "${label} .PKGINFO contains a forbidden byte"
  last_byte="$(tail -c 1 -- "${output_path}" | od -An -tu1 | tr -d '[:space:]')"
  [[ "${last_byte}" == 10 ]] ||
    fail "${label} .PKGINFO must end with LF"
  mapfile -t versions < <(sed -n 's/^pkgver = //p' "${output_path}")
  (( ${#versions[@]} == 1 )) ||
    fail "${label} .PKGINFO must contain exactly one package version"
  [[ "${versions[0]}" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$ ]] ||
    fail "${label} package version is outside the closed grammar"
  printf '%s\n' "${versions[0]}"
}

OLD_EXPECTED_VERSION="$(expected_package_version "${OLD_SOURCE_COMMIT}")"
NEW_EXPECTED_VERSION="$(expected_package_version "${NEW_SOURCE_COMMIT}")"
readonly OLD_EXPECTED_VERSION NEW_EXPECTED_VERSION
OLD_PACKAGE_VERSION="$(
  read_package_version old "${OLD_PACKAGE_SNAPSHOT}" "${TEMPORARY_ROOT}/old.PKGINFO"
)"
NEW_PACKAGE_VERSION="$(
  read_package_version new "${NEW_PACKAGE_SNAPSHOT}" "${TEMPORARY_ROOT}/new.PKGINFO"
)"
readonly OLD_PACKAGE_VERSION NEW_PACKAGE_VERSION
[[ "${OLD_PACKAGE_VERSION}" == "${OLD_EXPECTED_VERSION}" ]] ||
  fail 'old package version does not match its exact source commit'
[[ "${NEW_PACKAGE_VERSION}" == "${NEW_EXPECTED_VERSION}" ]] ||
  fail 'new package version does not match its exact source commit'
(( $(vercmp "${NEW_PACKAGE_VERSION}" "${OLD_PACKAGE_VERSION}") > 0 )) ||
  fail 'new package version does not sort after old package version'

readonly COMMITTED_VERIFIER="${TEMPORARY_ROOT}/committed-verifier"
git -C "${REPOSITORY_ROOT}" show \
  "${SOURCE_HEAD}:scripts/verify-arch-package-skeleton.sh" \
  >"${COMMITTED_VERIFIER}" ||
  fail 'current committed verifier object is unavailable'
cmp -- "${COMMITTED_VERIFIER}" "${VERIFIER}" ||
  fail 'working verifier differs from the current committed policy'
chmod 0500 -- "${COMMITTED_VERIFIER}"
COMMITTED_VERIFIER_SHA256="$(sha256sum -- "${COMMITTED_VERIFIER}" | cut -d ' ' -f 1)"
readonly COMMITTED_VERIFIER_SHA256
[[ "$(stat -c '%u:%a:%h:%F' -- "${COMMITTED_VERIFIER}")" == \
  "$(id -u):500:1:regular file" ]] ||
  fail 'committed verifier snapshot is not one private executable regular file'

assert_static_inputs_unchanged() {
  local stage="$1"
  local current_head
  local current_status
  [[ "$(sha256sum -- "${OLD_PACKAGE_SNAPSHOT}" | cut -d ' ' -f 1)" == \
      "${OLD_PACKAGE_SHA256}" &&
    "$(sha256sum -- "${NEW_PACKAGE_SNAPSHOT}" | cut -d ' ' -f 1)" == \
      "${NEW_PACKAGE_SHA256}" ]] ||
    fail "a private package snapshot changed ${stage}"
  [[ "$(sha256sum -- "${COMMITTED_VERIFIER}" | cut -d ' ' -f 1)" == \
    "${COMMITTED_VERIFIER_SHA256}" ]] ||
    fail "committed verifier snapshot changed ${stage}"
  current_head="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)" ||
    fail "source repository HEAD could not be reinspected ${stage}"
  current_status="$(
    git -C "${REPOSITORY_ROOT}" -c core.fsmonitor=false \
      status --porcelain=v1 --untracked-files=normal
  )" || fail "source repository cleanliness could not be reinspected ${stage}"
  [[ "${current_head}" == "${SOURCE_HEAD}" && -z "${current_status}" ]] ||
    fail "source repository changed ${stage}"
}

A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${COMMITTED_VERIFIER}" "${OLD_PACKAGE_SNAPSHOT}" "${OLD_SOURCE_COMMIT}"
A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${COMMITTED_VERIFIER}" "${NEW_PACKAGE_SNAPSHOT}" "${NEW_SOURCE_COMMIT}"
assert_static_inputs_unchanged 'after exact package verification'

# No package-manager state exists before both source/package pairs, their
# ancestry and ordering, and the current committed verification policy pass.
readonly INSTALL_ROOT="${TEMPORARY_ROOT}/root"
readonly DATABASE_PATH="${TEMPORARY_ROOT}/pacman-db"
readonly CACHE_PATH="${TEMPORARY_ROOT}/pacman-cache"
readonly GPG_PATH="${TEMPORARY_ROOT}/pacman-gnupg"
readonly HOOK_PATH="${TEMPORARY_ROOT}/empty-hooks"
readonly LOG_PATH="${TEMPORARY_ROOT}/pacman.log"
readonly PACMAN_CONFIG="${TEMPORARY_ROOT}/pacman.conf"
readonly ADMIN_HOME="${TEMPORARY_ROOT}/admin-home"
readonly FAKEROOT_STATE="${TEMPORARY_ROOT}/fakeroot.state"
readonly EVALUATOR_HOME="${INSTALL_ROOT}/home/a-quo-evaluator"
readonly EVALUATOR_DATA="${EVALUATOR_HOME}/.local/share"
readonly EVALUATOR_CONFIG="${EVALUATOR_HOME}/.config"
readonly HOST_TEMP="${TEMPORARY_ROOT}/tmp"

mkdir -m 0700 -- \
  "${INSTALL_ROOT}" "${DATABASE_PATH}" "${CACHE_PATH}" "${GPG_PATH}" \
  "${HOOK_PATH}" "${ADMIN_HOME}" "${HOST_TEMP}"
mkdir -m 0700 -- "${DATABASE_PATH}/local" "${INSTALL_ROOT}/home"
mkdir -m 0700 -- "${EVALUATOR_HOME}" "${EVALUATOR_HOME}/.local" \
  "${EVALUATOR_HOME}/.config"
mkdir -m 0700 -- "${EVALUATOR_DATA}" "${EVALUATOR_CONFIG}/omarchy"
mkdir -m 0700 -- "${EVALUATOR_DATA}/a-quo" \
  "${EVALUATOR_CONFIG}/omarchy/plugins"
mkdir -m 0700 -- "${EVALUATOR_CONFIG}/omarchy/plugins/existing.example"

readonly PERSONA_SENTINEL="${EVALUATOR_DATA}/a-quo/personas.sqlite3"
readonly PLUGIN_SENTINEL="${EVALUATOR_CONFIG}/omarchy/plugins/existing.example/user-state"
printf '%s\n' 'synthetic persona state; package manager must preserve' \
  >"${PERSONA_SENTINEL}"
printf '%s\n' 'synthetic plugin state; package manager must preserve' \
  >"${PLUGIN_SENTINEL}"
PERSONA_SENTINEL_SHA256="$(
  sha256sum "${PERSONA_SENTINEL}" | cut -d ' ' -f 1
)"
PLUGIN_SENTINEL_SHA256="$(
  sha256sum "${PLUGIN_SENTINEL}" | cut -d ' ' -f 1
)"
readonly PERSONA_SENTINEL_SHA256 PLUGIN_SENTINEL_SHA256
PERSONA_SENTINEL_STAT="$(
  stat -c '%d:%i:%u:%g:%a:%h:%F:%s' -- "${PERSONA_SENTINEL}"
)"
PLUGIN_SENTINEL_STAT="$(
  stat -c '%d:%i:%u:%g:%a:%h:%F:%s' -- "${PLUGIN_SENTINEL}"
)"
readonly PERSONA_SENTINEL_STAT PLUGIN_SENTINEL_STAT

printf '%s\n' \
  '[options]' \
  'Architecture = aarch64' \
  'SigLevel = Never' \
  'LocalFileSigLevel = Never' \
  >"${PACMAN_CONFIG}"
chmod 0600 -- "${PACMAN_CONFIG}"

readonly -a PACMAN_COMMON=(
  --root "${INSTALL_ROOT}"
  --dbpath "${DATABASE_PATH}"
  --cachedir "${CACHE_PATH}"
  --gpgdir "${GPG_PATH}"
  --hookdir "${HOOK_PATH}"
  --logfile "${LOG_PATH}"
  --config "${PACMAN_CONFIG}"
  --arch aarch64
  --noconfirm
)

run_initial_fakeroot() {
  env -i HOME="${ADMIN_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
    TMPDIR="${HOST_TEMP}" \
    fakeroot --unknown-is-real -s "${FAKEROOT_STATE}" -- "$@"
}

run_saved_fakeroot() {
  env -i HOME="${ADMIN_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
    TMPDIR="${HOST_TEMP}" \
    fakeroot --unknown-is-real \
    -i "${FAKEROOT_STATE}" -s "${FAKEROOT_STATE}" -- "$@"
}

assert_user_state() {
  local stage="$1"
  [[ "$(sha256sum "${PERSONA_SENTINEL}" | cut -d ' ' -f 1)" == \
      "${PERSONA_SENTINEL_SHA256}" &&
    "$(sha256sum "${PLUGIN_SENTINEL}" | cut -d ' ' -f 1)" == \
      "${PLUGIN_SENTINEL_SHA256}" &&
    "$(stat -c '%d:%i:%u:%g:%a:%h:%F:%s' -- "${PERSONA_SENTINEL}")" == \
      "${PERSONA_SENTINEL_STAT}" &&
    "$(stat -c '%d:%i:%u:%g:%a:%h:%F:%s' -- "${PLUGIN_SENTINEL}")" == \
      "${PLUGIN_SENTINEL_STAT}" ]] ||
    fail "package ${stage} changed seeded persona or plugin state"
}

readonly EXPECTED_INVENTORY="${TEMPORARY_ROOT}/expected-inventory"
printf '%s\n' \
  usr \
  usr/bin \
  usr/bin/a-quo \
  usr/bin/a-quo-daemon \
  usr/lib \
  usr/lib/a-quo \
  usr/lib/a-quo/a-quo-consent \
  usr/lib/systemd \
  usr/lib/systemd/user \
  usr/lib/systemd/user/a-quo-daemon.service \
  usr/lib/systemd/user-preset \
  usr/lib/systemd/user-preset/90-a-quo.preset \
  usr/share \
  usr/share/a-quo \
  usr/share/a-quo/provider-registry-v1.json \
  usr/share/doc \
  usr/share/doc/a-quo \
  usr/share/doc/a-quo/PACKAGING.md \
  usr/share/doc/a-quo/README.md \
  usr/share/doc/a-quo/SECURITY.md \
  usr/share/doc/a-quo/THREAT-MODEL.md \
  usr/share/licenses \
  usr/share/licenses/a-quo \
  usr/share/licenses/a-quo/LICENSE | sort >"${EXPECTED_INVENTORY}"

assert_offline_service_disabled() {
  local output
  local status
  set +e
  output="$(
    env -i LC_ALL=C PATH=/usr/bin:/bin TMPDIR="${HOST_TEMP}" \
      systemctl --root="${INSTALL_ROOT}" --global --no-pager \
      is-enabled a-quo-daemon.service 2>&1
  )"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && "${output}" == disabled ]] ||
    fail "offline user service is not exactly disabled: status=${status}"
  if find "${INSTALL_ROOT}" -type l -name a-quo-daemon.service -print -quit |
    grep -q .; then
    fail 'package transition created a user-service enablement link'
  fi
}

assert_installed_package() {
  local stage="$1"
  local package_snapshot="$2"
  local package_version="$3"
  local extracted="${TEMPORARY_ROOT}/extracted-${stage}"
  local observed_inventory_raw="${TEMPORARY_ROOT}/inventory-${stage}.raw"
  local observed_inventory="${TEMPORARY_ROOT}/inventory-${stage}"
  local query
  local relative_path
  local installed_path
  local expected_mode
  local expected_kind
  local observed_stat

  query="$(run_saved_fakeroot pacman -Q "${PACMAN_COMMON[@]}" a-quo)"
  [[ "${query}" == "a-quo ${package_version}" ]] ||
    fail "${stage} package query is not the expected version"
  run_saved_fakeroot pacman -Qkk "${PACMAN_COMMON[@]}" a-quo >/dev/null
  run_saved_fakeroot pacman -Qlq "${PACMAN_COMMON[@]}" a-quo \
    >"${observed_inventory_raw}"
  while IFS= read -r installed_path; do
    case "${installed_path}" in
      "${INSTALL_ROOT}"/*)
        relative_path="${installed_path#"${INSTALL_ROOT}/"}"
        ;;
      /*)
        relative_path="${installed_path#/}"
        ;;
      *)
        fail "pacman returned a nonabsolute path during ${stage}"
        ;;
    esac
    printf '%s\n' "${relative_path%/}"
  done <"${observed_inventory_raw}" | sort >"${observed_inventory}"
  cmp -- "${EXPECTED_INVENTORY}" "${observed_inventory}" ||
    fail "installed inventory differs during ${stage}"

  mkdir -m 0700 -- "${extracted}"
  bsdtar --no-same-owner -xf "${package_snapshot}" -C "${extracted}"
  while IFS= read -r relative_path; do
    installed_path="${INSTALL_ROOT}/${relative_path}"
    if [[ -f "${extracted}/${relative_path}" ]]; then
      if [[ ! -f "${installed_path}" || -L "${installed_path}" ]] ||
        ! cmp -- "${extracted}/${relative_path}" "${installed_path}"; then
        fail "installed file differs during ${stage}: ${relative_path}"
      fi
      expected_mode=644
      case "${relative_path}" in
        usr/bin/a-quo | usr/bin/a-quo-daemon | usr/lib/a-quo/a-quo-consent)
          expected_mode=755
          ;;
      esac
      expected_kind='regular file'
    else
      [[ -d "${installed_path}" && ! -L "${installed_path}" ]] ||
        fail "installed directory is unsafe during ${stage}: ${relative_path}"
      expected_mode=755
      expected_kind=directory
    fi
    observed_stat="$(
      run_saved_fakeroot stat -c '%u:%g %a %F' -- "${installed_path}"
    )"
    [[ "${observed_stat}" == "0:0 ${expected_mode} ${expected_kind}" ]] ||
      fail "installed metadata differs during ${stage}: ${relative_path}"
  done <"${EXPECTED_INVENTORY}"

  [[ "$(<"${INSTALL_ROOT}/usr/share/a-quo/provider-registry-v1.json")" == \
    '{"providers":[],"schema":"urn:a-quo:omarchy-plugin-risk-provider-registry:v1"}' ]] ||
    fail "optional reviewer registry is not empty during ${stage}"
  assert_offline_service_disabled
  assert_user_state "${stage}"
}

if env -i HOME="${ADMIN_HOME}" LC_ALL=C PATH=/usr/bin:/bin \
  TMPDIR="${HOST_TEMP}" \
  pacman -Q "${PACMAN_COMMON[@]}" a-quo >/dev/null 2>&1; then
  fail 'isolated package database was not empty before installation'
fi

assert_static_inputs_unchanged 'immediately before package-manager mutation'
run_initial_fakeroot pacman -U "${PACMAN_COMMON[@]}" \
  --nodeps --nodeps --noscriptlet "${OLD_PACKAGE_SNAPSHOT}"
assert_installed_package old-install "${OLD_PACKAGE_SNAPSHOT}" \
  "${OLD_PACKAGE_VERSION}"

run_saved_fakeroot pacman -U "${PACMAN_COMMON[@]}" \
  --nodeps --nodeps --noscriptlet "${NEW_PACKAGE_SNAPSHOT}"
assert_installed_package new-upgrade "${NEW_PACKAGE_SNAPSHOT}" \
  "${NEW_PACKAGE_VERSION}"

run_saved_fakeroot pacman -R "${PACMAN_COMMON[@]}" \
  --nodeps --nodeps --noscriptlet a-quo
if run_saved_fakeroot pacman -Q "${PACMAN_COMMON[@]}" a-quo \
  >/dev/null 2>&1; then
  fail 'package remains registered after simulated removal'
fi
while IFS= read -r relative_path; do
  if [[ -e "${INSTALL_ROOT}/${relative_path}" ||
    -L "${INSTALL_ROOT}/${relative_path}" ]]; then
    fail "package-owned path remains after removal: ${relative_path}"
  fi
done <"${EXPECTED_INVENTORY}"
assert_user_state removal

run_saved_fakeroot pacman -U "${PACMAN_COMMON[@]}" \
  --nodeps --nodeps --noscriptlet "${NEW_PACKAGE_SNAPSHOT}"
assert_installed_package new-reinstall "${NEW_PACKAGE_SNAPSHOT}" \
  "${NEW_PACKAGE_VERSION}"

assert_static_inputs_unchanged 'during the package transition'

printf '%s\n' \
  'passed isolated fakeroot/libalpm old-to-new transition, removal, and reinstall' \
  "policy_commit=${SOURCE_HEAD}" \
  "old_source_commit=${OLD_SOURCE_COMMIT}" \
  "old_package_version=${OLD_PACKAGE_VERSION}" \
  "old_package_sha256=${OLD_PACKAGE_SHA256}" \
  "new_source_commit=${NEW_SOURCE_COMMIT}" \
  "new_package_version=${NEW_PACKAGE_VERSION}" \
  "new_package_sha256=${NEW_PACKAGE_SHA256}" \
  'package_transition_tested=isolated-fakeroot-libalpm' \
  'caller_pinned_package_sha256_matched=true' \
  'user_state_preserved=true' \
  'package_signature_verified=false' \
  'package_source_to_binary_provenance_established=false' \
  'dependencies_resolved=false' \
  'scriptlets_and_hooks_executed=false' \
  'network_or_repository_sync_performed=false' \
  'git_lazy_fetch_disabled=true' \
  'same_uid_snapshot_substitution_resistance_tested=false' \
  'archive_resource_exhaustion_containment_tested=false' \
  'real_root_ownership_tested=false' \
  'live_package_upgrade_tested=false' \
  'package_downgrade_refusal_tested=false' \
  'package_interruption_recovery_tested=false' \
  'clean_system_tested=false' \
  'systemd_user_manager_tested=false' \
  'wayland_consent_tested=false' \
  'omarchy_integration_tested=false' \
  'behavioural_analysis_tested=false' \
  'signed_does_not_mean_safe=true'
