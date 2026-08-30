#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export GIT_NO_REPLACE_OBJECTS=1

for git_environment_override in \
  GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_COMMON_DIR \
  GIT_DIR \
  GIT_INDEX_FILE \
  GIT_NAMESPACE \
  GIT_OBJECT_DIRECTORY \
  GIT_QUARANTINE_PATH \
  GIT_WORK_TREE; do
  if [[ -v "${git_environment_override}" ]]; then
    printf 'refusing inherited Git repository override: %s\n' \
      "${git_environment_override}" >&2
    exit 1
  fi
done

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s PACKAGE_PATH EXPECTED_SOURCE_COMMIT\n' "$0" >&2
  exit 2
fi

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly PACKAGE_INPUT="$1"
readonly EXPECTED_COMMIT="$2"

if [[ ! "${EXPECTED_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'expected source commit must be a full lowercase Git object ID' >&2
  exit 1
fi
if [[ ! -f "${PACKAGE_INPUT}" || -L "${PACKAGE_INPUT}" ]]; then
  printf '%s\n' 'package must be a real regular file' >&2
  exit 1
fi
PACKAGE_PATH="$(realpath -e -- "${PACKAGE_INPUT}")"
readonly PACKAGE_PATH
if [[ "$(uname -m)" != aarch64 || ! -f /etc/arch-release ]]; then
  printf '%s\n' 'the lifecycle smoke requires a native aarch64 Arch-family host' >&2
  exit 1
fi
if [[ "${EUID}" -eq 0 ]]; then
  printf '%s\n' 'refusing to run the fakeroot lifecycle smoke as real root' >&2
  exit 1
fi

for required_tool in \
  bsdtar bwrap cmp cp fakeroot find git pacman realpath sha256sum stat systemctl; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required lifecycle-smoke tool is unavailable: %s\n' \
      "${required_tool}" >&2
    exit 1
  fi
done

SOURCE_HEAD="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)"
readonly SOURCE_HEAD
if [[ "${SOURCE_HEAD}" != "${EXPECTED_COMMIT}" ]]; then
  printf 'lifecycle smoke only accepts the current source commit: expected=%s head=%s\n' \
    "${EXPECTED_COMMIT}" "${SOURCE_HEAD}" >&2
  exit 1
fi
if [[ -n "$(git -C "${REPOSITORY_ROOT}" status --porcelain=v1 --untracked-files=normal)" ]]; then
  printf '%s\n' 'refusing lifecycle smoke from a dirty source tree' >&2
  exit 1
fi
WORKSPACE_VERSION="$(
  git -C "${REPOSITORY_ROOT}" show "${EXPECTED_COMMIT}:Cargo.toml" |
    sed -n 's/^version = "\([^"]*\)"$/\1/p' |
    head -n 1
)"
readonly WORKSPACE_VERSION
if [[ ! "${WORKSPACE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '%s\n' 'committed workspace version is not a simple semantic version' >&2
  exit 1
fi
umask 077
mkdir -p -- "${REPOSITORY_ROOT}/target"
TEMPORARY_ROOT="$(
  mktemp -d "${REPOSITORY_ROOT}/target/.a-quo-package-lifecycle.XXXXXX"
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
mkdir -m 0700 -- "${SNAPSHOT_DIRECTORY}"
PACKAGE_SNAPSHOT="${SNAPSHOT_DIRECTORY}/$(basename -- "${PACKAGE_PATH}")"
readonly PACKAGE_SNAPSHOT
cp --reflink=never --no-preserve=all -- "${PACKAGE_PATH}" "${PACKAGE_SNAPSHOT}"
chmod 0400 -- "${PACKAGE_SNAPSHOT}"
if [[ ! -f "${PACKAGE_SNAPSHOT}" || -L "${PACKAGE_SNAPSHOT}" ]]; then
  printf '%s\n' 'private package snapshot is not a real regular file' >&2
  exit 1
fi
PACKAGE_SHA256_BEFORE="$(sha256sum "${PACKAGE_SNAPSHOT}" | cut -d ' ' -f 1)"
readonly PACKAGE_SHA256_BEFORE
PACKAGE_VERSION="$(
  bsdtar -xOf "${PACKAGE_SNAPSHOT}" .PKGINFO |
    sed -n 's/^pkgver = //p'
)"
readonly PACKAGE_VERSION
if [[ -z "${PACKAGE_VERSION}" || "${PACKAGE_VERSION}" == *$'\n'* ]]; then
  printf '%s\n' 'package contains an invalid package version record' >&2
  exit 1
fi

readonly COMMITTED_VERIFIER="${TEMPORARY_ROOT}/verify-arch-package-skeleton.sh"
git -C "${REPOSITORY_ROOT}" show \
  "${EXPECTED_COMMIT}:scripts/verify-arch-package-skeleton.sh" \
  >"${COMMITTED_VERIFIER}"
chmod 0500 -- "${COMMITTED_VERIFIER}"
A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${COMMITTED_VERIFIER}" "${PACKAGE_SNAPSHOT}" "${EXPECTED_COMMIT}"

readonly INSTALL_ROOT="${TEMPORARY_ROOT}/root"
readonly DATABASE_PATH="${TEMPORARY_ROOT}/pacman-db"
readonly CACHE_PATH="${TEMPORARY_ROOT}/pacman-cache"
readonly GPG_PATH="${TEMPORARY_ROOT}/pacman-gnupg"
readonly HOOK_PATH="${TEMPORARY_ROOT}/empty-hooks"
readonly LOG_PATH="${TEMPORARY_ROOT}/pacman.log"
readonly PACMAN_CONFIG="${TEMPORARY_ROOT}/pacman.conf"
readonly ADMIN_HOME="${TEMPORARY_ROOT}/admin-home"
readonly FAKEROOT_STATE="${TEMPORARY_ROOT}/fakeroot.state"
readonly EXTRACTED_PACKAGE="${TEMPORARY_ROOT}/package"
readonly EVALUATOR_HOME="${INSTALL_ROOT}/home/a-quo-evaluator"
readonly EVALUATOR_DATA="${EVALUATOR_HOME}/.local/share"
readonly EVALUATOR_CONFIG="${EVALUATOR_HOME}/.config"
readonly EVALUATOR_RUNTIME="${TEMPORARY_ROOT}/runtime"
readonly HOST_TEMP="${TEMPORARY_ROOT}/tmp"

mkdir -m 0700 -- \
  "${INSTALL_ROOT}" \
  "${DATABASE_PATH}" \
  "${CACHE_PATH}" \
  "${GPG_PATH}" \
  "${HOOK_PATH}" \
  "${ADMIN_HOME}" \
  "${EXTRACTED_PACKAGE}" \
  "${EVALUATOR_RUNTIME}" \
  "${HOST_TEMP}"
mkdir -m 0700 -- \
  "${DATABASE_PATH}/local" \
  "${INSTALL_ROOT}/home"
mkdir -m 0700 -- "${EVALUATOR_HOME}"
mkdir -m 0700 -- \
  "${EVALUATOR_HOME}/.local" \
  "${EVALUATOR_HOME}/.config"
mkdir -m 0700 -- \
  "${EVALUATOR_DATA}" \
  "${EVALUATOR_CONFIG}/omarchy"
mkdir -m 0700 -- \
  "${EVALUATOR_DATA}/a-quo" \
  "${EVALUATOR_CONFIG}/omarchy/plugins"
mkdir -m 0700 -- \
  "${EVALUATOR_CONFIG}/omarchy/plugins/existing.example"

readonly PERSONA_SENTINEL="${EVALUATOR_DATA}/a-quo/personas.sqlite3"
readonly PLUGIN_SENTINEL="${EVALUATOR_CONFIG}/omarchy/plugins/existing.example/user-state"
printf '%s\n' 'synthetic persona state; package manager must not touch' \
  >"${PERSONA_SENTINEL}"
printf '%s\n' 'synthetic plugin state; package manager must not touch' \
  >"${PLUGIN_SENTINEL}"
PERSONA_SENTINEL_SHA256="$(sha256sum "${PERSONA_SENTINEL}" | cut -d ' ' -f 1)"
readonly PERSONA_SENTINEL_SHA256
PLUGIN_SENTINEL_SHA256="$(sha256sum "${PLUGIN_SENTINEL}" | cut -d ' ' -f 1)"
readonly PLUGIN_SENTINEL_SHA256

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
  env -i \
    HOME="${ADMIN_HOME}" \
    LC_ALL=C \
    PATH=/usr/bin:/bin \
    TMPDIR="${HOST_TEMP}" \
    fakeroot --unknown-is-real -s "${FAKEROOT_STATE}" -- "$@"
}

run_saved_fakeroot() {
  env -i \
    HOME="${ADMIN_HOME}" \
    LC_ALL=C \
    PATH=/usr/bin:/bin \
    TMPDIR="${HOST_TEMP}" \
    fakeroot --unknown-is-real \
    -i "${FAKEROOT_STATE}" -s "${FAKEROOT_STATE}" -- "$@"
}

if env -i \
  HOME="${ADMIN_HOME}" \
  LC_ALL=C \
  PATH=/usr/bin:/bin \
  TMPDIR="${HOST_TEMP}" \
  pacman -Q "${PACMAN_COMMON[@]}" a-quo >/dev/null 2>&1; then
  printf '%s\n' 'isolated package database was not empty before installation' >&2
  exit 1
fi

run_initial_fakeroot pacman -U \
  "${PACMAN_COMMON[@]}" \
  --nodeps --nodeps \
  --noscriptlet \
  "${PACKAGE_SNAPSHOT}"

OBSERVED_QUERY="$(
  run_saved_fakeroot pacman -Q "${PACMAN_COMMON[@]}" a-quo
)"
readonly OBSERVED_QUERY
if [[ "${OBSERVED_QUERY}" != "a-quo ${PACKAGE_VERSION}" ]]; then
  printf 'unexpected installed package query: expected=%s observed=%s\n' \
    "a-quo ${PACKAGE_VERSION}" "${OBSERVED_QUERY:-missing}" >&2
  exit 1
fi
run_saved_fakeroot pacman -Qkk "${PACMAN_COMMON[@]}" a-quo >/dev/null

readonly EXPECTED_INVENTORY="${TEMPORARY_ROOT}/expected-inventory"
readonly OBSERVED_INVENTORY_RAW="${TEMPORARY_ROOT}/observed-inventory-raw"
readonly OBSERVED_INVENTORY="${TEMPORARY_ROOT}/observed-inventory"
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
run_saved_fakeroot pacman -Qlq "${PACMAN_COMMON[@]}" a-quo \
  >"${OBSERVED_INVENTORY_RAW}"
while IFS= read -r installed_path; do
  case "${installed_path}" in
    "${INSTALL_ROOT}"/*)
      relative_path="${installed_path#"${INSTALL_ROOT}/"}"
      ;;
    /*)
      relative_path="${installed_path#/}"
      ;;
    *)
      printf 'pacman returned a nonabsolute installed path: %q\n' \
        "${installed_path}" >&2
      exit 1
      ;;
  esac
  printf '%s\n' "${relative_path%/}"
done <"${OBSERVED_INVENTORY_RAW}" | sort >"${OBSERVED_INVENTORY}"
if ! cmp -- "${EXPECTED_INVENTORY}" "${OBSERVED_INVENTORY}"; then
  printf '%s\n' 'installed package inventory differs from the closed contract' >&2
  exit 1
fi

bsdtar --no-same-owner -xf "${PACKAGE_SNAPSHOT}" -C "${EXTRACTED_PACKAGE}"
while IFS= read -r relative_path; do
  installed_path="${INSTALL_ROOT}/${relative_path}"
  if [[ -f "${EXTRACTED_PACKAGE}/${relative_path}" ]]; then
    if [[ ! -f "${installed_path}" || -L "${installed_path}" ]] ||
      ! cmp -- "${EXTRACTED_PACKAGE}/${relative_path}" "${installed_path}"; then
      printf 'installed file differs from the verified package: %s\n' \
        "${relative_path}" >&2
      exit 1
    fi
    expected_mode=644
    case "${relative_path}" in
      usr/bin/a-quo | usr/bin/a-quo-daemon | usr/lib/a-quo/a-quo-consent)
        expected_mode=755
        ;;
    esac
    expected_kind='regular file'
  else
    if [[ ! -d "${installed_path}" || -L "${installed_path}" ]]; then
      printf 'installed package directory is unavailable or unsafe: %s\n' \
        "${relative_path}" >&2
      exit 1
    fi
    expected_mode=755
    expected_kind=directory
  fi
  observed_stat="$(
    run_saved_fakeroot stat -c '%u:%g %a %F' -- "${installed_path}"
  )"
  if [[ "${observed_stat}" != "0:0 ${expected_mode} ${expected_kind}" ]]; then
    printf 'unexpected simulated installed metadata: path=%s observed=%s\n' \
      "${relative_path}" "${observed_stat:-missing}" >&2
    exit 1
  fi
done <"${EXPECTED_INVENTORY}"

if find "${INSTALL_ROOT}" -type l -name a-quo-daemon.service -print -quit |
  grep -q .; then
  printf '%s\n' 'package transaction unexpectedly enabled the user service' >&2
  exit 1
fi

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
  if [[ "${status}" -ne 1 || "${output}" != disabled ]]; then
    printf 'offline user service state is not exactly disabled: status=%s output=%q\n' \
      "${status}" "${output}" >&2
    exit 1
  fi
}

assert_offline_service_disabled
env -i LC_ALL=C PATH=/usr/bin:/bin TMPDIR="${HOST_TEMP}" \
  systemctl --root="${INSTALL_ROOT}" --global --no-pager \
  preset a-quo-daemon.service >/dev/null
assert_offline_service_disabled
if find "${INSTALL_ROOT}" -type l -name a-quo-daemon.service -print -quit |
  grep -q .; then
  printf '%s\n' 'the disable preset created an enablement link' >&2
  exit 1
fi

run_packaged_probe() {
  local installed_program="$1"
  shift
  local relative_program
  case "${installed_program}" in
    "${INSTALL_ROOT}/usr/"*)
      relative_program="${installed_program#"${INSTALL_ROOT}/usr/"}"
      ;;
    *)
      printf 'refusing binary probe outside the installed package: %q\n' \
        "${installed_program}" >&2
      return 1
      ;;
  esac
  env -i LC_ALL=C PATH=/usr/bin:/bin TMPDIR="${HOST_TEMP}" \
    bwrap \
    --die-with-parent \
    --new-session \
    --unshare-all \
    --ro-bind /usr /usr \
    --symlink usr/bin /bin \
    --symlink usr/lib /lib \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --tmpfs /home \
    --dir /home/a-quo-evaluator \
    --tmpfs /run \
    --dir /run/a-quo-evaluator \
    --dir /opt \
    --ro-bind "${INSTALL_ROOT}/usr" /opt/a-quo \
    --clearenv \
    --setenv HOME /home/a-quo-evaluator \
    --setenv LC_ALL C \
    --setenv PATH /usr/bin:/bin \
    --setenv XDG_CONFIG_HOME /home/a-quo-evaluator/.config \
    --setenv XDG_DATA_HOME /home/a-quo-evaluator/.local/share \
    --setenv XDG_RUNTIME_DIR /run/a-quo-evaluator \
    --chdir /home/a-quo-evaluator \
    "/opt/a-quo/${relative_program}" "$@"
}

if [[ "$(run_packaged_probe "${INSTALL_ROOT}/usr/bin/a-quo" --version)" != \
  "a-quo ${WORKSPACE_VERSION}" ]]; then
  printf '%s\n' 'installed CLI version probe failed' >&2
  exit 1
fi
if [[ "$(run_packaged_probe "${INSTALL_ROOT}/usr/bin/a-quo-daemon" --version)" != \
  "a-quo-daemon ${WORKSPACE_VERSION}" ]]; then
  printf '%s\n' 'installed daemon version probe failed' >&2
  exit 1
fi
set +e
CONSENT_OUTPUT="$(
  run_packaged_probe \
    "${INSTALL_ROOT}/usr/lib/a-quo/a-quo-consent" </dev/null 2>&1
)"
CONSENT_STATUS="$?"
set -e
readonly CONSENT_OUTPUT CONSENT_STATUS
if [[ "${CONSENT_STATUS}" -eq 0 || "${CONSENT_OUTPUT}" != \
  'A Quo consent unavailable: invalid daemon prompt' ]]; then
  printf 'installed consent helper did not fail closed: status=%s output=%q\n' \
    "${CONSENT_STATUS}" "${CONSENT_OUTPUT}" >&2
  exit 1
fi

if [[ "$(sha256sum "${PERSONA_SENTINEL}" | cut -d ' ' -f 1)" != \
    "${PERSONA_SENTINEL_SHA256}" || \
  "$(sha256sum "${PLUGIN_SENTINEL}" | cut -d ' ' -f 1)" != \
    "${PLUGIN_SENTINEL_SHA256}" ]]; then
  printf '%s\n' 'package installation changed seeded user state' >&2
  exit 1
fi

run_saved_fakeroot pacman -R \
  "${PACMAN_COMMON[@]}" \
  --nodeps --nodeps \
  --noscriptlet \
  a-quo

if run_saved_fakeroot pacman -Q "${PACMAN_COMMON[@]}" a-quo \
  >/dev/null 2>&1; then
  printf '%s\n' 'package remains registered after simulated removal' >&2
  exit 1
fi
while IFS= read -r relative_path; do
  if [[ -e "${INSTALL_ROOT}/${relative_path}" || \
    -L "${INSTALL_ROOT}/${relative_path}" ]]; then
    printf 'package-owned path remains after simulated removal: %s\n' \
      "${relative_path}" >&2
    exit 1
  fi
done <"${EXPECTED_INVENTORY}"
if [[ "$(sha256sum "${PERSONA_SENTINEL}" | cut -d ' ' -f 1)" != \
    "${PERSONA_SENTINEL_SHA256}" || \
  "$(sha256sum "${PLUGIN_SENTINEL}" | cut -d ' ' -f 1)" != \
    "${PLUGIN_SENTINEL_SHA256}" ]]; then
  printf '%s\n' 'package removal changed seeded user state' >&2
  exit 1
fi
if [[ "$(sha256sum "${PACKAGE_SNAPSHOT}" | cut -d ' ' -f 1)" != \
  "${PACKAGE_SHA256_BEFORE}" ]]; then
  printf '%s\n' 'package bytes changed during the lifecycle smoke' >&2
  exit 1
fi

printf '%s\n' \
  'passed simulated libalpm install/remove lifecycle under fakeroot' \
  "package_sha256=${PACKAGE_SHA256_BEFORE}" \
  "package_version=${PACKAGE_VERSION}" \
  "source_commit=${EXPECTED_COMMIT}" \
  "pacman_version=$(pacman --version | sed -n 's/.*Pacman v\([^ ]*\).*/\1/p' | head -n 1)" \
  'package_signature_verified=false' \
  'dependencies_resolved=false' \
  'scriptlets_and_hooks_executed=false' \
  'packaged_binary_probe_isolated=true' \
  'packaged_binary_probe_uses_host_usr=true' \
  'offline_disable_preset_tested=true' \
  'real_root_ownership_tested=false' \
  'package_upgrade_tested=false' \
  'clean_system_tested=false' \
  'systemd_user_manager_tested=false' \
  'wayland_consent_tested=false' \
  'omarchy_integration_tested=false'
