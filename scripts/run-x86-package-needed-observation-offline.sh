#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

fail_offline_observation() {
  printf 'offline x86_64 package NEEDED observation refused: %s\n' "$1" >&2
  exit 1
}

if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'usage: %s EXPECTED_SOURCE_COMMIT\n' "${0##*/}" >&2
  exit 2
fi
readonly EXPECTED_SOURCE_COMMIT="$1"
readonly EXPECTED_UID=1001
readonly EXPECTED_GID=1001
readonly EXPECTED_WORKSPACE=/workspace
readonly EXPECTED_HOME=/home/a-quo-observer
readonly EXPECTED_NAMESPACE=physical-x86_64-official-omarchy-4.0.2
readonly EXPECTED_MISE_SHA256=cff4832ded79af2951e800bddcb5a22acac58630d765a2d062c1180680a0bb35
readonly PROFILE="${EXPECTED_WORKSPACE}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly BUNDLE="${EXPECTED_WORKSPACE}/target/arch-package-needed-observations/${EXPECTED_NAMESPACE}/${EXPECTED_SOURCE_COMMIT}"

for required_tool in bash cat chmod find git id mktemp readlink rm sha256sum sort uname; do
  command -v "${required_tool}" >/dev/null ||
    fail_offline_observation "required offline tool is unavailable: ${required_tool}"
done

[[ "$(id -u)" == "${EXPECTED_UID}" && "$(id -g)" == "${EXPECTED_GID}" ]] ||
  fail_offline_observation 'container process does not have the reviewed non-root UID/GID'
[[ "$(uname -m)" == x86_64 ]] ||
  fail_offline_observation 'container execution architecture is not x86_64'
[[ "${HOME:-}" == "${EXPECTED_HOME}" && "${PWD}" == "${EXPECTED_WORKSPACE}" ]] ||
  fail_offline_observation 'container HOME or working directory differs from policy'
[[ "${MISE_OFFLINE:-}" == 1 && "${MISE_TRUSTED_CONFIG_PATHS:-}" == "${EXPECTED_WORKSPACE}" ]] ||
  fail_offline_observation 'offline Mise policy is missing or malformed'
[[ -d /sys/class/net/lo ]] ||
  fail_offline_observation 'offline container has no loopback interface'
mapfile -t network_interfaces < <(
  find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort
)
[[ "${#network_interfaces[@]}" -eq 1 && "${network_interfaces[0]}" == lo ]] ||
  fail_offline_observation 'offline container has a non-loopback network interface'

if ( : >/.a-quo-read-only-rootfs-probe ) 2>/dev/null; then
  rm -f -- /.a-quo-read-only-rootfs-probe
  fail_offline_observation 'container root filesystem is writable'
fi
if ( : >"${EXPECTED_WORKSPACE}/.a-quo-read-only-workspace-probe" ) 2>/dev/null; then
  rm -f -- "${EXPECTED_WORKSPACE}/.a-quo-read-only-workspace-probe"
  fail_offline_observation 'repository root is writable outside the target submount'
fi
target_probe="$(mktemp "${EXPECTED_WORKSPACE}/target/.a-quo-target-write-probe.XXXXXX")" ||
  fail_offline_observation 'target output mount is not writable'
rm -f -- "${target_probe}"
home_probe="$(mktemp "${EXPECTED_HOME}/.a-quo-home-write-probe.XXXXXX")" ||
  fail_offline_observation 'observer home mount is not writable'
rm -f -- "${home_probe}"
[[ "$(readlink -f -- /usr/local/bin/mise)" == /usr/local/bin/mise ]] ||
  fail_offline_observation 'read-only Mise mount did not resolve to its reviewed path'
mise_digest="$(sha256sum -- /usr/local/bin/mise)" ||
  fail_offline_observation 'Mise bind mount cannot be hashed'
[[ "${mise_digest%% *}" == "${EXPECTED_MISE_SHA256}" ]] ||
  fail_offline_observation 'Mise bind mount bytes differ from the reviewed input'
if ( chmod u+w /usr/local/bin/mise ) 2>/dev/null; then
  fail_offline_observation 'Mise bind mount is writable'
fi

source_commit="$(git -C "${EXPECTED_WORKSPACE}" rev-parse --verify HEAD)"
readonly source_commit
[[ "${source_commit}" == "${EXPECTED_SOURCE_COMMIT}" ]] ||
  fail_offline_observation 'checkout does not match the expected source commit'
[[ "$(git -C "${EXPECTED_WORKSPACE}" rev-parse --is-shallow-repository)" == false ]] ||
  fail_offline_observation 'checkout is shallow'
[[ -z "$(git -C "${EXPECTED_WORKSPACE}" status --porcelain=v1 --untracked-files=normal)" ]] ||
  fail_offline_observation 'checkout is dirty before observation'

readonly BUILDER_STDOUT=/tmp/a-quo-x86-builder.stdout
readonly BUILDER_STDERR=/tmp/a-quo-x86-builder.stderr
set +e
"${EXPECTED_WORKSPACE}/scripts/build-arch-package-skeleton.sh" \
  --observe-unconfirmed-needed "${PROFILE}" \
  >"${BUILDER_STDOUT}" 2>"${BUILDER_STDERR}"
builder_status="$?"
set -e
cat -- "${BUILDER_STDOUT}"
cat -- "${BUILDER_STDERR}" >&2
[[ "${builder_status}" -eq 1 && -d "${BUNDLE}" ]] ||
  fail_offline_observation 'builder did not produce the expected non-accepting bundle and status'

exec "${EXPECTED_WORKSPACE}/scripts/verify-arch-package-needed-observation-bundle.sh" \
  "${EXPECTED_SOURCE_COMMIT}"
