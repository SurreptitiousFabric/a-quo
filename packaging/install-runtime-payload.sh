#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s ABSOLUTE_EMPTY_DESTDIR ABSOLUTE_RELEASE_BINARY_DIRECTORY\n' "$0" >&2
  exit 2
fi

readonly DESTINATION_INPUT="$1"
readonly BINARY_DIRECTORY_INPUT="$2"
SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT

case "${DESTINATION_INPUT}" in
  /*) ;;
  *)
    printf '%s\n' 'destination must be an absolute path' >&2
    exit 1
    ;;
esac
case "${BINARY_DIRECTORY_INPUT}" in
  /*) ;;
  *)
    printf '%s\n' 'release binary directory must be an absolute path' >&2
    exit 1
    ;;
esac

if [[ ! -d "${DESTINATION_INPUT}" || -L "${DESTINATION_INPUT}" ]]; then
  printf '%s\n' 'destination must be an existing real directory' >&2
  exit 1
fi
if [[ ! -d "${BINARY_DIRECTORY_INPUT}" || -L "${BINARY_DIRECTORY_INPUT}" ]]; then
  printf '%s\n' 'release binary directory must be an existing real directory' >&2
  exit 1
fi

DESTINATION="$(realpath -e -- "${DESTINATION_INPUT}")"
readonly DESTINATION
BINARY_DIRECTORY="$(realpath -e -- "${BINARY_DIRECTORY_INPUT}")"
readonly BINARY_DIRECTORY
if [[ "${DESTINATION}" == / ]]; then
  printf '%s\n' 'refusing to use the filesystem root as a package destination' >&2
  exit 1
fi
if [[ -n "$(find "${DESTINATION}" -mindepth 1 -print -quit)" ]]; then
  printf '%s\n' 'package destination must be empty; refusing replacement or merge' >&2
  exit 1
fi

readonly CLI_SOURCE="${BINARY_DIRECTORY}/a-quo"
readonly DAEMON_SOURCE="${BINARY_DIRECTORY}/a-quo-daemon"
readonly CONSENT_SOURCE="${BINARY_DIRECTORY}/a-quo-consent"
readonly UNIT_SOURCE="${REPOSITORY_ROOT}/packaging/systemd/a-quo-daemon.service"
readonly PRESET_SOURCE="${REPOSITORY_ROOT}/packaging/systemd/90-a-quo.preset"
readonly REGISTRY_SOURCE="${REPOSITORY_ROOT}/packaging/provider-registry-v1.json"

for source_path in \
  "${CLI_SOURCE}" \
  "${DAEMON_SOURCE}" \
  "${CONSENT_SOURCE}" \
  "${UNIT_SOURCE}" \
  "${PRESET_SOURCE}" \
  "${REGISTRY_SOURCE}" \
  "${REPOSITORY_ROOT}/README.md" \
  "${REPOSITORY_ROOT}/docs/PACKAGING.md" \
  "${REPOSITORY_ROOT}/SECURITY.md" \
  "${REPOSITORY_ROOT}/docs/THREAT-MODEL.md" \
  "${REPOSITORY_ROOT}/LICENSE"; do
  if [[ ! -f "${source_path}" || -L "${source_path}" ]]; then
    printf 'required package source is not a real regular file: %s\n' "${source_path}" >&2
    exit 1
  fi
done
for binary_path in "${CLI_SOURCE}" "${DAEMON_SOURCE}" "${CONSENT_SOURCE}"; do
  if [[ ! -x "${binary_path}" ]]; then
    printf 'required release binary is not executable: %s\n' "${binary_path}" >&2
    exit 1
  fi
done

umask 022
install -d -m 0755 -- \
  "${DESTINATION}/usr/bin" \
  "${DESTINATION}/usr/lib/a-quo" \
  "${DESTINATION}/usr/lib/systemd/user" \
  "${DESTINATION}/usr/lib/systemd/user-preset" \
  "${DESTINATION}/usr/share/a-quo" \
  "${DESTINATION}/usr/share/doc/a-quo" \
  "${DESTINATION}/usr/share/licenses/a-quo"

install -T -m 0755 -- "${CLI_SOURCE}" "${DESTINATION}/usr/bin/a-quo"
install -T -m 0755 -- "${DAEMON_SOURCE}" "${DESTINATION}/usr/bin/a-quo-daemon"
install -T -m 0755 -- "${CONSENT_SOURCE}" "${DESTINATION}/usr/lib/a-quo/a-quo-consent"
install -T -m 0644 -- "${UNIT_SOURCE}" \
  "${DESTINATION}/usr/lib/systemd/user/a-quo-daemon.service"
install -T -m 0644 -- "${PRESET_SOURCE}" \
  "${DESTINATION}/usr/lib/systemd/user-preset/90-a-quo.preset"
install -T -m 0644 -- "${REGISTRY_SOURCE}" \
  "${DESTINATION}/usr/share/a-quo/provider-registry-v1.json"
install -T -m 0644 -- "${REPOSITORY_ROOT}/README.md" \
  "${DESTINATION}/usr/share/doc/a-quo/README.md"
install -T -m 0644 -- "${REPOSITORY_ROOT}/docs/PACKAGING.md" \
  "${DESTINATION}/usr/share/doc/a-quo/PACKAGING.md"
install -T -m 0644 -- "${REPOSITORY_ROOT}/SECURITY.md" \
  "${DESTINATION}/usr/share/doc/a-quo/SECURITY.md"
install -T -m 0644 -- "${REPOSITORY_ROOT}/docs/THREAT-MODEL.md" \
  "${DESTINATION}/usr/share/doc/a-quo/THREAT-MODEL.md"
install -T -m 0644 -- "${REPOSITORY_ROOT}/LICENSE" \
  "${DESTINATION}/usr/share/licenses/a-quo/LICENSE"

if find "${DESTINATION}" -mindepth 1 ! -type d ! -type f -print -quit | grep -q .; then
  printf '%s\n' 'package payload unexpectedly contains a link or special entry' >&2
  exit 1
fi

readonly EXPECTED_FILE_COUNT=11
OBSERVED_FILE_COUNT="$(find "${DESTINATION}" -type f -printf '.' | wc -c)"
readonly OBSERVED_FILE_COUNT
if [[ "${OBSERVED_FILE_COUNT}" -ne "${EXPECTED_FILE_COUNT}" ]]; then
  printf 'package payload file count differs from the closed inventory: expected=%s observed=%s\n' \
    "${EXPECTED_FILE_COUNT}" "${OBSERVED_FILE_COUNT}" >&2
  exit 1
fi
