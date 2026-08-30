#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
if ! command -v systemctl >/dev/null; then
  printf '%s\n' 'systemctl is required for the offline user-preset check' >&2
  exit 1
fi
TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-package-assets.XXXXXX")"
readonly TEMPORARY_ROOT

cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

readonly BINARY_DIRECTORY="${TEMPORARY_ROOT}/binaries"
readonly DESTINATION="${TEMPORARY_ROOT}/destination"
mkdir -m 0755 -- "${BINARY_DIRECTORY}" "${DESTINATION}"
for binary_name in a-quo a-quo-daemon a-quo-consent; do
  printf '#!/usr/bin/env false\n' >"${BINARY_DIRECTORY}/${binary_name}"
  chmod 0755 -- "${BINARY_DIRECTORY}/${binary_name}"
done

"${REPOSITORY_ROOT}/packaging/install-runtime-payload.sh" \
  "${DESTINATION}" "${BINARY_DIRECTORY}"

readonly EXPECTED_FILES="${TEMPORARY_ROOT}/expected-files"
readonly OBSERVED_FILES="${TEMPORARY_ROOT}/observed-files"
printf '%s\n' \
  usr/bin/a-quo \
  usr/bin/a-quo-daemon \
  usr/lib/a-quo/a-quo-consent \
  usr/lib/systemd/user-preset/90-a-quo.preset \
  usr/lib/systemd/user/a-quo-daemon.service \
  usr/share/a-quo/provider-registry-v1.json \
  usr/share/doc/a-quo/PACKAGING.md \
  usr/share/doc/a-quo/README.md \
  usr/share/doc/a-quo/SECURITY.md \
  usr/share/doc/a-quo/THREAT-MODEL.md \
  usr/share/licenses/a-quo/LICENSE >"${EXPECTED_FILES}"
(
  cd -- "${DESTINATION}"
  find . -type f -printf '%P\n' | sort
) >"${OBSERVED_FILES}"
cmp -- "${EXPECTED_FILES}" "${OBSERVED_FILES}"

while IFS=' ' read -r expected_mode relative_path; do
  observed_mode="$(stat -c '%a' -- "${DESTINATION}/${relative_path}")"
  if [[ "${observed_mode}" != "${expected_mode}" ]]; then
    printf 'unexpected installed mode: path=%s expected=%s observed=%s\n' \
      "${relative_path}" "${expected_mode}" "${observed_mode}" >&2
    exit 1
  fi
done <<'EOF'
755 usr/bin/a-quo
755 usr/bin/a-quo-daemon
755 usr/lib/a-quo/a-quo-consent
644 usr/lib/systemd/user/a-quo-daemon.service
644 usr/lib/systemd/user-preset/90-a-quo.preset
644 usr/share/a-quo/provider-registry-v1.json
644 usr/share/doc/a-quo/PACKAGING.md
644 usr/share/doc/a-quo/README.md
644 usr/share/doc/a-quo/SECURITY.md
644 usr/share/doc/a-quo/THREAT-MODEL.md
644 usr/share/licenses/a-quo/LICENSE
EOF

cmp -- "${REPOSITORY_ROOT}/packaging/systemd/a-quo-daemon.service" \
  "${DESTINATION}/usr/lib/systemd/user/a-quo-daemon.service"
cmp -- "${REPOSITORY_ROOT}/packaging/systemd/90-a-quo.preset" \
  "${DESTINATION}/usr/lib/systemd/user-preset/90-a-quo.preset"
cmp -- "${REPOSITORY_ROOT}/packaging/provider-registry-v1.json" \
  "${DESTINATION}/usr/share/a-quo/provider-registry-v1.json"

if grep -Eiq '(^|[^a-z])(dbus|busname|systemctl|execstartpre|execstartpost)([^a-z]|$)' \
  "${DESTINATION}/usr/lib/systemd/user/a-quo-daemon.service"; then
  printf '%s\n' 'packaged unit contains a forbidden authority or activation directive' >&2
  exit 1
fi
if ! grep -Fxq 'ExecStart=/usr/bin/a-quo-daemon --runtime-directory=%t' \
  "${DESTINATION}/usr/lib/systemd/user/a-quo-daemon.service"; then
  printf '%s\n' 'packaged unit has the wrong daemon command' >&2
  exit 1
fi
if ! grep -Fxq 'Restart=no' "${DESTINATION}/usr/lib/systemd/user/a-quo-daemon.service"; then
  printf '%s\n' 'packaged unit must not restart automatically' >&2
  exit 1
fi
if [[ "$(<"${DESTINATION}/usr/lib/systemd/user-preset/90-a-quo.preset")" != \
  'disable a-quo-daemon.service' ]]; then
  printf '%s\n' 'packaged user preset does not fail closed by default' >&2
  exit 1
fi

assert_offline_service_disabled() {
  local output
  local status
  set +e
  output="$(
    env -i LC_ALL=C PATH=/usr/bin:/bin \
      systemctl --root="${DESTINATION}" --global --no-pager \
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

readonly INVENTORY_BEFORE_PRESET="${TEMPORARY_ROOT}/inventory-before-preset"
readonly INVENTORY_AFTER_PRESET="${TEMPORARY_ROOT}/inventory-after-preset"
(
  cd -- "${DESTINATION}"
  find . -mindepth 1 -printf '%P %y\n' | sort
) >"${INVENTORY_BEFORE_PRESET}"
assert_offline_service_disabled
env -i LC_ALL=C PATH=/usr/bin:/bin \
  systemctl --root="${DESTINATION}" --global --no-pager \
  preset a-quo-daemon.service >/dev/null
assert_offline_service_disabled
(
  cd -- "${DESTINATION}"
  find . -mindepth 1 -printf '%P %y\n' | sort
) >"${INVENTORY_AFTER_PRESET}"
if ! cmp -- "${INVENTORY_BEFORE_PRESET}" "${INVENTORY_AFTER_PRESET}"; then
  printf '%s\n' 'disable preset changed the passive package tree' >&2
  exit 1
fi
if [[ "$(tr -d '\n' <"${DESTINATION}/usr/share/a-quo/provider-registry-v1.json")" != \
  '{"providers":[],"schema":"urn:a-quo:omarchy-plugin-risk-provider-registry:v1"}' ]]; then
  printf '%s\n' 'base package provider registry is not the exact empty registry' >&2
  exit 1
fi

if "${REPOSITORY_ROOT}/packaging/install-runtime-payload.sh" \
  "${DESTINATION}" "${BINARY_DIRECTORY}" >/dev/null 2>&1; then
  printf '%s\n' 'payload installer accepted a non-empty destination' >&2
  exit 1
fi
readonly LINK_DESTINATION="${TEMPORARY_ROOT}/linked-destination"
readonly REAL_DESTINATION="${TEMPORARY_ROOT}/real-destination"
mkdir -m 0755 -- "${REAL_DESTINATION}"
ln -s -- "${REAL_DESTINATION}" "${LINK_DESTINATION}"
if "${REPOSITORY_ROOT}/packaging/install-runtime-payload.sh" \
  "${LINK_DESTINATION}" "${BINARY_DIRECTORY}" >/dev/null 2>&1; then
  printf '%s\n' 'payload installer accepted a symlink destination' >&2
  exit 1
fi

printf '%s\n' 'package payload assets passed closed-inventory checks'
