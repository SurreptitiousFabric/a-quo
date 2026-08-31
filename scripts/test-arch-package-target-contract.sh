#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly RESOLVER="${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh"
readonly AARCH64_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly X86_64_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-arch-target-contract.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

assert_refused() {
  local label="$1"
  local expected="$2"
  shift 2
  local output
  local status
  set +e
  output="$("${RESOLVER}" "$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != *"${expected}"* ]]; then
    printf 'package target mutation was not refused: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

AARCH64_EXPECTED="$(printf '%s\n' \
  'profile_id=a-quo-omarchy4-aarch64-dec29fa-v2' \
  'profile_repository_path=packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile' \
  'profile_sha256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6' \
  'target_kind=virtual-reference-target' \
  'architecture=aarch64' \
  'rust_host=aarch64-unknown-linux-gnu' \
  'elf_machine=EM_AARCH64' \
  'elf_machine_bytes_le=b700' \
  'elf_interpreter=/lib/ld-linux-aarch64.so.1' \
  'package_suffix=aarch64.pkg.tar.zst' \
  'evidence_namespace=phase-a-aarch64-dec29fa' \
  'output_layout=legacy-commit' \
  'build_environment=native-host-nonhermetic' \
  'cli_needed=ld-linux-aarch64.so.1,libc.so.6,libgcc_s.so.1,libm.so.6' \
  'consent_needed=libc.so.6,libgcc_s.so.1,libm.so.6,libwayland-client.so.0' \
  'needed_evidence=native-aarch64-package-regression')"
readonly AARCH64_EXPECTED
X86_64_EXPECTED="$(printf '%s\n' \
  'profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'profile_repository_path=packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile' \
  'profile_sha256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d' \
  'target_kind=physical-bare-metal' \
  'architecture=x86_64' \
  'rust_host=x86_64-unknown-linux-gnu' \
  'elf_machine=EM_X86_64' \
  'elf_machine_bytes_le=3e00' \
  'elf_interpreter=/lib64/ld-linux-x86-64.so.2' \
  'package_suffix=x86_64.pkg.tar.zst' \
  'evidence_namespace=physical-x86_64-official-omarchy-4.0.2' \
  'output_layout=namespaced-commit' \
  'build_environment=architecture-matched-host-nonhermetic' \
  'cli_needed=unconfirmed' \
  'consent_needed=unconfirmed' \
  'needed_evidence=unconfirmed-architecture-matched-x86_64-package-required')"
readonly X86_64_EXPECTED

[[ "$("${RESOLVER}")" == "${AARCH64_EXPECTED}" ]] || {
  printf '%s\n' 'legacy default no longer selects the exact AArch64 mapping' >&2
  exit 1
}
[[ "$("${RESOLVER}" "${AARCH64_PROFILE}")" == "${AARCH64_EXPECTED}" ]] || {
  printf '%s\n' 'explicit AArch64 mapping differs from its compatibility default' >&2
  exit 1
}
[[ "$("${RESOLVER}" "${X86_64_PROFILE}")" == "${X86_64_EXPECTED}" ]] || {
  printf '%s\n' 'explicit x86_64 mapping differs from its frozen tuple' >&2
  exit 1
}

while IFS='=' read -r key value; do
  [[ "$("${RESOLVER}" --field "${key}" "${AARCH64_PROFILE}")" == "${value}" ]] || {
    printf 'AArch64 field lookup mismatch: %s\n' "${key}" >&2
    exit 1
  }
done <<<"${AARCH64_EXPECTED}"
while IFS='=' read -r key value; do
  [[ "$("${RESOLVER}" --field "${key}" "${X86_64_PROFILE}")" == "${value}" ]] || {
    printf 'x86_64 field lookup mismatch: %s\n' "${key}" >&2
    exit 1
  }
done <<<"${X86_64_EXPECTED}"

cp -- "${X86_64_PROFILE}" "${TEMPORARY_ROOT}/copied-profile"
assert_refused copied-profile \
  'profile is not one of the two canonical package targets' \
  "${TEMPORARY_ROOT}/copied-profile"
ln -s -- "${X86_64_PROFILE}" "${TEMPORARY_ROOT}/profile-link"
assert_refused symlink 'profile must be one existing regular non-symlink file' \
  "${TEMPORARY_ROOT}/profile-link"
printf '%s\n' 'format=unknown' >"${TEMPORARY_ROOT}/unknown-profile"
assert_refused unknown-profile \
  'profile is not one of the two canonical package targets' \
  "${TEMPORARY_ROOT}/unknown-profile"
assert_refused unknown-field \
  'requested field is not part of the closed target mapping' \
  --field arbitrary "${AARCH64_PROFILE}"

set +e
USAGE_OUTPUT="$("${RESOLVER}" --field 2>&1)"
USAGE_STATUS="$?"
set -e
[[ "${USAGE_STATUS}" -eq 2 && "${USAGE_OUTPUT}" == usage:* ]] || {
  printf 'target resolver usage refusal mismatch: status=%s output=%q\n' \
    "${USAGE_STATUS}" "${USAGE_OUTPUT}" >&2
  exit 1
}

[[ "$(grep -Fc 'readonly PROFILE_ID=' "${RESOLVER}")" -eq 2 ]] || {
  printf '%s\n' 'target resolver does not contain exactly two profile mappings' >&2
  exit 1
}
if grep -Eq '^[[:space:]]*(source|eval)[[:space:]]' "${RESOLVER}"; then
  printf '%s\n' 'target resolver executes source or eval' >&2
  exit 1
fi

printf '%s\n' \
  'Arch package target resolver preserved two closed profile-bound mappings'
