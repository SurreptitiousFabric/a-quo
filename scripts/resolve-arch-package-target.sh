#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly AARCH64_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly X86_64_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly DEFAULT_PROFILE="${AARCH64_PROFILE}"

fail() {
  printf 'Arch package target refused: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--field FIELD] [PROFILE]\n' "${0##*/}" >&2
  exit 2
}

field=''
profile_path="${DEFAULT_PROFILE}"
case "$#" in
  0) ;;
  1)
    [[ "$1" != --* ]] || usage
    profile_path="$1"
    ;;
  2)
    [[ "$1" == --field && "$2" != --* ]] || usage
    field="$2"
    ;;
  3)
    [[ "$1" == --field && "$2" != --* && "$3" != --* ]] || usage
    field="$2"
    profile_path="$3"
    ;;
  *) usage ;;
esac
readonly field profile_path

for required_tool in realpath sha256sum; do
  command -v "${required_tool}" >/dev/null ||
    fail "required target-resolution tool is unavailable: ${required_tool}"
done
[[ -f "${profile_path}" && ! -L "${profile_path}" ]] ||
  fail 'profile must be one existing regular non-symlink file'
RESOLVED_PROFILE="$(realpath -e -- "${profile_path}")" ||
  fail 'profile path could not be resolved'
readonly RESOLVED_PROFILE

# This is the sole closed package-target mapping. Architecture, Rust host, ELF
# policy, package suffix, evidence namespace, and expected libraries always
# move together and cannot be supplied independently by a caller.
case "${RESOLVED_PROFILE}" in
  "${AARCH64_PROFILE}")
    readonly PROFILE_ID=a-quo-omarchy4-aarch64-dec29fa-v2
    readonly PROFILE_REPOSITORY_PATH=packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile
    readonly PROFILE_SHA256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6
    readonly TARGET_KIND=virtual-reference-target
    readonly ARCHITECTURE=aarch64
    readonly RUST_HOST=aarch64-unknown-linux-gnu
    readonly ELF_MACHINE=EM_AARCH64
    readonly ELF_MACHINE_BYTES_LE=b700
    readonly ELF_INTERPRETER=/lib/ld-linux-aarch64.so.1
    readonly PACKAGE_SUFFIX=aarch64.pkg.tar.zst
    readonly EVIDENCE_NAMESPACE=phase-a-aarch64-dec29fa
    readonly OUTPUT_LAYOUT=legacy-commit
    readonly BUILD_ENVIRONMENT=native-host-nonhermetic
    readonly CLI_NEEDED=ld-linux-aarch64.so.1,libc.so.6,libgcc_s.so.1,libm.so.6
    readonly CONSENT_NEEDED=libc.so.6,libgcc_s.so.1,libm.so.6,libwayland-client.so.0
    readonly NEEDED_EVIDENCE=native-aarch64-package-regression
    readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-evaluation-target-profile.sh"
    ;;
  "${X86_64_PROFILE}")
    readonly PROFILE_ID=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1
    readonly PROFILE_REPOSITORY_PATH=packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile
    readonly PROFILE_SHA256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d
    readonly TARGET_KIND=physical-bare-metal
    readonly ARCHITECTURE=x86_64
    readonly RUST_HOST=x86_64-unknown-linux-gnu
    readonly ELF_MACHINE=EM_X86_64
    readonly ELF_MACHINE_BYTES_LE=3e00
    readonly ELF_INTERPRETER=/lib64/ld-linux-x86-64.so.2
    readonly PACKAGE_SUFFIX=x86_64.pkg.tar.zst
    readonly EVIDENCE_NAMESPACE=physical-x86_64-official-omarchy-4.0.2
    readonly OUTPUT_LAYOUT=namespaced-commit
    readonly BUILD_ENVIRONMENT=architecture-matched-host-nonhermetic
    readonly CLI_NEEDED=unconfirmed
    readonly CONSENT_NEEDED=unconfirmed
    readonly NEEDED_EVIDENCE=unconfirmed-architecture-matched-x86_64-package-required
    readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh"
    ;;
  *) fail 'profile is not one of the two canonical package targets' ;;
esac

[[ "$(sha256sum -- "${RESOLVED_PROFILE}" | cut -d ' ' -f 1)" == \
  "${PROFILE_SHA256}" ]] || fail 'profile bytes differ from the reviewed target mapping'
[[ -f "${PROFILE_VERIFIER}" && ! -L "${PROFILE_VERIFIER}" &&
  -x "${PROFILE_VERIFIER}" ]] || fail 'profile verifier is unavailable or unsafe'
"${PROFILE_VERIFIER}" "${RESOLVED_PROFILE}" >/dev/null ||
  fail 'profile did not pass its dedicated immutable verifier'

emit_mapping() {
  printf '%s\n' \
    "profile_id=${PROFILE_ID}" \
    "profile_repository_path=${PROFILE_REPOSITORY_PATH}" \
    "profile_sha256=${PROFILE_SHA256}" \
    "target_kind=${TARGET_KIND}" \
    "architecture=${ARCHITECTURE}" \
    "rust_host=${RUST_HOST}" \
    "elf_machine=${ELF_MACHINE}" \
    "elf_machine_bytes_le=${ELF_MACHINE_BYTES_LE}" \
    "elf_interpreter=${ELF_INTERPRETER}" \
    "package_suffix=${PACKAGE_SUFFIX}" \
    "evidence_namespace=${EVIDENCE_NAMESPACE}" \
    "output_layout=${OUTPUT_LAYOUT}" \
    "build_environment=${BUILD_ENVIRONMENT}" \
    "cli_needed=${CLI_NEEDED}" \
    "consent_needed=${CONSENT_NEEDED}" \
    "needed_evidence=${NEEDED_EVIDENCE}"
}

if [[ -z "${field}" ]]; then
  emit_mapping
  exit 0
fi
case "${field}" in
  profile_id) printf '%s\n' "${PROFILE_ID}" ;;
  profile_repository_path) printf '%s\n' "${PROFILE_REPOSITORY_PATH}" ;;
  profile_sha256) printf '%s\n' "${PROFILE_SHA256}" ;;
  target_kind) printf '%s\n' "${TARGET_KIND}" ;;
  architecture) printf '%s\n' "${ARCHITECTURE}" ;;
  rust_host) printf '%s\n' "${RUST_HOST}" ;;
  elf_machine) printf '%s\n' "${ELF_MACHINE}" ;;
  elf_machine_bytes_le) printf '%s\n' "${ELF_MACHINE_BYTES_LE}" ;;
  elf_interpreter) printf '%s\n' "${ELF_INTERPRETER}" ;;
  package_suffix) printf '%s\n' "${PACKAGE_SUFFIX}" ;;
  evidence_namespace) printf '%s\n' "${EVIDENCE_NAMESPACE}" ;;
  output_layout) printf '%s\n' "${OUTPUT_LAYOUT}" ;;
  build_environment) printf '%s\n' "${BUILD_ENVIRONMENT}" ;;
  cli_needed) printf '%s\n' "${CLI_NEEDED}" ;;
  consent_needed) printf '%s\n' "${CONSENT_NEEDED}" ;;
  needed_evidence) printf '%s\n' "${NEEDED_EVIDENCE}" ;;
  *) fail 'requested field is not part of the closed target mapping' ;;
esac
