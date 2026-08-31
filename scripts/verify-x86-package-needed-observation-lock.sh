#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

fail() {
  printf 'x86_64 NEEDED observation lock refused: %s\n' "$1" >&2
  exit 1
}

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s LOCK\n' "${0##*/}" >&2
  exit 2
fi

readonly LOCK_INPUT="$1"
readonly EXPECTED_LOCK_SHA256=216ec3cd2e0698fd42390ade8394e0077ea9a915382de87ae1fe5e864966c9b0
readonly MAXIMUM_LOCK_BYTES=4096

for required_tool in chmod dd id mktemp od rm sha256sum stat tail tr wc; do
  command -v "${required_tool}" >/dev/null ||
    fail "required lock-verification tool is unavailable: ${required_tool}"
done
[[ -f "${LOCK_INPUT}" && ! -L "${LOCK_INPUT}" ]] ||
  fail 'lock must be one regular non-symlink file'

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-x86-needed-lock.XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_ROOT_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
  fail 'temporary lock-verification directory identity is unavailable'
readonly TEMPORARY_ROOT_IDENTITY
cleanup() {
  local exit_status="$?"
  local current_identity
  trap - EXIT
  case "${TEMPORARY_ROOT}" in
    "${TMPDIR:-/tmp}/a-quo-x86-needed-lock."??????) ;;
    *) fail 'unsafe temporary lock-verification cleanup target' ;;
  esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] ||
    fail 'temporary lock-verification cleanup target changed type'
  current_identity="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
    fail 'temporary lock-verification cleanup identity is unavailable'
  [[ "${current_identity}" == "${TEMPORARY_ROOT_IDENTITY}" ]] ||
    fail 'temporary lock-verification cleanup target was substituted'
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${exit_status}"
}
trap cleanup EXIT

readonly SNAPSHOT="${TEMPORARY_ROOT}/lock"
METADATA_BEFORE="$(stat -c '%d:%i:%s:%f:%Y:%Z' -- "${LOCK_INPUT}")" ||
  fail 'lock metadata is unavailable before snapshot'
readonly METADATA_BEFORE
if ! dd if="${LOCK_INPUT}" of="${SNAPSHOT}" \
  bs=$((MAXIMUM_LOCK_BYTES + 1)) count=1 \
  iflag=fullblock,nofollow,nonblock status=none; then
  fail 'lock could not be copied through the bounded no-follow reader'
fi
METADATA_AFTER="$(stat -c '%d:%i:%s:%f:%Y:%Z' -- "${LOCK_INPUT}")" ||
  fail 'lock metadata is unavailable after snapshot'
readonly METADATA_AFTER
[[ "${METADATA_BEFORE}" == "${METADATA_AFTER}" ]] ||
  fail 'lock changed while its private snapshot was created'
chmod 0400 -- "${SNAPSHOT}"
SNAPSHOT_SIZE="$(stat -c '%s' -- "${SNAPSHOT}")"
readonly SNAPSHOT_SIZE
[[ "${SNAPSHOT_SIZE}" =~ ^[1-9][0-9]*$ ]] ||
  fail 'lock snapshot has an invalid size'
(( SNAPSHOT_SIZE <= MAXIMUM_LOCK_BYTES )) ||
  fail 'lock exceeds the closed byte bound'
[[ "$(stat -c '%u:%a:%h:%F' -- "${SNAPSHOT}")" == \
  "$(id -u):400:1:regular file" ]] ||
  fail 'lock snapshot is not one private singly linked regular file'
[[ "$(tail -c 1 -- "${SNAPSHOT}" | od -An -tu1 | tr -d '[:space:]')" == 10 ]] ||
  fail 'lock must end with exactly one LF'
[[ "$(tr -cd '\11\12\40-\176' <"${SNAPSHOT}" | wc -c)" == \
  "${SNAPSHOT_SIZE}" ]] || fail 'lock contains a forbidden byte'

LOCK_SHA256="$(sha256sum -- "${SNAPSHOT}")"
LOCK_SHA256="${LOCK_SHA256%% *}"
readonly LOCK_SHA256
[[ "${LOCK_SHA256}" == "${EXPECTED_LOCK_SHA256}" ]] ||
  fail 'lock bytes differ from the reviewed observation record'

printf '%s\n' \
  'x86_64 NEEDED observation lock passed exact reviewed-byte checks' \
  'format=a-quo-x86_64-needed-observation-lock-verification-v1' \
  "lock_sha256=${LOCK_SHA256}" \
  'record_role=reviewed-static-needed-policy-source' \
  'review_scope=elf-machine-interpreter-and-dt-needed-only' \
  'observation_authority=none' \
  'observation_source_commit=cbbe29b6bc76949182777d7ec10dc73a219f7592' \
  'observation_run_id=33447883884' \
  'observation_artifact_id=9778938759' \
  'observation_artifact_zip_sha256=97e2dac4a83e8f43f540199bb3b140532159001442ece926b32c9c3d829af394' \
  'observation_package_sha256=52394e2115b0b235dcad849bb91856725e945579266628f0f74fd9e5d64fa264' \
  'architecture=x86_64' \
  'elf_machine=EM_X86_64' \
  'elf_machine_bytes_le=3e00' \
  'elf_interpreter=/lib64/ld-linux-x86-64.so.2' \
  'cli_needed=ld-linux-x86-64.so.2,libc.so.6,libgcc_s.so.1,libm.so.6' \
  'consent_needed=ld-linux-x86-64.so.2,libc.so.6,libgcc_s.so.1,libm.so.6,libwayland-client.so.0' \
  'historical_package_static_acceptance=false' \
  'historical_needed_observation_accepted_as_policy=false' \
  'native_hardware_claim=not-established' \
  'physical_target_evidence=false' \
  'package_source_to_binary_provenance_established=false' \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false'
