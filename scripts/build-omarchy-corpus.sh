#!/usr/bin/env bash

set -euo pipefail
if [[ -v GIT_CONFIG_COUNT ]]; then
  printf '%s\n' 'refusing inherited counted Git configuration' >&2
  exit 1
fi
export LC_ALL=C
export TZ=UTC
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
umask 022

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
if [[ -v CARGO_TARGET_DIR ]]; then
  printf '%s\n' 'refusing inherited Cargo target-directory override' >&2
  exit 1
fi

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s ABSOLUTE_SOURCE_ROOT ABSOLUTE_OUTPUT_ROOT\n' "$0" >&2
  exit 2
fi
readonly SOURCE_ROOT="$1"
readonly OUTPUT_ROOT="$2"
for path in "${SOURCE_ROOT}" "${OUTPUT_ROOT}"; do
  if [[ "${path}" != /* || "${path}" == / ]]; then
    printf 'corpus roots must be absolute non-root paths: %s\n' "${path}" >&2
    exit 1
  fi
done
if [[ -L "${SOURCE_ROOT}" || ! -d "${SOURCE_ROOT}" ]]; then
  printf 'source root must be a non-symlink directory: %s\n' "${SOURCE_ROOT}" >&2
  exit 1
fi

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
cd -- "${REPOSITORY_ROOT}"

for required_tool in cargo git sha256sum; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required corpus build tool is unavailable: %s\n' "${required_tool}" >&2
    exit 1
  fi
done
GIT_PROGRAM="$(command -v git)"
readonly GIT_PROGRAM
if [[ "${GIT_PROGRAM}" != /* || -L "${GIT_PROGRAM}" || ! -f "${GIT_PROGRAM}" ]]; then
  printf 'Git program must resolve to an absolute regular non-symlink: %s\n' \
    "${GIT_PROGRAM}" >&2
  exit 1
fi

BUILDER_COMMIT="$(git rev-parse --verify HEAD)"
readonly BUILDER_COMMIT
if [[ ! "${BUILDER_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'builder commit is not a full lowercase Git object ID' >&2
  exit 1
fi
if [[ "$(git rev-parse --is-shallow-repository)" != false ]]; then
  printf '%s\n' 'refusing corpus build from a shallow A Quo repository' >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
  printf '%s\n' 'refusing corpus build from a dirty A Quo source tree' >&2
  exit 1
fi

mkdir -p -- "${OUTPUT_ROOT}"
if [[ -L "${OUTPUT_ROOT}" || ! -d "${OUTPUT_ROOT}" ]]; then
  printf 'output root must be a non-symlink directory: %s\n' "${OUTPUT_ROOT}" >&2
  exit 1
fi
readonly FINAL_OUTPUT="${OUTPUT_ROOT}/${BUILDER_COMMIT}"
if [[ -e "${FINAL_OUTPUT}" || -L "${FINAL_OUTPUT}" ]]; then
  printf 'refusing to replace existing corpus cohort: %s\n' "${FINAL_OUTPUT}" >&2
  exit 1
fi

STAGING_OUTPUT="$(mktemp -d "${OUTPUT_ROOT}/.${BUILDER_COMMIT}.XXXXXX")"
readonly STAGING_OUTPUT
CHECKSUM_TEMPORARY="$(mktemp "${OUTPUT_ROOT}/.a-quo-corpus-checksums.XXXXXX")"
readonly CHECKSUM_TEMPORARY
cleanup() {
  local status="$?"
  trap - EXIT
  rm -f -- "${CHECKSUM_TEMPORARY}"
  if [[ "${status}" -ne 0 ]]; then
    rm -rf -- "${STAGING_OUTPUT}"
  fi
  exit "${status}"
}
trap cleanup EXIT

readonly REGISTRY="${REPOSITORY_ROOT}/fixtures/omarchy/corpus-v1/sources.json"
CARGO_NET_OFFLINE=true cargo build --quiet --locked \
  --package a-quo-omarchy-corpus
readonly BUILDER="${REPOSITORY_ROOT}/target/debug/a-quo-omarchy-corpus"
if [[ -L "${BUILDER}" || ! -x "${BUILDER}" ]]; then
  printf 'corpus builder executable is unavailable: %s\n' "${BUILDER}" >&2
  exit 1
fi

mapfile -t FIXTURES < <("${BUILDER}" list --registry "${REGISTRY}")
if [[ "${#FIXTURES[@]}" -ne 6 ]]; then
  printf 'initial corpus registry must contain exactly six fixtures: observed=%s\n' \
    "${#FIXTURES[@]}" >&2
  exit 1
fi
for fixture in "${FIXTURES[@]}"; do
  mapfile -t SOURCE < <(
    "${BUILDER}" source --registry "${REGISTRY}" --fixture "${fixture}"
  )
  if [[ "${#SOURCE[@]}" -ne 3 ]]; then
    printf 'builder returned malformed source coordinates: %s\n' "${fixture}" >&2
    exit 1
  fi
  SOURCE_REPOSITORY_ID="${SOURCE[0]}"
  SOURCE_GIT_DIRECTORY="${SOURCE_ROOT}/${SOURCE_REPOSITORY_ID}.git"
  if [[ -L "${SOURCE_GIT_DIRECTORY}" || ! -d "${SOURCE_GIT_DIRECTORY}" ]]; then
    printf 'required bare source repository is unavailable: %s\n' \
      "${SOURCE_GIT_DIRECTORY}" >&2
    exit 1
  fi
  "${BUILDER}" build \
    --registry "${REGISTRY}" \
    --fixture "${fixture}" \
    --git-program "${GIT_PROGRAM}" \
    --git-dir "${SOURCE_GIT_DIRECTORY}" \
    --builder-commit "${BUILDER_COMMIT}" \
    --output-directory "${STAGING_OUTPUT}/${fixture}"
done

(
  cd -- "${STAGING_OUTPUT}"
  find . -type f -print0 | sort -z | xargs -0 sha256sum >"${CHECKSUM_TEMPORARY}"
  mv -- "${CHECKSUM_TEMPORARY}" SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)
mv --no-clobber --no-target-directory -- "${STAGING_OUTPUT}" "${FINAL_OUTPUT}"
if [[ -e "${STAGING_OUTPUT}" || ! -d "${FINAL_OUTPUT}" ]]; then
  printf 'atomic corpus cohort publication lost a no-replace race: %s\n' \
    "${FINAL_OUTPUT}" >&2
  exit 1
fi
trap - EXIT
printf 'unsigned, non-published corpus cohort written to: %s\n' "${FINAL_OUTPUT}"
