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
  printf 'usage: %s ABSOLUTE_A_QUO_BARE_GIT_DIRECTORY ABSOLUTE_OUTPUT_ROOT\n' \
    "$0" >&2
  exit 2
fi
readonly SOURCE_GIT_DIRECTORY="$1"
readonly OUTPUT_ROOT="$2"
for path in "${SOURCE_GIT_DIRECTORY}" "${OUTPUT_ROOT}"; do
  if [[ "${path}" != /* || "${path}" == / ]]; then
    printf 'joined-fixture roots must be absolute non-root paths: %s\n' \
      "${path}" >&2
    exit 1
  fi
done
if [[ -L "${SOURCE_GIT_DIRECTORY}" || ! -d "${SOURCE_GIT_DIRECTORY}" ]]; then
  printf 'source Git directory must be a non-symlink directory: %s\n' \
    "${SOURCE_GIT_DIRECTORY}" >&2
  exit 1
fi

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
cd -- "${REPOSITORY_ROOT}"

for required_tool in cargo git jq sha256sum; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required joined-fixture build tool is unavailable: %s\n' \
      "${required_tool}" >&2
    exit 1
  fi
done
GIT_PROGRAM="$(command -v git)"
readonly GIT_PROGRAM
if [[ "${GIT_PROGRAM}" != /* || -L "${GIT_PROGRAM}" || \
  ! -f "${GIT_PROGRAM}" ]]; then
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
  printf '%s\n' 'refusing joined-fixture build from a shallow A Quo repository' >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
  printf '%s\n' 'refusing joined-fixture build from a dirty A Quo source tree' >&2
  exit 1
fi

readonly PROFILE_ID='a-quo-omarchy4-aarch64-dec29fa-v2'
readonly PROFILE_ARCHITECTURE='aarch64'
readonly EVIDENCE_NAMESPACE='aarch64-reference-joined-lifecycle-fixtures-v1'
readonly PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/${PROFILE_ID}.profile"
readonly EXPECTED_PROFILE_SHA256='3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6'
readonly REGISTRY="${REPOSITORY_ROOT}/fixtures/omarchy/joined-lifecycle-v1/sources.json"
readonly EXPECTED_REGISTRY_SHA256='88a5ed29e6cb33fe372eba0621789feae543efd79718cd0ee2806edae19e2fbf'
readonly SOURCE_REPOSITORY='https://github.com/SurreptitiousFabric/a-quo'
readonly SOURCE_COMMIT='fbeb6257b0ec96b462d4d41073e798532cdf3e7e'
readonly V1_FIXTURE='joined-lifecycle-1-0-0'
readonly V2_FIXTURE='joined-lifecycle-2-0-0'
readonly V1_SOURCE_SUBDIRECTORY='fixtures/omarchy/joined-lifecycle-v1/v1'
readonly V2_SOURCE_SUBDIRECTORY='fixtures/omarchy/joined-lifecycle-v1/v2'
readonly V1_SOURCE_TREE='8672d1283d23be50affecbd79f4a94f49f51c4d4'
readonly V2_SOURCE_TREE='70d9948522bf458b70bf2b053958661814fbfb82'

if [[ -L "${PROFILE}" || ! -f "${PROFILE}" || \
  "$(sha256sum "${PROFILE}" | cut -d ' ' -f 1)" != \
    "${EXPECTED_PROFILE_SHA256}" ]]; then
  printf '%s\n' 'joined-fixture target profile differs from the reviewed pin' >&2
  exit 1
fi
if [[ -L "${REGISTRY}" || ! -f "${REGISTRY}" || \
  "$(sha256sum "${REGISTRY}" | cut -d ' ' -f 1)" != \
    "${EXPECTED_REGISTRY_SHA256}" ]]; then
  printf '%s\n' 'joined-fixture registry differs from the reviewed pin' >&2
  exit 1
fi
if [[ "$(grep -Fxc "profile_id=${PROFILE_ID}" "${PROFILE}")" -ne 1 || \
  "$(grep -Fxc "architecture=${PROFILE_ARCHITECTURE}" "${PROFILE}")" -ne 1 ]]; then
  printf '%s\n' 'joined-fixture profile identity or architecture is malformed' >&2
  exit 1
fi

if [[ "$("${GIT_PROGRAM}" --git-dir="${SOURCE_GIT_DIRECTORY}" \
  rev-parse --is-bare-repository)" != true ]]; then
  printf '%s\n' 'joined-fixture source Git directory must be bare' >&2
  exit 1
fi

mkdir -p -- "${OUTPUT_ROOT}"
if [[ -L "${OUTPUT_ROOT}" || ! -d "${OUTPUT_ROOT}" ]]; then
  printf 'output root must be a non-symlink directory: %s\n' \
    "${OUTPUT_ROOT}" >&2
  exit 1
fi
readonly NAMESPACED_OUTPUT="${OUTPUT_ROOT}/${EVIDENCE_NAMESPACE}"
mkdir -p -- "${NAMESPACED_OUTPUT}"
if [[ -L "${NAMESPACED_OUTPUT}" || ! -d "${NAMESPACED_OUTPUT}" ]]; then
  printf 'joined-fixture namespace must be a non-symlink directory: %s\n' \
    "${NAMESPACED_OUTPUT}" >&2
  exit 1
fi
readonly FINAL_OUTPUT="${NAMESPACED_OUTPUT}/${BUILDER_COMMIT}"
if [[ -e "${FINAL_OUTPUT}" || -L "${FINAL_OUTPUT}" ]]; then
  printf 'refusing to replace existing joined-fixture bundle: %s\n' \
    "${FINAL_OUTPUT}" >&2
  exit 1
fi

STAGING_OUTPUT="$(mktemp -d "${NAMESPACED_OUTPUT}/.${BUILDER_COMMIT}.XXXXXX")"
readonly STAGING_OUTPUT
CHECKSUM_TEMPORARY="$(mktemp "${NAMESPACED_OUTPUT}/.a-quo-joined-checksums.XXXXXX")"
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

CARGO_NET_OFFLINE=true cargo build --quiet --locked \
  --package a-quo-omarchy-corpus
readonly BUILDER="${REPOSITORY_ROOT}/target/debug/a-quo-omarchy-corpus"
if [[ -L "${BUILDER}" || ! -x "${BUILDER}" ]]; then
  printf 'joined-fixture builder executable is unavailable: %s\n' \
    "${BUILDER}" >&2
  exit 1
fi
BUILDER_SHA256="$(sha256sum "${BUILDER}" | cut -d ' ' -f 1)"
readonly BUILDER_SHA256

mapfile -t FIXTURES < <("${BUILDER}" list --registry "${REGISTRY}")
if [[ "${#FIXTURES[@]}" -ne 2 || \
  "${FIXTURES[0]}" != "${V1_FIXTURE}" || \
  "${FIXTURES[1]}" != "${V2_FIXTURE}" ]]; then
  printf '%s\n' 'joined-fixture registry does not have the exact ordered pair' >&2
  exit 1
fi

for fixture in "${FIXTURES[@]}"; do
  mapfile -t SOURCE < <(
    "${BUILDER}" source --registry "${REGISTRY}" --fixture "${fixture}"
  )
  if [[ "${#SOURCE[@]}" -ne 3 || "${SOURCE[0]}" != a-quo || \
    "${SOURCE[1]}" != "${SOURCE_REPOSITORY}" || \
    "${SOURCE[2]}" != "${SOURCE_COMMIT}" ]]; then
    printf 'builder returned unexpected source coordinates: %s\n' \
      "${fixture}" >&2
    exit 1
  fi
done

"${BUILDER}" build \
  --registry "${REGISTRY}" \
  --fixture "${V1_FIXTURE}" \
  --git-program "${GIT_PROGRAM}" \
  --git-dir "${SOURCE_GIT_DIRECTORY}" \
  --builder-commit "${BUILDER_COMMIT}" \
  --output-directory "${STAGING_OUTPUT}/v1"
"${BUILDER}" build \
  --registry "${REGISTRY}" \
  --fixture "${V2_FIXTURE}" \
  --git-program "${GIT_PROGRAM}" \
  --git-dir "${SOURCE_GIT_DIRECTORY}" \
  --builder-commit "${BUILDER_COMMIT}" \
  --output-directory "${STAGING_OUTPUT}/v2"

validate_observation() {
  local observation="$1"
  local fixture="$2"
  local subdirectory="$3"
  local tree="$4"
  local version="$5"
  jq -e \
    --arg fixture "${fixture}" \
    --arg repository "${SOURCE_REPOSITORY}" \
    --arg commit "${SOURCE_COMMIT}" \
    --arg subdirectory "${subdirectory}" \
    --arg tree "${tree}" \
    --arg builder "${BUILDER_COMMIT}" \
    --arg version "${version}" \
    'type == "object" and
     .schema == "urn:a-quo:omarchy-corpus-build-observation:v1" and
     .fixture_id == $fixture and
     .source_repository == $repository and
     .source_commit == $commit and
     .source_subdirectory == $subdirectory and
     .source_tree == $tree and
     .builder_commit == $builder and
     .plugin_id == "aquo.test.joined-lifecycle" and
     .plugin_version == $version and
     .entries == 3 and .files == 3 and .directories == 0 and
     .executable_files == [] and
     .package_signature == "not_produced" and
     .behavioral_analysis == "not_performed" and
     .safety_evaluation == "not_performed" and
     .package_publication == "not_performed" and
     .publication_permission_record == null' \
    "${observation}" >/dev/null
}

validate_observation \
  "${STAGING_OUTPUT}/v1/observation.json" \
  "${V1_FIXTURE}" "${V1_SOURCE_SUBDIRECTORY}" "${V1_SOURCE_TREE}" '1.0.0'
validate_observation \
  "${STAGING_OUTPUT}/v2/observation.json" \
  "${V2_FIXTURE}" "${V2_SOURCE_SUBDIRECTORY}" "${V2_SOURCE_TREE}" '2.0.0'

V1_PACKAGE_SHA256="$(sha256sum "${STAGING_OUTPUT}/v1/package.tar.zst" | cut -d ' ' -f 1)"
V2_PACKAGE_SHA256="$(sha256sum "${STAGING_OUTPUT}/v2/package.tar.zst" | cut -d ' ' -f 1)"
V1_OBSERVATION_SHA256="$(sha256sum "${STAGING_OUTPUT}/v1/observation.json" | cut -d ' ' -f 1)"
V2_OBSERVATION_SHA256="$(sha256sum "${STAGING_OUTPUT}/v2/observation.json" | cut -d ' ' -f 1)"
readonly V1_PACKAGE_SHA256 V2_PACKAGE_SHA256
readonly V1_OBSERVATION_SHA256 V2_OBSERVATION_SHA256
if [[ "${V1_PACKAGE_SHA256}" == "${V2_PACKAGE_SHA256}" ]]; then
  printf '%s\n' 'joined lifecycle fixture versions produced identical packages' >&2
  exit 1
fi
if [[ "$(jq -r .package_sha256 "${STAGING_OUTPUT}/v1/observation.json")" != \
    "${V1_PACKAGE_SHA256}" || \
  "$(jq -r .package_sha256 "${STAGING_OUTPUT}/v2/observation.json")" != \
    "${V2_PACKAGE_SHA256}" ]]; then
  printf '%s\n' 'joined-fixture observation/package digest mismatch' >&2
  exit 1
fi

readonly BUNDLE_RECEIPT="${STAGING_OUTPUT}/bundle.receipt"
printf '%s\n' \
  'schema=a-quo-joined-lifecycle-fixture-bundle-v1' \
  "profile_id=${PROFILE_ID}" \
  "profile_sha256=${EXPECTED_PROFILE_SHA256}" \
  "architecture=${PROFILE_ARCHITECTURE}" \
  "evidence_namespace=${EVIDENCE_NAMESPACE}" \
  "builder_commit=${BUILDER_COMMIT}" \
  "builder_sha256=${BUILDER_SHA256}" \
  "registry_sha256=${EXPECTED_REGISTRY_SHA256}" \
  "source_repository=${SOURCE_REPOSITORY}" \
  "source_commit=${SOURCE_COMMIT}" \
  'fixture_count=2' \
  "v1_fixture_id=${V1_FIXTURE}" \
  "v1_source_subdirectory=${V1_SOURCE_SUBDIRECTORY}" \
  "v1_source_tree=${V1_SOURCE_TREE}" \
  "v1_package_sha256=${V1_PACKAGE_SHA256}" \
  "v1_observation_sha256=${V1_OBSERVATION_SHA256}" \
  "v2_fixture_id=${V2_FIXTURE}" \
  "v2_source_subdirectory=${V2_SOURCE_SUBDIRECTORY}" \
  "v2_source_tree=${V2_SOURCE_TREE}" \
  "v2_package_sha256=${V2_PACKAGE_SHA256}" \
  "v2_observation_sha256=${V2_OBSERVATION_SHA256}" \
  'package_signatures=not_produced' \
  'behavioral_analysis=not_performed' \
  'safety_evaluation=not_performed' \
  'package_publication=not_performed' \
  'omarchy_manifest_validation=not_performed_by_bundle_builder' \
  'input_class_10_closed=false' \
  'aarch64_evaluation_gate_satisfied=false' \
  'real_package_lifecycle_executed=false' \
  'physical_target_evidence=false' \
  'armed_evaluator_authorized=false' >"${BUNDLE_RECEIPT}"

(
  cd -- "${STAGING_OUTPUT}"
  find . -type f -print0 | sort -z | xargs -0 sha256sum \
    >"${CHECKSUM_TEMPORARY}"
  mv -- "${CHECKSUM_TEMPORARY}" SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)

if [[ "$(find "${STAGING_OUTPUT}" -type f -printf '%P\n' | sort)" != \
  $'SHA256SUMS\nbundle.receipt\nv1/observation.json\nv1/package.tar.zst\nv2/observation.json\nv2/package.tar.zst' ]]; then
  printf '%s\n' 'joined-fixture bundle does not have the closed six-file inventory' >&2
  exit 1
fi

mv --no-clobber --no-target-directory -- "${STAGING_OUTPUT}" "${FINAL_OUTPUT}"
if [[ -e "${STAGING_OUTPUT}" || ! -d "${FINAL_OUTPUT}" ]]; then
  printf 'atomic joined-fixture publication lost a no-replace race: %s\n' \
    "${FINAL_OUTPUT}" >&2
  exit 1
fi
trap - EXIT
printf 'unsigned, non-published joined fixture bundle written to: %s\n' \
  "${FINAL_OUTPUT}"
