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

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
cd -- "${REPOSITORY_ROOT}"

for required_tool in git jq sha256sum tar zstd; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required joined-fixture contract tool is unavailable: %s\n' \
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

readonly WRAPPER="${REPOSITORY_ROOT}/scripts/build-joined-lifecycle-fixtures.sh"
readonly REGISTRY="${REPOSITORY_ROOT}/fixtures/omarchy/joined-lifecycle-v1/sources.json"
readonly EVIDENCE_NAMESPACE='aarch64-reference-joined-lifecycle-fixtures-v1'
readonly SOURCE_COMMIT='54c44f4d4e4bf316ff91af3992c47f0bc3bf9e04'
readonly EXPECTED_V1_PACKAGE_SHA256='2141fc8de82f40ac6a44b412e640846667b0cc78fd7b83280d157c24f87eaa71'
readonly EXPECTED_V2_PACKAGE_SHA256='806966a0bf27e902fc1e059c2a7004c72afcce085039c568c4ac5e17fead130a'

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-joined-fixtures.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

readonly BARE_REPOSITORY="${TEMPORARY_ROOT}/a-quo.git"
readonly FIRST_OUTPUT_ROOT="${TEMPORARY_ROOT}/first"
readonly SECOND_OUTPUT_ROOT="${TEMPORARY_ROOT}/second"
readonly MUTANT_OUTPUT_ROOT="${TEMPORARY_ROOT}/mutants"
mkdir -m 0755 -- \
  "${FIRST_OUTPUT_ROOT}" "${SECOND_OUTPUT_ROOT}" "${MUTANT_OUTPUT_ROOT}"

git clone --quiet --bare --no-local --no-tags \
  "${REPOSITORY_ROOT}" "${BARE_REPOSITORY}"
if [[ -e "${BARE_REPOSITORY}/objects/info/alternates" ]]; then
  printf '%s\n' 'contract bare repository unexpectedly uses alternates' >&2
  exit 1
fi

BUILDER_COMMIT="$(git rev-parse --verify HEAD)"
readonly BUILDER_COMMIT
readonly FIRST_BUNDLE="${FIRST_OUTPUT_ROOT}/${EVIDENCE_NAMESPACE}/${BUILDER_COMMIT}"
readonly SECOND_BUNDLE="${SECOND_OUTPUT_ROOT}/${EVIDENCE_NAMESPACE}/${BUILDER_COMMIT}"

bash "${WRAPPER}" "${BARE_REPOSITORY}" "${FIRST_OUTPUT_ROOT}" >/dev/null
bash "${WRAPPER}" "${BARE_REPOSITORY}" "${SECOND_OUTPUT_ROOT}" >/dev/null

readonly EXPECTED_INVENTORY=$'SHA256SUMS\nbundle.receipt\nv1/observation.json\nv1/package.tar.zst\nv2/observation.json\nv2/package.tar.zst'
for bundle in "${FIRST_BUNDLE}" "${SECOND_BUNDLE}"; do
  if [[ "$(find "${bundle}" -type f -printf '%P\n' | sort)" != \
    "${EXPECTED_INVENTORY}" ]]; then
    printf 'joined-fixture bundle inventory differs from the closed set: %s\n' \
      "${bundle}" >&2
    exit 1
  fi
  if [[ "$(find "${bundle}" -type l -print -quit)" != '' ]]; then
    printf 'joined-fixture bundle contains a symbolic link: %s\n' \
      "${bundle}" >&2
    exit 1
  fi
  (
    cd -- "${bundle}"
    sha256sum --check --strict SHA256SUMS >/dev/null
  )
  if [[ "$(wc -l <"${bundle}/SHA256SUMS")" -ne 5 ]]; then
    printf '%s\n' 'joined-fixture checksum inventory is not exact' >&2
    exit 1
  fi
done

for relative_path in \
  SHA256SUMS \
  bundle.receipt \
  v1/observation.json \
  v1/package.tar.zst \
  v2/observation.json \
  v2/package.tar.zst; do
  cmp -- "${FIRST_BUNDLE}/${relative_path}" "${SECOND_BUNDLE}/${relative_path}"
done

if [[ "$(sha256sum "${FIRST_BUNDLE}/v1/package.tar.zst" | cut -d ' ' -f 1)" != \
    "${EXPECTED_V1_PACKAGE_SHA256}" || \
  "$(sha256sum "${FIRST_BUNDLE}/v2/package.tar.zst" | cut -d ' ' -f 1)" != \
    "${EXPECTED_V2_PACKAGE_SHA256}" ]]; then
  printf '%s\n' 'joined-fixture package bytes differ from the reviewed pins' >&2
  exit 1
fi

readonly RECEIPT="${FIRST_BUNDLE}/bundle.receipt"
if [[ "$(wc -l <"${RECEIPT}")" -ne 31 ]]; then
  printf '%s\n' 'joined-fixture bundle receipt field count differs from 31' >&2
  exit 1
fi
for expected_line in \
  'schema=a-quo-joined-lifecycle-fixture-bundle-v1' \
  'profile_id=a-quo-omarchy4-aarch64-dec29fa-v2' \
  'profile_sha256=3c059094f820ee9ee3891e42a9f965c04a3d889b8b86904f7457175e307fc7b6' \
  'architecture=aarch64' \
  "evidence_namespace=${EVIDENCE_NAMESPACE}" \
  "builder_commit=${BUILDER_COMMIT}" \
  'registry_sha256=73037188e202b9e06f8c402e494ad0aaf9a072deeac343b4b24cd5ca00e4fda0' \
  'source_repository=https://github.com/SurreptitiousFabric/a-quo' \
  "source_commit=${SOURCE_COMMIT}" \
  'fixture_count=2' \
  'v1_fixture_id=joined-lifecycle-1-0-0' \
  'v1_source_subdirectory=fixtures/omarchy/joined-lifecycle-v1/v1' \
  'v1_source_tree=8672d1283d23be50affecbd79f4a94f49f51c4d4' \
  "v1_package_sha256=${EXPECTED_V1_PACKAGE_SHA256}" \
  'v2_fixture_id=joined-lifecycle-2-0-0' \
  'v2_source_subdirectory=fixtures/omarchy/joined-lifecycle-v1/v2' \
  'v2_source_tree=70d9948522bf458b70bf2b053958661814fbfb82' \
  "v2_package_sha256=${EXPECTED_V2_PACKAGE_SHA256}" \
  'package_signatures=not_produced' \
  'behavioral_analysis=not_performed' \
  'safety_evaluation=not_performed' \
  'package_publication=not_performed' \
  'omarchy_manifest_validation=not_performed_by_bundle_builder' \
  'input_class_10_closed=false' \
  'aarch64_evaluation_gate_satisfied=false' \
  'real_package_lifecycle_executed=false' \
  'physical_target_evidence=false' \
  'armed_evaluator_authorized=false'; do
  if [[ "$(grep -Fxc "${expected_line}" "${RECEIPT}")" -ne 1 ]]; then
    printf 'joined-fixture receipt lacks exact field: %s\n' \
      "${expected_line}" >&2
    exit 1
  fi
done
if ! grep -Eq '^builder_sha256=[0-9a-f]{64}$' "${RECEIPT}" || \
  ! grep -Eq '^v1_observation_sha256=[0-9a-f]{64}$' "${RECEIPT}" || \
  ! grep -Eq '^v2_observation_sha256=[0-9a-f]{64}$' "${RECEIPT}"; then
  printf '%s\n' 'joined-fixture receipt has malformed builder/observation digest' >&2
  exit 1
fi

validate_observation() {
  local version_name="$1"
  local fixture="$2"
  local source_subdirectory="$3"
  local source_tree="$4"
  local plugin_version="$5"
  jq -e \
    --arg fixture "${fixture}" \
    --arg source_commit "${SOURCE_COMMIT}" \
    --arg source_subdirectory "${source_subdirectory}" \
    --arg source_tree "${source_tree}" \
    --arg builder_commit "${BUILDER_COMMIT}" \
    --arg plugin_version "${plugin_version}" \
    '.fixture_id == $fixture and
     .source_commit == $source_commit and
     .source_subdirectory == $source_subdirectory and
     .source_tree == $source_tree and
     .builder_commit == $builder_commit and
     .plugin_id == "aquo.test.joined-lifecycle" and
     .plugin_version == $plugin_version and
     .entries == 3 and .files == 3 and .directories == 0 and
     .executable_files == [] and
     .package_signature == "not_produced" and
     .behavioral_analysis == "not_performed" and
     .safety_evaluation == "not_performed" and
     .package_publication == "not_performed" and
     .publication_permission_record == null' \
    "${FIRST_BUNDLE}/${version_name}/observation.json" >/dev/null
}
validate_observation \
  v1 joined-lifecycle-1-0-0 \
  fixtures/omarchy/joined-lifecycle-v1/v1 \
  8672d1283d23be50affecbd79f4a94f49f51c4d4 1.0.0
validate_observation \
  v2 joined-lifecycle-2-0-0 \
  fixtures/omarchy/joined-lifecycle-v1/v2 \
  70d9948522bf458b70bf2b053958661814fbfb82 2.0.0

for version_name in v1 v2; do
  archive="${FIRST_BUNDLE}/${version_name}/package.tar.zst"
  observed_paths="${TEMPORARY_ROOT}/${version_name}.paths"
  extract_root="${TEMPORARY_ROOT}/${version_name}.extract"
  mkdir -m 0755 -- "${extract_root}"
  zstd --quiet --decompress --stdout "${archive}" | \
    tar --list --file=- >"${observed_paths}"
  if [[ "$(cat "${observed_paths}")" != $'LICENSE\nREADME.md\nmanifest.json' ]]; then
    printf 'joined-fixture archive path inventory is unexpected: %s\n' \
      "${version_name}" >&2
    exit 1
  fi
  zstd --quiet --decompress --stdout "${archive}" | \
    tar --extract --file=- --directory="${extract_root}" --no-same-owner
  if [[ "$(find "${extract_root}" -type f -printf '%m %P\n' | sort)" != \
    $'644 LICENSE\n644 README.md\n644 manifest.json' ]]; then
    printf 'joined-fixture extracted file modes are unexpected: %s\n' \
      "${version_name}" >&2
    exit 1
  fi
done

FIRST_BUNDLE_SHA256="$(sha256sum "${FIRST_BUNDLE}/SHA256SUMS" | cut -d ' ' -f 1)"
readonly FIRST_BUNDLE_SHA256
if bash "${WRAPPER}" "${BARE_REPOSITORY}" "${FIRST_OUTPUT_ROOT}" \
  >/dev/null 2>&1; then
  printf '%s\n' 'joined-fixture wrapper replaced an existing bundle' >&2
  exit 1
fi
if [[ "$(sha256sum "${FIRST_BUNDLE}/SHA256SUMS" | cut -d ' ' -f 1)" != \
  "${FIRST_BUNDLE_SHA256}" ]]; then
  printf '%s\n' 'failed no-replace build changed the existing bundle' >&2
  exit 1
fi

readonly TRANSPLANT="${TEMPORARY_ROOT}/transplant"
cp -a -- "${FIRST_BUNDLE}" "${TRANSPLANT}"
cp -- "${TRANSPLANT}/v2/package.tar.zst" "${TRANSPLANT}/v1/package.tar.zst"
if (cd -- "${TRANSPLANT}" && \
  sha256sum --check --strict SHA256SUMS >/dev/null 2>&1); then
  printf '%s\n' 'bundle checksums accepted a transplanted package' >&2
  exit 1
fi

readonly CLAIM_FLIP="${TEMPORARY_ROOT}/claim-flip"
cp -a -- "${FIRST_BUNDLE}" "${CLAIM_FLIP}"
sed -i 's/^safety_evaluation=not_performed$/safety_evaluation=passed/' \
  "${CLAIM_FLIP}/bundle.receipt"
if (cd -- "${CLAIM_FLIP}" && \
  sha256sum --check --strict SHA256SUMS >/dev/null 2>&1); then
  printf '%s\n' 'bundle checksums accepted an escalated safety claim' >&2
  exit 1
fi

readonly BUILDER="${REPOSITORY_ROOT}/target/debug/a-quo-omarchy-corpus"
if [[ -L "${BUILDER}" || ! -x "${BUILDER}" ]]; then
  printf '%s\n' 'joined-fixture contract cannot find the built corpus tool' >&2
  exit 1
fi

reject_registry_list_mutant() {
  local name="$1"
  local filter="$2"
  local mutant="${TEMPORARY_ROOT}/${name}.json"
  jq "${filter}" "${REGISTRY}" >"${mutant}"
  if "${BUILDER}" list --registry "${mutant}" >/dev/null 2>&1; then
    printf 'joined-fixture registry accepted list mutant: %s\n' "${name}" >&2
    exit 1
  fi
}

reject_registry_build_mutant() {
  local name="$1"
  local filter="$2"
  local mutant="${TEMPORARY_ROOT}/${name}.json"
  local output="${MUTANT_OUTPUT_ROOT}/${name}"
  jq "${filter}" "${REGISTRY}" >"${mutant}"
  if "${BUILDER}" build \
    --registry "${mutant}" \
    --fixture joined-lifecycle-1-0-0 \
    --git-program "${GIT_PROGRAM}" \
    --git-dir "${BARE_REPOSITORY}" \
    --builder-commit "${BUILDER_COMMIT}" \
    --output-directory "${output}" >/dev/null 2>&1; then
    printf 'joined-fixture registry accepted build mutant: %s\n' "${name}" >&2
    exit 1
  fi
  if [[ -e "${output}" || -L "${output}" ]]; then
    printf 'failed joined-fixture mutant retained an output: %s\n' "${name}" >&2
    exit 1
  fi
}

reject_registry_list_mutant \
  source-path-traversal \
  '.sources[0].source_subdirectory = "../outside"'
reject_registry_list_mutant \
  unknown-field \
  '.sources[0].safety = "passed"'
reject_registry_build_mutant \
  missing-subdirectory \
  'del(.sources[0].source_subdirectory)'
reject_registry_build_mutant \
  swapped-subdirectory \
  '.sources[0].source_subdirectory = .sources[1].source_subdirectory'
reject_registry_build_mutant \
  transplanted-subtree \
  '(.sources[0].source_subdirectory = .sources[1].source_subdirectory) |
   (.sources[0].source_tree = .sources[1].source_tree)'
reject_registry_build_mutant \
  changed-tree \
  '.sources[0].source_tree = "0000000000000000000000000000000000000000"'

printf '%s\n' \
  'joined lifecycle fixture contract passed: deterministic unsigned inert packages; input class 10 remains open'
