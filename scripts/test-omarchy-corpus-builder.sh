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

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
cd -- "${REPOSITORY_ROOT}"

for required_tool in cargo git sha256sum tar zstd; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required corpus test tool is unavailable: %s\n' "${required_tool}" >&2
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

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-omarchy-corpus.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

readonly SOURCE_REPOSITORY="${TEMPORARY_ROOT}/source"
readonly BARE_REPOSITORY="${TEMPORARY_ROOT}/source.git"
readonly REGISTRY="${TEMPORARY_ROOT}/sources.json"
readonly OUTPUT_ROOT="${TEMPORARY_ROOT}/output"
mkdir -m 0755 -- "${SOURCE_REPOSITORY}" "${OUTPUT_ROOT}"

git -C "${SOURCE_REPOSITORY}" init --quiet --object-format=sha1
git -C "${SOURCE_REPOSITORY}" config user.name 'A Quo corpus test'
git -C "${SOURCE_REPOSITORY}" config user.email 'corpus-test@a-quo.invalid'
mkdir -m 0755 -- "${SOURCE_REPOSITORY}/bin"
printf '%s\n' 'MIT License' 'Synthetic offline corpus fixture.' \
  >"${SOURCE_REPOSITORY}/LICENSE"
printf '%s\n' \
  '{"schemaVersion":1,"id":"test.synthetic.plugin","version":"1.2.3"}' \
  >"${SOURCE_REPOSITORY}/manifest.json"
printf '%s\n' '#!/usr/bin/env sh' 'exit 0' >"${SOURCE_REPOSITORY}/bin/run"
chmod 0755 -- "${SOURCE_REPOSITORY}/bin/run"
printf '%s\n' 'must survive export-ignore' >"${SOURCE_REPOSITORY}/secret.txt"
printf '%s\n' 'secret.txt export-ignore' >"${SOURCE_REPOSITORY}/.gitattributes"
git -C "${SOURCE_REPOSITORY}" add -- .
GIT_AUTHOR_DATE='@1700000000 +0000' \
GIT_COMMITTER_DATE='@1700000000 +0000' \
  git -C "${SOURCE_REPOSITORY}" commit --quiet --message 'synthetic corpus source'

git init --bare --quiet --object-format=sha1 "${BARE_REPOSITORY}"
git -C "${SOURCE_REPOSITORY}" push --quiet \
  "${BARE_REPOSITORY}" HEAD:refs/heads/main

SOURCE_COMMIT="$(git -C "${SOURCE_REPOSITORY}" rev-parse --verify HEAD)"
SOURCE_TREE="$(git -C "${SOURCE_REPOSITORY}" rev-parse --verify 'HEAD^{tree}')"
SOURCE_COMMIT_TIME="$(git -C "${SOURCE_REPOSITORY}" show -s --format=%ct HEAD)"
MANIFEST_SHA256="$(sha256sum "${SOURCE_REPOSITORY}/manifest.json" | cut -d ' ' -f 1)"
LICENSE_SHA256="$(sha256sum "${SOURCE_REPOSITORY}/LICENSE" | cut -d ' ' -f 1)"
readonly SOURCE_COMMIT SOURCE_TREE SOURCE_COMMIT_TIME MANIFEST_SHA256 LICENSE_SHA256

cat >"${REGISTRY}" <<EOF
{
  "schema": "urn:a-quo:omarchy-corpus-sources:v1",
  "sources": [
    {
      "fixture_id": "synthetic-1-2-3",
      "repository_id": "synthetic-plugin",
      "repository_url": "https://github.com/example/synthetic-plugin",
      "source_commit": "${SOURCE_COMMIT}",
      "source_tree": "${SOURCE_TREE}",
      "source_commit_time": ${SOURCE_COMMIT_TIME},
      "manifest": {
        "path": "manifest.json",
        "sha256": "${MANIFEST_SHA256}",
        "plugin_id": "test.synthetic.plugin",
        "plugin_version": "1.2.3"
      },
      "license": {
        "path": "LICENSE",
        "sha256": "${LICENSE_SHA256}",
        "spdx": "MIT"
      },
      "selection_rationale": "Synthetic offline builder test; not a behavioral finding",
      "publication": {
        "package_bytes": "not_published",
        "permission_record": null
      }
    }
  ],
  "relationships": []
}
EOF
chmod 0644 -- "${REGISTRY}"

readonly BUILDER_COMMIT='ffffffffffffffffffffffffffffffffffffffff'
run_builder() {
  local output_directory="$1"
  CARGO_NET_OFFLINE=true cargo run --quiet --locked \
    --package a-quo-omarchy-corpus -- \
    build \
    --registry "${REGISTRY}" \
    --fixture synthetic-1-2-3 \
    --git-program "${GIT_PROGRAM}" \
    --git-dir "${BARE_REPOSITORY}" \
    --builder-commit "${BUILDER_COMMIT}" \
    --output-directory "${output_directory}"
}

readonly FIRST_OUTPUT="${OUTPUT_ROOT}/first"
readonly SECOND_OUTPUT="${OUTPUT_ROOT}/second"
run_builder "${FIRST_OUTPUT}"
run_builder "${SECOND_OUTPUT}"

cmp -- "${FIRST_OUTPUT}/package.tar.zst" "${SECOND_OUTPUT}/package.tar.zst"
cmp -- "${FIRST_OUTPUT}/observation.json" "${SECOND_OUTPUT}/observation.json"
if [[ "$(find "${FIRST_OUTPUT}" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)" != \
  $'observation.json\npackage.tar.zst' ]]; then
  printf '%s\n' 'fixture directory does not have the closed two-file inventory' >&2
  exit 1
fi
grep -Fq '"entries": 6,' "${FIRST_OUTPUT}/observation.json"
grep -Fq '"files": 5,' "${FIRST_OUTPUT}/observation.json"
grep -Fq '"directories": 1,' "${FIRST_OUTPUT}/observation.json"
grep -Fq '"bin/run"' "${FIRST_OUTPUT}/observation.json"
grep -Fq '"behavioral_analysis": "not_performed"' \
  "${FIRST_OUTPUT}/observation.json"
grep -Fq '"safety_evaluation": "not_performed"' \
  "${FIRST_OUTPUT}/observation.json"
grep -Fq '"package_publication": "not_performed"' \
  "${FIRST_OUTPUT}/observation.json"
grep -Eq '"git_program_sha256": "[0-9a-f]{64}"' \
  "${FIRST_OUTPUT}/observation.json"

readonly OBSERVED_TAR_PATHS="${TEMPORARY_ROOT}/observed-tar-paths"
readonly EXPECTED_TAR_PATHS="${TEMPORARY_ROOT}/expected-tar-paths"
zstd --quiet --decompress --stdout "${FIRST_OUTPUT}/package.tar.zst" | \
  tar --list --file=- >"${OBSERVED_TAR_PATHS}"
printf '%s\n' \
  .gitattributes \
  LICENSE \
  bin/ \
  bin/run \
  manifest.json \
  secret.txt >"${EXPECTED_TAR_PATHS}"
cmp -- "${EXPECTED_TAR_PATHS}" "${OBSERVED_TAR_PATHS}"
if [[ "$(zstd --quiet --decompress --stdout "${FIRST_OUTPUT}/package.tar.zst" | \
  tar --extract --to-stdout --file=- secret.txt)" != 'must survive export-ignore' ]]; then
  printf '%s\n' 'raw-object package omitted or changed export-ignored source' >&2
  exit 1
fi

FIRST_SHA256="$(sha256sum "${FIRST_OUTPUT}/package.tar.zst" | cut -d ' ' -f 1)"
readonly FIRST_SHA256
if run_builder "${FIRST_OUTPUT}" >/dev/null 2>&1; then
  printf '%s\n' 'corpus builder replaced an existing fixture directory' >&2
  exit 1
fi
if [[ "$(sha256sum "${FIRST_OUTPUT}/package.tar.zst" | cut -d ' ' -f 1)" != \
  "${FIRST_SHA256}" ]]; then
  printf '%s\n' 'failed no-replace build changed the existing package' >&2
  exit 1
fi

ln -s -- "${FIRST_OUTPUT}" "${OUTPUT_ROOT}/linked"
if run_builder "${OUTPUT_ROOT}/linked" >/dev/null 2>&1; then
  printf '%s\n' 'corpus builder accepted an existing symlink output' >&2
  exit 1
fi

mkdir -p -- "${BARE_REPOSITORY}/objects/info"
printf '%s\n' '/untrusted/alternate/object/store' \
  >"${BARE_REPOSITORY}/objects/info/alternates"
if run_builder "${OUTPUT_ROOT}/alternates" >/dev/null 2>&1; then
  printf '%s\n' 'corpus builder accepted a Git alternates object store' >&2
  exit 1
fi
rm -f -- "${BARE_REPOSITORY}/objects/info/alternates"

git --git-dir="${BARE_REPOSITORY}" config remote.origin.promisor true
if run_builder "${OUTPUT_ROOT}/promisor" >/dev/null 2>&1; then
  printf '%s\n' 'corpus builder accepted a promisor repository' >&2
  exit 1
fi
git --git-dir="${BARE_REPOSITORY}" config --unset remote.origin.promisor

printf '%s\n' "${SOURCE_COMMIT}" >"${BARE_REPOSITORY}/shallow"
if run_builder "${OUTPUT_ROOT}/shallow" >/dev/null 2>&1; then
  printf '%s\n' 'corpus builder accepted a shallow repository' >&2
  exit 1
fi
rm -f -- "${BARE_REPOSITORY}/shallow"

printf 'deterministic offline corpus builder test passed: sha256=%s\n' \
  "${FIRST_SHA256}"
