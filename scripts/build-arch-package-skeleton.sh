#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export GIT_NO_REPLACE_OBJECTS=1

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

observe_unconfirmed_needed=false
if [[ "${1:-}" == --observe-unconfirmed-needed ]]; then
  observe_unconfirmed_needed=true
  shift
fi
readonly observe_unconfirmed_needed
if [[ "$#" -gt 1 ]]; then
  printf 'usage: %s [--observe-unconfirmed-needed] [PROFILE]\n' "${0##*/}" >&2
  exit 2
fi
readonly TARGET_RESOLVER="${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh"
[[ -f "${TARGET_RESOLVER}" && ! -L "${TARGET_RESOLVER}" &&
  -x "${TARGET_RESOLVER}" ]] || {
  printf '%s\n' 'the committed package-target resolver is unavailable or unsafe' >&2
  exit 1
}
TARGET_PROFILE="${1:-${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile}"
readonly TARGET_PROFILE
TARGET_MAPPING="$("${TARGET_RESOLVER}" "${TARGET_PROFILE}")"
readonly TARGET_MAPPING
declare -A target=()
readonly -a TARGET_KEYS=(
  profile_id profile_repository_path profile_sha256 target_kind architecture
  rust_host elf_machine elf_machine_bytes_le elf_interpreter package_suffix
  evidence_namespace output_layout build_environment cli_needed consent_needed
  needed_evidence
)
target_index=0
while IFS='=' read -r key value; do
  [[ "${target_index}" -lt "${#TARGET_KEYS[@]}" &&
    "${key}" == "${TARGET_KEYS[${target_index}]}" && -n "${value}" &&
    "${value}" != *'='* ]] || {
    printf '%s\n' 'package-target resolver returned a malformed or reordered mapping' >&2
    exit 1
  }
  target["${key}"]="${value}"
  ((target_index += 1))
done <<<"${TARGET_MAPPING}"
[[ "${target_index}" -eq "${#TARGET_KEYS[@]}" ]] || {
  printf '%s\n' 'package-target resolver returned an incomplete mapping' >&2
  exit 1
}
readonly PROFILE_ID="${target[profile_id]}"
readonly PROFILE_REPOSITORY_PATH="${target[profile_repository_path]}"
readonly PROFILE_SHA256="${target[profile_sha256]}"
readonly TARGET_KIND="${target[target_kind]}"
readonly PACKAGE_ARCHITECTURE="${target[architecture]}"
readonly EXPECTED_RUST_HOST="${target[rust_host]}"
readonly EVIDENCE_NAMESPACE="${target[evidence_namespace]}"
readonly OUTPUT_LAYOUT="${target[output_layout]}"
readonly BUILD_ENVIRONMENT="${target[build_environment]}"
readonly NEEDED_EVIDENCE="${target[needed_evidence]}"
if "${observe_unconfirmed_needed}" &&
  [[ "${PACKAGE_ARCHITECTURE}|${NEEDED_EVIDENCE}" != \
    'x86_64|unconfirmed-architecture-matched-x86_64-package-required' ]]; then
  printf '%s\n' 'NEEDED observation mode is only valid for the unconfirmed x86_64 mapping' >&2
  exit 1
fi

for required_tool in git makepkg mise sha256sum; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required package build tool is unavailable: %s\n' "${required_tool}" >&2
    exit 1
  fi
done
if [[ "$(uname -m)" != "${PACKAGE_ARCHITECTURE}" ]]; then
  printf 'the package skeleton requires its mapped architecture: expected=%s observed=%s\n' \
    "${PACKAGE_ARCHITECTURE}" "$(uname -m)" >&2
  exit 1
fi

SOURCE_COMMIT="$(git rev-parse --verify HEAD)"
readonly SOURCE_COMMIT
if [[ ! "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'source commit is not a full lowercase Git object ID' >&2
  exit 1
fi
if [[ "$(git rev-parse --is-shallow-repository)" != false ]]; then
  printf '%s\n' 'refusing package skeleton build from a shallow repository' >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
  printf '%s\n' 'refusing package skeleton build from a dirty source tree' >&2
  exit 1
fi
SOURCE_COMMIT_COUNT="$(git rev-list --count "${SOURCE_COMMIT}")"
readonly SOURCE_COMMIT_COUNT
if [[ ! "${SOURCE_COMMIT_COUNT}" =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' 'source commit count is not a positive integer' >&2
  exit 1
fi

EXPECTED_RUST_VERSION="$(
  git show "${SOURCE_COMMIT}:.mise.toml" |
    sed -n 's/^rust = "\([^"]*\)"$/\1/p' |
    head -n 1
)"
readonly EXPECTED_RUST_VERSION
if [[ ! "${EXPECTED_RUST_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '%s\n' 'committed Mise Rust version is not a simple release version' >&2
  exit 1
fi
if [[ -v MISE_RUST_VERSION ]]; then
  printf '%s\n' 'refusing an externally overridden Mise Rust version' >&2
  exit 1
fi
RUST_VERBOSE="$(
  MISE_OFFLINE=1 \
    MISE_RUST_VERSION="${EXPECTED_RUST_VERSION}" \
    MISE_TRUSTED_CONFIG_PATHS="${REPOSITORY_ROOT}" \
    mise exec -- rustc -vV
)"
readonly RUST_VERBOSE
RUST_HOST="$(sed -n 's/^host: //p' <<<"${RUST_VERBOSE}")"
readonly RUST_HOST
if [[ "${RUST_HOST}" != "${EXPECTED_RUST_HOST}" ]]; then
  printf 'pinned Mise Rust host differs from the reviewed target mapping: expected=%s observed=%s\n' \
    "${EXPECTED_RUST_HOST}" "${RUST_HOST}" >&2
  exit 1
fi
OBSERVED_RUST_VERSION="$(sed -n 's/^release: //p' <<<"${RUST_VERBOSE}")"
readonly OBSERVED_RUST_VERSION
if [[ "${OBSERVED_RUST_VERSION}" != "${EXPECTED_RUST_VERSION}" ]]; then
  printf 'Mise selected the wrong Rust release: expected=%s observed=%s\n' \
    "${EXPECTED_RUST_VERSION}" "${OBSERVED_RUST_VERSION:-missing}" >&2
  exit 1
fi

WORKSPACE_VERSION="$(
  git show "${SOURCE_COMMIT}:Cargo.toml" |
    sed -n 's/^version = "\([^"]*\)"$/\1/p' |
    head -n 1
)"
readonly WORKSPACE_VERSION
if [[ ! "${WORKSPACE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '%s\n' 'workspace version is not a simple semantic version' >&2
  exit 1
fi
readonly COMMIT_ABBREVIATION="${SOURCE_COMMIT:0:12}"
readonly PACKAGE_VERSION="${WORKSPACE_VERSION}.r${SOURCE_COMMIT_COUNT}.g${COMMIT_ABBREVIATION}"

OUTPUT_ROOT="${A_QUO_ARCH_PACKAGE_OUTPUT_DIRECTORY:-${REPOSITORY_ROOT}/target/arch-package-skeleton}"
readonly OUTPUT_ROOT
case "${OUTPUT_ROOT}" in
  /*) ;;
  *)
    printf '%s\n' 'A_QUO_ARCH_PACKAGE_OUTPUT_DIRECTORY must be absolute when set' >&2
    exit 1
    ;;
esac
if [[ "${OUTPUT_ROOT}" == / ]]; then
  printf '%s\n' 'refusing filesystem root as package output directory' >&2
  exit 1
fi
case "${OUTPUT_LAYOUT}" in
  legacy-commit)
    NAMESPACE_OUTPUT_ROOT="${OUTPUT_ROOT}"
    ;;
  namespaced-commit)
    NAMESPACE_OUTPUT_ROOT="${OUTPUT_ROOT}/${EVIDENCE_NAMESPACE}"
    ;;
  *)
    printf '%s\n' 'package-target resolver selected an unknown output layout' >&2
    exit 1
    ;;
esac
readonly NAMESPACE_OUTPUT_ROOT
mkdir -p -- "${NAMESPACE_OUTPUT_ROOT}" "${REPOSITORY_ROOT}/target"
readonly FINAL_OUTPUT="${NAMESPACE_OUTPUT_ROOT}/${SOURCE_COMMIT}"
if [[ -e "${FINAL_OUTPUT}" ]]; then
  printf 'refusing to replace existing package output: %s\n' "${FINAL_OUTPUT}" >&2
  exit 1
fi

TEMPORARY_ROOT="$(mktemp -d "${REPOSITORY_ROOT}/target/.a-quo-arch-package.XXXXXX")"
readonly TEMPORARY_ROOT
STAGING_OUTPUT="$(mktemp -d "${OUTPUT_ROOT}/.${SOURCE_COMMIT}.XXXXXX")"
readonly STAGING_OUTPUT
cleanup() {
  local status="$?"
  trap - EXIT
  rm -rf -- "${TEMPORARY_ROOT}"
  if [[ "${status}" -ne 0 ]]; then
    rm -rf -- "${STAGING_OUTPUT}"
  fi
  exit "${status}"
}
trap cleanup EXIT

readonly BUILD_CONTEXT="${TEMPORARY_ROOT}/context"
readonly PACKAGE_DESTINATION="${TEMPORARY_ROOT}/packages"
readonly MAKEPKG_BUILD_DIRECTORY="${TEMPORARY_ROOT}/makepkg-build"
readonly SOURCE_PACKAGE_DESTINATION="${TEMPORARY_ROOT}/source-packages"
mkdir -m 0755 -- \
  "${BUILD_CONTEXT}" \
  "${PACKAGE_DESTINATION}" \
  "${MAKEPKG_BUILD_DIRECTORY}" \
  "${SOURCE_PACKAGE_DESTINATION}"
readonly SOURCE_ARCHIVE_NAME="a-quo-${SOURCE_COMMIT}.tar"
readonly SOURCE_ARCHIVE="${BUILD_CONTEXT}/${SOURCE_ARCHIVE_NAME}"
git archive --format=tar --prefix="a-quo-${SOURCE_COMMIT}/" \
  --output="${SOURCE_ARCHIVE}" "${SOURCE_COMMIT}"
SOURCE_SHA256="$(sha256sum "${SOURCE_ARCHIVE}" | cut -d ' ' -f 1)"
readonly SOURCE_SHA256

git show "${SOURCE_COMMIT}:packaging/arch/PKGBUILD.in" | sed \
  -e "s/@PACKAGE_VERSION@/${PACKAGE_VERSION}/g" \
  -e "s/@PACKAGE_ARCHITECTURE@/${PACKAGE_ARCHITECTURE}/g" \
  -e "s/@PROFILE_ID@/${PROFILE_ID}/g" \
  -e "s/@EVIDENCE_NAMESPACE@/${EVIDENCE_NAMESPACE}/g" \
  -e "s/@RUST_VERSION@/${EXPECTED_RUST_VERSION}/g" \
  -e "s/@SOURCE_COMMIT@/${SOURCE_COMMIT}/g" \
  -e "s/@SOURCE_SHA256@/${SOURCE_SHA256}/g" \
  >"${BUILD_CONTEXT}/PKGBUILD"
if grep -Eq '@(PACKAGE_VERSION|PACKAGE_ARCHITECTURE|PROFILE_ID|EVIDENCE_NAMESPACE|RUST_VERSION|SOURCE_COMMIT|SOURCE_SHA256)@' \
  "${BUILD_CONTEXT}/PKGBUILD"; then
  printf '%s\n' 'rendered PKGBUILD still contains an unresolved placeholder' >&2
  exit 1
fi

(
  cd -- "${BUILD_CONTEXT}"
  makepkg --printsrcinfo >.SRCINFO
  BUILDDIR="${MAKEPKG_BUILD_DIRECTORY}" \
    CARGO_NET_OFFLINE=true \
    PACKAGER='A Quo package skeleton <noreply@a-quo.invalid>' \
    PKGDEST="${PACKAGE_DESTINATION}" \
    PKGEXT=.pkg.tar.zst \
    SRCDEST="${BUILD_CONTEXT}" \
    SRCPKGDEST="${SOURCE_PACKAGE_DESTINATION}" \
    makepkg \
    --clean \
    --cleanbuild \
    --force \
    --nodeps \
    --noconfirm \
    --nosign
)

mapfile -d '' PACKAGE_PATHS < <(
  find "${PACKAGE_DESTINATION}" -maxdepth 1 -type f -name '*.pkg.tar.zst' -print0
)
if [[ "${#PACKAGE_PATHS[@]}" -ne 1 ]]; then
  printf 'package build produced an unexpected archive count: %s\n' \
    "${#PACKAGE_PATHS[@]}" >&2
  exit 1
fi
readonly PACKAGE_PATH="${PACKAGE_PATHS[0]}"
readonly COMMITTED_VERIFIER="${TEMPORARY_ROOT}/verify-arch-package-skeleton.sh"
git show "${SOURCE_COMMIT}:scripts/verify-arch-package-skeleton.sh" \
  >"${COMMITTED_VERIFIER}"
chmod 0500 -- "${COMMITTED_VERIFIER}"
verifier_arguments=("${PACKAGE_PATH}" "${SOURCE_COMMIT}" "${TARGET_PROFILE}")
if "${observe_unconfirmed_needed}"; then
  verifier_arguments=(--observe-unconfirmed-needed "${verifier_arguments[@]}")
fi
if "${observe_unconfirmed_needed}"; then
  set +e
  verifier_output="$(A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
    "${COMMITTED_VERIFIER}" "${verifier_arguments[@]}" 2>&1)"
  verifier_status="$?"
  set -e
  printf '%s\n' \
    'builder_observation_wrapper=a-quo-arch-package-needed-observation-builder-v1' \
    "build_host_architecture=$(uname -m)" \
    "rust_host_observed=${RUST_HOST}" \
    "rust_toolchain_expected=${EXPECTED_RUST_VERSION}" \
    "rust_toolchain_observed=${OBSERVED_RUST_VERSION}" \
    'build_host_profile_match=not-established' \
    'native_hardware_claim=not-established' \
    'observation_authority=none' \
    "${verifier_output}"
  [[ "${verifier_status}" -eq 1 && "${verifier_output}" == \
    *'needed_observation_accepted_as_policy=false'* ]] || {
    printf 'NEEDED observation did not fail closed: verifier_status=%s\n' \
      "${verifier_status}" >&2
    exit 1
  }
  exit 1
fi
A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${COMMITTED_VERIFIER}" "${verifier_arguments[@]}"

install -m 0644 -- "${PACKAGE_PATH}" "${STAGING_OUTPUT}/$(basename -- "${PACKAGE_PATH}")"
install -m 0644 -- "${SOURCE_ARCHIVE}" "${STAGING_OUTPUT}/${SOURCE_ARCHIVE_NAME}"
install -m 0644 -- "${BUILD_CONTEXT}/PKGBUILD" "${STAGING_OUTPUT}/PKGBUILD"
install -m 0644 -- "${BUILD_CONTEXT}/.SRCINFO" "${STAGING_OUTPUT}/.SRCINFO"

cat >"${STAGING_OUTPUT}/PACKAGE-SKELETON-METADATA.txt" <<EOF
format=a-quo-arch-package-skeleton-metadata-v1
profile_binding_role=package-target-policy
profile_id=${PROFILE_ID}
profile_repository_path=${PROFILE_REPOSITORY_PATH}
profile_sha256=${PROFILE_SHA256}
package_target_kind=${TARGET_KIND}
evidence_namespace=${EVIDENCE_NAMESPACE}
build_host_architecture=$(uname -m)
build_host_profile_match=not-established
native_hardware_claim=not-established
physical_target_evidence=false
project_version=${WORKSPACE_VERSION}
package_version=${PACKAGE_VERSION}-1
source_commit=${SOURCE_COMMIT}
source_commit_count=${SOURCE_COMMIT_COUNT}
source_archive=${SOURCE_ARCHIVE_NAME}
source_archive_sha256=${SOURCE_SHA256}
source_dirty=false
architecture=${PACKAGE_ARCHITECTURE}
package_format=arch-pkg-tar-zst
build_tool=makepkg
language_toolchain=pinned-mise-rust-${EXPECTED_RUST_VERSION}
rust_toolchain_expected=${EXPECTED_RUST_VERSION}
rust_toolchain_observed=${OBSERVED_RUST_VERSION}
mise_network=offline
cargo_locked=true
cargo_network=offline
service_enabled=false
service_preset=disable
provider_registry=empty
plug_and_prejudice_dependency=false
build_environment=${BUILD_ENVIRONMENT}
clean_system_test=not_performed
package_install_test=not_performed
provenance_attestation=not_produced
signature=not_produced
publication=not_performed
artifact_status=PACKAGE-SKELETON-NONPUBLISHABLE
EOF
chmod 0644 -- "${STAGING_OUTPUT}/PACKAGE-SKELETON-METADATA.txt"

(
  cd -- "${STAGING_OUTPUT}"
  find . -type f -print0 | sort -z | xargs -0 sha256sum >"${TEMPORARY_ROOT}/SHA256SUMS"
  install -m 0644 -- "${TEMPORARY_ROOT}/SHA256SUMS" SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)

if [[ "$(git rev-parse --verify HEAD)" != "${SOURCE_COMMIT}" || \
  -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
  printf '%s\n' 'source HEAD or worktree changed during the package build' >&2
  exit 1
fi

mv --no-clobber --no-target-directory -- "${STAGING_OUTPUT}" "${FINAL_OUTPUT}"
trap - EXIT
rm -rf -- "${TEMPORARY_ROOT}"
printf 'non-publishable package skeleton written to: %s\n' "${FINAL_OUTPUT}"
