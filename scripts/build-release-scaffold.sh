#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
cd -- "${REPOSITORY_ROOT}"
umask 022

EXPECTED_RUST_TOOLCHAIN="$(sed -n 's/^rust = "\([^"]*\)"$/\1/p' .mise.toml | head -n 1)"
readonly EXPECTED_RUST_TOOLCHAIN
EXPECTED_CYCLONEDX_TOOL="$(sed -n 's/^"cargo:cargo-cyclonedx" = "\([^"]*\)"$/\1/p' .mise.toml | head -n 1)"
readonly EXPECTED_CYCLONEDX_TOOL
OBSERVED_RUST_TOOLCHAIN="$(rustc --version --verbose | sed -n 's/^release: //p')"
readonly OBSERVED_RUST_TOOLCHAIN
OBSERVED_CARGO_TOOL="$(cargo --version)"
readonly OBSERVED_CARGO_TOOL
OBSERVED_CARGO_RELEASE="${OBSERVED_CARGO_TOOL#cargo }"
OBSERVED_CARGO_RELEASE="${OBSERVED_CARGO_RELEASE%% *}"
readonly OBSERVED_CARGO_RELEASE
OBSERVED_CYCLONEDX_OUTPUT="$(cargo cyclonedx --version)"
readonly OBSERVED_CYCLONEDX_OUTPUT
OBSERVED_CYCLONEDX_TOOL="${OBSERVED_CYCLONEDX_OUTPUT##* }"
readonly OBSERVED_CYCLONEDX_TOOL

if [[ -z "${EXPECTED_RUST_TOOLCHAIN}" || "${OBSERVED_RUST_TOOLCHAIN}" != "${EXPECTED_RUST_TOOLCHAIN}" ]]; then
  printf 'rustc release does not match .mise.toml: expected=%s observed=%s\n' \
    "${EXPECTED_RUST_TOOLCHAIN:-missing}" "${OBSERVED_RUST_TOOLCHAIN:-missing}" >&2
  exit 1
fi
if [[ -z "${EXPECTED_CYCLONEDX_TOOL}" || "${OBSERVED_CYCLONEDX_TOOL}" != "${EXPECTED_CYCLONEDX_TOOL}" ]]; then
  printf 'cargo-cyclonedx does not match .mise.toml: expected=%s observed=%s\n' \
    "${EXPECTED_CYCLONEDX_TOOL:-missing}" "${OBSERVED_CYCLONEDX_TOOL:-missing}" >&2
  exit 1
fi
if [[ "${OBSERVED_CARGO_RELEASE}" != "${EXPECTED_RUST_TOOLCHAIN}" ]]; then
  printf 'cargo release does not match pinned Rust toolchain: expected=%s observed=%s\n' \
    "${EXPECTED_RUST_TOOLCHAIN}" "${OBSERVED_CARGO_RELEASE:-missing}" >&2
  exit 1
fi

RELEASE_TARGET="${A_QUO_RELEASE_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
readonly RELEASE_TARGET
readonly OUTPUT_ROOT="${A_QUO_RELEASE_OUTPUT_DIRECTORY:-${REPOSITORY_ROOT}/target/release-scaffold}"
readonly ALLOW_DIRTY="${A_QUO_RELEASE_ALLOW_DIRTY:-0}"

case "${RELEASE_TARGET}" in
  aarch64-unknown-linux-gnu)
    readonly EXPECTED_ELF_MACHINE=b700
    ;;
  x86_64-unknown-linux-gnu)
    readonly EXPECTED_ELF_MACHINE=3e00
    ;;
  *)
    printf 'unsupported release-scaffold target: %s\n' "${RELEASE_TARGET}" >&2
    exit 1
    ;;
esac

if [[ "${OUTPUT_ROOT}" != /* ]]; then
  printf '%s\n' 'A_QUO_RELEASE_OUTPUT_DIRECTORY must be absolute when set' >&2
  exit 1
fi

SOURCE_COMMIT="$(git rev-parse --verify HEAD)"
readonly SOURCE_COMMIT
SOURCE_DATE_EPOCH_VALUE="$(git show -s --format=%ct HEAD)"
readonly SOURCE_DATE_EPOCH_VALUE
SOURCE_VERSION="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1)"
readonly SOURCE_VERSION
MISE_CONFIG_SHA256="$(sha256sum .mise.toml | cut -d ' ' -f 1)"
readonly MISE_CONFIG_SHA256
CARGO_LOCK_SHA256="$(sha256sum Cargo.lock | cut -d ' ' -f 1)"
readonly CARGO_LOCK_SHA256

if [[ ! "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'source commit is not a full lowercase Git object ID' >&2
  exit 1
fi
if [[ ! "${SOURCE_DATE_EPOCH_VALUE}" =~ ^[0-9]+$ ]]; then
  printf '%s\n' 'source commit time is not a nonnegative Unix timestamp' >&2
  exit 1
fi
if [[ ! "${SOURCE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  printf '%s\n' 'workspace version is not a supported semantic version' >&2
  exit 1
fi

SOURCE_STATUS="$(git status --porcelain=v1 --untracked-files=normal)"
readonly SOURCE_STATUS
if [[ -n "${SOURCE_STATUS}" ]]; then
  readonly SOURCE_DIRTY=true
else
  readonly SOURCE_DIRTY=false
fi
if [[ "${SOURCE_DIRTY}" == true && "${ALLOW_DIRTY}" != 1 ]]; then
  printf '%s\n' \
    'refusing release scaffold from a dirty tree; set A_QUO_RELEASE_ALLOW_DIRTY=1 only for development validation' >&2
  exit 1
fi
if [[ "${SOURCE_DIRTY}" == true ]]; then
  readonly DEVELOPMENT_SUFFIX=-DIRTY-NONPUBLISHABLE
else
  readonly DEVELOPMENT_SUFFIX=""
fi

export LC_ALL=C
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH_VALUE}"
export TZ=UTC
export CARGO_NET_OFFLINE=true
RELEASE_TARGET_ENV_KEY="${RELEASE_TARGET^^}"
RELEASE_TARGET_ENV_KEY="${RELEASE_TARGET_ENV_KEY//-/_}"
RELEASE_TARGET_ENV_KEY_LOWER="${RELEASE_TARGET//-/_}"
readonly RELEASE_TARGET_ENV_KEY RELEASE_TARGET_ENV_KEY_LOWER
unset AR CC CFLAGS CPPFLAGS CXX CXXFLAGS LDFLAGS RANLIB
unset RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTDOC RUSTDOCFLAGS RUSTFLAGS
unset CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTDOC
unset CARGO_BUILD_RUSTFLAGS CARGO_BUILD_RUSTDOCFLAGS
unset CARGO_BUILD_TARGET CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR
unset "AR_${RELEASE_TARGET_ENV_KEY}" "CC_${RELEASE_TARGET_ENV_KEY}"
unset "CFLAGS_${RELEASE_TARGET_ENV_KEY}" "CXX_${RELEASE_TARGET_ENV_KEY}"
unset "CXXFLAGS_${RELEASE_TARGET_ENV_KEY}" "RANLIB_${RELEASE_TARGET_ENV_KEY}"
unset "AR_${RELEASE_TARGET_ENV_KEY_LOWER}" "CC_${RELEASE_TARGET_ENV_KEY_LOWER}"
unset "CFLAGS_${RELEASE_TARGET_ENV_KEY_LOWER}" "CXX_${RELEASE_TARGET_ENV_KEY_LOWER}"
unset "CXXFLAGS_${RELEASE_TARGET_ENV_KEY_LOWER}" "RANLIB_${RELEASE_TARGET_ENV_KEY_LOWER}"
unset "CARGO_TARGET_${RELEASE_TARGET_ENV_KEY}_LINKER"
unset "CARGO_TARGET_${RELEASE_TARGET_ENV_KEY}_RUNNER"
unset "CARGO_TARGET_${RELEASE_TARGET_ENV_KEY}_RUSTFLAGS"
unset CARGO_PROFILE_RELEASE_CODEGEN_UNITS CARGO_PROFILE_RELEASE_DEBUG
unset CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS CARGO_PROFILE_RELEASE_INCREMENTAL
unset CARGO_PROFILE_RELEASE_LTO CARGO_PROFILE_RELEASE_OPT_LEVEL
unset CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS CARGO_PROFILE_RELEASE_PANIC
unset CARGO_PROFILE_RELEASE_RPATH CARGO_PROFILE_RELEASE_STRIP

readonly STAGING_NAME="a-quo-${SOURCE_VERSION}-${RELEASE_TARGET}${DEVELOPMENT_SUFFIX}"
readonly FINAL_STAGING_DIRECTORY="${OUTPUT_ROOT}/${STAGING_NAME}"

if [[ -e "${FINAL_STAGING_DIRECTORY}" ]]; then
  printf 'refusing to replace existing release scaffold: %s\n' "${FINAL_STAGING_DIRECTORY}" >&2
  exit 1
fi

mkdir -p -- "${OUTPUT_ROOT}" "${REPOSITORY_ROOT}/target"
STAGING_DIRECTORY=""
BUILD_TARGET_DIRECTORY=""
CHECKSUM_TEMPORARY=""
GENERATED_SBOM_PATHS=()

cleanup_generated_sboms() {
  if [[ "${#GENERATED_SBOM_PATHS[@]}" -gt 0 ]]; then
    rm -f -- "${GENERATED_SBOM_PATHS[@]}"
    GENERATED_SBOM_PATHS=()
  fi
}

cleanup_on_exit() {
  local status="$?"
  trap - EXIT
  if [[ -n "${CHECKSUM_TEMPORARY}" && -e "${CHECKSUM_TEMPORARY}" ]]; then
    rm -f -- "${CHECKSUM_TEMPORARY}"
  fi
  cleanup_generated_sboms
  if [[ "${status}" -ne 0 && -n "${STAGING_DIRECTORY}" && -d "${STAGING_DIRECTORY}" ]]; then
    rm -rf -- "${STAGING_DIRECTORY}"
  fi
  if [[ -n "${BUILD_TARGET_DIRECTORY}" && -d "${BUILD_TARGET_DIRECTORY}" ]]; then
    rm -rf -- "${BUILD_TARGET_DIRECTORY}"
  fi
  exit "${status}"
}
trap cleanup_on_exit EXIT

STAGING_DIRECTORY="$(mktemp -d "${OUTPUT_ROOT}/.${STAGING_NAME}.XXXXXX")"
chmod 0755 -- "${STAGING_DIRECTORY}"
BUILD_TARGET_DIRECTORY="$(mktemp -d "${REPOSITORY_ROOT}/target/.a-quo-release-build.XXXXXX")"
readonly STAGING_DIRECTORY BUILD_TARGET_DIRECTORY
readonly BUILD_DIRECTORY="${BUILD_TARGET_DIRECTORY}/${RELEASE_TARGET}/release"
readonly SBOM_DIRECTORY="${STAGING_DIRECTORY}/usr/share/a-quo/sbom"

install -d -m 0755 -- \
  "${STAGING_DIRECTORY}/usr/bin" \
  "${STAGING_DIRECTORY}/usr/lib/a-quo" \
  "${STAGING_DIRECTORY}/usr/share/a-quo" \
  "${SBOM_DIRECTORY}"

cargo build --locked --release --target "${RELEASE_TARGET}" \
  --target-dir "${BUILD_TARGET_DIRECTORY}" \
  -p a-quo-cli \
  -p a-quo-daemon \
  -p a-quo-consent

install -m 0755 -- "${BUILD_DIRECTORY}/a-quo" "${STAGING_DIRECTORY}/usr/bin/a-quo"
install -m 0755 -- "${BUILD_DIRECTORY}/a-quo-daemon" "${STAGING_DIRECTORY}/usr/bin/a-quo-daemon"
install -m 0755 -- "${BUILD_DIRECTORY}/a-quo-consent" "${STAGING_DIRECTORY}/usr/lib/a-quo/a-quo-consent"

verify_elf_machine() {
  local artifact_path="$1"
  local elf_magic
  local elf_class_and_data
  local elf_machine
  elf_magic="$(od -An -tx1 -N4 -- "${artifact_path}" | tr -d ' \n')"
  elf_class_and_data="$(od -An -tx1 -N2 -j4 -- "${artifact_path}" | tr -d ' \n')"
  elf_machine="$(od -An -tx1 -N2 -j18 -- "${artifact_path}" | tr -d ' \n')"
  if [[ "${elf_magic}" != 7f454c46 || "${elf_class_and_data}" != 0201 || "${elf_machine}" != "${EXPECTED_ELF_MACHINE}" ]]; then
    printf 'staged binary is not the expected 64-bit little-endian Linux ELF: %s\n' \
      "${artifact_path}" >&2
    return 1
  fi
}

verify_elf_machine "${STAGING_DIRECTORY}/usr/bin/a-quo"
verify_elf_machine "${STAGING_DIRECTORY}/usr/bin/a-quo-daemon"
verify_elf_machine "${STAGING_DIRECTORY}/usr/lib/a-quo/a-quo-consent"

generate_workspace_sboms() {
  local filename_prefix=.a-quo-release
  local generated_path
  local manifest_path
  local manifest_count=0

  while IFS= read -r -d '' manifest_path; do
    generated_path="$(dirname -- "${manifest_path}")/${filename_prefix}.json"
    if [[ -e "${generated_path}" ]]; then
      printf 'refusing to replace existing SBOM path: %s\n' "${generated_path}" >&2
      return 1
    fi
    GENERATED_SBOM_PATHS+=("${generated_path}")
    manifest_count=$((manifest_count + 1))
  done < <(find crates -mindepth 2 -maxdepth 2 -type f -name Cargo.toml -print0)

  if [[ "${manifest_count}" -eq 0 ]]; then
    printf '%s\n' 'cannot find workspace crate manifests for SBOM generation' >&2
    return 1
  fi

  cargo cyclonedx \
    --manifest-path crates/a-quo-cli/Cargo.toml \
    --format json \
    --all \
    --target "${RELEASE_TARGET}" \
    --license-strict \
    --spec-version 1.5 \
    --override-filename "${filename_prefix}"

  local sbom_mapping
  for sbom_mapping in \
    "crates/a-quo-cli/${filename_prefix}.json:${SBOM_DIRECTORY}/a-quo.cdx.json" \
    "crates/a-quo-daemon/${filename_prefix}.json:${SBOM_DIRECTORY}/a-quo-daemon.cdx.json" \
    "crates/a-quo-consent/${filename_prefix}.json:${SBOM_DIRECTORY}/a-quo-consent.cdx.json"; do
    generated_path="${sbom_mapping%%:*}"
    local output_path="${sbom_mapping#*:}"
    if [[ ! -f "${generated_path}" ]]; then
      printf 'cargo-cyclonedx did not produce required output: %s\n' "${generated_path}" >&2
      return 1
    fi
    install -m 0644 -- "${generated_path}" "${output_path}"
    rm -f -- "${generated_path}"
  done
}

generate_workspace_sboms
cleanup_generated_sboms

if [[ "$(sha256sum .mise.toml | cut -d ' ' -f 1)" != "${MISE_CONFIG_SHA256}" ]]; then
  printf '%s\n' '.mise.toml changed during the release-scaffold build' >&2
  exit 1
fi
if [[ "$(sha256sum Cargo.lock | cut -d ' ' -f 1)" != "${CARGO_LOCK_SHA256}" ]]; then
  printf '%s\n' 'Cargo.lock changed during the release-scaffold build' >&2
  exit 1
fi
if [[ "${SOURCE_DIRTY}" == false && -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
  printf '%s\n' 'source tree changed during the release-scaffold build' >&2
  exit 1
fi

cat >"${STAGING_DIRECTORY}/usr/share/a-quo/BUILD-METADATA.txt" <<EOF
format=a-quo-release-build-metadata-v1
project_version=${SOURCE_VERSION}
source_commit=${SOURCE_COMMIT}
source_date_epoch=${SOURCE_DATE_EPOCH_VALUE}
source_dirty=${SOURCE_DIRTY}
target_triple=${RELEASE_TARGET}
rust_toolchain=${OBSERVED_RUST_TOOLCHAIN}
cargo_tool=${OBSERVED_CARGO_TOOL}
cargo_locked=true
artifact_scope=three_uninstalled_linux_binaries
build_environment=targeted_mise_non_hermetic
mise_config_sha256=${MISE_CONFIG_SHA256}
cargo_lock_sha256=${CARGO_LOCK_SHA256}
build_command=cargo build --locked --release --target ${RELEASE_TARGET} --target-dir FRESH_DIRECTORY -p a-quo-cli -p a-quo-daemon -p a-quo-consent
ambient_compiler_and_rust_environment=common_overrides_cleared
ambient_cargo_configuration=not_isolated
cyclonedx_tool=${OBSERVED_CYCLONEDX_TOOL}
cyclonedx_specification=1.5
sbom_scope=rust_crate_dependency_graphs_for_shipped_binaries
sbom_native_packages=not_inventoried
sbom_packaged_files=not_inventoried
sbom_license_review=required
native_package=not_produced
reproducibility_comparison=not_performed
sigstore_bundle=not_produced
provenance_attestation=not_produced
publication=not_performed
EOF
chmod 0644 -- "${STAGING_DIRECTORY}/usr/share/a-quo/BUILD-METADATA.txt"

CHECKSUM_TEMPORARY="$(mktemp "${OUTPUT_ROOT}/.a-quo-sha256sums.XXXXXX")"
(
  cd -- "${STAGING_DIRECTORY}"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum
) >"${CHECKSUM_TEMPORARY}"
chmod 0644 -- "${CHECKSUM_TEMPORARY}"
mv -- "${CHECKSUM_TEMPORARY}" "${STAGING_DIRECTORY}/SHA256SUMS"
CHECKSUM_TEMPORARY=""
(
  cd -- "${STAGING_DIRECTORY}"
  sha256sum --check --strict SHA256SUMS
)

rm -rf -- "${BUILD_TARGET_DIRECTORY}"
mv --no-clobber --no-target-directory -- \
  "${STAGING_DIRECTORY}" "${FINAL_STAGING_DIRECTORY}"
if [[ -d "${STAGING_DIRECTORY}" ]]; then
  printf 'refusing release-scaffold destination created during build: %s\n' \
    "${FINAL_STAGING_DIRECTORY}" >&2
  exit 1
fi
trap - EXIT
printf 'release scaffold written without publication: %s\n' "${FINAL_STAGING_DIRECTORY}"
