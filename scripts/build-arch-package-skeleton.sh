#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
cd -- "${REPOSITORY_ROOT}"

for required_tool in git makepkg mise sha256sum; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required package build tool is unavailable: %s\n' "${required_tool}" >&2
    exit 1
  fi
done
if [[ "$(uname -m)" != aarch64 ]]; then
  printf '%s\n' 'the Phase-A package skeleton must be built natively on aarch64' >&2
  exit 1
fi
RUST_HOST="$(mise exec -- rustc -vV | sed -n 's/^host: //p')"
readonly RUST_HOST
if [[ "${RUST_HOST}" != aarch64-unknown-linux-gnu ]]; then
  printf 'pinned Mise Rust host is not the Phase-A target: %s\n' "${RUST_HOST}" >&2
  exit 1
fi

SOURCE_COMMIT="$(git rev-parse --verify HEAD)"
readonly SOURCE_COMMIT
if [[ ! "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'source commit is not a full lowercase Git object ID' >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=normal)" ]]; then
  printf '%s\n' 'refusing package skeleton build from a dirty source tree' >&2
  exit 1
fi

WORKSPACE_VERSION="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1)"
readonly WORKSPACE_VERSION
if [[ ! "${WORKSPACE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '%s\n' 'workspace version is not a simple semantic version' >&2
  exit 1
fi
readonly COMMIT_ABBREVIATION="${SOURCE_COMMIT:0:12}"
readonly PACKAGE_VERSION="${WORKSPACE_VERSION}.r0.g${COMMIT_ABBREVIATION}"

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
mkdir -p -- "${OUTPUT_ROOT}" "${REPOSITORY_ROOT}/target"
readonly FINAL_OUTPUT="${OUTPUT_ROOT}/${SOURCE_COMMIT}"
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

sed \
  -e "s/@PACKAGE_VERSION@/${PACKAGE_VERSION}/g" \
  -e "s/@SOURCE_COMMIT@/${SOURCE_COMMIT}/g" \
  -e "s/@SOURCE_SHA256@/${SOURCE_SHA256}/g" \
  packaging/arch/PKGBUILD.in >"${BUILD_CONTEXT}/PKGBUILD"
if grep -Eq '@(PACKAGE_VERSION|SOURCE_COMMIT|SOURCE_SHA256)@' "${BUILD_CONTEXT}/PKGBUILD"; then
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
"${REPOSITORY_ROOT}/scripts/verify-arch-package-skeleton.sh" \
  "${PACKAGE_PATH}" "${SOURCE_COMMIT}"

install -m 0644 -- "${PACKAGE_PATH}" "${STAGING_OUTPUT}/$(basename -- "${PACKAGE_PATH}")"
install -m 0644 -- "${SOURCE_ARCHIVE}" "${STAGING_OUTPUT}/${SOURCE_ARCHIVE_NAME}"
install -m 0644 -- "${BUILD_CONTEXT}/PKGBUILD" "${STAGING_OUTPUT}/PKGBUILD"
install -m 0644 -- "${BUILD_CONTEXT}/.SRCINFO" "${STAGING_OUTPUT}/.SRCINFO"

cat >"${STAGING_OUTPUT}/PACKAGE-SKELETON-METADATA.txt" <<EOF
format=a-quo-arch-package-skeleton-metadata-v1
project_version=${WORKSPACE_VERSION}
package_version=${PACKAGE_VERSION}-1
source_commit=${SOURCE_COMMIT}
source_archive=${SOURCE_ARCHIVE_NAME}
source_archive_sha256=${SOURCE_SHA256}
source_dirty=false
architecture=aarch64
package_format=arch-pkg-tar-zst
build_tool=makepkg
language_toolchain=pinned-mise
mise_network=offline
cargo_locked=true
cargo_network=offline
service_enabled=false
provider_registry=empty
plug_and_prejudice_dependency=false
build_environment=native-host-nonhermetic
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

mv --no-clobber --no-target-directory -- "${STAGING_OUTPUT}" "${FINAL_OUTPUT}"
trap - EXIT
rm -rf -- "${TEMPORARY_ROOT}"
printf 'non-publishable package skeleton written to: %s\n' "${FINAL_OUTPUT}"
