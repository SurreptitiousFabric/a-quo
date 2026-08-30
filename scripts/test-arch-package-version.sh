#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT

for required_tool in git install sed; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required package-version test tool is unavailable: %s\n' \
      "${required_tool}" >&2
    exit 1
  fi
done

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-package-version.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

readonly SOURCE_REPOSITORY="${TEMPORARY_ROOT}/source"
readonly STUB_DIRECTORY="${TEMPORARY_ROOT}/bin"
readonly OUTPUT_DIRECTORY="${TEMPORARY_ROOT}/output"
readonly BUILDER_CAPTURE="${TEMPORARY_ROOT}/builder-version"
mkdir -m 0755 -- \
  "${SOURCE_REPOSITORY}" \
  "${STUB_DIRECTORY}" \
  "${OUTPUT_DIRECTORY}"
mkdir -m 0755 -- \
  "${SOURCE_REPOSITORY}/scripts" \
  "${SOURCE_REPOSITORY}/packaging"
mkdir -m 0755 -- "${SOURCE_REPOSITORY}/packaging/arch"

install -m 0755 -- \
  "${REPOSITORY_ROOT}/scripts/build-arch-package-skeleton.sh" \
  "${SOURCE_REPOSITORY}/scripts/build-arch-package-skeleton.sh"
install -m 0755 -- \
  "${REPOSITORY_ROOT}/scripts/verify-arch-package-skeleton.sh" \
  "${SOURCE_REPOSITORY}/scripts/verify-arch-package-skeleton.sh"
printf '%s\n' '/target/' >"${SOURCE_REPOSITORY}/.gitignore"
printf '%s\n' '[tools]' 'rust = "1.98.0"' >"${SOURCE_REPOSITORY}/.mise.toml"
printf '%s\n' '[workspace.package]' 'version = "0.1.0"' \
  >"${SOURCE_REPOSITORY}/Cargo.toml"
printf '%s\n' \
  'pkgname=a-quo' \
  'pkgver=@PACKAGE_VERSION@' \
  'pkgrel=1' \
  'arch=(aarch64)' \
  >"${SOURCE_REPOSITORY}/packaging/arch/PKGBUILD.in"

git -C "${SOURCE_REPOSITORY}" init --quiet --initial-branch=main
git -C "${SOURCE_REPOSITORY}" add --all
git -C "${SOURCE_REPOSITORY}" \
  -c user.name='A Quo package-version test' \
  -c user.email='noreply@a-quo.invalid' \
  commit --quiet --message=ancestor
ANCESTOR_COMMIT="$(git -C "${SOURCE_REPOSITORY}" rev-parse HEAD)"
readonly ANCESTOR_COMMIT
printf '%s\n' descendant >"${SOURCE_REPOSITORY}/progression.txt"
git -C "${SOURCE_REPOSITORY}" add progression.txt
git -C "${SOURCE_REPOSITORY}" \
  -c user.name='A Quo package-version test' \
  -c user.email='noreply@a-quo.invalid' \
  commit --quiet --message=descendant
DESCENDANT_COMMIT="$(git -C "${SOURCE_REPOSITORY}" rev-parse HEAD)"
readonly DESCENDANT_COMMIT

package_version() {
  local commit="$1"
  local commit_count
  commit_count="$(git -C "${SOURCE_REPOSITORY}" rev-list --count "${commit}")"
  printf '0.1.0.r%s.g%s-1\n' "${commit_count}" "${commit:0:12}"
}

ANCESTOR_COUNT="$(
  git -C "${SOURCE_REPOSITORY}" rev-list --count "${ANCESTOR_COMMIT}"
)"
readonly ANCESTOR_COUNT
DESCENDANT_COUNT="$(
  git -C "${SOURCE_REPOSITORY}" rev-list --count "${DESCENDANT_COMMIT}"
)"
readonly DESCENDANT_COUNT
if (( ANCESTOR_COUNT >= DESCENDANT_COUNT )); then
  printf 'ancestor commit count does not precede descendant: ancestor=%s descendant=%s\n' \
    "${ANCESTOR_COUNT}" "${DESCENDANT_COUNT}" >&2
  exit 1
fi

ANCESTOR_VERSION="$(package_version "${ANCESTOR_COMMIT}")"
readonly ANCESTOR_VERSION
DESCENDANT_VERSION="$(package_version "${DESCENDANT_COMMIT}")"
readonly DESCENDANT_VERSION
if command -v vercmp >/dev/null; then
  VERCMP_RESULT="$(vercmp "${ANCESTOR_VERSION}" "${DESCENDANT_VERSION}")"
  readonly VERCMP_RESULT
  if (( VERCMP_RESULT >= 0 )); then
    printf 'ancestor package version does not precede descendant: ancestor=%s descendant=%s vercmp=%s\n' \
      "${ANCESTOR_VERSION}" "${DESCENDANT_VERSION}" "${VERCMP_RESULT}" >&2
    exit 1
  fi
  printf '%s\n' 'package-version ordering check: Git counts and Arch vercmp'
else
  printf '%s\n' 'package-version ordering check: Git counts (vercmp unavailable)'
fi

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" aarch64' \
  >"${STUB_DIRECTORY}/uname"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  "printf '%s\\n' 'host: aarch64-unknown-linux-gnu' 'release: 1.98.0'" \
  >"${STUB_DIRECTORY}/mise"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  "sed -n 's/^pkgver=//p' PKGBUILD >\"${BUILDER_CAPTURE}\"" \
  'exit 73' \
  >"${STUB_DIRECTORY}/makepkg"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'exit 73' \
  >"${STUB_DIRECTORY}/bsdtar"
chmod 0755 -- "${STUB_DIRECTORY}/uname" "${STUB_DIRECTORY}/mise" \
  "${STUB_DIRECTORY}/makepkg" "${STUB_DIRECTORY}/bsdtar"

assert_builder_version() {
  local commit="$1"
  local expected_version="$2"
  local output
  local status

  git -C "${SOURCE_REPOSITORY}" checkout --quiet --detach "${commit}"
  set +e
  output="$(
    PATH="${STUB_DIRECTORY}:${PATH}" \
      A_QUO_ARCH_PACKAGE_OUTPUT_DIRECTORY="${OUTPUT_DIRECTORY}" \
      "${SOURCE_REPOSITORY}/scripts/build-arch-package-skeleton.sh" 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -ne 73 ]]; then
    printf 'builder did not reach the makepkg boundary: commit=%s status=%s output=%s\n' \
      "${commit}" "${status}" "${output}" >&2
    exit 1
  fi
  if [[ "$(<"${BUILDER_CAPTURE}")-1" != "${expected_version}" ]]; then
    printf 'builder rendered the wrong package version: expected=%s observed=%s\n' \
      "${expected_version%-1}" "$(<"${BUILDER_CAPTURE}")" >&2
    exit 1
  fi
}

assert_verifier_version() {
  local commit="$1"
  local expected_version="$2"
  local package_path="${TEMPORARY_ROOT}/a-quo-${expected_version}-aarch64.pkg.tar.zst"
  local output
  local status

  : >"${package_path}"
  set +e
  output="$(
    PATH="${STUB_DIRECTORY}:${PATH}" \
      A_QUO_VERIFIER_REPOSITORY_ROOT="${SOURCE_REPOSITORY}" \
      "${SOURCE_REPOSITORY}/scripts/verify-arch-package-skeleton.sh" \
      "${package_path}" "${commit}" 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -ne 73 ]]; then
    printf 'verifier rejected the expected package version before archive inspection: commit=%s status=%s output=%s\n' \
      "${commit}" "${status}" "${output}" >&2
    exit 1
  fi
}

assert_builder_version "${ANCESTOR_COMMIT}" "${ANCESTOR_VERSION}"
assert_builder_version "${DESCENDANT_COMMIT}" "${DESCENDANT_VERSION}"
assert_verifier_version "${ANCESTOR_COMMIT}" "${ANCESTOR_VERSION}"
assert_verifier_version "${DESCENDANT_COMMIT}" "${DESCENDANT_VERSION}"

git -C "${SOURCE_REPOSITORY}" checkout --quiet main
readonly SHALLOW_REPOSITORY="${TEMPORARY_ROOT}/shallow"
git clone --quiet --depth=1 "file://${SOURCE_REPOSITORY}" "${SHALLOW_REPOSITORY}"
SHALLOW_COMMIT="$(git -C "${SHALLOW_REPOSITORY}" rev-parse HEAD)"
readonly SHALLOW_COMMIT

set +e
SHALLOW_BUILD_OUTPUT="$(
  PATH="${STUB_DIRECTORY}:${PATH}" \
    A_QUO_ARCH_PACKAGE_OUTPUT_DIRECTORY="${OUTPUT_DIRECTORY}" \
    "${SHALLOW_REPOSITORY}/scripts/build-arch-package-skeleton.sh" 2>&1
)"
SHALLOW_BUILD_STATUS="$?"
set -e
readonly SHALLOW_BUILD_OUTPUT SHALLOW_BUILD_STATUS
if [[ "${SHALLOW_BUILD_STATUS}" -ne 1 || \
  "${SHALLOW_BUILD_OUTPUT}" != \
    'refusing package skeleton build from a shallow repository' ]]; then
  printf 'builder did not reject shallow history: status=%s output=%s\n' \
    "${SHALLOW_BUILD_STATUS}" "${SHALLOW_BUILD_OUTPUT}" >&2
  exit 1
fi

readonly SHALLOW_PACKAGE="${TEMPORARY_ROOT}/shallow-package.pkg.tar.zst"
: >"${SHALLOW_PACKAGE}"
set +e
SHALLOW_VERIFY_OUTPUT="$(
  PATH="${STUB_DIRECTORY}:${PATH}" \
    A_QUO_VERIFIER_REPOSITORY_ROOT="${SHALLOW_REPOSITORY}" \
    "${SHALLOW_REPOSITORY}/scripts/verify-arch-package-skeleton.sh" \
    "${SHALLOW_PACKAGE}" "${SHALLOW_COMMIT}" 2>&1
)"
SHALLOW_VERIFY_STATUS="$?"
set -e
readonly SHALLOW_VERIFY_OUTPUT SHALLOW_VERIFY_STATUS
if [[ "${SHALLOW_VERIFY_STATUS}" -ne 1 || \
  "${SHALLOW_VERIFY_OUTPUT}" != \
    'refusing package verification from a shallow repository' ]]; then
  printf 'verifier did not reject shallow history: status=%s output=%s\n' \
    "${SHALLOW_VERIFY_STATUS}" "${SHALLOW_VERIFY_OUTPUT}" >&2
  exit 1
fi

printf 'Arch package versions preserve Git ancestry: %s < %s\n' \
  "${ANCESTOR_VERSION}" "${DESCENDANT_VERSION}"
