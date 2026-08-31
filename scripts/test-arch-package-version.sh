#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly X86_NEEDED_LOCK_VERIFIER="${REPOSITORY_ROOT}/scripts/verify-x86-package-needed-observation-lock.sh"
readonly X86_NEEDED_LOCK="${REPOSITORY_ROOT}/packaging/evaluation-input-locks/a-quo-x86_64-needed-observation-cbbe29b6-v1.lock"
readonly EXPECTED_X86_NEEDED_LOCK_VERIFIER_SHA256=6f0d8f2ae41f73e094b7d16182e99ef285012eabea4acb894a46cc2ad2491f73
readonly EXPECTED_X86_NEEDED_LOCK_SHA256=216ec3cd2e0698fd42390ade8394e0077ea9a915382de87ae1fe5e864966c9b0

for required_tool in git install sed sha256sum; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required package-version test tool is unavailable: %s\n' \
      "${required_tool}" >&2
    exit 1
  fi
done
[[ -f "${X86_NEEDED_LOCK_VERIFIER}" &&
  ! -L "${X86_NEEDED_LOCK_VERIFIER}" &&
  -x "${X86_NEEDED_LOCK_VERIFIER}" ]] || {
  printf '%s\n' 'x86 NEEDED lock verifier is missing, unsafe, or non-executable' >&2
  exit 1
}
[[ -f "${X86_NEEDED_LOCK}" && ! -L "${X86_NEEDED_LOCK}" ]] || {
  printf '%s\n' 'x86 NEEDED lock is missing or unsafe' >&2
  exit 1
}
X86_NEEDED_LOCK_VERIFIER_SHA256="$(
  sha256sum -- "${X86_NEEDED_LOCK_VERIFIER}"
)"
X86_NEEDED_LOCK_SHA256="$(sha256sum -- "${X86_NEEDED_LOCK}")"
readonly X86_NEEDED_LOCK_VERIFIER_SHA256 X86_NEEDED_LOCK_SHA256
[[ "${X86_NEEDED_LOCK_VERIFIER_SHA256%% *}" == \
    "${EXPECTED_X86_NEEDED_LOCK_VERIFIER_SHA256}" &&
  "${X86_NEEDED_LOCK_SHA256%% *}" == "${EXPECTED_X86_NEEDED_LOCK_SHA256}" ]] || {
  printf '%s\n' 'x86 NEEDED policy input bytes changed without package-version review' >&2
  exit 1
}

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
mkdir -m 0755 -- "${SOURCE_REPOSITORY}/packaging/evaluation-targets"
mkdir -m 0755 -- "${SOURCE_REPOSITORY}/packaging/evaluation-input-locks"

install -m 0755 -- \
  "${REPOSITORY_ROOT}/scripts/build-arch-package-skeleton.sh" \
  "${SOURCE_REPOSITORY}/scripts/build-arch-package-skeleton.sh"
install -m 0755 -- \
  "${REPOSITORY_ROOT}/scripts/verify-arch-package-skeleton.sh" \
  "${SOURCE_REPOSITORY}/scripts/verify-arch-package-skeleton.sh"
for helper in \
  resolve-arch-package-target.sh \
  verify-omarchy-evaluation-target-profile.sh \
  verify-omarchy-x86_64-physical-target-profile.sh \
  verify-x86-package-needed-observation-lock.sh; do
  install -m 0755 -- \
    "${REPOSITORY_ROOT}/scripts/${helper}" \
    "${SOURCE_REPOSITORY}/scripts/${helper}"
done
install -m 0644 -- "${X86_NEEDED_LOCK}" \
  "${SOURCE_REPOSITORY}/packaging/evaluation-input-locks/a-quo-x86_64-needed-observation-cbbe29b6-v1.lock"
for profile in \
  a-quo-omarchy4-aarch64-dec29fa-v2.profile \
  a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile; do
  install -m 0644 -- \
    "${REPOSITORY_ROOT}/packaging/evaluation-targets/${profile}" \
    "${SOURCE_REPOSITORY}/packaging/evaluation-targets/${profile}"
done
printf '%s\n' '/target/' >"${SOURCE_REPOSITORY}/.gitignore"
printf '%s\n' '[tools]' 'rust = "1.98.0"' >"${SOURCE_REPOSITORY}/.mise.toml"
printf '%s\n' '[workspace.package]' 'version = "0.1.0"' \
  >"${SOURCE_REPOSITORY}/Cargo.toml"
printf '%s\n' \
  'pkgname=a-quo' \
  'pkgver=@PACKAGE_VERSION@' \
  'pkgrel=1' \
  'arch=(@PACKAGE_ARCHITECTURE@)' \
  'xdata=(a-quo-profile-id=@PROFILE_ID@ a-quo-evidence-namespace=@EVIDENCE_NAMESPACE@)' \
  '_rust_version=@RUST_VERSION@' \
  '_source_commit=@SOURCE_COMMIT@' \
  'sha256sums=(@SOURCE_SHA256@)' \
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

assert_x86_mapping_boundary() {
  local output
  local status
  git -C "${SOURCE_REPOSITORY}" checkout --quiet main
  set +e
  output="$(
    PATH="${STUB_DIRECTORY}:${PATH}" \
      A_QUO_ARCH_PACKAGE_OUTPUT_DIRECTORY="${OUTPUT_DIRECTORY}" \
      "${SOURCE_REPOSITORY}/scripts/build-arch-package-skeleton.sh" \
      "${SOURCE_REPOSITORY}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile" 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != \
    *'expected=x86_64 observed=aarch64'* ]]; then
    printf 'builder did not bind explicit x86 profile before build: status=%s output=%q\n' \
      "${status}" "${output}" >&2
    exit 1
  fi
}

assert_cross_profile_filename_refused() {
  local package_path="${TEMPORARY_ROOT}/a-quo-${DESCENDANT_VERSION}-aarch64.pkg.tar.zst"
  local output
  local status
  : >"${package_path}"
  set +e
  output="$(
    PATH="${STUB_DIRECTORY}:${PATH}" \
      A_QUO_VERIFIER_REPOSITORY_ROOT="${SOURCE_REPOSITORY}" \
      "${SOURCE_REPOSITORY}/scripts/verify-arch-package-skeleton.sh" \
      "${package_path}" "${DESCENDANT_COMMIT}" \
      "${SOURCE_REPOSITORY}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile" 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != \
    *'-x86_64.pkg.tar.zst observed='* ]]; then
    printf 'verifier accepted a cross-profile package suffix: status=%s output=%q\n' \
      "${status}" "${output}" >&2
    exit 1
  fi
}

assert_builder_version "${ANCESTOR_COMMIT}" "${ANCESTOR_VERSION}"
assert_builder_version "${DESCENDANT_COMMIT}" "${DESCENDANT_VERSION}"
assert_verifier_version "${ANCESTOR_COMMIT}" "${ANCESTOR_VERSION}"
assert_verifier_version "${DESCENDANT_COMMIT}" "${DESCENDANT_VERSION}"
assert_x86_mapping_boundary
assert_cross_profile_filename_refused

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
