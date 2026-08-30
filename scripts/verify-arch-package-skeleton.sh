#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  printf 'usage: %s PACKAGE_PATH [EXPECTED_SOURCE_COMMIT]\n' "$0" >&2
  exit 2
fi

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
PACKAGE_INPUT="$1"
readonly PACKAGE_INPUT
EXPECTED_COMMIT="${2:-$(git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)}"
readonly EXPECTED_COMMIT

if [[ ! "${EXPECTED_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'expected source commit must be a full lowercase Git object ID' >&2
  exit 1
fi
if [[ ! -f "${PACKAGE_INPUT}" || -L "${PACKAGE_INPUT}" ]]; then
  printf '%s\n' 'package must be a real regular file' >&2
  exit 1
fi
PACKAGE_PATH="$(realpath -e -- "${PACKAGE_INPUT}")"
readonly PACKAGE_PATH

for required_tool in bsdtar cmp find gzip od readelf sort stat tar; do
  if ! command -v "${required_tool}" >/dev/null; then
    printf 'required package verification tool is unavailable: %s\n' "${required_tool}" >&2
    exit 1
  fi
done

WORKSPACE_VERSION="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "${REPOSITORY_ROOT}/Cargo.toml" | head -n 1)"
readonly WORKSPACE_VERSION
readonly COMMIT_ABBREVIATION="${EXPECTED_COMMIT:0:12}"
readonly EXPECTED_PACKAGE_VERSION="${WORKSPACE_VERSION}.r0.g${COMMIT_ABBREVIATION}-1"
readonly EXPECTED_PACKAGE_BASENAME="a-quo-${EXPECTED_PACKAGE_VERSION}-aarch64.pkg.tar.zst"
if [[ "$(basename -- "${PACKAGE_PATH}")" != "${EXPECTED_PACKAGE_BASENAME}" ]]; then
  printf 'unexpected package filename: expected=%s observed=%s\n' \
    "${EXPECTED_PACKAGE_BASENAME}" "$(basename -- "${PACKAGE_PATH}")" >&2
  exit 1
fi

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-package-verify.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

readonly RAW_ENTRIES="${TEMPORARY_ROOT}/raw-entries"
readonly NORMALIZED_ENTRIES="${TEMPORARY_ROOT}/normalized-entries"
readonly UNIQUE_ENTRIES="${TEMPORARY_ROOT}/unique-entries"
readonly EXPECTED_ENTRIES="${TEMPORARY_ROOT}/expected-entries"
readonly VERBOSE_ENTRIES="${TEMPORARY_ROOT}/verbose-entries"
readonly EXTRACTED="${TEMPORARY_ROOT}/extracted"
mkdir -m 0700 -- "${EXTRACTED}"

bsdtar -tf "${PACKAGE_PATH}" >"${RAW_ENTRIES}"
if LC_ALL=C grep -n '[^ -~]' "${RAW_ENTRIES}" >/dev/null; then
  printf '%s\n' 'package archive contains a non-printable entry name' >&2
  exit 1
fi
while IFS= read -r entry_name; do
  normalized_name="${entry_name#./}"
  normalized_name="${normalized_name%/}"
  if [[ -z "${normalized_name}" || "${normalized_name}" == /* || \
    "${normalized_name}" == *\\* || "/${normalized_name}/" == *'/../'* ]]; then
    printf 'package archive contains an unsafe entry name: %q\n' "${entry_name}" >&2
    exit 1
  fi
  printf '%s\n' "${normalized_name}"
done <"${RAW_ENTRIES}" >"${NORMALIZED_ENTRIES}"
sort -- "${NORMALIZED_ENTRIES}" >"${UNIQUE_ENTRIES}"
if [[ "$(wc -l <"${NORMALIZED_ENTRIES}")" -ne "$(sort -u "${NORMALIZED_ENTRIES}" | wc -l)" ]]; then
  printf '%s\n' 'package archive contains duplicate entry names' >&2
  exit 1
fi

printf '%s\n' \
  .BUILDINFO \
  .MTREE \
  .PKGINFO \
  usr \
  usr/bin \
  usr/bin/a-quo \
  usr/bin/a-quo-daemon \
  usr/lib \
  usr/lib/a-quo \
  usr/lib/a-quo/a-quo-consent \
  usr/lib/systemd \
  usr/lib/systemd/user \
  usr/lib/systemd/user/a-quo-daemon.service \
  usr/share \
  usr/share/a-quo \
  usr/share/a-quo/provider-registry-v1.json \
  usr/share/doc \
  usr/share/doc/a-quo \
  usr/share/doc/a-quo/PACKAGING.md \
  usr/share/doc/a-quo/README.md \
  usr/share/doc/a-quo/SECURITY.md \
  usr/share/doc/a-quo/THREAT-MODEL.md \
  usr/share/licenses \
  usr/share/licenses/a-quo \
  usr/share/licenses/a-quo/LICENSE | sort >"${EXPECTED_ENTRIES}"
if ! cmp -- "${EXPECTED_ENTRIES}" "${UNIQUE_ENTRIES}"; then
  printf '%s\n' 'package archive differs from the closed payload and metadata inventory' >&2
  exit 1
fi

tar --zstd --numeric-owner -tvf "${PACKAGE_PATH}" >"${VERBOSE_ENTRIES}"
while IFS= read -r verbose_entry; do
  case "${verbose_entry:0:1}" in
    - | d) ;;
    *)
      printf '%s\n' 'package archive contains a link or special entry' >&2
      exit 1
      ;;
  esac
done <"${VERBOSE_ENTRIES}"

bsdtar --no-same-owner -xf "${PACKAGE_PATH}" -C "${EXTRACTED}"
if find "${EXTRACTED}" -mindepth 1 ! -type d ! -type f -print -quit | grep -q .; then
  printf '%s\n' 'extracted package contains a link or special entry' >&2
  exit 1
fi

readonly PKGINFO="${EXTRACTED}/.PKGINFO"
grep -Fxq 'pkgname = a-quo' "${PKGINFO}"
grep -Fxq "pkgver = ${EXPECTED_PACKAGE_VERSION}" "${PKGINFO}"
grep -Fxq 'arch = aarch64' "${PKGINFO}"
readonly EXPECTED_DEPENDENCIES="${TEMPORARY_ROOT}/expected-dependencies"
readonly OBSERVED_DEPENDENCIES="${TEMPORARY_ROOT}/observed-dependencies"
printf '%s\n' \
  bubblewrap \
  gcc-libs \
  glibc \
  noto-fonts \
  omarchy \
  openssh \
  systemd \
  util-linux \
  wayland | sort >"${EXPECTED_DEPENDENCIES}"
sed -n 's/^depend = //p' "${PKGINFO}" | sort >"${OBSERVED_DEPENDENCIES}"
if ! cmp -- "${EXPECTED_DEPENDENCIES}" "${OBSERVED_DEPENDENCIES}"; then
  printf '%s\n' 'package dependency set differs from the Phase-A skeleton contract' >&2
  exit 1
fi
if grep -Eiq 'plug.?and.?prejudice|provider-plug' "${PKGINFO}"; then
  printf '%s\n' 'base package unexpectedly depends on a behavioural reviewer' >&2
  exit 1
fi

assert_archive_header() {
  local expected_header="$1"
  local archive_path="$2"
  local observed_header
  observed_header="$(awk -v path="${archive_path}" '$NF == path || $NF == path "/" { print $1 " " $2 }' "${VERBOSE_ENTRIES}")"
  if [[ "${observed_header}" != "${expected_header}" ]]; then
    printf 'unexpected archive owner or mode: path=%s expected=%s observed=%s\n' \
      "${archive_path}" "${expected_header}" "${observed_header:-missing}" >&2
    exit 1
  fi
}

for executable_path in usr/bin/a-quo usr/bin/a-quo-daemon usr/lib/a-quo/a-quo-consent; do
  assert_archive_header '-rwxr-xr-x 0/0' "${executable_path}"
done
for data_path in \
  usr/lib/systemd/user/a-quo-daemon.service \
  usr/share/a-quo/provider-registry-v1.json \
  usr/share/doc/a-quo/PACKAGING.md \
  usr/share/doc/a-quo/README.md \
  usr/share/doc/a-quo/SECURITY.md \
  usr/share/doc/a-quo/THREAT-MODEL.md \
  usr/share/licenses/a-quo/LICENSE; do
  assert_archive_header '-rw-r--r-- 0/0' "${data_path}"
done
for owned_directory in usr/lib/a-quo usr/share/a-quo usr/share/doc/a-quo usr/share/licenses/a-quo; do
  assert_archive_header 'drwxr-xr-x 0/0' "${owned_directory}"
done

cmp -- "${REPOSITORY_ROOT}/packaging/systemd/a-quo-daemon.service" \
  "${EXTRACTED}/usr/lib/systemd/user/a-quo-daemon.service"
cmp -- "${REPOSITORY_ROOT}/packaging/provider-registry-v1.json" \
  "${EXTRACTED}/usr/share/a-quo/provider-registry-v1.json"
cmp -- "${REPOSITORY_ROOT}/README.md" "${EXTRACTED}/usr/share/doc/a-quo/README.md"
cmp -- "${REPOSITORY_ROOT}/docs/PACKAGING.md" \
  "${EXTRACTED}/usr/share/doc/a-quo/PACKAGING.md"
cmp -- "${REPOSITORY_ROOT}/SECURITY.md" "${EXTRACTED}/usr/share/doc/a-quo/SECURITY.md"
cmp -- "${REPOSITORY_ROOT}/docs/THREAT-MODEL.md" \
  "${EXTRACTED}/usr/share/doc/a-quo/THREAT-MODEL.md"
cmp -- "${REPOSITORY_ROOT}/LICENSE" "${EXTRACTED}/usr/share/licenses/a-quo/LICENSE"

for binary_path in \
  "${EXTRACTED}/usr/bin/a-quo" \
  "${EXTRACTED}/usr/bin/a-quo-daemon" \
  "${EXTRACTED}/usr/lib/a-quo/a-quo-consent"; do
  elf_machine="$(od -An -tx1 -N2 -j18 -- "${binary_path}" | tr -d ' \n')"
  if [[ "${elf_machine}" != b700 ]]; then
    printf 'packaged executable is not AArch64 ELF: %s\n' "${binary_path}" >&2
    exit 1
  fi
  if ! readelf -l -- "${binary_path}" | grep -Fq \
    '[Requesting program interpreter: /lib/ld-linux-aarch64.so.1]'; then
    printf 'packaged executable does not use the expected glibc interpreter: %s\n' \
      "${binary_path}" >&2
    exit 1
  fi
done

printf 'verified passive A Quo package skeleton: %s\n' "${PACKAGE_PATH}"
