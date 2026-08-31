#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh"
readonly PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"

for required_tool in bsdtar chmod cut find git install mkdir mktemp sed sha256sum sort tar; do
  command -v "${required_tool}" >/dev/null || {
    printf 'package-binding contract tool is unavailable: %s\n' \
      "${required_tool}" >&2
    exit 1
  }
done

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-package-binding.XXXXXX")"
readonly TEMPORARY_ROOT
cleanup() {
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT
readonly STAGING="${TEMPORARY_ROOT}/staging"
mkdir -m 0755 -- "${STAGING}"

SOURCE_COMMIT="$(git -C "${REPOSITORY_ROOT}" rev-parse --verify HEAD)"
SOURCE_COMMIT_COUNT="$(git -C "${REPOSITORY_ROOT}" rev-list --count "${SOURCE_COMMIT}")"
WORKSPACE_VERSION="$(
  git -C "${REPOSITORY_ROOT}" show "${SOURCE_COMMIT}:Cargo.toml" |
    sed -n 's/^version = "\([^"]*\)"$/\1/p' | head -n 1
)"
readonly SOURCE_COMMIT SOURCE_COMMIT_COUNT WORKSPACE_VERSION
readonly PACKAGE_VERSION="${WORKSPACE_VERSION}.r${SOURCE_COMMIT_COUNT}.g${SOURCE_COMMIT:0:12}-1"
readonly PACKAGE="${TEMPORARY_ROOT}/a-quo-${PACKAGE_VERSION}-aarch64.pkg.tar.zst"

mkdir -p -- \
  "${STAGING}/usr/bin" \
  "${STAGING}/usr/lib/a-quo" \
  "${STAGING}/usr/lib/systemd/user" \
  "${STAGING}/usr/lib/systemd/user-preset" \
  "${STAGING}/usr/share/a-quo" \
  "${STAGING}/usr/share/doc/a-quo" \
  "${STAGING}/usr/share/licenses/a-quo"
find "${STAGING}" -type d -exec chmod 0755 -- {} +
for binary_path in \
  usr/bin/a-quo usr/bin/a-quo-daemon usr/lib/a-quo/a-quo-consent; do
  printf '%s\n' 'synthetic non-ELF executable' >"${STAGING}/${binary_path}"
  chmod 0755 -- "${STAGING}/${binary_path}"
done
printf '%s\n' synthetic >"${STAGING}/.BUILDINFO"
printf '%s\n' synthetic >"${STAGING}/.MTREE"
chmod 0644 -- "${STAGING}/.BUILDINFO" "${STAGING}/.MTREE"
write_committed_asset() {
  local source_path="$1"
  local destination_path="$2"
  git -C "${REPOSITORY_ROOT}" show "${SOURCE_COMMIT}:${source_path}" \
    >"${destination_path}"
  chmod 0644 -- "${destination_path}"
}
write_committed_asset packaging/systemd/a-quo-daemon.service \
  "${STAGING}/usr/lib/systemd/user/a-quo-daemon.service"
write_committed_asset packaging/systemd/90-a-quo.preset \
  "${STAGING}/usr/lib/systemd/user-preset/90-a-quo.preset"
write_committed_asset packaging/provider-registry-v1.json \
  "${STAGING}/usr/share/a-quo/provider-registry-v1.json"
write_committed_asset README.md "${STAGING}/usr/share/doc/a-quo/README.md"
write_committed_asset docs/PACKAGING.md \
  "${STAGING}/usr/share/doc/a-quo/PACKAGING.md"
write_committed_asset SECURITY.md "${STAGING}/usr/share/doc/a-quo/SECURITY.md"
write_committed_asset docs/THREAT-MODEL.md \
  "${STAGING}/usr/share/doc/a-quo/THREAT-MODEL.md"
write_committed_asset LICENSE "${STAGING}/usr/share/licenses/a-quo/LICENSE"

write_pkginfo() {
  local arch_lines="$1"
  local xdata_lines="$2"
  {
    printf '%s\n' \
      'pkgname = a-quo' \
      "pkgver = ${PACKAGE_VERSION}"
    printf '%s\n' "${arch_lines}"
    printf '%s\n' "${xdata_lines}"
    printf '%s\n' \
      'depend = bubblewrap' \
      'depend = glibc' \
      'depend = libgcc' \
      'depend = noto-fonts' \
      'depend = omarchy' \
      'depend = openssh' \
      'depend = systemd' \
      'depend = util-linux' \
      'depend = wayland'
  } >"${STAGING}/.PKGINFO"
  chmod 0644 -- "${STAGING}/.PKGINFO"
}

build_package() {
  local output_path="${1:-${PACKAGE}}"
  local inventory="${TEMPORARY_ROOT}/inventory"
  (
    cd -- "${STAGING}"
    find . -mindepth 1 -printf '%P\n' | sort >"${inventory}"
    tar --zstd --numeric-owner --owner=0 --group=0 --no-recursion \
      -cf "${output_path}" -T "${inventory}"
  )
}

assert_refused() {
  local label="$1"
  local expected="$2"
  local arch_lines="$3"
  local xdata_lines="$4"
  local output
  local status
  write_pkginfo "${arch_lines}" "${xdata_lines}"
  build_package
  set +e
  output="$(A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
    "${VERIFIER}" "${PACKAGE}" "${SOURCE_COMMIT}" "${PROFILE}" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != *"${expected}"* ]]; then
    printf 'package binding mutation was not refused: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

readonly VALID_ARCH='arch = aarch64'
VALID_XDATA="$(printf '%s\n' \
  'xdata = pkgtype=pkg' \
  'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
  'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa')"
readonly VALID_XDATA

assert_refused missing-profile-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa')"
assert_refused missing-architecture \
  'package architecture is missing, duplicated, or cross-profile' \
  '' "${VALID_XDATA}"
assert_refused missing-namespace-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2')"
assert_refused duplicate-profile-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa')"
assert_refused conflicting-profile-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa')"
assert_refused cross-profile-namespace \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
    'xdata = a-quo-evidence-namespace=physical-x86_64-official-omarchy-4.0.2')"
assert_refused duplicate-namespace-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa')"
assert_refused conflicting-namespace-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa' \
    'xdata = a-quo-evidence-namespace=physical-x86_64-official-omarchy-4.0.2')"
assert_refused duplicate-pkgtype-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa')"
assert_refused extra-pkgtype-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = pkgtype=unexpected' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa')"
assert_refused reordered-xdata \
  'package xdata lacks the exact ordered profile and evidence binding' \
  "${VALID_ARCH}" "$(printf '%s\n' \
    'xdata = pkgtype=pkg' \
    'xdata = a-quo-evidence-namespace=phase-a-aarch64-dec29fa' \
    'xdata = a-quo-profile-id=a-quo-omarchy4-aarch64-dec29fa-v2')"
assert_refused duplicate-architecture \
  'package architecture is missing, duplicated, or cross-profile' \
  "$(printf '%s\n' 'arch = aarch64' 'arch = aarch64')" "${VALID_XDATA}"
assert_refused conflicting-architecture \
  'package architecture is missing, duplicated, or cross-profile' \
  "$(printf '%s\n' 'arch = aarch64' 'arch = x86_64')" "${VALID_XDATA}"
assert_refused valid-binding-reaches-elf-policy \
  'packaged executable has the wrong ELF machine' \
  "${VALID_ARCH}" "${VALID_XDATA}"

readonly X86_64_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly X86_64_PACKAGE="${TEMPORARY_ROOT}/a-quo-${PACKAGE_VERSION}-x86_64.pkg.tar.zst"
write_pkginfo 'arch = x86_64' "$(printf '%s\n' \
  'xdata = pkgtype=pkg' \
  'xdata = a-quo-profile-id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'xdata = a-quo-evidence-namespace=physical-x86_64-official-omarchy-4.0.2')"
build_package "${X86_64_PACKAGE}"
set +e
X86_64_OUTPUT="$(A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${VERIFIER}" "${X86_64_PACKAGE}" "${SOURCE_COMMIT}" \
  "${X86_64_PROFILE}" 2>&1)"
X86_64_STATUS="$?"
set -e
readonly X86_64_OUTPUT X86_64_STATUS
if [[ "${X86_64_STATUS}" -ne 1 || "${X86_64_OUTPUT}" != \
    *'x86_64 NEEDED policy is unconfirmed'* ||
  "${X86_64_OUTPUT}" == *'verified passive A Quo package skeleton'* ]]; then
  printf 'unconfirmed x86 tuple did not fail closed: status=%s output=%q\n' \
    "${X86_64_STATUS}" "${X86_64_OUTPUT}" >&2
  exit 1
fi

readonly OBSERVATION_STUBS="${TEMPORARY_ROOT}/observation-stubs"
mkdir -m 0755 -- "${OBSERVATION_STUBS}"
install -m 0755 /dev/stdin "${OBSERVATION_STUBS}/od" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *' -j18 '* ]]; then
  printf '%s\n' ' 3e00'
else
  exec /usr/bin/od "$@"
fi
STUB
install -m 0755 /dev/stdin "${OBSERVATION_STUBS}/readelf" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -l)
    printf '%s\n' \
      '      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]'
    ;;
  -d)
    binary_path="$3"
    if [[ "${binary_path}" == */a-quo-consent ]]; then
      libraries=(libc.so.6 libgcc_s.so.1 libm.so.6 libwayland-client.so.0)
    else
      libraries=(ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1 libm.so.6)
    fi
    for library in "${libraries[@]}"; do
      printf ' 0x0000000000000001 (NEEDED) Shared library: [%s]\n' "${library}"
    done
    ;;
  *) exit 64 ;;
esac
STUB
X86_64_PACKAGE_SHA256="$(sha256sum -- "${X86_64_PACKAGE}" | cut -d ' ' -f 1)"
readonly X86_64_PACKAGE_SHA256
set +e
X86_64_OBSERVATION_OUTPUT="$(PATH="${OBSERVATION_STUBS}:${PATH}" \
  A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${VERIFIER}" --observe-unconfirmed-needed "${X86_64_PACKAGE}" \
  "${SOURCE_COMMIT}" "${X86_64_PROFILE}" 2>&1)"
X86_64_OBSERVATION_STATUS="$?"
set -e
readonly X86_64_OBSERVATION_OUTPUT X86_64_OBSERVATION_STATUS
for observation_literal in \
  'format=a-quo-arch-package-needed-observation-v1' \
  'observation_authority=none' \
  "package_sha256=${X86_64_PACKAGE_SHA256}" \
  "expected_source_commit=${SOURCE_COMMIT}" \
  'profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'profile_sha256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d' \
  'profile_binding_role=package-target-policy' \
  'package_target_kind=physical-bare-metal' \
  'architecture=x86_64' \
  'evidence_namespace=physical-x86_64-official-omarchy-4.0.2' \
  'verification_host_profile_match=not-established' \
  'native_hardware_claim=not-established' \
  'physical_target_evidence=false' \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false' \
  'observed_needed_usr_bin_a-quo=ld-linux-x86-64.so.2,libc.so.6,libgcc_s.so.1,libm.so.6' \
  'observed_needed_usr_bin_a-quo-daemon=ld-linux-x86-64.so.2,libc.so.6,libgcc_s.so.1,libm.so.6' \
  'observed_needed_usr_lib_a-quo_a-quo-consent=libc.so.6,libgcc_s.so.1,libm.so.6,libwayland-client.so.0' \
  'needed_observation_accepted_as_policy=false'; do
  [[ "${X86_64_OBSERVATION_OUTPUT}" == *"${observation_literal}"* ]] || {
    printf 'x86 observation receipt lost binding: %s output=%q\n' \
      "${observation_literal}" "${X86_64_OBSERVATION_OUTPUT}" >&2
    exit 1
  }
done
if [[ "${X86_64_OBSERVATION_STATUS}" -ne 1 ||
  "${X86_64_OBSERVATION_OUTPUT}" == \
    *'verified passive A Quo package skeleton'* ]]; then
  printf 'x86 observation mode did not remain non-accepting: status=%s output=%q\n' \
    "${X86_64_OBSERVATION_STATUS}" "${X86_64_OBSERVATION_OUTPUT}" >&2
  exit 1
fi

printf '%s\n' \
  'Arch package metadata binding rejected missing, duplicate, and mixed tuples'
