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

readonly X86_POLICY_STUBS="${TEMPORARY_ROOT}/x86-policy-stubs"
mkdir -m 0755 -- "${X86_POLICY_STUBS}"
install -m 0755 /dev/stdin "${X86_POLICY_STUBS}/od" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *' -j18 '* ]]; then
  printf ' %s\n' "${TEST_ELF_MACHINE_BYTES:-3e00}"
else
  exec /usr/bin/od "$@"
fi
STUB
install -m 0755 /dev/stdin "${X86_POLICY_STUBS}/readelf" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -l)
    printf '      [Requesting program interpreter: %s]\n' \
      "${TEST_ELF_INTERPRETER:-/lib64/ld-linux-x86-64.so.2}"
    ;;
  -d)
    binary_path="$3"
    if [[ "${binary_path}" == */a-quo-consent ]]; then
      libraries=(
        ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1 libm.so.6
        libwayland-client.so.0
      )
    else
      libraries=(ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1 libm.so.6)
    fi
    case "${TEST_NEEDED_MUTATION:-none}|${binary_path##*/}" in
      a-quo-missing\|a-quo) libraries=(ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1) ;;
      a-quo-wrong\|a-quo) libraries=(ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1 libdl.so.2) ;;
      a-quo-extra\|a-quo) libraries+=(libdl.so.2) ;;
      daemon-missing\|a-quo-daemon) libraries=(ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1) ;;
      daemon-wrong\|a-quo-daemon) libraries=(ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1 libdl.so.2) ;;
      daemon-extra\|a-quo-daemon) libraries+=(libdl.so.2) ;;
      consent-missing-loader\|a-quo-consent) libraries=(libc.so.6 libgcc_s.so.1 libm.so.6 libwayland-client.so.0) ;;
      consent-missing-wayland\|a-quo-consent) libraries=(ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1 libm.so.6) ;;
      consent-wrong\|a-quo-consent) libraries=(ld-linux-x86-64.so.2 libc.so.6 libgcc_s.so.1 libm.so.6 libwayland-server.so.0) ;;
      consent-extra\|a-quo-consent) libraries+=(libdl.so.2) ;;
    esac
    for library in "${libraries[@]}"; do
      printf ' 0x0000000000000001 (NEEDED) Shared library: [%s]\n' "${library}"
    done
    ;;
  *) exit 64 ;;
esac
STUB

run_x86_verifier() {
  env PATH="${X86_POLICY_STUBS}:${PATH}" \
    A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
    "${VERIFIER}" "${X86_64_PACKAGE}" "${SOURCE_COMMIT}" \
    "${X86_64_PROFILE}"
}

X86_64_OUTPUT="$(run_x86_verifier)"
readonly X86_64_OUTPUT
for accepted_literal in \
  'verified passive A Quo package skeleton:' \
  'profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'profile_sha256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d' \
  'profile_binding_role=package-target-policy' \
  'package_target_kind=physical-bare-metal' \
  'architecture=x86_64' \
  'physical_target_evidence=false' \
  'evidence_namespace=physical-x86_64-official-omarchy-4.0.2' \
  'needed_evidence=reviewed-x86_64-needed-policy-sha256-216ec3cd2e0698fd42390ade8394e0077ea9a915382de87ae1fe5e864966c9b0' \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  [[ "${X86_64_OUTPUT}" == *"${accepted_literal}"* ]] || {
    printf 'accepted x86 receipt lost field: %s output=%q\n' \
      "${accepted_literal}" "${X86_64_OUTPUT}" >&2
    exit 1
  }
done

assert_x86_policy_refused() {
  local label="$1"
  local expected="$2"
  shift 2
  local output status
  set +e
  output="$(env PATH="${X86_POLICY_STUBS}:${PATH}" "$@" \
    A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
    "${VERIFIER}" "${X86_64_PACKAGE}" "${SOURCE_COMMIT}" \
    "${X86_64_PROFILE}" 2>&1)"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && "${output}" == *"${expected}"* &&
    "${output}" != *'verified passive A Quo package skeleton'* ]] || {
    printf 'accepted x86 policy mutation was not refused: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  }
}

assert_x86_policy_refused machine \
  'packaged executable has the wrong ELF machine: path=usr/bin/a-quo expected=EM_X86_64 observed=b700' \
  TEST_ELF_MACHINE_BYTES=b700
assert_x86_policy_refused interpreter \
  'packaged executable does not use the expected glibc interpreter: usr/bin/a-quo' \
  TEST_ELF_INTERPRETER=/lib/ld-linux-aarch64.so.1
for mutation in \
  a-quo-missing a-quo-wrong a-quo-extra \
  daemon-missing daemon-wrong daemon-extra \
  consent-missing-loader consent-missing-wayland consent-wrong consent-extra; do
  case "${mutation}" in
    a-quo-*) expected_path=usr/bin/a-quo ;;
    daemon-*) expected_path=usr/bin/a-quo-daemon ;;
    consent-*) expected_path=usr/lib/a-quo/a-quo-consent ;;
  esac
  assert_x86_policy_refused "${mutation}" \
    "packaged executable has an unexpected shared-library set: ${expected_path}" \
    TEST_NEEDED_MUTATION="${mutation}"
done

set +e
X86_64_OBSERVATION_OUTPUT="$(PATH="${X86_POLICY_STUBS}:${PATH}" \
  A_QUO_VERIFIER_REPOSITORY_ROOT="${REPOSITORY_ROOT}" \
  "${VERIFIER}" --observe-unconfirmed-needed "${X86_64_PACKAGE}" \
  "${SOURCE_COMMIT}" "${X86_64_PROFILE}" 2>&1)"
X86_64_OBSERVATION_STATUS="$?"
set -e
readonly X86_64_OBSERVATION_OUTPUT X86_64_OBSERVATION_STATUS
if [[ "${X86_64_OBSERVATION_STATUS}" -ne 1 ||
  "${X86_64_OBSERVATION_OUTPUT}" != \
    'NEEDED observation mode is only valid for the unconfirmed x86_64 mapping' ||
  "${X86_64_OBSERVATION_OUTPUT}" == *'needed_observation_accepted_as_policy='* ||
  "${X86_64_OBSERVATION_OUTPUT}" == *'verified passive A Quo package skeleton'* ]]; then
  printf 'accepted x86 mapping allowed observation mode: status=%s output=%q\n' \
    "${X86_64_OBSERVATION_STATUS}" "${X86_64_OBSERVATION_OUTPUT}" >&2
  exit 1
fi

printf '%s\n' \
  'Arch package metadata and reviewed x86 library policy rejected hostile tuples'
