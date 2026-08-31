#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
umask 077

fail_offline_acceptance() {
  printf 'offline x86_64 package static acceptance refused: %s\n' "$1" >&2
  exit 1
}

if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'usage: %s EXPECTED_SOURCE_COMMIT\n' "${0##*/}" >&2
  exit 2
fi
readonly EXPECTED_SOURCE_COMMIT="$1"
readonly EXPECTED_UID=1001
readonly EXPECTED_GID=1001
readonly EXPECTED_WORKSPACE=/workspace
readonly EXPECTED_HOME=/home/a-quo-observer
readonly EXPECTED_NAMESPACE=physical-x86_64-official-omarchy-4.0.2
readonly EXPECTED_PROFILE_ID=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1
readonly EXPECTED_PROFILE_SHA256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d
readonly EXPECTED_NEEDED_EVIDENCE=reviewed-x86_64-needed-policy-sha256-216ec3cd2e0698fd42390ade8394e0077ea9a915382de87ae1fe5e864966c9b0
readonly EXPECTED_MISE_SHA256=cff4832ded79af2951e800bddcb5a22acac58630d765a2d062c1180680a0bb35
readonly PROFILE="${EXPECTED_WORKSPACE}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly PACKAGE_OUTPUT="${EXPECTED_WORKSPACE}/target/arch-package-skeleton/${EXPECTED_NAMESPACE}/${EXPECTED_SOURCE_COMMIT}"
readonly ACCEPTANCE_ROOT="${EXPECTED_WORKSPACE}/target/arch-package-static-acceptance/${EXPECTED_NAMESPACE}/${EXPECTED_SOURCE_COMMIT}"

for git_environment_override in \
  GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_CEILING_DIRECTORIES \
  GIT_COMMON_DIR \
  GIT_CONFIG \
  GIT_CONFIG_COUNT \
  GIT_CONFIG_GLOBAL \
  GIT_CONFIG_NOSYSTEM \
  GIT_CONFIG_PARAMETERS \
  GIT_CONFIG_SYSTEM \
  GIT_DIR \
  GIT_DISCOVERY_ACROSS_FILESYSTEM \
  GIT_EXEC_PATH \
  GIT_GRAFT_FILE \
  GIT_INDEX_FILE \
  GIT_NAMESPACE \
  GIT_OBJECT_DIRECTORY \
  GIT_OPTIONAL_LOCKS \
  GIT_QUARANTINE_PATH \
  GIT_REPLACE_REF_BASE \
  GIT_SHALLOW_FILE \
  GIT_WORK_TREE; do
  [[ ! -v "${git_environment_override}" ]] ||
    fail_offline_acceptance \
      "inherited Git repository override: ${git_environment_override}"
done
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_NO_LAZY_FETCH=1
export GIT_NO_REPLACE_OBJECTS=1
export GIT_OPTIONAL_LOCKS=0

for required_tool in \
  bash basename cat chmod find git grep id install mktemp readlink rm \
  sha256sum sort stat uname; do
  command -v "${required_tool}" >/dev/null ||
    fail_offline_acceptance "required offline tool is unavailable: ${required_tool}"
done

[[ "$(id -u)" == "${EXPECTED_UID}" && "$(id -g)" == "${EXPECTED_GID}" ]] ||
  fail_offline_acceptance 'container process does not have the reviewed non-root UID/GID'
[[ "$(uname -m)" == x86_64 ]] ||
  fail_offline_acceptance 'container execution architecture is not x86_64'
[[ -f /etc/arch-release ]] ||
  fail_offline_acceptance 'container is not the reviewed Arch-family environment'
[[ "${HOME:-}" == "${EXPECTED_HOME}" && "${PWD}" == "${EXPECTED_WORKSPACE}" ]] ||
  fail_offline_acceptance 'container HOME or working directory differs from policy'
[[ "${MISE_OFFLINE:-}" == 1 &&
  "${MISE_TRUSTED_CONFIG_PATHS:-}" == "${EXPECTED_WORKSPACE}" &&
  "${CARGO_NET_OFFLINE:-}" == true ]] ||
  fail_offline_acceptance 'offline toolchain policy is missing or malformed'
[[ -d /sys/class/net/lo ]] ||
  fail_offline_acceptance 'offline container has no loopback interface'
mapfile -t network_interfaces < <(
  find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort
)
[[ "${#network_interfaces[@]}" -eq 1 && "${network_interfaces[0]}" == lo ]] ||
  fail_offline_acceptance 'offline container has a non-loopback network interface'

if ( : >/.a-quo-read-only-rootfs-probe ) 2>/dev/null; then
  rm -f -- /.a-quo-read-only-rootfs-probe
  fail_offline_acceptance 'container root filesystem is writable'
fi
if ( : >"${EXPECTED_WORKSPACE}/.a-quo-read-only-workspace-probe" ) 2>/dev/null; then
  rm -f -- "${EXPECTED_WORKSPACE}/.a-quo-read-only-workspace-probe"
  fail_offline_acceptance 'repository root is writable outside the target submount'
fi
target_probe="$(mktemp \
  "${EXPECTED_WORKSPACE}/target/.a-quo-target-write-probe.XXXXXX")" ||
  fail_offline_acceptance 'target output mount is not writable'
rm -f -- "${target_probe}"
home_probe="$(mktemp "${EXPECTED_HOME}/.a-quo-home-write-probe.XXXXXX")" ||
  fail_offline_acceptance 'observer home mount is not writable'
rm -f -- "${home_probe}"
[[ "$(readlink -f -- /usr/local/bin/mise)" == /usr/local/bin/mise ]] ||
  fail_offline_acceptance 'read-only Mise mount did not resolve to its reviewed path'
mise_digest="$(sha256sum -- /usr/local/bin/mise)" ||
  fail_offline_acceptance 'Mise bind mount cannot be hashed'
[[ "${mise_digest%% *}" == "${EXPECTED_MISE_SHA256}" ]] ||
  fail_offline_acceptance 'Mise bind mount bytes differ from the reviewed input'
if ( chmod u+w /usr/local/bin/mise ) 2>/dev/null; then
  fail_offline_acceptance 'Mise bind mount is writable'
fi

source_commit="$(git -C "${EXPECTED_WORKSPACE}" rev-parse --verify HEAD)"
readonly source_commit
[[ "${source_commit}" == "${EXPECTED_SOURCE_COMMIT}" ]] ||
  fail_offline_acceptance 'checkout does not match the expected source commit'
GIT_COMMON_DIRECTORY="$(
  git -C "${EXPECTED_WORKSPACE}" rev-parse \
    --path-format=absolute --git-common-dir
)" || fail_offline_acceptance 'checkout Git common directory could not be inspected'
readonly GIT_COMMON_DIRECTORY
[[ -d "${GIT_COMMON_DIRECTORY}" && ! -L "${GIT_COMMON_DIRECTORY}" ]] ||
  fail_offline_acceptance 'checkout Git common directory is unavailable or unsafe'
[[ ! -e "${GIT_COMMON_DIRECTORY}/info/grafts" &&
  ! -L "${GIT_COMMON_DIRECTORY}/info/grafts" ]] ||
  fail_offline_acceptance 'checkout contains a legacy graft file'
for alternate_file in \
  "${GIT_COMMON_DIRECTORY}/objects/info/alternates" \
  "${GIT_COMMON_DIRECTORY}/objects/info/http-alternates"; do
  [[ ! -e "${alternate_file}" && ! -L "${alternate_file}" ]] ||
    fail_offline_acceptance 'checkout uses an alternate Git object store'
done
[[ "$(git -C "${EXPECTED_WORKSPACE}" rev-parse --is-shallow-repository)" == false ]] ||
  fail_offline_acceptance 'checkout is shallow'
set +e
PARTIAL_CLONE_CONFIGURATION="$(
  git -C "${EXPECTED_WORKSPACE}" config --local --get-regexp \
    '^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$'
)"
PARTIAL_CLONE_STATUS="$?"
set -e
readonly PARTIAL_CLONE_CONFIGURATION PARTIAL_CLONE_STATUS
[[ "${PARTIAL_CLONE_STATUS}" -eq 1 &&
  -z "${PARTIAL_CLONE_CONFIGURATION}" ]] ||
  fail_offline_acceptance 'checkout has partial-clone or promisor configuration'
REPLACEMENT_REF="$(
  git -C "${EXPECTED_WORKSPACE}" for-each-ref --count=1 \
    --format='%(refname)' refs/replace
)" || fail_offline_acceptance 'checkout replacement refs could not be inspected'
readonly REPLACEMENT_REF
[[ -z "${REPLACEMENT_REF}" ]] ||
  fail_offline_acceptance 'checkout contains replacement refs'
[[ -z "$(git -C "${EXPECTED_WORKSPACE}" -c core.fsmonitor=false \
  status --porcelain=v1 --untracked-files=normal)" ]] ||
  fail_offline_acceptance 'checkout is dirty before static verification'
git -C "${EXPECTED_WORKSPACE}" cat-file -e \
  "${EXPECTED_SOURCE_COMMIT}^{commit}" 2>/dev/null ||
  fail_offline_acceptance 'expected source commit is unavailable'

"${EXPECTED_WORKSPACE}/scripts/verify-x86-package-needed-observation-lock.sh" \
  "${EXPECTED_WORKSPACE}/packaging/evaluation-input-locks/a-quo-x86_64-needed-observation-cbbe29b6-v1.lock" \
  >/dev/null
"${EXPECTED_WORKSPACE}/scripts/build-arch-package-skeleton.sh" "${PROFILE}"
[[ -d "${PACKAGE_OUTPUT}" && ! -L "${PACKAGE_OUTPUT}" ]] ||
  fail_offline_acceptance 'builder did not produce the fixed accepted package output'
(
  cd -- "${PACKAGE_OUTPUT}"
  sha256sum --check --strict SHA256SUMS
)
mapfile -d '' packages < <(
  find "${PACKAGE_OUTPUT}" -maxdepth 1 -type f \
    -name 'a-quo-*-x86_64.pkg.tar.zst' -print0
)
[[ "${#packages[@]}" -eq 1 ]] ||
  fail_offline_acceptance 'accepted package output has an unexpected package count'
readonly PACKAGE="${packages[0]}"
PACKAGE_SHA256="$(sha256sum -- "${PACKAGE}")"
PACKAGE_SHA256="${PACKAGE_SHA256%% *}"
readonly PACKAGE_SHA256

[[ ! -e "${ACCEPTANCE_ROOT}" && ! -L "${ACCEPTANCE_ROOT}" ]] ||
  fail_offline_acceptance 'refusing to replace existing static acceptance evidence'
install -d -m 0755 -- "${ACCEPTANCE_ROOT}"
readonly VERIFIER_RECEIPT="${ACCEPTANCE_ROOT}/VERIFIER-RECEIPT.txt"
"${EXPECTED_WORKSPACE}/scripts/verify-arch-package-skeleton.sh" \
  "${PACKAGE}" "${EXPECTED_SOURCE_COMMIT}" "${PROFILE}" \
  >"${VERIFIER_RECEIPT}"
chmod 0644 -- "${VERIFIER_RECEIPT}"
for required_receipt in \
  "profile_id=${EXPECTED_PROFILE_ID}" \
  "profile_sha256=${EXPECTED_PROFILE_SHA256}" \
  'profile_binding_role=package-target-policy' \
  'package_target_kind=physical-bare-metal' \
  'architecture=x86_64' \
  'physical_target_evidence=false' \
  "evidence_namespace=${EXPECTED_NAMESPACE}" \
  "needed_evidence=${EXPECTED_NEEDED_EVIDENCE}" \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  [[ "$(grep -Fxc -- "${required_receipt}" "${VERIFIER_RECEIPT}")" -eq 1 ]] ||
    fail_offline_acceptance "accepted verifier receipt lost binding: ${required_receipt}"
done
VERIFIER_RECEIPT_SHA256="$(sha256sum -- "${VERIFIER_RECEIPT}")"
VERIFIER_RECEIPT_SHA256="${VERIFIER_RECEIPT_SHA256%% *}"
readonly VERIFIER_RECEIPT_SHA256
cat >"${ACCEPTANCE_ROOT}/STATIC-ACCEPTANCE.txt" <<EOF
format=a-quo-x86_64-static-package-acceptance-v1
policy_commit=${EXPECTED_SOURCE_COMMIT}
profile_id=${EXPECTED_PROFILE_ID}
profile_sha256=${EXPECTED_PROFILE_SHA256}
profile_binding_role=package-target-policy
package_target_kind=physical-bare-metal
architecture=x86_64
evidence_namespace=${EXPECTED_NAMESPACE}
needed_evidence=${EXPECTED_NEEDED_EVIDENCE}
package_filename=$(basename -- "${PACKAGE}")
package_sha256=${PACKAGE_SHA256}
verifier_receipt_sha256=${VERIFIER_RECEIPT_SHA256}
build_environment=architecture-matched-host-nonhermetic
build_host_profile_match=not-established
native_hardware_claim=not-established
physical_target_evidence=false
package_static_acceptance=true
stage_4_completed=true
stage_5_executed=false
stage_6_authorized=false
cross_profile_evidence_accepted=false
aarch64_gate_satisfied_by_x86_64=false
publication_performed=false
EOF
chmod 0644 -- "${ACCEPTANCE_ROOT}/STATIC-ACCEPTANCE.txt"
(
  cd -- "${ACCEPTANCE_ROOT}"
  sha256sum STATIC-ACCEPTANCE.txt VERIFIER-RECEIPT.txt >SHA256SUMS
  chmod 0644 SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)
[[ "$(git -C "${EXPECTED_WORKSPACE}" rev-parse --verify HEAD)" == \
    "${EXPECTED_SOURCE_COMMIT}" &&
  -z "$(git -C "${EXPECTED_WORKSPACE}" -c core.fsmonitor=false \
    status --porcelain=v1 --untracked-files=normal)" ]] ||
  fail_offline_acceptance 'source checkout changed during static verification'

cat -- "${VERIFIER_RECEIPT}"
exec sha256sum --check --strict "${ACCEPTANCE_ROOT}/SHA256SUMS"
