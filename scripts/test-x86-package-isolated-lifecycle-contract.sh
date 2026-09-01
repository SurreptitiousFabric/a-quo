#!/usr/bin/env bash
# shellcheck disable=SC2016 # Exact workflow and source literals must not expand.

set -euo pipefail
export LC_ALL=C
umask 077

fail_contract() {
  printf 'x86_64 isolated lifecycle contract failed: %s\n' "$1" >&2
  exit 1
}

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly WORKFLOW="${REPOSITORY_ROOT}/.github/workflows/x86-package-isolated-lifecycle.yml"
readonly DOCKERFILE="${REPOSITORY_ROOT}/.github/workflows/x86-package-isolated-lifecycle.Dockerfile"
readonly OFFLINE_RUNNER="${SCRIPT_DIRECTORY}/run-x86-package-isolated-lifecycle-offline.sh"
readonly CONTAINER_VERIFIER="${SCRIPT_DIRECTORY}/verify-x86-package-isolated-lifecycle-container-policy.sh"
readonly F1_LOCK_VERIFIER="${SCRIPT_DIRECTORY}/verify-x86-package-stage4-f1-lock.sh"
readonly F1_LOCK="${REPOSITORY_ROOT}/packaging/evaluation-input-locks/a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock"
readonly TARGET_RESOLVER="${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh"
readonly BUILDER="${SCRIPT_DIRECTORY}/build-arch-package-skeleton.sh"
readonly PACKAGE_VERIFIER="${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh"
readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh"
readonly UPGRADE_SMOKE="${SCRIPT_DIRECTORY}/test-arch-package-upgrade-smoke.sh"
readonly UPGRADE_CONTRACT="${SCRIPT_DIRECTORY}/test-arch-package-upgrade-contract.sh"
readonly EXPECTED_WORKFLOW_SHA256=fc7f9e51855b07cfbe52903a238bb12dad9a2ec3273f924852068ae0f7c462d8
readonly EXPECTED_DOCKERFILE_SHA256=7ec1efb3216a481fea5e7dc5953f6a79dc80678081feb4e94b2e180f972563b7
readonly EXPECTED_OFFLINE_RUNNER_SHA256=0ce6fd8d3dfba16a5e909a8395c8fe5d9c93ad0c1293bca2d1ae50f9f603934c
readonly EXPECTED_CONTAINER_VERIFIER_SHA256=f70f96794ed37202139c0a9896d3d8fdf97c9cd5d73f0bed3400f20c3202fc36
readonly EXPECTED_F1_LOCK_VERIFIER_SHA256=56511a76b8f1dccf1c80489f3b4ecf7434a5122f5c30479cc0909903d87c7ea0
readonly EXPECTED_F1_LOCK_SHA256=333c9ae548e0f9c269a62859d11a4ccaf0ea4a88c7b0ed0c9a4f19ed785d5d48
readonly EXPECTED_TARGET_RESOLVER_SHA256=e1cbb386db5f890ae61509a2ca33acd6180c459c4a9778c203f9cefbe9b88831
readonly EXPECTED_BUILDER_SHA256=63c54347df158778bcafaa307acae49cec38e1eddf6727a1e5bf6316769d9fee
readonly EXPECTED_PACKAGE_VERIFIER_SHA256=f0427319b1d6903261903c3756d1c2bf77b261be9a298b413fe317c41d495c92
readonly EXPECTED_PROFILE_VERIFIER_SHA256=af95814e6844362afce6e5cc1a4275abc18b3202f62776e19f17c87a699dc2fc
readonly EXPECTED_UPGRADE_SMOKE_SHA256=48414a001bee094422790417e86eb950ae044db4258ef9d150b86f8a98e77f71
readonly EXPECTED_UPGRADE_CONTRACT_SHA256=7908867db8971b8ba04504c11c8aab7c6862cbb291b677c38c88abc3ea3fede5

for required_tool in \
  awk bash cmp cp cut grep head install ln mkdir mktemp mv rm sed sha256sum \
  sort stat tail tr wc; do
  command -v "${required_tool}" >/dev/null ||
    fail_contract "required offline contract tool is unavailable: ${required_tool}"
done

file_sha256() {
  local digest
  digest="$(sha256sum -- "$1")" || return 1
  printf '%s\n' "${digest%% *}"
}

while IFS='|' read -r path expected executable; do
  [[ -f "${path}" && ! -L "${path}" ]] ||
    fail_contract "reviewed input is unavailable or unsafe: ${path}"
  [[ "$(file_sha256 "${path}")" == "${expected}" ]] ||
    fail_contract "reviewed input bytes changed: ${path}"
  [[ "${executable}" == false || -x "${path}" ]] ||
    fail_contract "reviewed script is not executable: ${path}"
done <<EOF
${WORKFLOW}|${EXPECTED_WORKFLOW_SHA256}|false
${DOCKERFILE}|${EXPECTED_DOCKERFILE_SHA256}|false
${OFFLINE_RUNNER}|${EXPECTED_OFFLINE_RUNNER_SHA256}|true
${CONTAINER_VERIFIER}|${EXPECTED_CONTAINER_VERIFIER_SHA256}|true
${F1_LOCK_VERIFIER}|${EXPECTED_F1_LOCK_VERIFIER_SHA256}|true
${F1_LOCK}|${EXPECTED_F1_LOCK_SHA256}|false
${TARGET_RESOLVER}|${EXPECTED_TARGET_RESOLVER_SHA256}|true
${BUILDER}|${EXPECTED_BUILDER_SHA256}|true
${PACKAGE_VERIFIER}|${EXPECTED_PACKAGE_VERIFIER_SHA256}|true
${PROFILE_VERIFIER}|${EXPECTED_PROFILE_VERIFIER_SHA256}|true
${UPGRADE_SMOKE}|${EXPECTED_UPGRADE_SMOKE_SHA256}|true
${UPGRADE_CONTRACT}|${EXPECTED_UPGRADE_CONTRACT_SHA256}|true
EOF

"${F1_LOCK_VERIFIER}" >/dev/null ||
  fail_contract 'canonical F1 lock verification failed'

for dockerfile_literal in \
  'FROM archlinux:base-devel@sha256:a26046b7363dad8e2614858f4313949ae9b05c9c5f31de343a54864b9e20806f' \
  'https://archive.archlinux.org/repos/2026/08/24/\$repo/os/\$arch' \
  'pacman --noconfirm -Syu --needed' \
  'groupadd --gid 1001 a-quo-observer' \
  '--uid 1001 --gid 1001 a-quo-observer' \
  'org.opencontainers.image.a-quo-lifecycle="isolated-fakeroot-libalpm-reviewed"'; do
  grep -Fq -- "${dockerfile_literal}" "${DOCKERFILE}" ||
    fail_contract "lifecycle Dockerfile lost reviewed input: ${dockerfile_literal}"
done
if grep -Eq '^(ARG|ADD|COPY|ENTRYPOINT|CMD|USER|VOLUME)[[:space:]]' \
  "${DOCKERFILE}"; then
  fail_contract 'lifecycle Dockerfile gained copied context or runtime policy'
fi

line_of() {
  local literal="$1" path="$2" line
  line="$(grep -nF -- "${literal}" "${path}" | head -n 1 | cut -d : -f 1)"
  [[ "${line}" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "${line}"
}

verify_runner_policy() {
  local runner="$1" literal
  local target_safe target_probe mise_safe mise_probe f1_safe f1_probe
  local harness_call harness_success stage5_claim
  for literal in \
    'readonly EXPECTED_UID=1001' \
    'readonly EXPECTED_HOME=/home/a-quo-observer' \
    'readonly EXPECTED_F1_ROOT=/stage4-f1' \
    'GIT_CEILING_DIRECTORIES' \
    'GIT_DISCOVERY_ACROSS_FILESYSTEM' \
    'GIT_OPTIONAL_LOCKS' \
    "'^(include\\.path|includeif\\..*\\.path|core\\.(alternaterefscommand|alternaterefsprefixes)|extensions\\.partialclone|remote\\..*\\.(promisor|partialclonefilter))$'" \
    '"${GIT_COMMON_DIRECTORY}" == "${EXPECTED_WORKSPACE}/.git"' \
    '"${GIT_COMMON_DIRECTORY}/info" "${GIT_OBJECTS_DIRECTORY}/info"' \
    'require_safe_user_directory "${EXPECTED_WORKSPACE}/target" 755' \
    'require_safe_user_directory "${EXPECTED_HOME}" 700' \
    'offline container has a non-loopback network interface' \
    'container root filesystem is writable' \
    'repository root is writable outside the target submount' \
    'root-custodied F1 mount has an unexpected inventory' \
    'root-custodied F1 receipt differs from its exact canonical bytes' \
    'root-custodied F1 checksum manifest is not the exact two-line relative manifest' \
    'env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_SYSTEM -u GIT_CONFIG_NOSYSTEM' \
    '-u GIT_OPTIONAL_LOCKS "${UPGRADE_SMOKE}"' \
    'F2-BUILDER-VERIFIER-RECEIPT.txt' \
    'transaction_sequence=install-upgrade-remove-reinstall' \
    'stage_5_executed=true' \
    'stage_6_authorized=false' \
    'physical_target_evidence=false' \
    'aarch64_gate_satisfied_by_x86_64=false'; do
    grep -Fq -- "${literal}" "${runner}" || return 1
  done
  target_safe="$(line_of 'require_safe_user_directory "${EXPECTED_WORKSPACE}/target" 755' "${runner}")" || return 1
  target_probe="$(line_of 'target_probe="$(mktemp' "${runner}")" || return 1
  mise_safe="$(line_of '[[ -f /usr/local/bin/mise && ! -L /usr/local/bin/mise &&' "${runner}")" || return 1
  mise_probe="$(line_of 'if ( chmod u+w /usr/local/bin/mise ) 2>/dev/null; then' "${runner}")" || return 1
  f1_safe="$(line_of 'for f1_file in "${F1_ARCHIVE}" "${F1_CUSTODY_RECEIPT}" "${F1_CUSTODY_MANIFEST}"; do' "${runner}")" || return 1
  f1_probe="$(line_of 'if ( chmod u+w "${F1_ARCHIVE}" ) 2>/dev/null; then' "${runner}")" || return 1
  harness_call="$(line_of 'env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_SYSTEM -u GIT_CONFIG_NOSYSTEM' "${runner}")" || return 1
  harness_success="$(line_of "'passed isolated fakeroot/libalpm old-to-new transition, removal, and reinstall'" "${runner}")" || return 1
  stage5_claim="$(line_of 'stage_5_executed=true' "${runner}")" || return 1
  ((target_safe < target_probe && mise_safe < mise_probe && f1_safe < f1_probe &&
    harness_call < harness_success && harness_success < stage5_claim)) || return 1
  ! grep -Eq 'stage_6_authorized=true|physical_target_evidence=true|aarch64_gate_satisfied_by_x86_64=true' \
    "${runner}"
}

verify_runner_policy "${OFFLINE_RUNNER}" ||
  fail_contract 'offline runner policy or ordering changed'

for verifier_literal in \
  'if [[ "$#" -ne 10 ]]' \
  '($c.HostConfig.Mounts | length) == 5' \
  '($c.Mounts | length) == 5' \
  'exact_mount($f1_root; "/stage4-f1"; "explicit-read-only")' \
  'exact_runtime_mount($f1_root; "/stage4-f1"; false)' \
  '$c.HostConfig.NetworkMode == "none"' \
  '$c.HostConfig.ReadonlyRootfs == true' \
  '$c.Config.User == "1001:1001"' \
  '$c.HostConfig.CapDrop[0] | ascii_downcase' \
  '$c.HostConfig.SecurityOpt == ["no-new-privileges=true"]' \
  '/workspace/scripts/run-x86-package-isolated-lifecycle-offline.sh'; do
  grep -Fq -- "${verifier_literal}" "${CONTAINER_VERIFIER}" ||
    fail_contract "container verifier lost boundary: ${verifier_literal}"
done

readonly TEMPORARY_PREFIX="${TMPDIR:-/tmp}/a-quo-x86-lifecycle-contract."
[[ "${TEMPORARY_PREFIX}" == /* ]] || fail_contract 'temporary prefix is not absolute'
TEMPORARY_ROOT="$(mktemp -d "${TEMPORARY_PREFIX}XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")"
readonly TEMPORARY_IDENTITY
cleanup() {
  local status="$?" identity
  trap - EXIT
  case "${TEMPORARY_ROOT}" in "${TEMPORARY_PREFIX}"??????) ;; *) exit 1 ;; esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] || exit 1
  identity="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" || exit 1
  [[ "${identity}" == "${TEMPORARY_IDENTITY}" ]] || exit 1
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${status}"
}
trap cleanup EXIT

verify_workflow_syntax() {
  local workflow="$1" syntax_root block_count block
  syntax_root="${TEMPORARY_ROOT}/syntax.$(basename -- "${workflow}")"
  mkdir -m 0700 -- "${syntax_root}"
  awk -v output_directory="${syntax_root}" '
    /^        run: \|$/ { in_run = 1; block += 1; next }
    in_run && /^          / {
      print substr($0, 11) > (output_directory "/block." block ".sh")
      next
    }
    in_run && /^[[:space:]]*$/ {
      print "" > (output_directory "/block." block ".sh")
      next
    }
    in_run { in_run = 0 }
    END { print block }
  ' "${workflow}" >"${syntax_root}/count" || return 1
  block_count="$(<"${syntax_root}/count")"
  [[ "${block_count}" == 7 ]] || return 1
  for block in "${syntax_root}"/block.*.sh; do
    bash -n "${block}" 2>/dev/null || return 1
    ! grep -Fq -- GITHUB_TOKEN "${block}" || return 1
  done
}

verify_workflow_policy() {
  local workflow="$1" literal prepare download freeze run upload
  local preverify prefreeze start postverify remove stage5
  verify_workflow_syntax "${workflow}" || return 1
  for literal in \
    'workflow_dispatch:' \
    'actions: read' \
    'contents: read' \
    "if: \${{ github.repository == 'SurreptitiousFabric/a-quo' && github.ref == 'refs/heads/main' }}" \
    'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803' \
    'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c' \
    'artifact-ids: ${{ env.A_QUO_F1_ARTIFACT_ID }}' \
    'run-id: ${{ env.A_QUO_F1_WORKFLOW_RUN_ID }}' \
    'repository: SurreptitiousFabric/a-quo' \
    'github-token: ${{ secrets.GITHUB_TOKEN }}' \
    'skip-decompress: true' \
    'digest-mismatch: error' \
    'A_QUO_F1_ARTIFACT_ID: "9781997778"' \
    'A_QUO_F1_ARTIFACT_ZIP_SHA256: 15e24d068cd31b2de8cd23730303b5ad95a5d534d96c76076ddc015558d34f75' \
    '--platform linux/amd64 --network none --read-only --user 1001:1001' \
    '--cap-drop ALL --security-opt no-new-privileges=true' \
    '--mount "type=bind,src=${A_QUO_F1_ROOT_HOST},dst=/stage4-f1,readonly"' \
    'A_QUO_F1_DOWNLOAD_IDENTITY=' \
    'A_QUO_F1_ROOT_IDENTITY=' \
    'f1_root_custody_unchanged=true' \
    'F2-BUILDER-VERIFIER-RECEIPT.txt' \
    'dependency_acquisition_network_used=true' \
    'f1_artifact_acquisition_network_used=true' \
    'isolated_lifecycle_network_or_repository_sync_performed=false' \
    'stage_5_executed=true' \
    'stage_6_authorized=false' \
    'physical_target_evidence=false' \
    'aarch64_gate_satisfied_by_x86_64=false' \
    'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'; do
    grep -Fq -- "${literal}" "${workflow}" || return 1
  done
  [[ "$(grep -Fc -- 'github-token: ${{ secrets.GITHUB_TOKEN }}' "${workflow}")" -eq 1 ]]
  if grep -Eq \
    '^[[:space:]]+(push|pull_request|schedule):|^[[:space:]]+(actions|contents): write|--privileged|--cap-add|--device([=[:space:]])|docker\.sock|--network[=[:space:]]+host|--pid[=[:space:]]+host|--ipc[=[:space:]]+host|--uts[=[:space:]]+host|--userns[=[:space:]]+host|--env-file|--env[=[:space:]]+(MISE_GITHUB_TOKEN|GITHUB_TOKEN)(=|[[:space:]]|$)|stage_6_authorized=true|physical_target_evidence=true|aarch64_gate_satisfied_by_x86_64=true|^[[:space:]]+network_or_repository_sync_performed=false' \
    "${workflow}"; then
    return 1
  fi
  prepare="$(line_of '      - name: Prepare the private raw F1 download directory' "${workflow}")" || return 1
  download="$(line_of '      - name: Download the exact accepted F1 artifact without decompression' "${workflow}")" || return 1
  freeze="$(line_of '      - name: Freeze the exact raw F1 artifact under root custody' "${workflow}")" || return 1
  run="$(line_of '      - name: Run the non-root offline isolated lifecycle' "${workflow}")" || return 1
  upload="$(line_of '      - name: Upload only the fixed accepted x86_64 stage-5 evidence' "${workflow}")" || return 1
  preverify="$(line_of '            pre-start "${staging}/OFFLINE-CONTAINER-INSPECT.json"' "${workflow}")" || return 1
  prefreeze="$(line_of '          sudo chmod 0555 -- "${pre_root}"' "${workflow}")" || return 1
  start="$(line_of '          docker start --attach "${container_id}"' "${workflow}")" || return 1
  postverify="$(line_of '            post-exit "${staging}/OFFLINE-CONTAINER-INSPECT.after.json"' "${workflow}")" || return 1
  remove="$(line_of '          docker container rm -- "${container_id}"' "${workflow}")" || return 1
  stage5="$(line_of '          stage_5_executed=true' "${workflow}")" || return 1
  ((prepare < download && download < freeze && freeze < run && run < upload &&
    preverify < prefreeze && prefreeze < start && start < postverify &&
    postverify < remove && remove < stage5))
}

verify_workflow_policy "${WORKFLOW}" ||
  fail_contract 'canonical lifecycle workflow policy changed'

make_workflow_mutant() {
  local name="$1" expression="$2" replacement="$3" mutant
  mutant="${TEMPORARY_ROOT}/${name}.yml"
  sed "${expression}" "${WORKFLOW}" >"${mutant}"
  [[ ! -L "${mutant}" && "$(cmp -s -- "${mutant}" "${WORKFLOW}"; printf '%s' "$?")" != 0 ]]
  if verify_workflow_policy "${mutant}"; then
    fail_contract "workflow policy accepted hostile mutant: ${name}"
  fi
  : "${replacement}"
}

make_workflow_mutant permissions-write \
  's/actions: read/actions: write/' unused
make_workflow_mutant decompress-enabled \
  's/skip-decompress: true/skip-decompress: false/' unused
make_workflow_mutant wrong-artifact \
  's/A_QUO_F1_ARTIFACT_ID: "9781997778"/A_QUO_F1_ARTIFACT_ID: "1"/' unused
make_workflow_mutant writable-f1 \
  's#,dst=/stage4-f1,readonly"#,dst=/stage4-f1"#' unused
make_workflow_mutant stage6 \
  's/stage_6_authorized=false/stage_6_authorized=true/g' unused
make_workflow_mutant broad-network \
  's/isolated_lifecycle_network_or_repository_sync_performed=false/network_or_repository_sync_performed=false/' unused

RUNNER_CASE_MUTANT="${TEMPORARY_ROOT}/runner-case-mutant.sh"
sed 's/includeif\\\./includeIf\\\./' "${OFFLINE_RUNNER}" >"${RUNNER_CASE_MUTANT}"
if verify_runner_policy "${RUNNER_CASE_MUTANT}"; then
  fail_contract 'runner policy accepted case-sensitive Git-key mutant'
fi
RUNNER_ENV_MUTANT="${TEMPORARY_ROOT}/runner-env-mutant.sh"
sed 's/env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_SYSTEM -u GIT_CONFIG_NOSYSTEM/env/' \
  "${OFFLINE_RUNNER}" >"${RUNNER_ENV_MUTANT}"
if verify_runner_policy "${RUNNER_ENV_MUTANT}"; then
  fail_contract 'runner policy accepted shared-harness environment mutant'
fi

LOCK_REPOSITORY="${TEMPORARY_ROOT}/lock-repository"
install -d -m 0700 -- "${LOCK_REPOSITORY}/scripts" \
  "${LOCK_REPOSITORY}/packaging/evaluation-input-locks"
install -m 0755 -- "${F1_LOCK_VERIFIER}" \
  "${LOCK_REPOSITORY}/scripts/verify-x86-package-stage4-f1-lock.sh"
install -m 0644 -- "${F1_LOCK}" \
  "${LOCK_REPOSITORY}/packaging/evaluation-input-locks/a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock"
"${LOCK_REPOSITORY}/scripts/verify-x86-package-stage4-f1-lock.sh" >/dev/null ||
  fail_contract 'copied canonical F1 lock failed verification'
sed 's/stage_6_authorized=false/stage_6_authorized=true/' \
  "${F1_LOCK}" >"${LOCK_REPOSITORY}/packaging/evaluation-input-locks/F1.mutant"
mv -- "${LOCK_REPOSITORY}/packaging/evaluation-input-locks/F1.mutant" \
  "${LOCK_REPOSITORY}/packaging/evaluation-input-locks/a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock"
if "${LOCK_REPOSITORY}/scripts/verify-x86-package-stage4-f1-lock.sh" \
  >/dev/null 2>&1; then
  fail_contract 'F1 lock verifier accepted a stage-6 escalation'
fi
rm -- "${LOCK_REPOSITORY}/packaging/evaluation-input-locks/a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock"
ln -s -- "${F1_LOCK}" \
  "${LOCK_REPOSITORY}/packaging/evaluation-input-locks/a-quo-x86_64-stage4-f1-ee47d7f1-v1.lock"
if "${LOCK_REPOSITORY}/scripts/verify-x86-package-stage4-f1-lock.sh" \
  >/dev/null 2>&1; then
  fail_contract 'F1 lock verifier accepted a symlinked lock'
fi

printf '%s\n' \
  'x86_64 isolated lifecycle contract passed without Docker, network, package, service, plugin, or physical-target mutation'
