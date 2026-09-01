#!/usr/bin/env bash
# shellcheck disable=SC2016 # Exact workflow and source literals must not expand.

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly WORKFLOW="${REPOSITORY_ROOT}/.github/workflows/x86-package-static-acceptance.yml"
readonly HISTORICAL_WORKFLOW="${REPOSITORY_ROOT}/.github/workflows/x86-package-needed-observation.yml"
readonly DOCKERFILE="${REPOSITORY_ROOT}/.github/workflows/x86-package-static-acceptance.Dockerfile"
readonly OFFLINE_RUNNER="${SCRIPT_DIRECTORY}/run-x86-package-static-acceptance-offline.sh"
readonly CONTAINER_VERIFIER="${SCRIPT_DIRECTORY}/verify-x86-package-static-acceptance-container-policy.sh"
readonly HISTORICAL_CONTAINER_VERIFIER="${SCRIPT_DIRECTORY}/verify-x86-package-observation-container-policy.sh"
readonly TARGET_RESOLVER="${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh"
readonly LOCK_VERIFIER="${SCRIPT_DIRECTORY}/verify-x86-package-needed-observation-lock.sh"
readonly LOCK="${REPOSITORY_ROOT}/packaging/evaluation-input-locks/a-quo-x86_64-needed-observation-cbbe29b6-v1.lock"
readonly BUILDER="${SCRIPT_DIRECTORY}/build-arch-package-skeleton.sh"
readonly PACKAGE_VERIFIER="${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh"
readonly PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh"
readonly HISTORY_CONTRACT="${SCRIPT_DIRECTORY}/test-arch-package-needed-observation-history-contract.sh"
readonly EXPECTED_WORKFLOW_SHA256=ff5bcfb90862cf0cbb354cafeace2f17760efb73d34cf4fe892895edac0865a7
readonly EXPECTED_HISTORICAL_WORKFLOW_SHA256=aed53536817cf51c781adef660d9c9c5b9b8970f4b07e63f2bbcd677f702787e
readonly EXPECTED_DOCKERFILE_SHA256=188c7b97faa3ee059806b4144e069fd348aaf641bd017311085985e2253735e6
readonly EXPECTED_OFFLINE_RUNNER_SHA256=bd785361d0c373d5a6b4d7a319f0409d30fe40ad9402e71b975ad8016c38da8b
readonly EXPECTED_CONTAINER_VERIFIER_SHA256=7217616c6731eda0282dce73ec10a693989f8a0600625f32341b1a1987b60802
readonly EXPECTED_HISTORICAL_CONTAINER_VERIFIER_SHA256=ff05ea2112494984ba70bce5974ff81849a60447fae02b5f4625bd45827da205
readonly EXPECTED_TARGET_RESOLVER_SHA256=e1cbb386db5f890ae61509a2ca33acd6180c459c4a9778c203f9cefbe9b88831
readonly EXPECTED_LOCK_VERIFIER_SHA256=6f0d8f2ae41f73e094b7d16182e99ef285012eabea4acb894a46cc2ad2491f73
readonly EXPECTED_LOCK_SHA256=216ec3cd2e0698fd42390ade8394e0077ea9a915382de87ae1fe5e864966c9b0
readonly EXPECTED_BUILDER_SHA256=63c54347df158778bcafaa307acae49cec38e1eddf6727a1e5bf6316769d9fee
readonly EXPECTED_PACKAGE_VERIFIER_SHA256=f0427319b1d6903261903c3756d1c2bf77b261be9a298b413fe317c41d495c92
readonly EXPECTED_PROFILE_VERIFIER_SHA256=af95814e6844362afce6e5cc1a4275abc18b3202f62776e19f17c87a699dc2fc
readonly EXPECTED_HISTORY_CONTRACT_SHA256=3ff073cba8c5571e1b1909b27ef3471216cbab63aec4717168b69bd4979e8326

fail_contract() {
  printf 'x86_64 static package acceptance contract failed: %s\n' "$1" >&2
  exit 1
}

for required_tool in \
  awk bash cmp cut grep head mkdir mktemp mv rm sed sha256sum stat tail wc; do
  command -v "${required_tool}" >/dev/null ||
    fail_contract "required offline contract tool is unavailable: ${required_tool}"
done

file_sha256() {
  local path="$1"
  local digest
  digest="$(sha256sum -- "${path}")" || return 1
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
${HISTORICAL_WORKFLOW}|${EXPECTED_HISTORICAL_WORKFLOW_SHA256}|false
${DOCKERFILE}|${EXPECTED_DOCKERFILE_SHA256}|false
${OFFLINE_RUNNER}|${EXPECTED_OFFLINE_RUNNER_SHA256}|true
${CONTAINER_VERIFIER}|${EXPECTED_CONTAINER_VERIFIER_SHA256}|true
${HISTORICAL_CONTAINER_VERIFIER}|${EXPECTED_HISTORICAL_CONTAINER_VERIFIER_SHA256}|true
${TARGET_RESOLVER}|${EXPECTED_TARGET_RESOLVER_SHA256}|true
${LOCK_VERIFIER}|${EXPECTED_LOCK_VERIFIER_SHA256}|true
${LOCK}|${EXPECTED_LOCK_SHA256}|false
${BUILDER}|${EXPECTED_BUILDER_SHA256}|true
${PACKAGE_VERIFIER}|${EXPECTED_PACKAGE_VERIFIER_SHA256}|true
${PROFILE_VERIFIER}|${EXPECTED_PROFILE_VERIFIER_SHA256}|true
${HISTORY_CONTRACT}|${EXPECTED_HISTORY_CONTRACT_SHA256}|true
EOF

grep -Fq -- \
  "github.sha == 'cbbe29b6bc76949182777d7ec10dc73a219f7592'" \
  "${HISTORICAL_WORKFLOW}" ||
  fail_contract 'historical observation workflow is dispatchable after its exact commit'

for dockerfile_literal in \
  'FROM archlinux:base-devel@sha256:a26046b7363dad8e2614858f4313949ae9b05c9c5f31de343a54864b9e20806f' \
  'https://archive.archlinux.org/repos/2026/08/24/\$repo/os/\$arch' \
  'pacman --noconfirm -Syu --needed' \
  'groupadd --gid 1001 a-quo-observer' \
  '--uid 1001 --gid 1001 a-quo-observer' \
  'org.opencontainers.image.a-quo-acceptance="static-policy-reviewed"'; do
  grep -Fq -- "${dockerfile_literal}" "${DOCKERFILE}" ||
    fail_contract "static Dockerfile lost reviewed input: ${dockerfile_literal}"
done
if grep -Eq '^(ARG|ADD|COPY|ENTRYPOINT|CMD|USER|VOLUME)[[:space:]]' \
  "${DOCKERFILE}"; then
  fail_contract 'static Dockerfile gained an override, copied context, or runtime policy'
fi

for runner_literal in \
  'readonly EXPECTED_UID=1001' \
  'readonly EXPECTED_GID=1001' \
  'readonly EXPECTED_WORKSPACE=/workspace' \
  'readonly EXPECTED_NEEDED_EVIDENCE=reviewed-x86_64-needed-policy-sha256-216ec3cd2e0698fd42390ade8394e0077ea9a915382de87ae1fe5e864966c9b0' \
  'inherited Git repository override:' \
  'GIT_ALTERNATE_OBJECT_DIRECTORIES' \
  'GIT_CONFIG_COUNT' \
  'GIT_GRAFT_FILE' \
  'GIT_REPLACE_REF_BASE' \
  'objects/info/alternates' \
  'objects/info/http-alternates' \
  'extensions\.partialclone|remote\..*\.(promisor|partialclonefilter)' \
  'for-each-ref --count=1' \
  'refs/replace' \
  'cat-file -e' \
  'find /sys/class/net -mindepth 1 -maxdepth 1' \
  'container root filesystem is writable' \
  'repository root is writable outside the target submount' \
  'scripts/build-arch-package-skeleton.sh" "${PROFILE}"' \
  'scripts/verify-arch-package-skeleton.sh"' \
  'package_static_acceptance=true' \
  'stage_4_completed=true' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'physical_target_evidence=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  grep -Fq -- "${runner_literal}" "${OFFLINE_RUNNER}" ||
    fail_contract "offline acceptance runner lost boundary: ${runner_literal}"
done
if grep -Eq \
  'curl|wget|--observe-unconfirmed-needed|sudo|docker|test-arch-package-(lifecycle|upgrade)|stage_5_executed=true|stage_6_authorized=true' \
  "${OFFLINE_RUNNER}"; then
  fail_contract 'offline acceptance runner gained acquisition, observation, privilege, or lifecycle behavior'
fi
[[ "$(tail -n 1 "${OFFLINE_RUNNER}")" == \
  'exec sha256sum --check --strict "${ACCEPTANCE_ROOT}/SHA256SUMS"' ]] ||
  fail_contract 'offline acceptance checksum replay is no longer the final operation'

[[ "$(grep -Fc -- \
  '/workspace/scripts/run-x86-package-static-acceptance-offline.sh' \
  "${CONTAINER_VERIFIER}")" -eq 1 &&
  "$(grep -Fc -- \
  '/workspace/scripts/run-x86-package-needed-observation-offline.sh' \
  "${CONTAINER_VERIFIER}")" -eq 0 ]] ||
  fail_contract 'live container policy does not bind the accepted runner exactly once'

readonly TEMPORARY_PREFIX="${TMPDIR:-/tmp}/a-quo-x86-static-contract."
[[ "${TEMPORARY_PREFIX}" == /* ]] ||
  fail_contract 'temporary contract prefix must be absolute'
TEMPORARY_ROOT="$(mktemp -d "${TEMPORARY_PREFIX}XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_ROOT_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
  fail_contract 'temporary contract identity is unavailable'
readonly TEMPORARY_ROOT_IDENTITY
cleanup() {
  local exit_status="$?" current_identity
  trap - EXIT
  case "${TEMPORARY_ROOT}" in
    "${TEMPORARY_PREFIX}"??????) ;;
    *) fail_contract 'unsafe temporary contract cleanup target' ;;
  esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] ||
    fail_contract 'temporary contract cleanup target changed type'
  current_identity="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
    fail_contract 'temporary contract cleanup identity is unavailable'
  [[ "${current_identity}" == "${TEMPORARY_ROOT_IDENTITY}" ]] ||
    fail_contract 'temporary contract cleanup target was substituted'
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${exit_status}"
}
trap cleanup EXIT

WORKFLOW_SYNTAX_COUNTER=0
verify_workflow_run_block_syntax() {
  local workflow="$1"
  local syntax_root count_file block_count run_block
  ((WORKFLOW_SYNTAX_COUNTER += 1))
  syntax_root="${TEMPORARY_ROOT}/workflow-syntax-${WORKFLOW_SYNTAX_COUNTER}"
  count_file="${syntax_root}/count"
  mkdir -m 0700 -- "${syntax_root}"
  awk -v output_directory="${syntax_root}" -v count_file="${count_file}" '
    /^        run: \|$/ {
      in_run = 1
      block += 1
      next
    }
    in_run && /^          / {
      print substr($0, 11) > (output_directory "/block." block ".sh")
      next
    }
    in_run && /^[[:space:]]*$/ {
      print "" > (output_directory "/block." block ".sh")
      next
    }
    in_run { in_run = 0 }
    END { print block > count_file }
  ' "${workflow}" || return 1
  block_count="$(<"${count_file}")"
  [[ "${block_count}" == 5 ]] || return 1
  for run_block in \
    "${syntax_root}/block.1.sh" \
    "${syntax_root}/block.2.sh" \
    "${syntax_root}/block.3.sh" \
    "${syntax_root}/block.4.sh" \
    "${syntax_root}/block.5.sh"; do
    [[ -f "${run_block}" && ! -L "${run_block}" ]] || return 1
    bash -n "${run_block}" 2>/dev/null || return 1
  done
}

NORMALIZED_CONTAINER_VERIFIER="${TEMPORARY_ROOT}/historical-container-verifier"
sed \
  's#run-x86-package-static-acceptance-offline\.sh#run-x86-package-needed-observation-offline.sh#' \
  "${CONTAINER_VERIFIER}" >"${NORMALIZED_CONTAINER_VERIFIER}"
[[ "$(file_sha256 "${NORMALIZED_CONTAINER_VERIFIER}")" == \
  "${EXPECTED_HISTORICAL_CONTAINER_VERIFIER_SHA256}" ]] ||
  fail_contract 'live container policy differs from the fully tested historical policy beyond its runner command'

verify_workflow_policy() {
  local workflow="$1"
  local literal step_order expected_order
  local tmpdir_line create_line inspect_line verify_line receipt_line
  local start_line post_inspect_line post_verify_line compare_line
  local accepted_line remove_line hosted_acceptance_line upload_line

  verify_workflow_run_block_syntax "${workflow}" || return 1

  for literal in \
    'workflow_dispatch:' \
    "if: \${{ github.repository == 'SurreptitiousFabric/a-quo' && github.ref == 'refs/heads/main' }}" \
    'permissions:' 'contents: read' 'runs-on: ubuntu-24.04' \
    '[[ "${RUNNER_ARCH:-}" == X64 ]]' \
    '[[ "$(uname -m)" == x86_64 ]]' \
    'A_QUO_ARCH_BASE_IMAGE: archlinux:base-devel@sha256:a26046b7363dad8e2614858f4313949ae9b05c9c5f31de343a54864b9e20806f' \
    'A_QUO_DOCKERFILE_SHA256: 188c7b97faa3ee059806b4144e069fd348aaf641bd017311085985e2253735e6' \
    'A_QUO_CONTAINER_POLICY_VERIFIER_SHA256: 7217616c6731eda0282dce73ec10a693989f8a0600625f32341b1a1987b60802' \
    'A_QUO_OFFLINE_RUNNER_SHA256: bd785361d0c373d5a6b4d7a319f0409d30fe40ad9402e71b975ad8016c38da8b' \
    'A_QUO_TARGET_RESOLVER_SHA256: e1cbb386db5f890ae61509a2ca33acd6180c459c4a9778c203f9cefbe9b88831' \
    'A_QUO_PACKAGE_BUILDER_SHA256: 63c54347df158778bcafaa307acae49cec38e1eddf6727a1e5bf6316769d9fee' \
    'A_QUO_PACKAGE_VERIFIER_SHA256: f0427319b1d6903261903c3756d1c2bf77b261be9a298b413fe317c41d495c92' \
    'A_QUO_NEEDED_LOCK_SHA256: 216ec3cd2e0698fd42390ade8394e0077ea9a915382de87ae1fe5e864966c9b0' \
    'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803' \
    'jdx/mise-action@c2a87611a18de5b3828c5652fe268e992400cb5c' \
    'docker pull --platform linux/amd64 "${A_QUO_ARCH_BASE_IMAGE}"' \
    'docker build --no-cache --pull=false --network=default' \
    'docker create --name "${container_name}" --pull=never' \
    '--platform linux/amd64 --network none --read-only --user 1001:1001' \
    '--cap-drop ALL --security-opt no-new-privileges=true' \
    '--pids-limit 512 --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777' \
    '--mount "type=bind,src=${A_QUO_WORKSPACE_HOST},dst=/workspace,readonly"' \
    '--mount "type=bind,src=${A_QUO_TARGET_HOST},dst=/workspace/target"' \
    '--mount "type=bind,src=${A_QUO_OBSERVER_HOME_HOST},dst=/home/a-quo-observer"' \
    '--mount "type=bind,src=${A_QUO_MISE_HOST},dst=/usr/local/bin/mise,readonly"' \
    '--env TMPDIR=/home/a-quo-observer/tmp' \
    '/workspace/scripts/run-x86-package-static-acceptance-offline.sh' \
    'hosted_receipt_mutable_by_offline_container=false' \
    'docker_daemon_authority=host-root' \
    'docker_rootless_claim=false' \
    'package_static_acceptance=true' \
    'stage_4_completed=true' \
    'stage_5_executed=false' \
    'stage_6_authorized=false' \
    'physical_target_evidence=false' \
    'aarch64_gate_satisfied_by_x86_64=false' \
    'target/arch-package-skeleton/physical-x86_64-official-omarchy-4.0.2/' \
    'target/arch-package-static-acceptance/physical-x86_64-official-omarchy-4.0.2/' \
    '${{ runner.temp }}/a-quo-arch-package-static-acceptance/physical-x86_64-official-omarchy-4.0.2/' \
    'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'; do
    grep -Fq -- "${literal}" "${workflow}" || return 1
  done
  if grep -Eq \
    '^[[:space:]]+(push|pull_request|schedule):|^[[:space:]]+container:|--privileged|--cap-add|--device([=[:space:]])|docker\.sock|--network[=[:space:]]+host|--pid[=[:space:]]+host|--ipc[=[:space:]]+host|--uts[=[:space:]]+host|--userns[=[:space:]]+host|--env-file|--env[=[:space:]]+(MISE_GITHUB_TOKEN|GITHUB_TOKEN)(=|[[:space:]]|$)|--observe-unconfirmed-needed|test-arch-package-(lifecycle|upgrade)|stage_5_executed=true|stage_6_authorized=true' \
    "${workflow}"; then
    return 1
  fi
  [[ "$(grep -Fc -- '--pull=never' "${workflow}")" -eq 4 &&
    "$(grep -Fc -- '--network none' "${workflow}")" -eq 3 &&
    "$(grep -Fc -- '--read-only' "${workflow}")" -eq 4 &&
    "$(grep -Fc -- '--user 1001:1001' "${workflow}")" -eq 4 &&
    "$(grep -Fc -- '--pids-limit 128' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- '--cap-drop ALL' "${workflow}")" -eq 4 &&
    "$(grep -Fc -- '--security-opt no-new-privileges=true' "${workflow}")" -eq 4 &&
    "$(grep -Fo -- '--env ' "${workflow}" | wc -l)" -eq 11 &&
    "$(grep -Fc -- '--env HOME=/home/a-quo-observer' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- '--env MISE_CACHE_DIR=/home/a-quo-observer/.cache/mise' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- '--env MISE_DATA_DIR=/home/a-quo-observer/.local/share/mise' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- '--env MISE_TRUSTED_CONFIG_PATHS=/workspace' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- '--env TMPDIR=' "${workflow}")" -eq 1 &&
    "$(grep -Fc -- '--env MISE_OFFLINE=1' "${workflow}")" -eq 1 &&
    "$(grep -Fc -- '--env CARGO_NET_OFFLINE=true' "${workflow}")" -eq 1 &&
    "$(grep -Fc -- 'MISE_GITHUB_TOKEN' "${workflow}")" -eq 0 &&
    "$(grep -Fc -- 'GITHUB_TOKEN' "${workflow}")" -eq 0 &&
    "$(grep -Fc -- 'A_QUO_PREPARED_IMAGE_ID' "${workflow}")" -eq 10 &&
    "$(grep -Fc -- 'A_QUO_PREPARED_IMAGE_TAG' "${workflow}")" -eq 1 &&
    "$(grep -Fc -- 'run-x86-package-static-acceptance-offline.sh' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- 'run-x86-package-needed-observation-offline.sh' "${workflow}")" -eq 0 &&
    "$(grep -Fc -- 'package_static_acceptance=true' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- 'stage_4_completed=true' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- 'stage_4_completed=false' "${workflow}")" -eq 1 &&
    "$(grep -Fc -- 'stage_5_executed=false' "${workflow}")" -eq 3 &&
    "$(grep -Fc -- 'stage_6_authorized=false' "${workflow}")" -eq 3 &&
    "$(grep -Fc -- 'aarch64_gate_satisfied_by_x86_64=false' "${workflow}")" -eq 3 ]] ||
    return 1
  [[ "$(grep -Fc -- 'dst=/workspace,readonly' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- 'dst=/workspace/target"' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- 'dst=/home/a-quo-observer"' "${workflow}")" -eq 2 &&
    "$(grep -Fc -- 'dst=/usr/local/bin/mise,readonly' "${workflow}")" -eq 2 ]] ||
    return 1

  tmpdir_line="$(grep -nF -- '--env TMPDIR=/home/a-quo-observer/tmp' "${workflow}" | head -n 1 | cut -d : -f 1)"
  create_line="$(grep -nF 'docker create --name "${container_name}" --pull=never' "${workflow}" | head -n 1 | cut -d : -f 1)"
  inspect_line="$(grep -nF 'docker inspect "${container_id}" >"${staging}/OFFLINE-CONTAINER-INSPECT.json"' "${workflow}" | head -n 1 | cut -d : -f 1)"
  verify_line="$(grep -nF '          "${GITHUB_WORKSPACE}/scripts/verify-x86-package-static-acceptance-container-policy.sh"' "${workflow}" | head -n 1 | cut -d : -f 1)"
  receipt_line="$(grep -nF 'sudo install -d -o root -g root -m 0755 -- "${hosted_parent}" "${pre_root}"' "${workflow}" | head -n 1 | cut -d : -f 1)"
  start_line="$(grep -nF 'docker start --attach "${container_id}"' "${workflow}" | head -n 1 | cut -d : -f 1)"
  post_inspect_line="$(grep -nF 'docker inspect "${container_id}" >"${staging}/OFFLINE-CONTAINER-INSPECT.after.json"' "${workflow}" | head -n 1 | cut -d : -f 1)"
  post_verify_line="$(grep -nF '            post-exit' "${workflow}" | head -n 1 | cut -d : -f 1)"
  compare_line="$(grep -nF '          cmp -- "${staging}/OFFLINE-CONTAINER-CONFIG.json"' "${workflow}" | head -n 1 | cut -d : -f 1)"
  accepted_line="$(grep -nF '          acceptance_root="${A_QUO_TARGET_HOST}/arch-package-static-acceptance/' "${workflow}" | head -n 1 | cut -d : -f 1)"
  remove_line="$(grep -nF '          docker container rm -- "${container_id}"' "${workflow}" | head -n 1 | cut -d : -f 1)"
  hosted_acceptance_line="$(grep -nF '          cat >"${staging}/HOSTED-ACCEPTANCE.txt"' "${workflow}" | head -n 1 | cut -d : -f 1)"
  upload_line="$(grep -nF 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' "${workflow}" | head -n 1 | cut -d : -f 1)"
  for line in "${tmpdir_line}" "${create_line}" "${inspect_line}" \
    "${verify_line}" "${receipt_line}" "${start_line}" "${post_inspect_line}" \
    "${post_verify_line}" "${compare_line}" "${accepted_line}" \
    "${remove_line}" "${hosted_acceptance_line}" "${upload_line}"; do
    [[ "${line}" =~ ^[1-9][0-9]*$ ]] || return 1
  done
  ((tmpdir_line < create_line && create_line < inspect_line &&
    inspect_line < verify_line && verify_line < receipt_line &&
    receipt_line < start_line && start_line < post_inspect_line &&
    post_inspect_line < post_verify_line && post_verify_line < compare_line &&
    compare_line < accepted_line && accepted_line < remove_line &&
    remove_line < hosted_acceptance_line && hosted_acceptance_line < upload_line)) ||
    return 1
  step_order="$(sed -n 's/^      - name: //p' "${workflow}")"
  expected_order="$(printf '%s\n' \
    'Require the hosted x86_64 Docker boundary' \
    'Check out the exact complete revision' \
    'Prepare the pinned ephemeral Arch static-verification image' \
    'Acquire the pinned Mise binary' \
    'Acquire pinned Rust and locked Cargo dependencies' \
    'Run the non-root offline static verifier' \
    'Upload only the fixed accepted x86_64 stage-4 evidence' \
    'Remove the ephemeral static-verification container and image')"
  [[ "${step_order}" == "${expected_order}" ]]
}

verify_workflow_policy "${WORKFLOW}" ||
  fail_contract 'accepted-static workflow lost its reviewed hosted boundary'

assert_workflow_mutant_refused() {
  local name="$1" old="$2" new="$3"
  local mutant="${TEMPORARY_ROOT}/workflow-${name}.yml"
  local replacement="${TEMPORARY_ROOT}/workflow-${name}.replacement"
  local line replaced=false
  : >"${replacement}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${replaced}" == false && "${line}" == *"${old}"* ]]; then
      line="${line/"${old}"/"${new}"}"
      replaced=true
    fi
    printf '%s\n' "${line}" >>"${replacement}"
  done <"${WORKFLOW}"
  [[ "${replaced}" == true ]] ||
    fail_contract "workflow mutant source literal was unavailable: ${name}"
  mv -- "${replacement}" "${mutant}"
  if verify_workflow_policy "${mutant}"; then
    fail_contract "workflow policy accepted mutant: ${name}"
  fi
}

assert_workflow_mutant_refused network '--network none' '--network bridge'
assert_workflow_mutant_refused rootfs '--read-only --user 1001:1001' '--user 1001:1001'
assert_workflow_mutant_refused root-user '--user 1001:1001' '--user 0:0'
assert_workflow_mutant_refused capability '--cap-drop ALL' '--cap-add SYS_ADMIN'
assert_workflow_mutant_refused privilege '--security-opt no-new-privileges=true' '--security-opt no-new-privileges=false'
assert_workflow_mutant_refused source-rw 'dst=/workspace,readonly' 'dst=/workspace'
assert_workflow_mutant_refused mutable-image '"${A_QUO_PREPARED_IMAGE_ID}"' '"${A_QUO_PREPARED_IMAGE_TAG}"'
assert_workflow_mutant_refused pull-policy '--pull=never' '--pull=always'
assert_workflow_mutant_refused observation-runner 'run-x86-package-static-acceptance-offline.sh' 'run-x86-package-needed-observation-offline.sh'
assert_workflow_mutant_refused stage4-nonclaim 'stage_4_completed=true' 'stage_4_completed=false'
assert_workflow_mutant_refused stage5 'stage_5_executed=false' 'stage_5_executed=true'
assert_workflow_mutant_refused stage6 'stage_6_authorized=false' 'stage_6_authorized=true'
assert_workflow_mutant_refused aarch-claim 'aarch64_gate_satisfied_by_x86_64=false' 'aarch64_gate_satisfied_by_x86_64=true'
assert_workflow_mutant_refused masked-token-forwarding \
  '--env TMPDIR=/home/a-quo-observer/tmp' \
  '--env TMPDIR=/home/a-quo-observer/tmp --env MISE_GITHUB_TOKEN'
assert_workflow_mutant_refused mise-digest-shell-newline "== \\" '=='

printf '%s\n' \
  'reviewed x86_64 accepted-static policy preserves the historical suite and rejects hosted boundary mutants'
