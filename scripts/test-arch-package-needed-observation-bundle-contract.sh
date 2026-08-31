#!/usr/bin/env bash
# shellcheck disable=SC2016

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly BUILDER="${SCRIPT_DIRECTORY}/build-arch-package-skeleton.sh"
readonly TARGET_RESOLVER="${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh"
readonly X86_PROFILE_VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh"
readonly PACKAGE_VERIFIER="${SCRIPT_DIRECTORY}/verify-arch-package-skeleton.sh"
readonly BUNDLE_VERIFIER="${SCRIPT_DIRECTORY}/verify-arch-package-needed-observation-bundle.sh"
readonly CONTAINER_POLICY_VERIFIER="${SCRIPT_DIRECTORY}/verify-x86-package-observation-container-policy.sh"
readonly WORKFLOW="${REPOSITORY_ROOT}/.github/workflows/x86-package-needed-observation.yml"
readonly OBSERVATION_DOCKERFILE="${REPOSITORY_ROOT}/.github/workflows/x86-package-needed-observation.Dockerfile"
readonly OFFLINE_RUNNER="${SCRIPT_DIRECTORY}/run-x86-package-needed-observation-offline.sh"
readonly X86_PROFILE_NAME=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile
readonly AARCH_PROFILE_NAME=a-quo-omarchy4-aarch64-dec29fa-v2.profile
readonly EVIDENCE_NAMESPACE=physical-x86_64-official-omarchy-4.0.2
readonly EXPECTED_BUILDER_SHA256=63c54347df158778bcafaa307acae49cec38e1eddf6727a1e5bf6316769d9fee
readonly EXPECTED_TARGET_RESOLVER_SHA256=60cc574be2340c94c8da353489c104ac6fc202f10b2b9d983d368852c392ffea
readonly EXPECTED_X86_PROFILE_VERIFIER_SHA256=af95814e6844362afce6e5cc1a4275abc18b3202f62776e19f17c87a699dc2fc
readonly EXPECTED_PACKAGE_VERIFIER_SHA256=f0427319b1d6903261903c3756d1c2bf77b261be9a298b413fe317c41d495c92
readonly EXPECTED_BUNDLE_VERIFIER_SHA256=37fbab65fe963a9f82091647d66a95de472d6212552be41988b824452815d796
readonly EXPECTED_CONTAINER_POLICY_VERIFIER_SHA256=1d799ba93af4b497b695d1c9e4e44296bee16fc01c1bbfa936438f9d69d058a0
readonly EXPECTED_WORKFLOW_SHA256=573d98de8b7804ed3260e963d3b884916949318b21df645fd7b74fd4693d9467
readonly EXPECTED_OBSERVATION_DOCKERFILE_SHA256=9cd4aeddb6357ac16c44558f8ec0cce6cc7cd65fa96807702272700d0416b45c
readonly EXPECTED_OFFLINE_RUNNER_SHA256=7cfa23ef011fd6ca169f9c50584cbe623dd0f843a1bb3d15f53c9494c1303254

fail_contract() {
  printf 'x86_64 package NEEDED observation contract failed: %s\n' "$1" >&2
  exit 1
}

for required_tool in \
  awk bash chmod cp cut env find git grep head id install jq ln mkdir mktemp mv rm sed \
  sha256sum sort stat tar xargs; do
  command -v "${required_tool}" >/dev/null ||
    fail_contract "required offline contract tool is unavailable: ${required_tool}"
done
for production_input in \
  "${BUILDER}" "${TARGET_RESOLVER}" "${X86_PROFILE_VERIFIER}" \
  "${PACKAGE_VERIFIER}" "${BUNDLE_VERIFIER}" "${CONTAINER_POLICY_VERIFIER}" \
  "${OFFLINE_RUNNER}"; do
  [[ -f "${production_input}" && ! -L "${production_input}" &&
    -x "${production_input}" ]] ||
    fail_contract "production input is unavailable or unsafe: ${production_input}"
done
[[ -f "${WORKFLOW}" && ! -L "${WORKFLOW}" ]] ||
  fail_contract 'manual observation workflow is unavailable or unsafe'
[[ -f "${OBSERVATION_DOCKERFILE}" && ! -L "${OBSERVATION_DOCKERFILE}" ]] ||
  fail_contract 'observation Dockerfile is unavailable or unsafe'

file_sha256() {
  local path="$1"
  local digest
  digest="$(sha256sum -- "${path}")" || return 1
  printf '%s\n' "${digest%% *}"
}

[[ "$(file_sha256 "${BUILDER}")" == "${EXPECTED_BUILDER_SHA256}" ]] ||
  fail_contract 'package builder bytes changed without observation-contract review'
[[ "$(file_sha256 "${TARGET_RESOLVER}")" == \
  "${EXPECTED_TARGET_RESOLVER_SHA256}" ]] ||
  fail_contract 'package-target resolver bytes changed'
[[ "$(file_sha256 "${X86_PROFILE_VERIFIER}")" == \
  "${EXPECTED_X86_PROFILE_VERIFIER_SHA256}" ]] ||
  fail_contract 'x86_64 profile verifier bytes changed'
[[ "$(file_sha256 "${PACKAGE_VERIFIER}")" == \
  "${EXPECTED_PACKAGE_VERIFIER_SHA256}" ]] ||
  fail_contract 'accepted package verifier bytes changed'
[[ "$(file_sha256 "${BUNDLE_VERIFIER}")" == \
  "${EXPECTED_BUNDLE_VERIFIER_SHA256}" ]] ||
  fail_contract 'bundle verifier bytes changed without hostile-contract review'
[[ "$(file_sha256 "${CONTAINER_POLICY_VERIFIER}")" == \
  "${EXPECTED_CONTAINER_POLICY_VERIFIER_SHA256}" ]] ||
  fail_contract 'stopped-container policy verifier bytes changed without hostile-contract review'
[[ "$(file_sha256 "${WORKFLOW}")" == "${EXPECTED_WORKFLOW_SHA256}" ]] ||
  fail_contract 'manual workflow bytes changed without boundary review'
[[ "$(file_sha256 "${OBSERVATION_DOCKERFILE}")" == \
  "${EXPECTED_OBSERVATION_DOCKERFILE_SHA256}" ]] ||
  fail_contract 'observation Dockerfile bytes changed without boundary review'
[[ "$(file_sha256 "${OFFLINE_RUNNER}")" == \
  "${EXPECTED_OFFLINE_RUNNER_SHA256}" ]] ||
  fail_contract 'offline observation runner bytes changed without boundary review'

for dockerfile_literal in \
  'FROM archlinux:base-devel@sha256:a26046b7363dad8e2614858f4313949ae9b05c9c5f31de343a54864b9e20806f' \
  'https://archive.archlinux.org/repos/2026/08/24/\$repo/os/\$arch' \
  'pacman --noconfirm -Syu --needed' \
  'git' 'libarchive' 'shadow' 'util-linux' 'wayland' 'zstd' \
  'groupadd --gid 1001 a-quo-observer' \
  '--uid 1001 --gid 1001 a-quo-observer' \
  'org.opencontainers.image.a-quo-acceptance="false"'; do
  grep -Fq -- "${dockerfile_literal}" "${OBSERVATION_DOCKERFILE}" ||
    fail_contract "observation Dockerfile lost required input: ${dockerfile_literal}"
done
if grep -Eq '^(ARG|ADD|COPY|ENTRYPOINT|CMD|USER|VOLUME)[[:space:]]' \
  "${OBSERVATION_DOCKERFILE}"; then
  fail_contract 'observation Dockerfile gained an override, copied context, or runtime policy'
fi

for offline_runner_literal in \
  'readonly EXPECTED_UID=1001' \
  'readonly EXPECTED_GID=1001' \
  'readonly EXPECTED_WORKSPACE=/workspace' \
  'readonly EXPECTED_MISE_SHA256=cff4832ded79af2951e800bddcb5a22acac58630d765a2d062c1180680a0bb35' \
  'find /sys/class/net -mindepth 1 -maxdepth 1' \
  'container root filesystem is writable' \
  'repository root is writable outside the target submount' \
  'target output mount is not writable' \
  'observer home mount is not writable' \
  'Mise bind mount is writable' \
  'rev-parse --is-shallow-repository' \
  'status --porcelain=v1 --untracked-files=normal' \
  '--observe-unconfirmed-needed' \
  'builder_status}" -eq 1' \
  'exec "${EXPECTED_WORKSPACE}/scripts/verify-arch-package-needed-observation-bundle.sh"'; do
  grep -Fq -- "${offline_runner_literal}" "${OFFLINE_RUNNER}" ||
    fail_contract "offline runner lost required boundary: ${offline_runner_literal}"
done
if grep -Eq 'curl|wget|--network|sudo|docker|test-arch-package-(lifecycle|upgrade)' \
  "${OFFLINE_RUNNER}"; then
  fail_contract 'offline runner gained acquisition, orchestration, privilege, or stage-5 behavior'
fi
EXPECTED_OFFLINE_RUNNER_TAIL="$(printf '%s %s\n%s\n' \
  'exec "${EXPECTED_WORKSPACE}/scripts/verify-arch-package-needed-observation-bundle.sh"' \
  $'\\' '  "${EXPECTED_SOURCE_COMMIT}"')"
readonly EXPECTED_OFFLINE_RUNNER_TAIL
[[ "$(tail -n 2 "${OFFLINE_RUNNER}")" == "${EXPECTED_OFFLINE_RUNNER_TAIL}" ]] ||
  fail_contract 'offline bundle verifier is no longer the final operation'

for container_policy_literal in \
  'offline container policy invariant failed: %s' \
  '"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' \
  '"LANG=C.UTF-8"' \
  '"MISE_OFFLINE=1"' \
  '"CARGO_NET_OFFLINE=true"' \
  'def exact_mount($source; $target_path; $read_only_state):' \
  'has("ReadOnly")' \
  '([$c.HostConfig.Mounts[].Source] | unique | length) == 4' \
  '([$c.HostConfig.Mounts[].Target] | unique | length) == 4' \
  'exact_mount($workspace; "/workspace"; "explicit-read-only")' \
  'exact_mount($target; "/workspace/target"; "omitted-writable")' \
  'exact_mount($observer_home; "/home/a-quo-observer"; "omitted-writable")' \
  'exact_mount($mise; "/usr/local/bin/mise"; "explicit-read-only")' \
  '["mode=1777", "nodev", "noexec", "nosuid", "rw"]' \
  '$c.HostConfig.SecurityOpt == ["no-new-privileges=true"]' \
  'offline container policy passed exact stopped-container checks'; do
  grep -Fq -- "${container_policy_literal}" "${CONTAINER_POLICY_VERIFIER}" ||
    fail_contract "container policy verifier lost required boundary: ${container_policy_literal}"
done
if grep -Eq \
  'HostConfig\.Mounts\[[0-9]+\]|MISE_GITHUB_TOKEN|GITHUB_TOKEN|(^|[[:space:]])env([[:space:]]|$)|cat[[:space:]].*INSPECT' \
  "${CONTAINER_POLICY_VERIFIER}"; then
  fail_contract 'container policy verifier gained positional mounts or raw environment/inspect output'
fi

verify_workflow_policy() {
  local workflow="$1"
  local workflow_literal
  local workflow_step_order
  local expected_workflow_step_order
  local tmpdir_line create_line inspect_line verify_line receipt_line start_line upload_line

for workflow_literal in \
  'workflow_dispatch:' \
  "if: \${{ github.repository == 'SurreptitiousFabric/a-quo' && github.ref == 'refs/heads/main' }}" \
  'permissions:' \
  'contents: read' \
  'runs-on: ubuntu-24.04' \
  '[[ "${RUNNER_ARCH:-}" == X64 ]]' \
  '[[ "$(uname -m)" == x86_64 ]]' \
  '[[ "$(docker version --format '\''{{.Server.Os}}/{{.Server.Arch}}'\'')" == linux/amd64 ]]' \
  'A_QUO_ARCH_BASE_IMAGE: archlinux:base-devel@sha256:a26046b7363dad8e2614858f4313949ae9b05c9c5f31de343a54864b9e20806f' \
  'A_QUO_ARCH_BASE_REPO_DIGEST: archlinux@sha256:a26046b7363dad8e2614858f4313949ae9b05c9c5f31de343a54864b9e20806f' \
  'A_QUO_DOCKERFILE_SHA256: 9cd4aeddb6357ac16c44558f8ec0cce6cc7cd65fa96807702272700d0416b45c' \
  'A_QUO_CONTAINER_POLICY_VERIFIER_SHA256: 1d799ba93af4b497b695d1c9e4e44296bee16fc01c1bbfa936438f9d69d058a0' \
  'A_QUO_OFFLINE_RUNNER_SHA256: 7cfa23ef011fd6ca169f9c50584cbe623dd0f843a1bb3d15f53c9494c1303254' \
  'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803' \
  'jdx/mise-action@c2a87611a18de5b3828c5652fe268e992400cb5c' \
  'version: 2026.8.16' \
  'sha256: cff4832ded79af2951e800bddcb5a22acac58630d765a2d062c1180680a0bb35' \
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
  'install -d -m 0700 -- "${observer_home_host}/tmp"' \
  'acquisition_tmp_host="$(realpath -e -- "${observer_home_host}/tmp")"' \
  '[[ "${acquisition_tmp_host}" == "${observer_home_host}/tmp" &&' \
  '[[ "$(stat -c '\''%u:%a'\'' -- "${acquisition_tmp_host}")" == 1001:700 ]]' \
  '--env TMPDIR=/home/a-quo-observer/tmp' \
  'staging_prefix="${RUNNER_TEMP}/a-quo-x86-hosted-receipt."' \
  'staging_identity="$(stat -c '\''%d:%i:%u'\'' -- "${staging}")"' \
  'current_identity="$(stat -c '\''%d:%i:%u'\'' -- "${staging}")"' \
  'rm -rf -- "${staging}"' \
  'docker inspect "${container_id}" >"${staging}/OFFLINE-CONTAINER-INSPECT.json"' \
  'scripts/verify-x86-package-observation-container-policy.sh"' \
  'docker start --attach "${container_id}"' \
  'run-x86-package-needed-observation-offline.sh' \
  'hosted_receipt_storage=host-root-created-runner-temp-outside-all-container-mounts' \
  'hosted_receipt_mutable_by_offline_container=false' \
  'docker_daemon_authority=host-root' \
  'docker_rootless_claim=false' \
  'offline_container_persistent_user_rw_bind_count=2' \
  'dependency_acquisition_tmpdir=/home/a-quo-observer/tmp' \
  'dependency_acquisition_tmpdir_scope=networked-observer-home-bind' \
  'offline_tmpdir_override=false' \
  'chmod 0555 -- "${hosted_root}"' \
  '"${staging}/OFFLINE-CONTAINER-CONFIG.after.json"' \
  'cmp -- "${staging}/OFFLINE-CONTAINER-CONFIG.json"' \
  'docker container rm -- "${container_id}"' \
  'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' \
  'path: |' \
  'target/arch-package-needed-observations/physical-x86_64-official-omarchy-4.0.2/' \
  '${{ runner.temp }}/a-quo-arch-package-needed-observations/physical-x86_64-official-omarchy-4.0.2/' \
  'retention-days: 14' \
  'include-hidden-files: true' \
  'package_static_acceptance=false' \
  'stage_4_completed=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  grep -Fq -- "${workflow_literal}" "${workflow}" || return 1
done
if grep -Eq \
  '^[[:space:]]+(push|pull_request|schedule):|--privileged|--cap-add|--device([=[:space:]])|docker\.sock|--network[=[:space:]]+host|--pid[=[:space:]]+host|--ipc[=[:space:]]+host|--uts[=[:space:]]+host|--userns[=[:space:]]+host|--env-file|--env[=[:space:]]+(MISE_GITHUB_TOKEN|GITHUB_TOKEN)(=|[[:space:]]|$)|HostConfig\.Mounts\[[0-9]+\]|test-arch-package-(lifecycle|upgrade)' \
  "${workflow}"; then
  return 1
fi
if grep -Eq '^[[:space:]]+container:' "${workflow}" ||
  grep -Fq -- '--mount "type=bind,src=${RUNNER_TEMP}' "${workflow}" ||
  grep -Fq -- 'dst=/var/run/docker.sock' "${workflow}" ||
  grep -Fq -- 'stage_5_executed=true' "${workflow}" ||
  grep -Fq -- 'stage_6_authorized=true' "${workflow}"; then
  return 1
fi
[[ "$(grep -Fc -- '--pull=never' "${workflow}")" -eq 4 &&
  "$(grep -Fc -- '--network none' "${workflow}")" -eq 3 &&
  "$(grep -Fc -- '--read-only' "${workflow}")" -eq 4 &&
  "$(grep -Fc -- '--user 1001:1001' "${workflow}")" -eq 4 &&
  "$(grep -Fc -- '--pids-limit 128' "${workflow}")" -eq 2 &&
  "$(grep -Fc -- '--cap-drop ALL' "${workflow}")" -eq 4 &&
  "$(grep -Fc -- '--security-opt no-new-privileges=true' "${workflow}")" -eq 4 ]] ||
  return 1
[[ "$(grep -Fc -- 'A_QUO_PREPARED_IMAGE_ID' "${workflow}")" -eq 9 &&
  "$(grep -Fc -- 'A_QUO_PREPARED_IMAGE_TAG' "${workflow}")" -eq 1 &&
  "$(grep -Fc -- '--env TMPDIR=' "${workflow}")" -eq 1 &&
  "$(grep -Fc -- '--env TMPDIR=/home/a-quo-observer/tmp' "${workflow}")" -eq 1 &&
  "$(grep -Fc -- 'OFFLINE-CONTAINER-CONFIG.after.json' "${workflow}")" -eq 2 ]] ||
  return 1
[[ "$(grep -Fc -- 'dst=/workspace,readonly' "${workflow}")" -eq 2 &&
  "$(grep -Fc -- 'dst=/workspace/target"' "${workflow}")" -eq 2 &&
  "$(grep -Fc -- 'dst=/home/a-quo-observer"' "${workflow}")" -eq 2 &&
  "$(grep -Fc -- 'dst=/usr/local/bin/mise,readonly' "${workflow}")" -eq 2 ]] ||
  return 1
tmpdir_line="$(grep -nF -- '--env TMPDIR=/home/a-quo-observer/tmp' \
  "${workflow}" | head -n 1 | cut -d : -f 1)"
create_line="$(grep -nF 'docker create --name "${container_name}" --pull=never' \
  "${workflow}" | head -n 1 | cut -d : -f 1)"
inspect_line="$(grep -nF 'docker inspect "${container_id}" >"${staging}/OFFLINE-CONTAINER-INSPECT.json"' \
  "${workflow}" | head -n 1 | cut -d : -f 1)"
verify_line="$(grep -nF '          "${GITHUB_WORKSPACE}/scripts/verify-x86-package-observation-container-policy.sh"' \
  "${workflow}" | head -n 1 | cut -d : -f 1)"
receipt_line="$(grep -nF 'sudo install -d -o root -g root -m 0755' \
  "${workflow}" | head -n 1 | cut -d : -f 1)"
start_line="$(grep -nF 'docker start --attach "${container_id}"' \
  "${workflow}" | head -n 1 | cut -d : -f 1)"
upload_line="$(grep -nF 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' \
  "${workflow}" | head -n 1 | cut -d : -f 1)"
for line in \
  "${tmpdir_line}" "${create_line}" "${inspect_line}" "${verify_line}" \
  "${receipt_line}" "${start_line}" "${upload_line}"; do
  [[ "${line}" =~ ^[1-9][0-9]*$ ]] || return 1
done
((tmpdir_line < create_line && create_line < inspect_line && inspect_line < verify_line &&
  verify_line < receipt_line &&
  receipt_line < start_line && start_line < upload_line)) || return 1
workflow_step_order="$(sed -n 's/^      - name: //p' "${workflow}")"
expected_workflow_step_order="$(printf '%s\n' \
  'Require the hosted x86_64 Docker boundary' \
  'Check out the exact complete revision' \
  'Prepare the pinned ephemeral Arch tool image' \
  'Acquire the pinned Mise binary' \
  'Acquire pinned Rust and locked Cargo dependencies' \
  'Create inspect and run the non-root offline container' \
  'Upload only the fixed non-accepting evidence namespace' \
  'Remove the ephemeral observation container and derived image')"
[[ "${workflow_step_order}" == "${expected_workflow_step_order}" ]]
}

verify_workflow_policy "${WORKFLOW}" ||
  fail_contract 'manual workflow lost its reviewed non-root offline Docker boundary'

readonly TEMPORARY_PREFIX="${TMPDIR:-/tmp}/a-quo-needed-observation-contract."
[[ "${TEMPORARY_PREFIX}" == /* ]] ||
  fail_contract 'temporary contract prefix must be absolute'
TEMPORARY_ROOT="$(mktemp -d "${TEMPORARY_PREFIX}XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_ROOT_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
  fail_contract 'temporary contract identity is unavailable'
readonly TEMPORARY_ROOT_IDENTITY
cleanup() {
  local exit_status="$?"
  local current_identity
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

assert_workflow_mutant_refused() {
  local mutant="$1"
  local description="$2"
  if verify_workflow_policy "${mutant}"; then
    fail_contract "workflow policy accepted mutant: ${description}"
  fi
}

readonly POLICY_CONTAINER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
readonly POLICY_IMAGE_ID=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
readonly POLICY_SOURCE_COMMIT=cccccccccccccccccccccccccccccccccccccccc
readonly POLICY_WORKSPACE=/host/workspace
readonly POLICY_TARGET=/host/workspace/target
readonly POLICY_OBSERVER_HOME=/host/observer-home
readonly POLICY_MISE=/host/tools/mise
readonly POLICY_FIXTURE="${TEMPORARY_ROOT}/container-policy.json"
jq -n \
  --arg container_id "${POLICY_CONTAINER_ID}" \
  --arg image_id "${POLICY_IMAGE_ID}" \
  --arg workspace "${POLICY_WORKSPACE}" \
  --arg target "${POLICY_TARGET}" \
  --arg observer_home "${POLICY_OBSERVER_HOME}" \
  --arg mise "${POLICY_MISE}" \
  --arg commit "${POLICY_SOURCE_COMMIT}" '[{
    Id: $container_id,
    Image: $image_id,
    Config: {
      User: "1001:1001",
      WorkingDir: "/workspace",
      Entrypoint: ["/usr/bin/bash"],
      Cmd: ["--noprofile", "--norc",
        "/workspace/scripts/run-x86-package-needed-observation-offline.sh", $commit],
      Env: [
        "MISE_OFFLINE=1",
        "LANG=C.UTF-8",
        "HOME=/home/a-quo-observer",
        "CARGO_NET_OFFLINE=true",
        "MISE_DATA_DIR=/home/a-quo-observer/.local/share/mise",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "MISE_TRUSTED_CONFIG_PATHS=/workspace",
        "MISE_CACHE_DIR=/home/a-quo-observer/.cache/mise"
      ]
    },
    HostConfig: {
      NetworkMode: "none",
      ReadonlyRootfs: true,
      Privileged: false,
      CapAdd: null,
      CapDrop: ["ALL"],
      SecurityOpt: ["no-new-privileges=true"],
      Devices: [],
      Binds: null,
      PidMode: "",
      IpcMode: "private",
      UTSMode: "",
      UsernsMode: "",
      PidsLimit: 512,
      Tmpfs: {"/tmp": "nodev,rw,mode=1777,nosuid,noexec"},
      Mounts: [
        {Type: "bind", Source: $observer_home,
          Target: "/home/a-quo-observer"},
        {Type: "bind", Source: $mise,
          Target: "/usr/local/bin/mise", ReadOnly: true},
        {Type: "bind", Source: $target,
          Target: "/workspace/target"},
        {Type: "bind", Source: $workspace,
          Target: "/workspace", ReadOnly: true}
      ]
    },
    Mounts: []
  }]' >"${POLICY_FIXTURE}"
chmod 0600 -- "${POLICY_FIXTURE}"

run_container_policy_verifier() {
  local fixture="$1"
  "${CONTAINER_POLICY_VERIFIER}" \
    "${fixture}" "${POLICY_CONTAINER_ID}" "${POLICY_IMAGE_ID}" \
    "${POLICY_WORKSPACE}" "${POLICY_TARGET}" \
    "${POLICY_OBSERVER_HOME}" "${POLICY_MISE}" "${POLICY_SOURCE_COMMIT}"
}

POLICY_SUCCESS_OUTPUT="$(run_container_policy_verifier "${POLICY_FIXTURE}")"
readonly POLICY_SUCCESS_OUTPUT
[[ "${POLICY_SUCCESS_OUTPUT}" == \
  'offline container policy passed exact stopped-container checks' ]] ||
  fail_contract 'reordered exact stopped-container fixture was refused'

POLICY_LOWERCASE_CAPDROP="${TEMPORARY_ROOT}/container-policy-capdrop-lowercase.json"
jq '.[0].HostConfig.CapDrop = ["all"]' \
  "${POLICY_FIXTURE}" >"${POLICY_LOWERCASE_CAPDROP}"
[[ "$(run_container_policy_verifier "${POLICY_LOWERCASE_CAPDROP}")" == \
  'offline container policy passed exact stopped-container checks' ]] ||
  fail_contract 'case-equivalent exact capability drop was refused'

assert_container_policy_mutant_refused() {
  local mutant="$1"
  local expected_invariant="$2"
  local description="$3"
  local output status
  set +e
  output="$(run_container_policy_verifier "${mutant}" 2>&1)"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && "${output}" == \
    "offline container policy invariant failed: ${expected_invariant}" ]] ||
    fail_contract "container policy accepted or over-reported mutant: ${description}"
}

create_and_refuse_policy_mutant() {
  local name="$1"
  local filter="$2"
  local expected_invariant="$3"
  local description="$4"
  local mutant="${TEMPORARY_ROOT}/container-policy-${name}.json"
  jq "${filter}" "${POLICY_FIXTURE}" >"${mutant}"
  assert_container_policy_mutant_refused \
    "${mutant}" "${expected_invariant}" "${description}"
}

create_and_refuse_policy_mutant id \
  '.[0].Id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"' \
  container-id 'container ID substitution'
create_and_refuse_policy_mutant image \
  '.[0].Image = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"' \
  prepared-image-id 'prepared image substitution'
create_and_refuse_policy_mutant user \
  '.[0].Config.User = "0:0"' process-user 'root process'
create_and_refuse_policy_mutant workdir \
  '.[0].Config.WorkingDir = "/tmp"' working-directory 'wrong working directory'
create_and_refuse_policy_mutant command \
  '.[0].Config.Cmd[-1] = "dddddddddddddddddddddddddddddddddddddddd"' \
  entrypoint-command 'source commit command substitution'
create_and_refuse_policy_mutant env-extra \
  '.[0].Config.Env += ["UNREVIEWED=synthetic"]' environment 'extra environment name'
create_and_refuse_policy_mutant env-token \
  '.[0].Config.Env += ["GITHUB_TOKEN=synthetic-not-a-secret"]' \
  environment 'token environment name'
create_and_refuse_policy_mutant env-missing \
  '.[0].Config.Env |= map(select(. != "MISE_OFFLINE=1"))' \
  environment 'missing offline environment'
create_and_refuse_policy_mutant env-value \
  '.[0].Config.Env |= map(if startswith("MISE_OFFLINE=") then "MISE_OFFLINE=0" else . end)' \
  environment 'wrong offline environment value'
create_and_refuse_policy_mutant network \
  '.[0].HostConfig.NetworkMode = "bridge"' network-mode 'network sharing'
create_and_refuse_policy_mutant rootfs \
  '.[0].HostConfig.ReadonlyRootfs = false' read-only-rootfs 'writable rootfs'
create_and_refuse_policy_mutant privileged \
  '.[0].HostConfig.Privileged = true' privileged 'privileged container'
create_and_refuse_policy_mutant cap-add \
  '.[0].HostConfig.CapAdd = ["SYS_ADMIN"]' added-capabilities 'added capability'
create_and_refuse_policy_mutant cap-drop-extra \
  '.[0].HostConfig.CapDrop = ["ALL", "NET_RAW"]' \
  dropped-capabilities 'extra capability-drop entry'
create_and_refuse_policy_mutant security-missing \
  '.[0].HostConfig.SecurityOpt = []' security-options 'missing no-new-privileges'
create_and_refuse_policy_mutant security-false \
  '.[0].HostConfig.SecurityOpt = ["no-new-privileges=false"]' \
  security-options 'disabled no-new-privileges'
create_and_refuse_policy_mutant security-extra \
  '.[0].HostConfig.SecurityOpt += ["label=disable"]' \
  security-options 'extra security option'
create_and_refuse_policy_mutant device \
  '.[0].HostConfig.Devices = [{PathOnHost:"/dev/kvm"}]' devices 'device exposure'
create_and_refuse_policy_mutant legacy-bind \
  '.[0].HostConfig.Binds = ["/tmp:/host"]' legacy-binds 'legacy bind exposure'
create_and_refuse_policy_mutant pid \
  '.[0].HostConfig.PidMode = "host"' pid-namespace 'host PID namespace'
create_and_refuse_policy_mutant ipc \
  '.[0].HostConfig.IpcMode = "host"' ipc-namespace 'host IPC namespace'
create_and_refuse_policy_mutant uts \
  '.[0].HostConfig.UTSMode = "host"' uts-namespace 'host UTS namespace'
create_and_refuse_policy_mutant userns \
  '.[0].HostConfig.UsernsMode = "host"' user-namespace 'host user namespace'
create_and_refuse_policy_mutant pids \
  '.[0].HostConfig.PidsLimit = 0' process-limit 'unbounded process count'
create_and_refuse_policy_mutant tmpfs-exec \
  '.[0].HostConfig.Tmpfs["/tmp"] = "rw,exec,nosuid,nodev,mode=1777"' \
  tmpfs 'executable tmpfs'
create_and_refuse_policy_mutant tmpfs-unknown \
  '.[0].HostConfig.Tmpfs["/tmp"] += ",size=1g"' tmpfs 'unknown tmpfs option'
create_and_refuse_policy_mutant tmpfs-duplicate \
  '.[0].HostConfig.Tmpfs["/tmp"] += ",noexec"' tmpfs 'duplicate tmpfs option'
create_and_refuse_policy_mutant mount-missing \
  'del(.[0].HostConfig.Mounts[-1])' mount-inventory 'missing mount'
create_and_refuse_policy_mutant mount-duplicate \
  '.[0].HostConfig.Mounts[3] = .[0].HostConfig.Mounts[2]' \
  mount-inventory 'duplicate mount'
create_and_refuse_policy_mutant mount-extra \
  '.[0].HostConfig.Mounts += [{Type:"bind",Source:"/host/extra",Target:"/extra",ReadOnly:true}]' \
  mount-inventory 'extra mount'
create_and_refuse_policy_mutant mount-crossed \
  '.[0].HostConfig.Mounts[3].Source = "/host/workspace/target"' \
  mount-inventory 'cross-mapped source and target'
create_and_refuse_policy_mutant mount-readonly \
  '.[0].HostConfig.Mounts[3].ReadOnly = false' \
  mount-inventory 'repository mount made writable'
create_and_refuse_policy_mutant mount-readonly-null \
  '.[0].HostConfig.Mounts[3].ReadOnly = null' \
  mount-inventory 'repository mount read-only field replaced with null'
create_and_refuse_policy_mutant mount-readonly-missing \
  'del(.[0].HostConfig.Mounts[3].ReadOnly)' \
  mount-inventory 'repository mount read-only field omitted'
create_and_refuse_policy_mutant mount-mise-false \
  '.[0].HostConfig.Mounts[1].ReadOnly = false' \
  mount-inventory 'Mise mount made writable'
create_and_refuse_policy_mutant mount-mise-null \
  '.[0].HostConfig.Mounts[1].ReadOnly = null' \
  mount-inventory 'Mise mount read-only field replaced with null'
create_and_refuse_policy_mutant mount-mise-missing \
  'del(.[0].HostConfig.Mounts[1].ReadOnly)' \
  mount-inventory 'Mise mount read-only field omitted'
create_and_refuse_policy_mutant mount-target-false \
  '.[0].HostConfig.Mounts[2].ReadOnly = false' \
  mount-inventory 'target writable representation substituted with false'
create_and_refuse_policy_mutant mount-target-true \
  '.[0].HostConfig.Mounts[2].ReadOnly = true' \
  mount-inventory 'target mount made read-only'
create_and_refuse_policy_mutant mount-target-null \
  '.[0].HostConfig.Mounts[2].ReadOnly = null' \
  mount-inventory 'target writable representation substituted with null'
create_and_refuse_policy_mutant mount-home-false \
  '.[0].HostConfig.Mounts[0].ReadOnly = false' \
  mount-inventory 'observer-home writable representation substituted with false'
create_and_refuse_policy_mutant mount-home-true \
  '.[0].HostConfig.Mounts[0].ReadOnly = true' \
  mount-inventory 'observer-home mount made read-only'
create_and_refuse_policy_mutant mount-home-null \
  '.[0].HostConfig.Mounts[0].ReadOnly = null' \
  mount-inventory 'observer-home writable representation substituted with null'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-network.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/--network none/s//--network bridge/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'offline network sharing'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-rootfs.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/--read-only --user 1001:1001/s//--user 1001:1001/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'writable container root filesystem'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-root-user.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/--user 1001:1001/s//--user 0:0/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'root container process'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-capability.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/--cap-drop ALL/s//--cap-drop NET_RAW/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'capability restoration'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-new-privileges.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/no-new-privileges=true/s//no-new-privileges=false/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'new-privileges enablement'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-source-rw.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/dst=\/workspace,readonly/s//dst=\/workspace/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'writable repository source mount'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-privileged.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker create --name/a\--privileged' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'privileged container'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-docker-socket.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker create --name/a\--mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'Docker socket mount'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-image-tag.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/A_QUO_PREPARED_IMAGE_ID/s//A_QUO_PREPARED_IMAGE_TAG/' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'mutable prepared-image tag substitution'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-pull-policy.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/--pull=never/s//--pull=missing/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'missing local-image-only pull policy'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-acquisition-tmpdir.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/--env TMPDIR=\/home\/a-quo-observer\/tmp/s//--env TMPDIR=\/tmp/' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'acquisition temp moved to container tmpfs'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-inherited-tmpdir.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/--env TMPDIR=\/home\/a-quo-observer\/tmp/s//--env TMPDIR/' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'host-inherited acquisition TMPDIR'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-offline-tmpdir.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker create --name/a\              --env TMPDIR=/home/a-quo-observer/tmp' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'TMPDIR override added to offline container'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-env-file.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker run --rm --pull=never/a\            --env-file /tmp/host-environment' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'host environment file propagation'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-token-env.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker run --rm --pull=never/a\            --env MISE_GITHUB_TOKEN' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'host token environment propagation'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-receipt-mount.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker create --name/a\              --mount "type=bind,src=${RUNNER_TEMP},dst=/receipt"' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'receipt storage mounted into container'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-host-architecture.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/\[\[ "${RUNNER_ARCH:-}" == X64 \]\]/d' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'missing hosted-runner architecture check'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-post-inspection.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i 's/OFFLINE-CONTAINER-CONFIG\.after\.json/OFFLINE-CONTAINER-CONFIG.post.json/g' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'missing post-exit container reinspection'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-cap-add.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker create --name/a\              --cap-add SYS_ADMIN' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'added container capability'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-device.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker create --name/a\              --device=/dev/kvm' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'host device exposure'

for host_namespace in pid ipc uts userns; do
  WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-host-${host_namespace}.yml"
  cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
  sed -i "/docker create --name/a\\              --${host_namespace}=host" \
    "${WORKFLOW_MUTANT}"
  assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" \
    "host ${host_namespace} namespace sharing"
done

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-stage-escalation.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/stage_5_executed=false/s//stage_5_executed=true/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'stage-5 claim escalation'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-stage-6-escalation.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '0,/stage_6_authorized=false/s//stage_6_authorized=true/' "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'stage-6 authorization escalation'

WORKFLOW_MUTANT="${TEMPORARY_ROOT}/workflow-uninspected-start.yml"
cp -- "${WORKFLOW}" "${WORKFLOW_MUTANT}"
sed -i '/docker inspect "${container_id}" >"${staging}\/OFFLINE-CONTAINER-INSPECT.json"/i\          docker start --attach "${container_id}"' \
  "${WORKFLOW_MUTANT}"
assert_workflow_mutant_refused "${WORKFLOW_MUTANT}" 'container start before inspection and receipt'

copy_profile_inputs() {
  local destination="$1"
  mkdir -p -- "${destination}/scripts" \
    "${destination}/packaging/evaluation-targets"
  install -m 0755 -- \
    "${SCRIPT_DIRECTORY}/resolve-arch-package-target.sh" \
    "${SCRIPT_DIRECTORY}/verify-omarchy-evaluation-target-profile.sh" \
    "${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh" \
    "${destination}/scripts/"
  install -m 0644 -- \
    "${REPOSITORY_ROOT}/packaging/evaluation-targets/${AARCH_PROFILE_NAME}" \
    "${REPOSITORY_ROOT}/packaging/evaluation-targets/${X86_PROFILE_NAME}" \
    "${destination}/packaging/evaluation-targets/"
}

# Exercise the builder with a committed synthetic verifier so the accepted
# default and observation-only branches can be compared without a real build.
readonly BUILDER_REPOSITORY="${TEMPORARY_ROOT}/builder-repository"
readonly BUILDER_STUBS="${TEMPORARY_ROOT}/builder-stubs"
readonly LEGACY_OUTPUT="${TEMPORARY_ROOT}/legacy-output"
readonly HOSTILE_CALLER_OUTPUT="${TEMPORARY_ROOT}/caller-selected-output"
mkdir -m 0755 -- "${BUILDER_REPOSITORY}" "${BUILDER_STUBS}" \
  "${LEGACY_OUTPUT}" "${HOSTILE_CALLER_OUTPUT}"
copy_profile_inputs "${BUILDER_REPOSITORY}"
mkdir -p -- "${BUILDER_REPOSITORY}/packaging/arch"
install -m 0755 -- "${BUILDER}" \
  "${BUILDER_REPOSITORY}/scripts/build-arch-package-skeleton.sh"
install -m 0644 -- "${REPOSITORY_ROOT}/packaging/arch/PKGBUILD.in" \
  "${BUILDER_REPOSITORY}/packaging/arch/PKGBUILD.in"
printf '%s\n' '/target/' >"${BUILDER_REPOSITORY}/.gitignore"
printf '%s\n' '[tools]' 'rust = "1.98.0"' \
  >"${BUILDER_REPOSITORY}/.mise.toml"
printf '%s\n' '[workspace.package]' 'version = "0.1.0"' \
  >"${BUILDER_REPOSITORY}/Cargo.toml"

install -m 0755 /dev/stdin \
  "${BUILDER_REPOSITORY}/scripts/verify-arch-package-skeleton.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != --observe-unconfirmed-needed ]]; then
  printf '%s\n' accepted-verifier-stdout-v1
  exit 0
fi
package="$2"
commit="$3"
package_sha256="$(sha256sum -- "${package}")"
package_sha256="${package_sha256%% *}"
printf '%s\n' \
  'format=a-quo-arch-package-needed-observation-v1' \
  'observation_authority=none' \
  "package_sha256=${package_sha256}" \
  "expected_source_commit=${commit}" \
  'profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'profile_sha256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d' \
  'profile_binding_role=package-target-policy' \
  'package_target_kind=physical-bare-metal' \
  'architecture=x86_64' \
  'evidence_namespace=physical-x86_64-official-omarchy-4.0.2' \
  'verification_host_architecture=x86_64' \
  'verification_host_profile_match=not-established' \
  'native_hardware_claim=not-established' \
  'physical_target_evidence=false' \
  'cross_profile_evidence_accepted=false' \
  'aarch64_gate_satisfied_by_x86_64=false' \
  'observed_needed_usr_bin_a-quo=synthetic.so.0' \
  'observed_needed_usr_bin_a-quo-daemon=synthetic.so.0' \
  'observed_needed_usr_lib_a-quo_a-quo-consent=synthetic.so.0' \
  'needed_observation_accepted_as_policy=false'
printf '%s\n' \
  'x86_64 NEEDED observation completed but cannot accept the package until policy is reviewed and frozen' >&2
exit 1
STUB

git -C "${BUILDER_REPOSITORY}" init --quiet --initial-branch=main
git -C "${BUILDER_REPOSITORY}" add --all
git -C "${BUILDER_REPOSITORY}" \
  -c user.name='A Quo x86 observation contract' \
  -c user.email='noreply@a-quo.invalid' \
  commit --quiet --message='synthetic builder fixture'
BUILDER_COMMIT="$(git -C "${BUILDER_REPOSITORY}" rev-parse HEAD)"
readonly BUILDER_COMMIT

install -m 0755 /dev/stdin "${BUILDER_STUBS}/uname" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -m ]]
printf '%s\n' "${TEST_PACKAGE_ARCHITECTURE:-aarch64}"
STUB
install -m 0755 /dev/stdin "${BUILDER_STUBS}/mise" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "${TEST_PACKAGE_ARCHITECTURE:-aarch64}" in
  aarch64) host=aarch64-unknown-linux-gnu ;;
  x86_64) host=x86_64-unknown-linux-gnu ;;
  *) exit 64 ;;
esac
printf '%s\n' "host: ${host}" 'release: 1.98.0'
STUB
install -m 0755 /dev/stdin "${BUILDER_STUBS}/makepkg" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == --printsrcinfo ]]; then
  printf '%s\n' 'pkgbase = a-quo' 'pkgver = synthetic' 'arch = synthetic'
  exit 0
fi
pkgver="$(sed -n 's/^pkgver=//p' PKGBUILD)"
arch="$(sed -n "s/^arch=('\([^']*\)').*/\1/p" PKGBUILD)"
printf '%s\n' synthetic-package >"${PKGDEST}/a-quo-${pkgver}-1-${arch}.pkg.tar.zst"
STUB

set +e
LEGACY_STDOUT="$(
  PATH="${BUILDER_STUBS}:/usr/bin" \
    TEST_PACKAGE_ARCHITECTURE=aarch64 \
    A_QUO_ARCH_PACKAGE_OUTPUT_DIRECTORY="${LEGACY_OUTPUT}" \
    "${BUILDER_REPOSITORY}/scripts/build-arch-package-skeleton.sh"
)"
LEGACY_STATUS="$?"
set -e
readonly LEGACY_STDOUT LEGACY_STATUS
readonly LEGACY_FINAL="${LEGACY_OUTPUT}/${BUILDER_COMMIT}"
readonly LEGACY_PACKAGE_NAME="a-quo-0.1.0.r1.g${BUILDER_COMMIT:0:12}-1-aarch64.pkg.tar.zst"
[[ "${LEGACY_STATUS}" -eq 0 && "${LEGACY_STDOUT}" == "$(printf '%s\n' \
  'accepted-verifier-stdout-v1' \
  './.SRCINFO: OK' \
  './PACKAGE-SKELETON-METADATA.txt: OK' \
  './PKGBUILD: OK' \
  "./${LEGACY_PACKAGE_NAME}: OK" \
  "./a-quo-${BUILDER_COMMIT}.tar: OK" \
  "non-publishable package skeleton written to: ${LEGACY_FINAL}")" ]] ||
  fail_contract 'default AArch64 builder stdout or success behavior changed'
[[ -d "${LEGACY_FINAL}" &&
  ! -e "${LEGACY_OUTPUT}/phase-a-aarch64-dec29fa/${BUILDER_COMMIT}" ]] ||
  fail_contract 'default AArch64 builder lost its exact legacy output path'
AARCH_MAPPING="$(
  "${BUILDER_REPOSITORY}/scripts/resolve-arch-package-target.sh"
)"
readonly AARCH_MAPPING
[[ "${AARCH_MAPPING}" == *$'architecture=aarch64\n'* &&
  "${AARCH_MAPPING}" == *$'evidence_namespace=phase-a-aarch64-dec29fa\n'* &&
  "${AARCH_MAPPING}" == *$'output_layout=legacy-commit\n'* ]] ||
  fail_contract 'no-argument resolver no longer selects the exact legacy AArch64 lane'

readonly BUILDER_X86_PROFILE="${BUILDER_REPOSITORY}/packaging/evaluation-targets/${X86_PROFILE_NAME}"
set +e
X86_BUILDER_STDOUT="$(
  PATH="${BUILDER_STUBS}:/usr/bin" \
    TEST_PACKAGE_ARCHITECTURE=x86_64 \
    A_QUO_ARCH_PACKAGE_OUTPUT_DIRECTORY="${HOSTILE_CALLER_OUTPUT}" \
    "${BUILDER_REPOSITORY}/scripts/build-arch-package-skeleton.sh" \
    --observe-unconfirmed-needed "${BUILDER_X86_PROFILE}"
)" 2>"${TEMPORARY_ROOT}/x86-builder.stderr"
X86_BUILDER_STATUS="$?"
set -e
readonly X86_BUILDER_STDOUT X86_BUILDER_STATUS
readonly BUILDER_OBSERVATION_BUNDLE="${BUILDER_REPOSITORY}/target/arch-package-needed-observations/${EVIDENCE_NAMESPACE}/${BUILDER_COMMIT}"
[[ "${X86_BUILDER_STATUS}" -eq 1 &&
  "${X86_BUILDER_STDOUT}" == *'needed_observation_accepted_as_policy=false'* &&
  -d "${BUILDER_OBSERVATION_BUNDLE}" ]] ||
  fail_contract 'x86 builder did not retain exactly one non-accepting observation'
[[ -z "$(find "${HOSTILE_CALLER_OUTPUT}" -mindepth 1 -print -quit)" ]] ||
  fail_contract 'x86 observation honored a caller-selected output path'
[[ "$(<"${BUILDER_OBSERVATION_BUNDLE}/OBSERVATION-NONACCEPTING")" == \
  *$'package_static_acceptance=false\n'* &&
  "$(<"${BUILDER_OBSERVATION_BUNDLE}/OBSERVATION-NONACCEPTING")" == \
  *$'stage_4_completed=false\n'* ]] ||
  fail_contract 'x86 builder retained a positive acceptance or stage claim'

# Build a structurally valid x86 package fixture around the unchanged package
# verifier. Synthetic ELF observations exercise control flow only.
readonly BUNDLE_REPOSITORY="${TEMPORARY_ROOT}/bundle-repository"
readonly PACKAGE_STAGING="${TEMPORARY_ROOT}/package-staging"
readonly OBSERVATION_STUBS="${TEMPORARY_ROOT}/observation-stubs"
mkdir -m 0755 -- "${BUNDLE_REPOSITORY}" "${PACKAGE_STAGING}" \
  "${OBSERVATION_STUBS}"
copy_profile_inputs "${BUNDLE_REPOSITORY}"
mkdir -p -- \
  "${BUNDLE_REPOSITORY}/docs" \
  "${BUNDLE_REPOSITORY}/packaging/arch" \
  "${BUNDLE_REPOSITORY}/packaging/systemd" \
  "${PACKAGE_STAGING}/usr/bin" \
  "${PACKAGE_STAGING}/usr/lib/a-quo" \
  "${PACKAGE_STAGING}/usr/lib/systemd/user" \
  "${PACKAGE_STAGING}/usr/lib/systemd/user-preset" \
  "${PACKAGE_STAGING}/usr/share/a-quo" \
  "${PACKAGE_STAGING}/usr/share/doc/a-quo" \
  "${PACKAGE_STAGING}/usr/share/licenses/a-quo"
install -m 0755 -- "${PACKAGE_VERIFIER}" "${BUNDLE_VERIFIER}" \
  "${BUNDLE_REPOSITORY}/scripts/"
for source_file in \
  Cargo.toml LICENSE README.md SECURITY.md \
  docs/PACKAGING.md docs/THREAT-MODEL.md \
  packaging/arch/PKGBUILD.in packaging/provider-registry-v1.json \
  packaging/systemd/90-a-quo.preset \
  packaging/systemd/a-quo-daemon.service; do
  install -m 0644 -- "${REPOSITORY_ROOT}/${source_file}" \
    "${BUNDLE_REPOSITORY}/${source_file}"
done
printf '%s\n' '/target/' >"${BUNDLE_REPOSITORY}/.gitignore"
git -C "${BUNDLE_REPOSITORY}" init --quiet --initial-branch=main
git -C "${BUNDLE_REPOSITORY}" add --all
git -C "${BUNDLE_REPOSITORY}" \
  -c user.name='A Quo x86 bundle contract' \
  -c user.email='noreply@a-quo.invalid' \
  commit --quiet --message='synthetic bundle fixture'
BUNDLE_COMMIT="$(git -C "${BUNDLE_REPOSITORY}" rev-parse HEAD)"
readonly BUNDLE_COMMIT
readonly PACKAGE_VERSION="0.1.0.r1.g${BUNDLE_COMMIT:0:12}-1"
readonly PACKAGE_NAME="a-quo-${PACKAGE_VERSION}-x86_64.pkg.tar.zst"
readonly BUNDLE="${BUNDLE_REPOSITORY}/target/arch-package-needed-observations/${EVIDENCE_NAMESPACE}/${BUNDLE_COMMIT}"
mkdir -p -- "${BUNDLE}"

find "${PACKAGE_STAGING}" -type d -exec chmod 0755 -- {} +
for binary_path in \
  usr/bin/a-quo usr/bin/a-quo-daemon usr/lib/a-quo/a-quo-consent; do
  printf '%s\n' synthetic-non-elf >"${PACKAGE_STAGING}/${binary_path}"
  chmod 0755 -- "${PACKAGE_STAGING}/${binary_path}"
done
printf '%s\n' synthetic >"${PACKAGE_STAGING}/.BUILDINFO"
printf '%s\n' synthetic >"${PACKAGE_STAGING}/.MTREE"
printf '%s\n' \
  'pkgname = a-quo' \
  "pkgver = ${PACKAGE_VERSION}" \
  'arch = x86_64' \
  'xdata = pkgtype=pkg' \
  'xdata = a-quo-profile-id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'xdata = a-quo-evidence-namespace=physical-x86_64-official-omarchy-4.0.2' \
  'depend = bubblewrap' \
  'depend = glibc' \
  'depend = libgcc' \
  'depend = noto-fonts' \
  'depend = omarchy' \
  'depend = openssh' \
  'depend = systemd' \
  'depend = util-linux' \
  'depend = wayland' \
  >"${PACKAGE_STAGING}/.PKGINFO"
chmod 0644 -- "${PACKAGE_STAGING}/.BUILDINFO" \
  "${PACKAGE_STAGING}/.MTREE" "${PACKAGE_STAGING}/.PKGINFO"
install -m 0644 -- \
  "${BUNDLE_REPOSITORY}/packaging/systemd/a-quo-daemon.service" \
  "${PACKAGE_STAGING}/usr/lib/systemd/user/a-quo-daemon.service"
install -m 0644 -- \
  "${BUNDLE_REPOSITORY}/packaging/systemd/90-a-quo.preset" \
  "${PACKAGE_STAGING}/usr/lib/systemd/user-preset/90-a-quo.preset"
install -m 0644 -- \
  "${BUNDLE_REPOSITORY}/packaging/provider-registry-v1.json" \
  "${PACKAGE_STAGING}/usr/share/a-quo/provider-registry-v1.json"
install -m 0644 -- "${BUNDLE_REPOSITORY}/README.md" \
  "${PACKAGE_STAGING}/usr/share/doc/a-quo/README.md"
install -m 0644 -- "${BUNDLE_REPOSITORY}/docs/PACKAGING.md" \
  "${PACKAGE_STAGING}/usr/share/doc/a-quo/PACKAGING.md"
install -m 0644 -- "${BUNDLE_REPOSITORY}/SECURITY.md" \
  "${PACKAGE_STAGING}/usr/share/doc/a-quo/SECURITY.md"
install -m 0644 -- "${BUNDLE_REPOSITORY}/docs/THREAT-MODEL.md" \
  "${PACKAGE_STAGING}/usr/share/doc/a-quo/THREAT-MODEL.md"
install -m 0644 -- "${BUNDLE_REPOSITORY}/LICENSE" \
  "${PACKAGE_STAGING}/usr/share/licenses/a-quo/LICENSE"
readonly PACKAGE_INVENTORY="${TEMPORARY_ROOT}/package-inventory"
(
  cd -- "${PACKAGE_STAGING}"
  find . -mindepth 1 -printf '%P\n' | sort >"${PACKAGE_INVENTORY}"
  tar --zstd --numeric-owner --owner=0 --group=0 --no-recursion \
    -cf "${BUNDLE}/${PACKAGE_NAME}" -T "${PACKAGE_INVENTORY}"
)
chmod 0644 -- "${BUNDLE}/${PACKAGE_NAME}"

readonly SOURCE_ARCHIVE_NAME="a-quo-${BUNDLE_COMMIT}.tar"
git -C "${BUNDLE_REPOSITORY}" archive --format=tar \
  --prefix="a-quo-${BUNDLE_COMMIT}/" \
  --output="${BUNDLE}/${SOURCE_ARCHIVE_NAME}" "${BUNDLE_COMMIT}"
chmod 0644 -- "${BUNDLE}/${SOURCE_ARCHIVE_NAME}"
SOURCE_ARCHIVE_SHA256="$(file_sha256 "${BUNDLE}/${SOURCE_ARCHIVE_NAME}")"
readonly SOURCE_ARCHIVE_SHA256
sed \
  -e 's/@PACKAGE_VERSION@/0.1.0.r1.synthetic/g' \
  -e 's/@PACKAGE_ARCHITECTURE@/x86_64/g' \
  -e 's/@PROFILE_ID@/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1/g' \
  -e "s/@EVIDENCE_NAMESPACE@/${EVIDENCE_NAMESPACE}/g" \
  -e 's/@RUST_VERSION@/1.98.0/g' \
  -e "s/@SOURCE_COMMIT@/${BUNDLE_COMMIT}/g" \
  -e "s/@SOURCE_SHA256@/${SOURCE_ARCHIVE_SHA256}/g" \
  "${BUNDLE_REPOSITORY}/packaging/arch/PKGBUILD.in" >"${BUNDLE}/PKGBUILD"
printf '%s\n' 'pkgbase = a-quo' 'arch = x86_64' >"${BUNDLE}/.SRCINFO"
chmod 0644 -- "${BUNDLE}/PKGBUILD" "${BUNDLE}/.SRCINFO"

install -m 0755 /dev/stdin "${OBSERVATION_STUBS}/uname" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -m ]]
printf '%s\n' x86_64
STUB
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
      printf ' 0x0000000000000001 (NEEDED) Shared library: [%s]\n' \
        "${library}"
    done
    ;;
  *) exit 64 ;;
esac
STUB

readonly BUNDLE_PROFILE="${BUNDLE_REPOSITORY}/packaging/evaluation-targets/${X86_PROFILE_NAME}"
set +e
PATH="${OBSERVATION_STUBS}:/usr/bin" \
  A_QUO_VERIFIER_REPOSITORY_ROOT="${BUNDLE_REPOSITORY}" \
  "${BUNDLE_REPOSITORY}/scripts/verify-arch-package-skeleton.sh" \
  --observe-unconfirmed-needed "${BUNDLE}/${PACKAGE_NAME}" \
  "${BUNDLE_COMMIT}" "${BUNDLE_PROFILE}" \
  >"${BUNDLE}/VERIFIER-OBSERVATION.txt" \
  2>"${BUNDLE}/VERIFIER-OBSERVATION.stderr"
PACKAGE_VERIFIER_STATUS="$?"
set -e
readonly PACKAGE_VERIFIER_STATUS
[[ "${PACKAGE_VERIFIER_STATUS}" -eq 1 ]] ||
  fail_contract 'synthetic package verifier did not fail closed after observation'
PACKAGE_SHA256="$(file_sha256 "${BUNDLE}/${PACKAGE_NAME}")"
VERIFIER_STDOUT_SHA256="$(file_sha256 "${BUNDLE}/VERIFIER-OBSERVATION.txt")"
VERIFIER_STDERR_SHA256="$(file_sha256 "${BUNDLE}/VERIFIER-OBSERVATION.stderr")"
readonly PACKAGE_SHA256 VERIFIER_STDOUT_SHA256 VERIFIER_STDERR_SHA256
cat >"${BUNDLE}/BUILDER-OBSERVATION.txt" <<EOF
format=a-quo-arch-package-needed-observation-builder-v1
observation_authority=none
package_sha256=${PACKAGE_SHA256}
expected_source_commit=${BUNDLE_COMMIT}
source_archive=${SOURCE_ARCHIVE_NAME}
source_archive_sha256=${SOURCE_ARCHIVE_SHA256}
profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1
profile_sha256=9e6295acb4e5dfa260227741566a58a45caf68f3a4e57ad4d7094f23eece0b6d
profile_binding_role=package-target-policy
package_target_kind=physical-bare-metal
architecture=x86_64
evidence_namespace=${EVIDENCE_NAMESPACE}
build_environment=architecture-matched-host-nonhermetic
build_host_architecture=x86_64
rust_host_observed=x86_64-unknown-linux-gnu
rust_toolchain_expected=1.98.0
rust_toolchain_observed=1.98.0
build_host_profile_match=not-established
native_hardware_claim=not-established
physical_target_evidence=false
verifier_stdout_sha256=${VERIFIER_STDOUT_SHA256}
verifier_stderr_sha256=${VERIFIER_STDERR_SHA256}
package_static_acceptance=false
needed_observation_accepted_as_policy=false
stage_4_completed=false
stage_5_executed=false
stage_6_authorized=false
stage_6_owner_decision=required
cross_profile_evidence_accepted=false
aarch64_gate_satisfied_by_x86_64=false
publication_performed=false
EOF
printf '%s\n' \
  'format=a-quo-arch-package-needed-observation-nonacceptance-v1' \
  'observation_authority=none' \
  'package_static_acceptance=false' \
  'needed_observation_accepted_as_policy=false' \
  'physical_target_evidence=false' \
  'stage_4_completed=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false' \
  >"${BUNDLE}/OBSERVATION-NONACCEPTING"
chmod 0644 -- "${BUNDLE}/BUILDER-OBSERVATION.txt" \
  "${BUNDLE}/OBSERVATION-NONACCEPTING" \
  "${BUNDLE}/VERIFIER-OBSERVATION.txt" \
  "${BUNDLE}/VERIFIER-OBSERVATION.stderr"

regenerate_checksums() {
  local temporary_checksums="${TEMPORARY_ROOT}/regenerated-checksums"
  (
    cd -- "${BUNDLE}"
    find . -type f ! -name SHA256SUMS -print0 | sort -z |
      xargs -0 sha256sum >"${temporary_checksums}"
  )
  install -m 0644 -- "${temporary_checksums}" "${BUNDLE}/SHA256SUMS"
}
regenerate_checksums

VALID_VERIFICATION_OUTPUT="$(PATH="${OBSERVATION_STUBS}:/usr/bin" \
  "${BUNDLE_REPOSITORY}/scripts/verify-arch-package-needed-observation-bundle.sh" \
  "${BUNDLE_COMMIT}")" ||
  fail_contract 'valid synthetic non-accepting bundle did not verify'
readonly VALID_VERIFICATION_OUTPUT
for nonclaim in \
  'observation_authority=none' \
  'package_static_acceptance=false' \
  'needed_observation_accepted_as_policy=false' \
  'physical_target_evidence=false' \
  'stage_4_completed=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false'; do
  [[ "${VALID_VERIFICATION_OUTPUT}" == *"${nonclaim}"* ]] ||
    fail_contract "verified bundle lost required nonclaim: ${nonclaim}"
done

readonly PRISTINE_BUNDLE="${TEMPORARY_ROOT}/pristine-bundle"
mkdir -m 0755 -- "${PRISTINE_BUNDLE}"
cp -a -- "${BUNDLE}/." "${PRISTINE_BUNDLE}/"
restore_bundle() {
  case "${BUNDLE}" in
    "${BUNDLE_REPOSITORY}/target/arch-package-needed-observations/${EVIDENCE_NAMESPACE}/"*) ;;
    *) fail_contract 'unsafe synthetic bundle restore target' ;;
  esac
  rm -rf -- "${BUNDLE}"
  mkdir -p -- "${BUNDLE}"
  cp -a -- "${PRISTINE_BUNDLE}/." "${BUNDLE}/"
}
assert_bundle_refused() {
  local label="$1"
  local expected="${2:-refused:}"
  local output
  local status
  set +e
  output="$(PATH="${OBSERVATION_STUBS}:/usr/bin" \
    "${BUNDLE_REPOSITORY}/scripts/verify-arch-package-needed-observation-bundle.sh" \
    "${BUNDLE_COMMIT}" 2>&1)"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && "${output}" == *"${expected}"* ]] ||
    fail_contract "hostile bundle mutation was not refused: ${label}"
  restore_bundle
}

assert_bundle_refused_with_environment() {
  local label="$1"
  local environment_name="$2"
  local environment_value="$3"
  local expected="$4"
  local output
  local status
  set +e
  output="$(env "${environment_name}=${environment_value}" \
    PATH="${OBSERVATION_STUBS}:/usr/bin" \
    "${BUNDLE_REPOSITORY}/scripts/verify-arch-package-needed-observation-bundle.sh" \
    "${BUNDLE_COMMIT}" 2>&1)"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && "${output}" == *"${expected}"* ]] ||
    fail_contract "inherited Git environment mutation was not refused: ${label}"
  restore_bundle
}

assert_bundle_repository_clean() {
  [[ -z "$(git -C "${BUNDLE_REPOSITORY}" -c core.fsmonitor=false \
    status --porcelain=v1 --untracked-files=normal)" ]] ||
    fail_contract 'synthetic bundle repository was not restored cleanly'
}

assert_bundle_refused_with_environment inherited-git-directory \
  GIT_DIR /nonexistent \
  'inherited Git repository override: GIT_DIR'
assert_bundle_refused_with_environment inherited-counted-config \
  GIT_CONFIG_COUNT 1 \
  'inherited Git repository override: GIT_CONFIG_COUNT'

printf '%s\n' 'exit 0' >>"${BUNDLE_REPOSITORY}/scripts/resolve-arch-package-target.sh"
assert_bundle_refused substituted-target-resolver \
  'package-target resolver bytes differ from the reviewed baseline'
install -m 0755 -- "${TARGET_RESOLVER}" \
  "${BUNDLE_REPOSITORY}/scripts/resolve-arch-package-target.sh"
assert_bundle_repository_clean

printf '%s\n' 'exit 0' \
  >>"${BUNDLE_REPOSITORY}/scripts/verify-omarchy-x86_64-physical-target-profile.sh"
assert_bundle_refused substituted-x86-profile-verifier \
  'x86_64 profile verifier bytes differ from the reviewed baseline'
install -m 0755 -- "${X86_PROFILE_VERIFIER}" \
  "${BUNDLE_REPOSITORY}/scripts/verify-omarchy-x86_64-physical-target-profile.sh"
assert_bundle_repository_clean

readonly BUNDLE_GIT_DIRECTORY="${BUNDLE_REPOSITORY}/.git"
readonly BUNDLE_ALTERNATE_OBJECTS="${TEMPORARY_ROOT}/alternate-objects"
mkdir -m 0755 -- "${BUNDLE_ALTERNATE_OBJECTS}"
printf '%s\n' "${BUNDLE_ALTERNATE_OBJECTS}" \
  >"${BUNDLE_GIT_DIRECTORY}/objects/info/alternates"
assert_bundle_refused local-alternate-object-store \
  'source checkout uses an alternate Git object store'
rm -- "${BUNDLE_GIT_DIRECTORY}/objects/info/alternates"
assert_bundle_repository_clean

mkdir -p -- "${BUNDLE_GIT_DIRECTORY}/info"
printf '%s %s\n' "${BUNDLE_COMMIT}" "${BUNDLE_COMMIT}" \
  >"${BUNDLE_GIT_DIRECTORY}/info/grafts"
assert_bundle_refused legacy-graft \
  'source checkout contains a legacy graft file'
rm -- "${BUNDLE_GIT_DIRECTORY}/info/grafts"
assert_bundle_repository_clean

printf '%s\n' "${BUNDLE_COMMIT}" >"${BUNDLE_GIT_DIRECTORY}/shallow"
assert_bundle_refused shallow-history \
  'bundle verification requires complete non-shallow Git history'
rm -- "${BUNDLE_GIT_DIRECTORY}/shallow"
assert_bundle_repository_clean

git -C "${BUNDLE_REPOSITORY}" config --local remote.origin.promisor true
assert_bundle_refused promisor-configuration \
  'source checkout has partial-clone or promisor configuration'
git -C "${BUNDLE_REPOSITORY}" config --local --unset-all remote.origin.promisor
assert_bundle_repository_clean

git -C "${BUNDLE_REPOSITORY}" config --local extensions.partialClone origin
assert_bundle_refused partial-clone-configuration \
  'source checkout has partial-clone or promisor configuration'
git -C "${BUNDLE_REPOSITORY}" config --local --unset-all extensions.partialClone
assert_bundle_repository_clean

mkdir -p -- "${BUNDLE_GIT_DIRECTORY}/refs/replace"
printf '%s\n' "${BUNDLE_COMMIT}" \
  >"${BUNDLE_GIT_DIRECTORY}/refs/replace/${BUNDLE_COMMIT}"
assert_bundle_refused replacement-ref \
  'source checkout contains replacement refs'
rm -- "${BUNDLE_GIT_DIRECTORY}/refs/replace/${BUNDLE_COMMIT}"
assert_bundle_repository_clean

printf '%s\n' dirty-tracked-checkout \
  >>"${BUNDLE_REPOSITORY}/README.md"
assert_bundle_refused dirty-tracked-checkout \
  'source checkout must be clean at the expected source commit'
install -m 0644 -- "${REPOSITORY_ROOT}/README.md" \
  "${BUNDLE_REPOSITORY}/README.md"
assert_bundle_repository_clean

sed -i 's/^profile_id=.*/profile_id=a-quo-omarchy4-aarch64-dec29fa-v2/' \
  "${BUNDLE}/BUILDER-OBSERVATION.txt"
regenerate_checksums
assert_bundle_refused cross-profile-builder

sed -i 's/^evidence_namespace=.*/evidence_namespace=phase-a-aarch64-dec29fa/' \
  "${BUNDLE}/VERIFIER-OBSERVATION.txt"
regenerate_checksums
assert_bundle_refused cross-profile-verifier

sed -i 's/^package_static_acceptance=false$/package_static_acceptance=true/' \
  "${BUNDLE}/OBSERVATION-NONACCEPTING"
regenerate_checksums
assert_bundle_refused false-to-true-marker

awk '{ print } /^package_sha256=/ { print }' \
  "${BUNDLE}/BUILDER-OBSERVATION.txt" \
  >"${BUNDLE}/BUILDER-OBSERVATION.txt.mutant"
mv -- "${BUNDLE}/BUILDER-OBSERVATION.txt.mutant" \
  "${BUNDLE}/BUILDER-OBSERVATION.txt"
chmod 0644 -- "${BUNDLE}/BUILDER-OBSERVATION.txt"
regenerate_checksums
assert_bundle_refused duplicate-builder-field

rm -- "${BUNDLE}/.SRCINFO"
regenerate_checksums
assert_bundle_refused missing-entry

printf '%s\n' hostile >"${BUNDLE}/EXTRA"
chmod 0644 -- "${BUNDLE}/EXTRA"
regenerate_checksums
assert_bundle_refused extra-entry

printf '%s\n' trailing-package-byte >>"${BUNDLE}/${PACKAGE_NAME}"
MUTATED_PACKAGE_SHA256="$(file_sha256 "${BUNDLE}/${PACKAGE_NAME}")"
sed -i "s/^package_sha256=.*/package_sha256=${MUTATED_PACKAGE_SHA256}/" \
  "${BUNDLE}/BUILDER-OBSERVATION.txt" \
  "${BUNDLE}/VERIFIER-OBSERVATION.txt"
regenerate_checksums
assert_bundle_refused transplanted-package

printf '%s\n' 'exit 0' >>"${BUNDLE_REPOSITORY}/scripts/verify-arch-package-skeleton.sh"
assert_bundle_refused substituted-package-verifier
install -m 0755 -- "${PACKAGE_VERIFIER}" \
  "${BUNDLE_REPOSITORY}/scripts/verify-arch-package-skeleton.sh"

readonly EARLY_SUCCESS_MUTANT="${TEMPORARY_ROOT}/bundle-verifier-early-success.sh"
awk '{ print } /^set -euo pipefail$/ { print "exit 0" }' \
  "${BUNDLE_VERIFIER}" >"${EARLY_SUCCESS_MUTANT}"
chmod 0755 -- "${EARLY_SUCCESS_MUTANT}"
[[ "$(file_sha256 "${EARLY_SUCCESS_MUTANT}")" != \
  "${EXPECTED_BUNDLE_VERIFIER_SHA256}" ]] ||
  fail_contract 'bundle verifier whole-file pin accepted an early-success mutant'

printf '%s\n' \
  'x86_64 package NEEDED observation bundle passed its offline hostile contract' \
  'contract_evidence=synthetic-control-flow-only' \
  'accepted_aarch64_default_regression=preserved' \
  'physical_intel_observation=false' \
  'physical_target_evidence=false' \
  'real_x86_64_package_evidence=false' \
  'needed_observation_accepted_as_policy=false' \
  'stage_4_completed=false' \
  'stage_5_executed=false' \
  'stage_6_authorized=false' \
  'aarch64_gate_satisfied_by_x86_64=false'
