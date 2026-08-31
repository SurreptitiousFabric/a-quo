#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

fail_policy() {
  printf 'offline container policy invariant failed: %s\n' "$1" >&2
  exit 1
}

if [[ "$#" -ne 8 ]]; then
  printf '%s\n' \
    'usage: verify-x86-package-observation-container-policy.sh INSPECT_JSON CONTAINER_ID IMAGE_ID WORKSPACE TARGET OBSERVER_HOME MISE SOURCE_COMMIT' >&2
  exit 2
fi

readonly INSPECT_JSON="$1"
readonly EXPECTED_CONTAINER_ID="$2"
readonly EXPECTED_IMAGE_ID="$3"
readonly EXPECTED_WORKSPACE="$4"
readonly EXPECTED_TARGET="$5"
readonly EXPECTED_OBSERVER_HOME="$6"
readonly EXPECTED_MISE="$7"
readonly EXPECTED_SOURCE_COMMIT="$8"

command -v jq >/dev/null || fail_policy jq-unavailable
[[ -f "${INSPECT_JSON}" && ! -L "${INSPECT_JSON}" ]] ||
  fail_policy inspect-input-type
[[ "${EXPECTED_CONTAINER_ID}" =~ ^[0-9a-f]{64}$ ]] ||
  fail_policy expected-container-id
[[ "${EXPECTED_IMAGE_ID}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  fail_policy expected-image-id
[[ "${EXPECTED_SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] ||
  fail_policy expected-source-commit
for expected_path in \
  "${EXPECTED_WORKSPACE}" "${EXPECTED_TARGET}" \
  "${EXPECTED_OBSERVER_HOME}" "${EXPECTED_MISE}"; do
  [[ "${expected_path}" == /* && "${expected_path}" != *","* ]] ||
    fail_policy expected-path
done
[[ "${EXPECTED_TARGET}" == "${EXPECTED_WORKSPACE}/target" ]] ||
  fail_policy expected-target-path

if ! jq -e '
  type == "array" and length == 1 and
  (.[0] | type == "object") and
  (.[0].Config | type == "object") and
  (.[0].HostConfig | type == "object")
' "${INSPECT_JSON}" >/dev/null 2>&1; then
  fail_policy json-shape
fi

set +e
FAILED_INVARIANTS="$(
  jq -r \
    --arg container_id "${EXPECTED_CONTAINER_ID}" \
    --arg image_id "${EXPECTED_IMAGE_ID}" \
    --arg workspace "${EXPECTED_WORKSPACE}" \
    --arg target "${EXPECTED_TARGET}" \
    --arg observer_home "${EXPECTED_OBSERVER_HOME}" \
    --arg mise "${EXPECTED_MISE}" \
    --arg commit "${EXPECTED_SOURCE_COMMIT}" '
      .[0] as $c |
      def empty_or_null($value):
        ($value == null) or (($value | type) == "array" and ($value | length) == 0);
      def exact_mount($source; $target_path; $read_only_state):
        ([($c.HostConfig.Mounts // [])[] |
          select(
            type == "object" and .Type == "bind" and
            .Source == $source and .Target == $target_path and
            (if $read_only_state == "explicit-read-only" then
              has("ReadOnly") and .ReadOnly == true
            elif $read_only_state == "omitted-writable" then
              (has("ReadOnly") | not)
            else false end)
          )] | length) == 1;
      def exact_environment:
        ($c.Config.Env | type) == "array" and
        (($c.Config.Env | sort) == ([
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "LANG=C.UTF-8",
          "HOME=/home/a-quo-observer",
          "MISE_CACHE_DIR=/home/a-quo-observer/.cache/mise",
          "MISE_DATA_DIR=/home/a-quo-observer/.local/share/mise",
          "MISE_TRUSTED_CONFIG_PATHS=/workspace",
          "MISE_OFFLINE=1",
          "CARGO_NET_OFFLINE=true"
        ] | sort));
      def exact_tmpfs:
        ($c.HostConfig.Tmpfs | type) == "object" and
        ($c.HostConfig.Tmpfs | keys) == ["/tmp"] and
        (($c.HostConfig.Tmpfs["/tmp"] | split(",") | sort) ==
          ["mode=1777", "nodev", "noexec", "nosuid", "rw"]);
      def exact_mount_inventory:
        ($c.HostConfig.Mounts | type) == "array" and
        ($c.HostConfig.Mounts | length) == 4 and
        ([$c.HostConfig.Mounts[].Type] | all(. == "bind")) and
        ([$c.HostConfig.Mounts[].Source] | unique | length) == 4 and
        ([$c.HostConfig.Mounts[].Target] | unique | length) == 4 and
        exact_mount($workspace; "/workspace"; "explicit-read-only") and
        exact_mount($target; "/workspace/target"; "omitted-writable") and
        exact_mount($observer_home; "/home/a-quo-observer"; "omitted-writable") and
        exact_mount($mise; "/usr/local/bin/mise"; "explicit-read-only");
      [
        {name:"container-id", ok:($c.Id == $container_id)},
        {name:"prepared-image-id", ok:($c.Image == $image_id)},
        {name:"process-user", ok:($c.Config.User == "1001:1001")},
        {name:"working-directory", ok:($c.Config.WorkingDir == "/workspace")},
        {name:"entrypoint-command", ok:(
          $c.Config.Entrypoint == ["/usr/bin/bash"] and
          $c.Config.Cmd == ["--noprofile", "--norc",
            "/workspace/scripts/run-x86-package-needed-observation-offline.sh", $commit]
        )},
        {name:"environment", ok:exact_environment},
        {name:"network-mode", ok:($c.HostConfig.NetworkMode == "none")},
        {name:"read-only-rootfs", ok:($c.HostConfig.ReadonlyRootfs == true)},
        {name:"privileged", ok:($c.HostConfig.Privileged == false)},
        {name:"added-capabilities", ok:empty_or_null($c.HostConfig.CapAdd)},
        {name:"dropped-capabilities", ok:(
          ($c.HostConfig.CapDrop | type) == "array" and
          ($c.HostConfig.CapDrop | length) == 1 and
          (($c.HostConfig.CapDrop[0] | ascii_downcase) == "all")
        )},
        {name:"security-options", ok:(
          $c.HostConfig.SecurityOpt == ["no-new-privileges=true"]
        )},
        {name:"devices", ok:empty_or_null($c.HostConfig.Devices)},
        {name:"legacy-binds", ok:empty_or_null($c.HostConfig.Binds)},
        {name:"pid-namespace", ok:($c.HostConfig.PidMode == "")},
        {name:"ipc-namespace", ok:($c.HostConfig.IpcMode == "private")},
        {name:"uts-namespace", ok:($c.HostConfig.UTSMode == "")},
        {name:"user-namespace", ok:($c.HostConfig.UsernsMode == "")},
        {name:"process-limit", ok:($c.HostConfig.PidsLimit == 512)},
        {name:"tmpfs", ok:exact_tmpfs},
        {name:"mount-inventory", ok:exact_mount_inventory}
      ] |
      .[] | select(.ok != true) | .name
    ' "${INSPECT_JSON}" 2>/dev/null
)"
JQ_STATUS="$?"
set -e
readonly FAILED_INVARIANTS JQ_STATUS

[[ "${JQ_STATUS}" -eq 0 ]] || fail_policy policy-evaluation
if [[ -n "${FAILED_INVARIANTS}" ]]; then
  while IFS= read -r invariant; do
    case "${invariant}" in
      container-id|prepared-image-id|process-user|working-directory|\
      entrypoint-command|environment|network-mode|read-only-rootfs|privileged|\
      added-capabilities|dropped-capabilities|security-options|devices|\
      legacy-binds|pid-namespace|ipc-namespace|uts-namespace|user-namespace|\
      process-limit|tmpfs|mount-inventory)
        printf 'offline container policy invariant failed: %s\n' "${invariant}" >&2
        ;;
      *) fail_policy policy-diagnostic ;;
    esac
  done <<<"${FAILED_INVARIANTS}"
  exit 1
fi

printf '%s\n' 'offline container policy passed exact stopped-container checks'
