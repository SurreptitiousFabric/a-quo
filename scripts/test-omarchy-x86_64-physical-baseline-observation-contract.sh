#!/usr/bin/env bash
# shellcheck disable=SC2016

set -euo pipefail
export LC_ALL=C
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly COLLECTOR="${SCRIPT_DIRECTORY}/collect-omarchy-x86_64-physical-baseline.sh"
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-baseline-observation.sh"
readonly PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1.profile"
readonly EXPECTED_COLLECTOR_SHA256=63a3d8d3cf56efa6728c123fdbc9d85f339b318d02593f06d818f4ead017099c
readonly EXPECTED_VERIFIER_SHA256=66f4dadad991e13b870b3d8105f7be678d0e2614ba1f782fa0f011c83deb9475

fail_contract() {
  printf 'x86_64 read-only baseline observation contract failed: %s\n' "$1" >&2
  exit 1
}

for required_tool in awk chmod cp env grep id install mkdir mktemp mv rm sed seq sha256sum stat; do
  command -v "${required_tool}" >/dev/null ||
    fail_contract "required contract tool is unavailable: ${required_tool}"
done

for production_input in "${COLLECTOR}" "${VERIFIER}" "${PROFILE}"; do
  [[ -f "${production_input}" && ! -L "${production_input}" ]] ||
    fail_contract "production input is unavailable or unsafe: ${production_input}"
done
[[ -x "${COLLECTOR}" && -x "${VERIFIER}" ]] ||
  fail_contract 'collector or verifier is not executable'

reviewed_source_hash_matches() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(sha256sum -- "${path}")" || return 1
  actual="${actual%% *}"
  [[ "${actual}" == "${expected}" ]]
}

reviewed_source_hash_matches "${COLLECTOR}" "${EXPECTED_COLLECTOR_SHA256}" ||
  fail_contract 'collector bytes differ from the reviewed whole-file digest'
reviewed_source_hash_matches "${VERIFIER}" "${EXPECTED_VERIFIER_SHA256}" ||
  fail_contract 'verifier bytes differ from the reviewed whole-file digest'

# The production collector may invoke only direct local observation tools. This
# source boundary is supplemental to the end-to-end synthetic execution below.
if grep -Eiq '(^|[^[:alnum:]_])(curl|wget|mise|sudo|doas|ssh|scp|rsync|tee|touch|mkdir|install|rm|mv|cp)([[:space:]]|$)' \
  "${COLLECTOR}"; then
  fail_contract 'collector names a networked, update-capable, privilege, or write tool'
fi
if grep -Eq '"\$\{PACMAN\}"[[:space:]]+-(S|R|U)|"\$\{SYSTEMCTL\}"[[:space:]]+--user[[:space:]]+(start|stop|enable|disable|restart)' \
  "${COLLECTOR}"; then
  fail_contract 'collector contains a package or service mutation command'
fi
for required_literal in \
  'readonly TOOL_ROOT=/usr/bin' \
  'readonly PACMAN="${TOOL_ROOT}/pacman"' \
  '"${PACMAN}" -Dk' \
  '"${PACMAN}" -Q --' \
  '"${PACMAN}" -Qi --' \
  '"${PACMAN}" -Qkk --' \
  '"${PACMAN}" -Qo --' \
  '"${PACMAN_CONF}" --repo-list' \
  '"${SYSTEMCTL}" --user show-environment' \
  '"${SYSTEMCTL}" --user is-active graphical-session.target' \
  '"${LOGINCTL}" show-user "${EXPECTED_DESKTOP_UID}" -p Display --value' \
  '"${LOGINCTL}" show-session' \
  '"${HYPRCTL}" version' \
  "'collector_mise_invoked=false'" \
  "'collector_network_command_invoked=false'" \
  "'collector_update_capable_command_invoked=false'" \
  "'physical_target_mutation_requested=false'" \
  "'stage_6_owner_decision=required'"; do
  grep -Fq -- "${required_literal}" "${COLLECTOR}" ||
    fail_contract "collector lost required read-only boundary: ${required_literal}"
done

readonly TEMPORARY_PREFIX="${TMPDIR:-/tmp}/a-quo-x86-baseline-contract."
[[ "${TEMPORARY_PREFIX}" == /* ]] ||
  fail_contract 'temporary directory prefix must be absolute'
TEMPORARY_ROOT="$(mktemp -d "${TEMPORARY_PREFIX}XXXXXX")"
readonly TEMPORARY_ROOT
TEMPORARY_ROOT_IDENTITY="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" ||
  fail_contract 'temporary directory identity is unavailable'
readonly TEMPORARY_ROOT_IDENTITY
[[ "${TEMPORARY_ROOT_IDENTITY}" == *":$(id -u)" &&
  "$(stat -c '%a:%F' -- "${TEMPORARY_ROOT}")" == '700:directory' ]] ||
  fail_contract 'temporary directory identity is unsafe'
cleanup() {
  local exit_status="$?"
  local current_identity
  trap - EXIT
  case "${TEMPORARY_ROOT}" in
    "${TEMPORARY_PREFIX}"??????) ;;
    *)
      printf '%s\n' 'refusing unsafe contract temporary-directory cleanup target' >&2
      exit 1
      ;;
  esac
  [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] || {
    printf '%s\n' 'refusing changed contract temporary-directory cleanup target' >&2
    exit 1
  }
  current_identity="$(stat -c '%d:%i:%u' -- "${TEMPORARY_ROOT}")" || {
    printf '%s\n' 'refusing unverifiable contract temporary-directory cleanup target' >&2
    exit 1
  }
  [[ "${current_identity}" == "${TEMPORARY_ROOT_IDENTITY}" ]] || {
    printf '%s\n' 'refusing substituted contract temporary-directory cleanup target' >&2
    exit 1
  }
  [[ "$(stat -c '%a:%F' -- "${TEMPORARY_ROOT}")" == '700:directory' ]] || {
    printf '%s\n' 'refusing unsafe contract temporary-directory cleanup shape' >&2
    exit 1
  }
  rm -rf -- "${TEMPORARY_ROOT}"
  exit "${exit_status}"
}
trap cleanup EXIT

readonly VERIFIER_EARLY_SUCCESS_MUTANT="${TEMPORARY_ROOT}/verifier-early-success.sh"
awk '
  { print }
  /^set -euo pipefail$/ { print "exit 0" }
' "${VERIFIER}" >"${VERIFIER_EARLY_SUCCESS_MUTANT}"
chmod 0755 -- "${VERIFIER_EARLY_SUCCESS_MUTANT}"
if reviewed_source_hash_matches \
  "${VERIFIER_EARLY_SUCCESS_MUTANT}" "${EXPECTED_VERIFIER_SHA256}"; then
  fail_contract 'whole-file verifier digest accepted an early-success substitution'
fi

readonly SYNTHETIC_REPOSITORY="${TEMPORARY_ROOT}/repository"
readonly SYNTHETIC_ROOT="${TEMPORARY_ROOT}/system"
readonly STUB_DIRECTORY="${TEMPORARY_ROOT}/bin"
readonly OBSERVATION="${TEMPORARY_ROOT}/observation.txt"
CONTRACT_UID="$(id -u)"
readonly CONTRACT_UID
mkdir -m 0755 -- \
  "${SYNTHETIC_REPOSITORY}" \
  "${SYNTHETIC_ROOT}" \
  "${STUB_DIRECTORY}"
mkdir -p -- \
  "${SYNTHETIC_REPOSITORY}/scripts" \
  "${SYNTHETIC_REPOSITORY}/packaging/evaluation-targets" \
  "${SYNTHETIC_ROOT}/etc" \
  "${SYNTHETIC_ROOT}/proc" \
  "${SYNTHETIC_ROOT}/sys/devices/virtual/dmi/id" \
  "${SYNTHETIC_ROOT}/run/user/${CONTRACT_UID}" \
  "${SYNTHETIC_ROOT}/usr/bin" \
  "${SYNTHETIC_ROOT}/usr/lib/os-release-parent" \
  "${SYNTHETIC_ROOT}/usr/lib/systemd/user" \
  "${SYNTHETIC_ROOT}/usr/lib/systemd/user-preset" \
  "${SYNTHETIC_ROOT}/usr/lib/a-quo" \
  "${SYNTHETIC_ROOT}/usr/share/a-quo" \
  "${SYNTHETIC_ROOT}/var/lib/pacman" \
  "${SYNTHETIC_ROOT}/cache" \
  "${SYNTHETIC_ROOT}/config/omarchy/plugins" \
  "${SYNTHETIC_ROOT}/data"
find "${SYNTHETIC_REPOSITORY}" "${SYNTHETIC_ROOT}" -type d \
  -exec chmod 0755 -- {} +

install -m 0644 -- "${PROFILE}" \
  "${SYNTHETIC_REPOSITORY}/packaging/evaluation-targets/$(basename -- "${PROFILE}")"
install -m 0755 -- \
  "${SCRIPT_DIRECTORY}/verify-omarchy-x86_64-physical-target-profile.sh" \
  "${SYNTHETIC_REPOSITORY}/scripts/verify-omarchy-x86_64-physical-target-profile.sh"
install -m 0755 -- "${VERIFIER}" \
  "${SYNTHETIC_REPOSITORY}/scripts/verify-omarchy-x86_64-physical-baseline-observation.sh"

sed \
  -e "s|^readonly TOOL_ROOT=/usr/bin$|readonly TOOL_ROOT=${STUB_DIRECTORY}|" \
  -e "s|^readonly ETC_ROOT=/etc$|readonly ETC_ROOT=${SYNTHETIC_ROOT}/etc|" \
  -e "s|^readonly PROC_ROOT=/proc$|readonly PROC_ROOT=${SYNTHETIC_ROOT}/proc|" \
  -e "s|^readonly SYS_ROOT=/sys$|readonly SYS_ROOT=${SYNTHETIC_ROOT}/sys|" \
  -e "s|^readonly RUN_ROOT=/run$|readonly RUN_ROOT=${SYNTHETIC_ROOT}/run|" \
  -e "s|^readonly USR_ROOT=/usr$|readonly USR_ROOT=${SYNTHETIC_ROOT}/usr|" \
  -e "s|^readonly EXPECTED_DESKTOP_UID=1000$|readonly EXPECTED_DESKTOP_UID=${CONTRACT_UID}|" \
  "${COLLECTOR}" \
  >"${SYNTHETIC_REPOSITORY}/scripts/collect-omarchy-x86_64-physical-baseline.sh"
chmod 0755 -- "${SYNTHETIC_REPOSITORY}/scripts/collect-omarchy-x86_64-physical-baseline.sh"

printf '%s\n' \
  'NAME="Omarchy"' \
  'VERSION="4.0.2"' \
  >"${SYNTHETIC_ROOT}/etc/os-release"
printf '%s\n' 'Apple Inc.' \
  >"${SYNTHETIC_ROOT}/sys/devices/virtual/dmi/id/sys_vendor"
printf '%s\n' 'MacBookAir7,2' \
  >"${SYNTHETIC_ROOT}/sys/devices/virtual/dmi/id/product_name"
: >"${SYNTHETIC_ROOT}/etc/passwd"
for processor in 0 1 2 3; do
  printf '%s\n' \
    "processor : ${processor}" \
    'model name : Intel(R) Core(TM) i5-5250U CPU @ 1.60GHz' \
    'cpu cores : 2' \
    ''
done >"${SYNTHETIC_ROOT}/proc/cpuinfo"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
  >"${SYNTHETIC_ROOT}/usr/bin/omarchy-plugin-validate"
printf '%s\n' '#!/usr/bin/env bash' '# rescanPlugins' 'exit 0' \
  >"${SYNTHETIC_ROOT}/usr/bin/omarchy-shell"
chmod 0755 -- \
  "${SYNTHETIC_ROOT}/usr/bin/omarchy-plugin-validate" \
  "${SYNTHETIC_ROOT}/usr/bin/omarchy-shell"
printf '%s\n' '{"version":1}' >"${SYNTHETIC_ROOT}/config/omarchy/shell.json"
chmod 0600 -- "${SYNTHETIC_ROOT}/config/omarchy/shell.json"
printf '%s\n' synthetic-omarchy-archive \
  >"${SYNTHETIC_ROOT}/cache/omarchy-4.0.2-1-any.pkg.tar.zst"
printf '%s\n' synthetic-settings-archive \
  >"${SYNTHETIC_ROOT}/cache/omarchy-settings-4.0.2-1-any.pkg.tar.zst"

for delegated_tool in awk find grep readlink sort; do
  ln -s -- "/usr/bin/${delegated_tool}" "${STUB_DIRECTORY}/${delegated_tool}"
done

install -m 0755 /dev/stdin "${STUB_DIRECTORY}/uname" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -m) printf '%s\n' x86_64 ;;
  -r) printf '%s\n' 7.1.9-arch1-2 ;;
  *) exit 64 ;;
esac
STUB

install -m 0755 /dev/stdin "${STUB_DIRECTORY}/pacman-conf" <<STUB
#!/usr/bin/env bash
set -euo pipefail
case "\$1" in
  Architecture) printf '%s\\n' x86_64 ;;
  --repo-list) printf '%s\\n' core extra multilib omarchy ;;
  CacheDir) printf '%s\\n' '${SYNTHETIC_ROOT}/cache/' ;;
  *) exit 64 ;;
esac
STUB

install -m 0755 /dev/stdin "${STUB_DIRECTORY}/pacman" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -Q)
    if [[ "$#" -eq 1 ]]; then
      for number in $(/usr/bin/seq -w 1 973); do
        printf 'synthetic%s 1.0-1\n' "${number}"
      done
      exit 0
    fi
    [[ "$2" == -- && "$#" -eq 3 ]]
    case "$3" in
      a-quo) exit 1 ;;
      omarchy) printf '%s\n' 'omarchy 4.0.2-1' ;;
      omarchy-settings) printf '%s\n' 'omarchy-settings 4.0.2-1' ;;
      glibc) printf '%s\n' 'glibc 2.44-1' ;;
      pacman) printf '%s\n' 'pacman 7.1.0.r9.g54d9411-2' ;;
      hyprland) printf '%s\n' 'hyprland 0.56.2-1' ;;
      quickshell) printf '%s\n' 'quickshell 0.3.1-1' ;;
      uwsm) printf '%s\n' 'uwsm 0.26.7-1' ;;
      systemd) printf '%s\n' 'systemd 261.2-1' ;;
      *) exit 65 ;;
    esac
    ;;
  -Qi)
    [[ "$2" == -- && "$#" -eq 3 ]]
    printf '%s\n' 'Architecture    : any'
    ;;
  -Dk)
    [[ "$#" -eq 1 ]]
    printf '%s\n' 'No database errors have been found!'
    ;;
  -Qkk)
    [[ "$2" == -- && "$#" -eq 3 ]]
    case "$3" in
      omarchy) printf '%s\n' 'omarchy: 100 total files, 0 altered files' ;;
      omarchy-settings)
        for number in 1 2 3 4; do
          printf 'warning: omarchy-settings: /etc/sudoers.d/synthetic%s (Permission denied)\n' "${number}"
        done
        printf '%s\n' 'omarchy-settings: 100 total files, 4 altered files'
        ;;
      *) exit 65 ;;
    esac
    ;;
  -Qo)
    [[ "$2" == -- && "$#" -eq 3 ]]
    printf 'omarchy 4.0.2-1 owns %s\n' "$3"
    ;;
  *) exit 64 ;;
esac
STUB

install -m 0755 /dev/stdin "${STUB_DIRECTORY}/systemctl" <<STUB
#!/usr/bin/env bash
set -euo pipefail
if [[ "\$*" == '--user show-environment' ]]; then
  printf '%s\\n' \\
    'XDG_CONFIG_HOME=${SYNTHETIC_ROOT}/config' \\
    'XDG_DATA_HOME=${SYNTHETIC_ROOT}/data' \\
    'XDG_RUNTIME_DIR=${SYNTHETIC_ROOT}/run/user/${CONTRACT_UID}' \\
    'WAYLAND_DISPLAY=wayland-1' \\
    'OMARCHY_PATH=/usr/share/omarchy'
elif [[ "\$*" == '--user is-active graphical-session.target' ]]; then
  printf '%s\\n' active
else
  exit 64
fi
STUB

install -m 0755 /dev/stdin "${STUB_DIRECTORY}/loginctl" <<STUB
#!/usr/bin/env bash
set -euo pipefail
if [[ "\$*" == 'show-user ${CONTRACT_UID} -p Display --value' ]]; then
  printf '%s\n' 3
elif [[ "\$*" == 'show-session 3 -p Type --value' ]]; then
  printf '%s\n' wayland
else
  exit 64
fi
STUB

install -m 0755 /dev/stdin "${STUB_DIRECTORY}/hyprctl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == version ]]
printf '%s\n' 'Hyprland 0.56.2 built from synthetic contract bytes.'
STUB

install -m 0755 /dev/stdin "${STUB_DIRECTORY}/stat" <<STUB
#!/usr/bin/env bash
set -euo pipefail
case "\$*" in
  "-L -c %u:%g:%F:%h -- ${SYNTHETIC_ROOT}/etc/os-release")
    printf '%s\\n' '0:0:regular file:1'
    ;;
  "-c %u:%g:%a:%F:%h -- ${SYNTHETIC_ROOT}/usr/bin/omarchy-plugin-validate"|\\
  "-c %u:%g:%a:%F:%h -- ${SYNTHETIC_ROOT}/usr/bin/omarchy-shell")
    printf '%s\\n' '0:0:755:regular file:1'
    ;;
  "-c %u:%a -- ${SYNTHETIC_ROOT}/run/user/${CONTRACT_UID}")
    printf '%s\\n' '1000:700'
    ;;
  "-f -c %T -- ${SYNTHETIC_ROOT}/run/user/${CONTRACT_UID}")
    printf '%s\\n' tmpfs
    ;;
  "-f -c %T -- ${SYNTHETIC_ROOT}/config")
    printf '%s\\n' btrfs
    ;;
  *) exec /usr/bin/stat "\$@" ;;
esac
STUB

install -m 0755 /dev/stdin "${STUB_DIRECTORY}/sha256sum" <<STUB
#!/usr/bin/env bash
set -euo pipefail
if [[ "\$#" -eq 0 ]]; then
  /usr/bin/awk '{ bytes += length(\$0) + 1 } END { if (bytes < 1) exit 1 }'
  printf '%s  -\\n' 7a492997f479a865b355e996fc4700881bd9160421428c133a02e38e97857e46
  exit 0
fi
path="\${!#}"
case "\${path}" in
  '${SYNTHETIC_ROOT}/etc/os-release')
    digest=db51e53a107054ea5d88b5cacfb705a732f1a4c643df83cc63a8590f0f12096c ;;
  '${SYNTHETIC_ROOT}/cache/omarchy-4.0.2-1-any.pkg.tar.zst')
    digest=cb24bb99a4b890fed643b4c92ab729daf353b6c632c29634d8cac09827ce5863 ;;
  '${SYNTHETIC_ROOT}/cache/omarchy-settings-4.0.2-1-any.pkg.tar.zst')
    digest=8f594aabc9d96cf136bd1192d65e7e2437901b7525f4a3cbf280125e6e6a6869 ;;
  '${SYNTHETIC_ROOT}/config/omarchy/shell.json')
    digest=0c521807f37fe76826db04cd17378a3571f021c59c20d27e72a7923a1f9ab4fc ;;
  *) exec /usr/bin/sha256sum "\$@" ;;
esac
printf '%s  %s\\n' "\${digest}" "\${path}"
STUB

set +e
USAGE_OUTPUT="$("${SYNTHETIC_REPOSITORY}/scripts/collect-omarchy-x86_64-physical-baseline.sh" unexpected 2>&1)"
USAGE_STATUS="$?"
set -e
[[ "${USAGE_STATUS}" -eq 2 && "${USAGE_OUTPUT}" == usage:* ]] ||
  fail_contract 'collector usage did not fail before observation'

env -i PATH="${STUB_DIRECTORY}:/usr/bin" \
  /usr/bin/bash --noprofile --norc \
  "${SYNTHETIC_REPOSITORY}/scripts/collect-omarchy-x86_64-physical-baseline.sh" \
  >"${OBSERVATION}"
chmod 0600 -- "${OBSERVATION}"

VERIFICATION_OUTPUT="$(PATH="${STUB_DIRECTORY}:/usr/bin" \
  "${SYNTHETIC_REPOSITORY}/scripts/verify-omarchy-x86_64-physical-baseline-observation.sh" \
  "${OBSERVATION}")" || fail_contract 'synthetic complete observation did not verify'
for expected_receipt in \
  'format=a-quo-omarchy-x86_64-read-only-observation-verification-v1' \
  'profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'evidence_namespace=physical-x86_64-official-omarchy-4.0.2' \
  'architecture=x86_64' \
  'profile_match=verified-non-authoritative' \
  'observation_authority=none' \
  'authenticated_physical_target_match=false' \
  'physical_target_execution=claimed-by-unauthenticated-receipt' \
  'formal_read_only_repeat=verified-receipt-non-authoritative' \
  'physical_target_mutation_requested=false' \
  'stage_4_package_evidence=false' \
  'stage_5_lifecycle_evidence=false' \
  'aarch64_gate_satisfied_by_x86_64=false' \
  'stage_6_owner_decision=required'; do
  [[ "${VERIFICATION_OUTPUT}" == *"${expected_receipt}"* ]] ||
    fail_contract "verification receipt lost required nonclaim: ${expected_receipt}"
done

assert_mutation_refused() {
  local label="$1"
  local before="$2"
  local after="$3"
  local mutant="${TEMPORARY_ROOT}/${label}.txt"
  local output
  local status
  sed "s|^${before}$|${after}|" "${OBSERVATION}" >"${mutant}"
  chmod 0600 -- "${mutant}"
  [[ "$(grep -Fxc -- "${after}" "${mutant}")" -eq 1 ]] ||
    fail_contract "hostile mutation did not change exactly one field: ${label}"
  set +e
  output="$(PATH="${STUB_DIRECTORY}:/usr/bin" \
    "${SYNTHETIC_REPOSITORY}/scripts/verify-omarchy-x86_64-physical-baseline-observation.sh" \
    "${mutant}" 2>&1)"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && "${output}" == *'refused:'* ]] ||
    fail_contract "hostile mutation was not refused: ${label}"
}

assert_mutation_refused profile-id \
  'profile_id=a-quo-omarchy4-x86_64-macbookair7_2-official-4.0.2-v1' \
  'profile_id=a-quo-omarchy4-aarch64-dec29fa-v2'
assert_mutation_refused architecture 'architecture=x86_64' 'architecture=aarch64'
assert_mutation_refused hardware-model 'hardware_model=MacBookAir7,2' \
  'hardware_model=synthetic-other'
assert_mutation_refused package-query-hash \
  'installed_package_query_sha256=7a492997f479a865b355e996fc4700881bd9160421428c133a02e38e97857e46' \
  'installed_package_query_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
assert_mutation_refused authority 'observation_authority=none' \
  'observation_authority=authoritative'
assert_mutation_refused mise 'collector_mise_invoked=false' \
  'collector_mise_invoked=true'
assert_mutation_refused mutation 'physical_target_mutation_requested=false' \
  'physical_target_mutation_requested=true'
assert_mutation_refused stage-6 'stage_6_owner_decision=required' \
  'stage_6_owner_decision=approved'

assert_observation_file_refused() {
  local label="$1"
  local path="$2"
  local output
  local status
  set +e
  output="$(PATH="${STUB_DIRECTORY}:/usr/bin" \
    "${SYNTHETIC_REPOSITORY}/scripts/verify-omarchy-x86_64-physical-baseline-observation.sh" \
    "${path}" 2>&1)"
  status="$?"
  set -e
  [[ "${status}" -eq 1 && "${output}" == *'refused:'* ]] ||
    fail_contract "hostile observation shape was not refused: ${label}"
}

readonly MISSING_FIELD="${TEMPORARY_ROOT}/missing-field.txt"
sed '/^architecture=x86_64$/d' "${OBSERVATION}" >"${MISSING_FIELD}"
chmod 0600 -- "${MISSING_FIELD}"
assert_observation_file_refused missing-field "${MISSING_FIELD}"

readonly DUPLICATE_FIELD="${TEMPORARY_ROOT}/duplicate-field.txt"
awk '{ print } /^architecture=x86_64$/ { print }' "${OBSERVATION}" \
  >"${DUPLICATE_FIELD}"
chmod 0600 -- "${DUPLICATE_FIELD}"
assert_observation_file_refused duplicate-field "${DUPLICATE_FIELD}"

readonly REORDERED_FIELDS="${TEMPORARY_ROOT}/reordered-fields.txt"
awk '
  /^architecture=x86_64$/ { held=$0; next }
  /^hardware_vendor=Apple$/ { print; print held; next }
  { print }
' "${OBSERVATION}" >"${REORDERED_FIELDS}"
chmod 0600 -- "${REORDERED_FIELDS}"
assert_observation_file_refused reordered-fields "${REORDERED_FIELDS}"

readonly EXTRA_FIELD="${TEMPORARY_ROOT}/extra-field.txt"
cp -- "${OBSERVATION}" "${EXTRA_FIELD}"
printf '%s\n' 'unexpected_field=unexpected' >>"${EXTRA_FIELD}"
chmod 0600 -- "${EXTRA_FIELD}"
assert_observation_file_refused extra-field "${EXTRA_FIELD}"

readonly EXTRA_FINAL_LF="${TEMPORARY_ROOT}/extra-final-lf.txt"
cp -- "${OBSERVATION}" "${EXTRA_FINAL_LF}"
printf '\n' >>"${EXTRA_FINAL_LF}"
chmod 0600 -- "${EXTRA_FINAL_LF}"
assert_observation_file_refused extra-final-lf "${EXTRA_FINAL_LF}"

readonly NUL_TERMINATED="${TEMPORARY_ROOT}/nul-terminated.txt"
cp -- "${OBSERVATION}" "${NUL_TERMINATED}"
printf '\0' >>"${NUL_TERMINATED}"
chmod 0600 -- "${NUL_TERMINATED}"
assert_observation_file_refused nul-terminated "${NUL_TERMINATED}"

readonly OBSERVATION_LINK="${TEMPORARY_ROOT}/observation-link.txt"
ln -s -- "${OBSERVATION}" "${OBSERVATION_LINK}"
assert_observation_file_refused symlink "${OBSERVATION_LINK}"

readonly OBSERVATION_HARDLINK="${TEMPORARY_ROOT}/observation-hardlink.txt"
readonly OBSERVATION_HARDLINK_SOURCE="${TEMPORARY_ROOT}/observation-hardlink-source.txt"
cp -- "${OBSERVATION}" "${OBSERVATION_HARDLINK_SOURCE}"
ln -- "${OBSERVATION_HARDLINK_SOURCE}" "${OBSERVATION_HARDLINK}"
assert_observation_file_refused hardlink "${OBSERVATION_HARDLINK}"

readonly COLLECTOR_BACKUP="${TEMPORARY_ROOT}/collector.backup"
cp -- "${SYNTHETIC_REPOSITORY}/scripts/collect-omarchy-x86_64-physical-baseline.sh" \
  "${COLLECTOR_BACKUP}"
printf '%s\n' '# hostile collector byte' \
  >>"${SYNTHETIC_REPOSITORY}/scripts/collect-omarchy-x86_64-physical-baseline.sh"
set +e
COLLECTOR_MUTATION_OUTPUT="$(PATH="${STUB_DIRECTORY}:/usr/bin" \
  "${SYNTHETIC_REPOSITORY}/scripts/verify-omarchy-x86_64-physical-baseline-observation.sh" \
  "${OBSERVATION}" 2>&1)"
COLLECTOR_MUTATION_STATUS="$?"
set -e
[[ "${COLLECTOR_MUTATION_STATUS}" -eq 1 && "${COLLECTOR_MUTATION_OUTPUT}" == \
  *'unexpected observation value: collector_sha256'* ]] ||
  fail_contract 'collector-byte substitution was not refused'
mv -- "${COLLECTOR_BACKUP}" \
  "${SYNTHETIC_REPOSITORY}/scripts/collect-omarchy-x86_64-physical-baseline.sh"
chmod 0755 -- "${SYNTHETIC_REPOSITORY}/scripts/collect-omarchy-x86_64-physical-baseline.sh"

printf '%s\n' \
  'x86_64 direct-tool baseline collector passed its synthetic hostile contract' \
  'contract_evidence=collector-and-receipt-control-flow-only' \
  'physical_intel_observation=false' \
  'physical_intel_state_accessed=false' \
  'physical_intel_state_mutated=false' \
  'mise_executed_on_physical_intel=false' \
  'stage_4_package_evidence=false' \
  'stage_5_lifecycle_evidence=false' \
  'stage_6_authorized=false'
