#!/usr/bin/env bash

set -euo pipefail

if [[ ${1:-} == "--no-lsan" ]]; then
  export ASAN_OPTIONS=detect_leaks=0
  leak_sanitizer=disabled-for-ptrace-constrained-runner
  libfuzzer_leak_option=-detect_leaks=0
elif [[ $# -ne 0 ]]; then
  printf 'usage: %s [--no-lsan]\n' "$0" >&2
  exit 2
else
  export ASAN_OPTIONS=detect_leaks=1
  leak_sanitizer=enabled
  libfuzzer_leak_option=-detect_leaks=1
fi

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

revision=$(git rev-parse HEAD)
if [[ -n ${GITHUB_RUN_ID:-} ]]; then
  run_name="${revision}-gha-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT:-1}"
else
  run_name="${revision}-local-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
run_root="fuzz/runs/${run_name}"
log_path="fuzz/logs/fuzz-smoke-${run_name}.log"

mkdir -p "$run_root/continuity_recovery_bytes" "$run_root/persona_backup_bytes"
mkdir -p "$run_root/root_distribution_bytes"
mkdir -p fuzz/logs fuzz/artifacts/continuity_recovery_bytes fuzz/artifacts/persona_backup_bytes
mkdir -p fuzz/artifacts/root_distribution_bytes

worktree_status=$(git status --porcelain)

exec 3>&1 4>&2
exec > >(tee "$log_path") 2>&1
tee_pid=$!

if [[ -z $worktree_status ]]; then
  worktree_clean=true
else
  worktree_clean=false
fi

printf 'revision=%s\n' "$revision"
printf 'worktree_clean=%s\n' "$worktree_clean"
printf 'leak_sanitizer=%s\n' "$leak_sanitizer"
c++ --version
rustc -vV
cargo fuzz --version

common_options=(
  -runs=25000
  -max_total_time=120
  "$libfuzzer_leak_option"
  -seed=424242
  -max_len=262144
  -timeout=5
  -rss_limit_mb=1024
  -malloc_limit_mb=256
  -print_final_stats=1
)

continuity_command=(
  cargo fuzz run --fuzz-dir fuzz continuity_recovery_bytes
  "$run_root/continuity_recovery_bytes"
  fuzz/seeds/continuity_recovery_bytes --
  "${common_options[@]}"
  -dict=fuzz/dictionaries/continuity_recovery.dict
)
printf 'command='
printf '%q ' "${continuity_command[@]}"
printf '\n'
"${continuity_command[@]}"

backup_command=(
  cargo fuzz run --fuzz-dir fuzz persona_backup_bytes
  "$run_root/persona_backup_bytes"
  fuzz/seeds/persona_backup_bytes --
  "${common_options[@]}"
  -dict=fuzz/dictionaries/persona_backup.dict
)
printf 'command='
printf '%q ' "${backup_command[@]}"
printf '\n'
"${backup_command[@]}"

root_distribution_command=(
  cargo fuzz run --fuzz-dir fuzz root_distribution_bytes
  "$run_root/root_distribution_bytes"
  fuzz/seeds/root_distribution_bytes --
  "${common_options[@]}"
  -dict=fuzz/dictionaries/root_distribution.dict
)
printf 'command='
printf '%q ' "${root_distribution_command[@]}"
printf '\n'
"${root_distribution_command[@]}"

artifact_file=$(find fuzz/artifacts -type f -print -quit)
if [[ -n $artifact_file ]]; then
  printf 'unexpected fuzz artifact: %s\n' "$artifact_file" >&2
  exit 1
fi
printf 'artifact_files=0\n'

exec 1>&3 2>&4
if ! wait "$tee_pid"; then
  printf 'failed to retain the fuzz campaign log at %s\n' "$log_path" >&2
  exit 1
fi
exec 3>&- 4>&-
