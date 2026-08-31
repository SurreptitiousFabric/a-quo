#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 077

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIRECTORY}/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly ACQUIRER="${SCRIPT_DIRECTORY}/acquire-omarchy-ubuntu-oci-candidate.sh"
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify-omarchy-ubuntu-oci-candidate.sh"
readonly CANONICAL_PROFILE="${REPOSITORY_ROOT}/packaging/evaluation-targets/a-quo-omarchy4-aarch64-dec29fa-v2.profile"
readonly OUTPUT_ROOT="${REPOSITORY_ROOT}/target/omarchy-evaluation-input-observations"
readonly TEST_PROFILE_REPOSITORY=https://example.invalid/a-quo.git
readonly TEST_PROFILE_COMMIT=1111111111111111111111111111111111111111
readonly TEST_PROFILE_REPOSITORY_PATH=fixtures/omarchy-ubuntu-oci-synthetic-v2.profile

for required_file in "${ACQUIRER}" "${VERIFIER}" "${CANONICAL_PROFILE}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] || {
    printf 'Ubuntu OCI contract input is missing or a symlink: %s\n' \
      "${required_file}" >&2
    exit 1
  }
done
[[ -x "${ACQUIRER}" && -x "${VERIFIER}" ]] || {
  printf '%s\n' 'Ubuntu OCI acquisition scripts must be executable' >&2
  exit 1
}

for required_tool in \
  awk basename chmod cp dd env find grep gzip head id ln mkdir mkfifo mktemp mv rm sed \
  setsid sha256sum sleep stat tar timeout tr wc; do
  command -v "${required_tool}" >/dev/null || {
    printf 'Ubuntu OCI contract tool is unavailable: %s\n' \
      "${required_tool}" >&2
    exit 1
  }
done

TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/a-quo-ubuntu-oci-contract.XXXXXX")"
readonly TEMPORARY_ROOT
created_output=''
cleanup() {
  if [[ -n "${created_output}" && "${created_output}" == "${OUTPUT_ROOT}/"* ]]; then
    rm -rf -- "${created_output}"
  fi
  rm -rf -- "${TEMPORARY_ROOT}"
}
trap cleanup EXIT

fail_contract() {
  printf 'Ubuntu OCI contract failed: %s\n' "$1" >&2
  exit 1
}

assert_refused() {
  local label="$1"
  local expected="$2"
  shift 2
  local output
  local status
  set +e
  output="$(timeout 10 "$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 1 || "${output}" != *"${expected}"* ]]; then
    printf 'Ubuntu OCI refusal mismatch: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

assert_usage_refused() {
  local label="$1"
  shift
  local output
  local status
  set +e
  output="$(timeout 10 "$@" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -ne 2 || "${output}" != usage:* ]]; then
    printf 'Ubuntu OCI usage mismatch: label=%s status=%s output=%q\n' \
      "${label}" "${status}" "${output}" >&2
    exit 1
  fi
}

file_sha256() {
  local result
  result="$(sha256sum -- "$1")"
  printf '%s\n' "${result%% *}"
}

file_size() {
  stat -c '%s' -- "$1"
}

replace_field() {
  local path="$1"
  local key="$2"
  local replacement="$3"
  local temporary
  temporary="$(mktemp "${TEMPORARY_ROOT}/profile-field.XXXXXX")"
  awk -v key="${key}" -v replacement="${replacement}" '
    index($0, key "=") == 1 { print key "=" replacement; found += 1; next }
    { print }
    END { if (found != 1) exit 73 }
  ' "${path}" >"${temporary}"
  mv -- "${temporary}" "${path}"
}

profile_field() {
  local path="$1"
  local key="$2"
  awk -v key="${key}" '
    index($0, key "=") == 1 { print substr($0, length(key) + 2); found += 1 }
    END { if (found != 1) exit 73 }
  ' "${path}"
}

# Exercise the acquirer's real redirect predicate in isolation. This remains
# offline and avoids restating the production predicate in the test.
REDIRECT_VALIDATOR_SOURCE="${TEMPORARY_ROOT}/validate-blob-redirect.sh"
readonly REDIRECT_VALIDATOR_SOURCE
awk '
  $0 == "validate_blob_redirect() {" { capture = 1 }
  capture { print }
  capture && $0 == "}" { exit }
' "${ACQUIRER}" >"${REDIRECT_VALIDATOR_SOURCE}"
[[ "$(grep -Fc 'validate_blob_redirect() {' "${REDIRECT_VALIDATOR_SOURCE}")" -eq 1 && \
  "$(tail -n 1 "${REDIRECT_VALIDATOR_SOURCE}")" == '}' ]] ||
  fail_contract 'could not isolate the exact production blob-redirect predicate'

assert_redirect_accepted() {
  local label="$1"
  local redirect_url="$2"
  local digest="$3"
  if ! bash -c '
    set -euo pipefail
    source "$1"
    validate_blob_redirect "$2" "$3"
  ' redirect-contract "${REDIRECT_VALIDATOR_SOURCE}" "${redirect_url}" "${digest}"; then
    fail_contract "production blob-redirect predicate rejected ${label}"
  fi
}

assert_redirect_refused() {
  local label="$1"
  local redirect_url="$2"
  local digest="$3"
  local status
  set +e
  bash -c '
    set -euo pipefail
    source "$1"
    validate_blob_redirect "$2" "$3"
  ' redirect-contract "${REDIRECT_VALIDATOR_SOURCE}" "${redirect_url}" "${digest}"
  status="$?"
  set -e
  [[ "${status}" -eq 1 ]] ||
    fail_contract "production blob-redirect predicate accepted ${label}"
}

readonly REDIRECT_TEST_HEX=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
readonly REDIRECT_TEST_DIGEST="sha256:${REDIRECT_TEST_HEX}"
readonly REDIRECT_TEST_PATH="/registry-v2/docker/registry/v2/blobs/sha256/aa/${REDIRECT_TEST_HEX}/data?verify=synthetic&ns=docker.io"
assert_redirect_accepted cloudflare \
  "https://production.cloudflare.docker.com${REDIRECT_TEST_PATH}" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_accepted cloudfront \
  "https://production.cloudfront.docker.com${REDIRECT_TEST_PATH}" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused cloudflare-lookalike \
  "https://production.cloudflare.docker.com.evil.invalid${REDIRECT_TEST_PATH}" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused cloudfront-lookalike \
  "https://production.cloudfront.docker.com.evil.invalid${REDIRECT_TEST_PATH}" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused wrong-digest-directory \
  "https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/ab/${REDIRECT_TEST_HEX}/data?verify=synthetic" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused wrong-digest \
  "https://production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/data?verify=synthetic" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused wrong-terminal-path \
  "https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/${REDIRECT_TEST_HEX}/data-extra?verify=synthetic" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused missing-query \
  "https://production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/${REDIRECT_TEST_HEX}/data" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused empty-query \
  "https://production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/${REDIRECT_TEST_HEX}/data?" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused non-https \
  "http://production.cloudfront.docker.com${REDIRECT_TEST_PATH}" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused fragment \
  "https://production.cloudflare.docker.com${REDIRECT_TEST_PATH}#fragment" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused embedded-quote \
  "https://production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/${REDIRECT_TEST_HEX}/data?verify=\"synthetic" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused backslash \
  "https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/${REDIRECT_TEST_HEX}/data?verify=synthetic\\value" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused whitespace \
  "https://production.cloudfront.docker.com/registry-v2/docker/registry/v2/blobs/sha256/aa/${REDIRECT_TEST_HEX}/data?verify=synthetic value" \
  "${REDIRECT_TEST_DIGEST}"
assert_redirect_refused control-newline \
  "https://production.cloudflare.docker.com${REDIRECT_TEST_PATH}"$'\n''extra' \
  "${REDIRECT_TEST_DIGEST}"

for allowed_redirect_host in \
  production.cloudflare.docker.com \
  production.cloudfront.docker.com; do
  [[ "$(grep -Fc \
    "https://${allowed_redirect_host}/registry-v2/docker/registry/v2/blobs/sha256/" \
    "${REDIRECT_VALIDATOR_SOURCE}")" -eq 1 ]] ||
    fail_contract "redirect predicate does not contain exactly one ${allowed_redirect_host} prefix"
done
# These assertions inspect literal source rather than expanding the variables.
# shellcheck disable=SC2016
grep -Fq 'elif [[ "${curl_status}" == 307 ]]' "${ACQUIRER}" ||
  fail_contract 'blob redirect handling no longer requires HTTP 307'
# shellcheck disable=SC2016
grep -Fq 'registry_request unauthenticated-private-config "${private_redirect}"' \
  "${ACQUIRER}" ||
  fail_contract 'blob redirect handling no longer strips registry authorization'

# Exercise the actual production request function, not a restated equivalent.
# The fake Curl accepts only a private config containing the exact redirect URL,
# rejects that URL or the sentinel bearer in argv, rejects Authorization in the
# config, and returns the metadata shape that registry_request must parse.
REGISTRY_REQUEST_SOURCE="${TEMPORARY_ROOT}/registry-request-source.sh"
PRIVATE_CONFIG_CURL="${TEMPORARY_ROOT}/private-config-curl"
PRIVATE_CONFIG_EVIDENCE="${TEMPORARY_ROOT}/private-config-evidence"
PRIVATE_CONFIG_OUTPUT="${TEMPORARY_ROOT}/private-config-output"
readonly REGISTRY_REQUEST_SOURCE PRIVATE_CONFIG_CURL PRIVATE_CONFIG_EVIDENCE
readonly PRIVATE_CONFIG_OUTPUT
awk '
  $0 == "registry_request() {" { capture = 1 }
  capture { print }
  capture && $0 == "}" { exit }
' "${ACQUIRER}" >"${REGISTRY_REQUEST_SOURCE}"
[[ "$(grep -Fc 'registry_request() {' "${REGISTRY_REQUEST_SOURCE}")" -eq 1 && \
  "$(tail -n 1 "${REGISTRY_REQUEST_SOURCE}")" == '}' ]] ||
  fail_contract 'could not isolate the exact production registry-request function'
# The following single-quoted lines are source for the disposable fake.
# shellcheck disable=SC2016
{
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    ': "${FAKE_PRIVATE_URL:?}" "${FAKE_SENTINEL_BEARER:?}" "${FAKE_PRIVATE_CONFIG_EVIDENCE:?}"' \
    'config_path=' \
    'expect_config_path=false' \
    'config_count=0' \
    'for argument in "$@"; do' \
    '  [[ "${argument}" != *"${FAKE_PRIVATE_URL}"* ]]' \
    '  [[ "${argument}" != *"${FAKE_SENTINEL_BEARER}"* ]]' \
    '  if [[ "${expect_config_path}" == true ]]; then' \
    '    config_path="${argument}"' \
    '    expect_config_path=false' \
    '  elif [[ "${argument}" == --config ]]; then' \
    '    ((config_count += 1))' \
    '    expect_config_path=true' \
    '  fi' \
    'done' \
    '[[ "${config_count}" -eq 1 && "${expect_config_path}" == false && -r "${config_path}" ]]' \
    '[[ "${config_path}" == /proc/self/fd/[0-9]* ]]' \
    'config_content="$(<"${config_path}")"' \
    '[[ "${config_content}" == "url = \"${FAKE_PRIVATE_URL}\"" ]]' \
    '[[ "${config_content,,}" != *authorization* && "${config_content,,}" != *bearer* ]]' \
    '[[ "${config_content}" != *"${FAKE_SENTINEL_BEARER}"* ]]' \
    'printf "%s\n" private-config-verified >"${FAKE_PRIVATE_CONFIG_EVIDENCE}"' \
    'printf "200\n\napplication/octet-stream"'
} >"${PRIVATE_CONFIG_CURL}"
chmod 0755 -- "${PRIVATE_CONFIG_CURL}"
PRIVATE_CONFIG_URL="https://production.cloudfront.docker.com${REDIRECT_TEST_PATH}"
PRIVATE_CONFIG_BEARER=sentinel-registry-bearer-must-not-cross-hosts
readonly PRIVATE_CONFIG_URL PRIVATE_CONFIG_BEARER
FAKE_PRIVATE_URL="${PRIVATE_CONFIG_URL}" \
FAKE_SENTINEL_BEARER="${PRIVATE_CONFIG_BEARER}" \
FAKE_PRIVATE_CONFIG_EVIDENCE="${PRIVATE_CONFIG_EVIDENCE}" \
  bash -c '
    set -euo pipefail
    ENV=/usr/bin/env
    CURL="$1"
    registry_bearer="${FAKE_SENTINEL_BEARER}"
    curl_status=""
    curl_content_type=""
    curl_redirect_url=""
    fail() { return 1; }
    source "$2"
    registry_request unauthenticated-private-config \
      "${FAKE_PRIVATE_URL}" "$3" 1024 application/octet-stream
    [[ "${curl_status}" == 200 && -z "${curl_redirect_url}" && \
      "${curl_content_type}" == application/octet-stream ]]
  ' private-config-contract "${PRIVATE_CONFIG_CURL}" \
    "${REGISTRY_REQUEST_SOURCE}" "${PRIVATE_CONFIG_OUTPUT}" ||
  fail_contract 'actual private-config request did not strip authorization and parse its response'
[[ "$(<"${PRIVATE_CONFIG_EVIDENCE}")" == private-config-verified ]] ||
  fail_contract 'private-config fake Curl did not record successful inspection'

write_config() {
  local candidate="$1"
  local diff_id="$2"
  printf '%s\n' \
    '{' \
    '  "architecture": "arm64",' \
    '  "config": {' \
    '    "Labels": {' \
    '      "org.opencontainers.image.version": "24.04"' \
    '    }' \
    '  },' \
    '  "created": "2026-08-31T00:00:00Z",' \
    '  "history": [],' \
    '  "os": "linux",' \
    '  "rootfs": {' \
    "    \"diff_ids\": [\"${diff_id}\"]," \
    '    "type": "layers"' \
    '  }' \
    '}' >"${candidate}/objects/config.json"
}

write_manifest() {
  local candidate="$1"
  local config_hash="${2:-$(file_sha256 "${candidate}/objects/config.json")}"
  local config_size="${3:-$(file_size "${candidate}/objects/config.json")}"
  local layer_hash="${4:-$(file_sha256 "${candidate}/objects/layer-01.tar.gz")}"
  local layer_size="${5:-$(file_size "${candidate}/objects/layer-01.tar.gz")}"
  printf '%s\n' \
    '{' \
    '  "schemaVersion": 2,' \
    '  "mediaType": "application/vnd.oci.image.manifest.v1+json",' \
    '  "config": {' \
    '    "mediaType": "application/vnd.oci.image.config.v1+json",' \
    "    \"digest\": \"sha256:${config_hash}\"," \
    "    \"size\": ${config_size}" \
    '  },' \
    '  "layers": [' \
    '    {' \
    '      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",' \
    "      \"digest\": \"sha256:${layer_hash}\"," \
    "      \"size\": ${layer_size}" \
    '    }' \
    '  ]' \
    '}' >"${candidate}/objects/manifest.json"
}

write_index() {
  local candidate="$1"
  local manifest_hash="${2:-$(file_sha256 "${candidate}/objects/manifest.json")}"
  local manifest_size="${3:-$(file_size "${candidate}/objects/manifest.json")}"
  local operating_system="${4:-linux}"
  local architecture="${5:-arm64}"
  local variant="${6:-v8}"
  printf '%s\n' \
    '{' \
    '  "schemaVersion": 2,' \
    '  "mediaType": "application/vnd.oci.image.index.v1+json",' \
    '  "manifests": [' \
    '    {' \
    '      "mediaType": "application/vnd.oci.image.manifest.v1+json",' \
    "      \"digest\": \"sha256:${manifest_hash}\"," \
    "      \"size\": ${manifest_size}," \
    '      "annotations": {' \
    '        "com.docker.official-images.bashbrew.arch": "arm64v8",' \
    '        "org.opencontainers.image.created": "2026-08-10T00:00:00Z",' \
    '        "org.opencontainers.image.revision": "73ecb123318a4fa4b264fae169d4773bc4c9c9c6",' \
    '        "org.opencontainers.image.source": "https://git.launchpad.net/cloud-images/+oci/ubuntu-base",' \
    '        "org.opencontainers.image.version": "24.04"' \
    '      },' \
    '      "platform": {' \
    "        \"architecture\": \"${architecture}\"," \
    "        \"os\": \"${operating_system}\"," \
    "        \"variant\": \"${variant}\"" \
    '      }' \
    '    }' \
    '  ]' \
    '}' >"${candidate}/objects/index.json"
}

rebind_profile_objects() {
  local profile="$1"
  local candidate="$2"
  local diff_id="$3"
  local index_path="${candidate}/objects/index.json"
  local manifest_path="${candidate}/objects/manifest.json"
  local config_path="${candidate}/objects/config.json"
  local layer_path="${candidate}/objects/layer-01.tar.gz"
  chmod 0600 -- "${profile}"
  replace_field "${profile}" builder_base_oci_index_size \
    "$(file_size "${index_path}")"
  replace_field "${profile}" builder_base_oci_index_digest \
    "sha256:$(file_sha256 "${index_path}")"
  replace_field "${profile}" builder_base_oci_manifest_size \
    "$(file_size "${manifest_path}")"
  replace_field "${profile}" builder_base_oci_manifest_digest \
    "sha256:$(file_sha256 "${manifest_path}")"
  replace_field "${profile}" builder_base_oci_config_size \
    "$(file_size "${config_path}")"
  replace_field "${profile}" builder_base_oci_config_digest \
    "sha256:$(file_sha256 "${config_path}")"
  replace_field "${profile}" builder_base_oci_layer_01_size \
    "$(file_size "${layer_path}")"
  replace_field "${profile}" builder_base_oci_layer_01_digest \
    "sha256:$(file_sha256 "${layer_path}")"
  replace_field "${profile}" builder_base_oci_diff_id_01 "${diff_id}"
  chmod 0400 -- "${profile}"
}

write_receipt() {
  local candidate="$1"
  local profile="$2"
  local profile_sha256
  local profile_id
  local repository
  local discovery_tag
  local diff_id
  profile_sha256="$(file_sha256 "${profile}")"
  profile_id="$(profile_field "${profile}" profile_id)"
  repository="$(profile_field "${profile}" builder_base_oci_repository)"
  discovery_tag="$(profile_field "${profile}" builder_base_oci_discovery_tag)"
  diff_id="$(profile_field "${profile}" builder_base_oci_diff_id_01)"
  {
    printf '%s\n' \
      'format=a-quo-omarchy-ubuntu-oci-candidate-v1' \
      'status=complete-candidate' \
      'authority=none' \
      "profile_id=${profile_id}" \
      "profile_sha256=${profile_sha256}" \
      "profile_repository=${TEST_PROFILE_REPOSITORY}" \
      "profile_commit=${TEST_PROFILE_COMMIT}" \
      "profile_path=${TEST_PROFILE_REPOSITORY_PATH}" \
      'profile_external_authentication=required-not-established-by-this-receipt' \
      'acquisition_history=not-authenticated-by-this-receipt' \
      "subject_repository=${repository}" \
      "discovery_tag=${discovery_tag}" \
      'discovery_tag_authority=none' \
      'platform=linux/arm64' \
      'variant=v8' \
      'object_count=4'
    local index=0
    local role
    local relative_path
    for role in index manifest config layer; do
      ((index += 1))
      case "${role}" in
        index) relative_path=objects/index.json ;;
        manifest) relative_path=objects/manifest.json ;;
        config) relative_path=objects/config.json ;;
        layer) relative_path=objects/layer-01.tar.gz ;;
      esac
      printf 'object_%02d=%s|%s|%s|%s\n' \
        "${index}" "${role}" "${relative_path}" \
        "$(file_size "${candidate}/${relative_path}")" \
        "$(file_sha256 "${candidate}/${relative_path}")"
    done
    printf '%s\n' \
      'descriptor_bindings=verified-non-authoritative' \
      "diff_id=${diff_id}" \
      'publisher_authentication=not-established' \
      'source_to_image_provenance=not-established' \
      'freshness=not-established' \
      'safety=not-established' \
      'byte_identity=verified-non-authoritative'
  } >"${candidate}/receipt.oci.v1"
  chmod 0400 -- "${candidate}/receipt.oci.v1"
}

snapshot_profile() {
  local candidate="$1"
  local profile="$2"
  rm -f -- "${candidate}/profile.snapshot"
  cp -- "${profile}" "${candidate}/profile.snapshot"
  chmod 0400 -- "${candidate}/profile.snapshot"
}

complete_candidate() {
  local candidate="$1"
  rm -f -- "${candidate}/INCOMPLETE"
  printf '%s\n' complete-candidate >"${candidate}/COMPLETE"
  chmod 0400 -- "${candidate}/COMPLETE"
}

copy_candidate() {
  local name="$1"
  local destination="${TEMPORARY_ROOT}/${name}"
  cp -a -- "${CANDIDATE}" "${destination}"
  printf '%s\n' "${destination}"
}

assert_candidate_refused() {
  local label="$1"
  local expected="$2"
  local candidate="$3"
  local profile="${4:-${TEST_PROFILE}}"
  local digest
  digest="$(file_sha256 "${profile}")"
  assert_refused "${label}" "${expected}" \
    "${VERIFIER}" --profile "${profile}" \
    --externally-expected-profile-sha256 "${digest}" \
    --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
    --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
    --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
    --candidate "${candidate}"
}

prepare_semantic_mutant() {
  local name="$1"
  MUTATED="$(copy_candidate "${name}")"
  MUTATED_PROFILE="${TEMPORARY_ROOT}/${name}.profile"
  cp -- "${TEST_PROFILE}" "${MUTATED_PROFILE}"
  rm -- "${MUTATED}/receipt.oci.v1" "${MUTATED}/COMPLETE"
  printf '%s\n' incomplete-candidate >"${MUTATED}/INCOMPLETE"
  chmod 0400 -- "${MUTATED}/INCOMPLETE" "${MUTATED_PROFILE}"
  find "${MUTATED}/objects" -type f -exec chmod 0600 -- {} +
}

finish_semantic_mutant() {
  local diff_id="$1"
  rebind_profile_objects "${MUTATED_PROFILE}" "${MUTATED}" "${diff_id}"
  snapshot_profile "${MUTATED}" "${MUTATED_PROFILE}"
  write_receipt "${MUTATED}" "${MUTATED_PROFILE}"
  find "${MUTATED}/objects" -type f -exec chmod 0400 -- {} +
  complete_candidate "${MUTATED}"
}

# Acquirer failures below must occur before any network-capable operation.
assert_usage_refused acquirer-no-arguments "${ACQUIRER}"
assert_usage_refused caller-url-refused \
  "${ACQUIRER}" --url https://example.invalid/hostile
assert_usage_refused verifier-no-arguments "${VERIFIER}"

if grep -Eq '(^|[;&|[:space:]/])(docker|podman|buildah|qemu-system|pacman|apt(-get)?|systemctl|mount|sudo)([;&|[:space:]]|$)' \
  "${ACQUIRER}" "${VERIFIER}"; then
  fail_contract 'OCI scripts contain a forbidden build, package, VM, service, mount, or privilege command'
fi
if grep -Eq '^[[:space:]]*(curl|wget|gh|skopeo|oras)([[:space:]]|$)|/usr/bin/(curl|wget|gh|skopeo|oras)([^A-Za-z0-9_-]|$)|\$\{(CURL|WGET|GH|SKOPEO|ORAS)\}' \
  "${VERIFIER}"; then
  fail_contract 'offline OCI verifier contains a network-capable command'
fi
for forbidden_word in bearer_token access_token refresh_token authorization_header; do
  if grep -Eiq "(^|[^a-z_])${forbidden_word}([^a-z_]|$)" "${VERIFIER}"; then
    fail_contract "offline OCI verifier unexpectedly handles secret material: ${forbidden_word}"
  fi
done
size_rejection_line="$(awk '/fail "object has the wrong size:/ {
  print NR; found += 1
} END { if (found != 1) exit 73 }' "${VERIFIER}")"
hash_computation_line="$(awk 'index($0, "observed_hash=") && index($0, "SHA256SUM") {
  print NR; found += 1
} END { if (found != 1) exit 73 }' "${VERIFIER}")"
[[ "${size_rejection_line}" -lt "${hash_computation_line}" ]] ||
  fail_contract 'verifier must reject object size before computing its SHA-256'

# Build a tiny, deterministic, syntactically valid OCI graph without network access.
TEST_PROFILE="${TEMPORARY_ROOT}/synthetic-v2.profile"
CANDIDATE="${TEMPORARY_ROOT}/synthetic-candidate"
readonly TEST_PROFILE CANDIDATE
cp -- "${CANONICAL_PROFILE}" "${TEST_PROFILE}"
mkdir -m 0700 -- "${CANDIDATE}" "${CANDIDATE}/objects"
printf '%s\n' incomplete-candidate >"${CANDIDATE}/INCOMPLETE"
mkdir -m 0700 -- "${TEMPORARY_ROOT}/layer-root"
printf '%s\n' 'A Quo synthetic OCI contract layer' \
  >"${TEMPORARY_ROOT}/layer-root/evidence.txt"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  -C "${TEMPORARY_ROOT}/layer-root" -cf "${TEMPORARY_ROOT}/layer.tar" .
gzip -n -c -- "${TEMPORARY_ROOT}/layer.tar" \
  >"${CANDIDATE}/objects/layer-01.tar.gz"
SYNTHETIC_DIFF_ID="sha256:$(file_sha256 "${TEMPORARY_ROOT}/layer.tar")"
readonly SYNTHETIC_DIFF_ID
write_config "${CANDIDATE}" "${SYNTHETIC_DIFF_ID}"
write_manifest "${CANDIDATE}"
write_index "${CANDIDATE}"
rebind_profile_objects "${TEST_PROFILE}" "${CANDIDATE}" "${SYNTHETIC_DIFF_ID}"
snapshot_profile "${CANDIDATE}" "${TEST_PROFILE}"
chmod 0400 -- "${CANDIDATE}/INCOMPLETE"
find "${CANDIDATE}/objects" -type f -exec chmod 0400 -- {} +

TEST_PROFILE_SHA256="$(file_sha256 "${TEST_PROFILE}")"
readonly TEST_PROFILE_SHA256
OBSERVATIONS="$("${VERIFIER}" --emit-observations \
  --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${CANDIDATE}")"
readonly OBSERVATIONS
[[ "${OBSERVATIONS}" == candidate_status=verified-incomplete-non-authoritative$'\n'* ]] ||
  fail_contract "synthetic observation output is unexpected: ${OBSERVATIONS@Q}"
[[ "${OBSERVATIONS}" == *$'\nnetwork_activity=false\nvm_started=false' ]] ||
  fail_contract 'synthetic observation output did not close the network and VM claims'

write_receipt "${CANDIDATE}" "${TEST_PROFILE}"
PRE_COMPLETION="$("${VERIFIER}" --pre-completion \
  --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${CANDIDATE}")"
readonly PRE_COMPLETION
[[ "${PRE_COMPLETION}" == candidate_status=verified-incomplete-non-authoritative$'\n'* ]] ||
  fail_contract "pre-completion output is unexpected: ${PRE_COMPLETION@Q}"
complete_candidate "${CANDIDATE}"

EXPECTED_OUTPUT="$(printf '%s\n' \
  'candidate_status=verified-non-authoritative' \
  'authority=none' \
  'profile_id=a-quo-omarchy4-aarch64-dec29fa-v2' \
  "profile_sha256=${TEST_PROFILE_SHA256}" \
  'object_count=4' \
  "object_01=index|objects/index.json|$(file_size "${CANDIDATE}/objects/index.json")|$(file_sha256 "${CANDIDATE}/objects/index.json")" \
  "object_02=manifest|objects/manifest.json|$(file_size "${CANDIDATE}/objects/manifest.json")|$(file_sha256 "${CANDIDATE}/objects/manifest.json")" \
  "object_03=config|objects/config.json|$(file_size "${CANDIDATE}/objects/config.json")|$(file_sha256 "${CANDIDATE}/objects/config.json")" \
  "object_04=layer|objects/layer-01.tar.gz|$(file_size "${CANDIDATE}/objects/layer-01.tar.gz")|$(file_sha256 "${CANDIDATE}/objects/layer-01.tar.gz")" \
  'descriptor_bindings=verified-non-authoritative' \
  "diff_id=${SYNTHETIC_DIFF_ID}" \
  'publisher_authentication=not-established' \
  'source_to_image_provenance=not-established' \
  'freshness=not-established' \
  'safety=not-established' \
  'byte_identity=verified-non-authoritative' \
  'network_activity=false' \
  'vm_started=false')"
readonly EXPECTED_OUTPUT
OBSERVED_OUTPUT="$("${VERIFIER}" \
  --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${CANDIDATE}")"
readonly OBSERVED_OUTPUT
[[ "${OBSERVED_OUTPUT}" == "${EXPECTED_OUTPUT}" ]] ||
  fail_contract "completed candidate output mismatch: ${OBSERVED_OUTPUT@Q}"

wrong_digest=0000000000000000000000000000000000000000000000000000000000000000
assert_refused wrong-external-digest \
  'external profile bytes do not match the caller-supplied expected digest' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${wrong_digest}" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${CANDIDATE}"

assert_refused unsafe-profile-repository \
  'externally expected profile repository is not one exact HTTPS .git locator' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --externally-expected-profile-repository http://example.invalid/a-quo.git \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${CANDIDATE}"

assert_refused unsafe-profile-commit \
  'externally expected profile commit is not one lowercase Git object identifier' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit ABCD \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${CANDIDATE}"

assert_refused unsafe-profile-path \
  'externally expected profile path is not one safe repository-relative profile path' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path ../synthetic.profile \
  --candidate "${CANDIDATE}"

assert_refused profile-locator-mismatch \
  'receipt field order or value is invalid' \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --externally-expected-profile-repository https://other.example.invalid/a-quo.git \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${CANDIDATE}"

assert_usage_refused duplicate-profile-locator \
  "${VERIFIER}" --profile "${TEST_PROFILE}" \
  --externally-expected-profile-sha256 "${TEST_PROFILE_SHA256}" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${CANDIDATE}"

MUTATED="$(copy_candidate missing-object)"
rm -- "${MUTATED}/objects/config.json"
assert_candidate_refused missing-object 'candidate is missing one or more required entries' "${MUTATED}"

MUTATED="$(copy_candidate unexpected-entry)"
printf '%s\n' hostile >"${MUTATED}/objects/unexpected"
chmod 0400 -- "${MUTATED}/objects/unexpected"
assert_candidate_refused unexpected-entry 'candidate contains an unexpected entry' "${MUTATED}"

MUTATED="$(copy_candidate symlink-object)"
cp -- "${MUTATED}/objects/config.json" "${TEMPORARY_ROOT}/symlink-target"
rm -- "${MUTATED}/objects/config.json"
ln -s -- "${TEMPORARY_ROOT}/symlink-target" "${MUTATED}/objects/config.json"
assert_candidate_refused symlink-object 'candidate file has the wrong type' "${MUTATED}"

MUTATED="$(copy_candidate hardlink-object)"
chmod 0600 -- "${MUTATED}/objects/config.json"
ln -- "${MUTATED}/objects/config.json" "${TEMPORARY_ROOT}/hardlink-peer"
chmod 0400 -- "${MUTATED}/objects/config.json"
assert_candidate_refused hardlink-object 'candidate file has the wrong owner, mode, or link count' "${MUTATED}"

MUTATED="$(copy_candidate special-object)"
rm -- "${MUTATED}/objects/config.json"
mkfifo -m 0400 -- "${MUTATED}/objects/config.json"
assert_candidate_refused special-object 'candidate file has the wrong type' "${MUTATED}"

MUTATED="$(copy_candidate wrong-object-mode)"
chmod 0600 -- "${MUTATED}/objects/config.json"
assert_candidate_refused wrong-object-mode 'candidate file has the wrong owner, mode, or link count' "${MUTATED}"

MUTATED="$(copy_candidate wrong-directory-mode)"
chmod 0755 -- "${MUTATED}/objects"
assert_candidate_refused wrong-directory-mode 'candidate directory has the wrong owner or mode' "${MUTATED}"

MUTATED="$(copy_candidate symlink-objects-directory)"
mv -- "${MUTATED}/objects" "${TEMPORARY_ROOT}/objects-target"
ln -s -- "${TEMPORARY_ROOT}/objects-target" "${MUTATED}/objects"
assert_candidate_refused symlink-objects-directory 'candidate directory has the wrong type' "${MUTATED}"

ln -s -- "${CANDIDATE}" "${TEMPORARY_ROOT}/candidate-directory-symlink"
assert_candidate_refused candidate-directory-symlink \
  'candidate must be one directory and not a symlink' \
  "${TEMPORARY_ROOT}/candidate-directory-symlink"

MUTATED="$(copy_candidate mutated-size)"
chmod 0600 -- "${MUTATED}/objects/config.json"
printf '%s' X >>"${MUTATED}/objects/config.json"
chmod 0400 -- "${MUTATED}/objects/config.json"
assert_candidate_refused mutated-size 'object has the wrong size' "${MUTATED}"

MUTATED="$(copy_candidate mutated-hash)"
chmod 0600 -- "${MUTATED}/objects/config.json"
printf X | dd of="${MUTATED}/objects/config.json" bs=1 count=1 conv=notrunc status=none
chmod 0400 -- "${MUTATED}/objects/config.json"
assert_candidate_refused mutated-hash 'object has the wrong SHA-256' "${MUTATED}"

for receipt_mutation in reorder unknown duplicate authority profile-locator; do
  MUTATED="$(copy_candidate "receipt-${receipt_mutation}")"
  chmod 0600 -- "${MUTATED}/receipt.oci.v1"
  case "${receipt_mutation}" in
    reorder)
      awk 'NR == 1 { first = $0; next } NR == 2 { print; print first; next } { print }' \
        "${MUTATED}/receipt.oci.v1" >"${MUTATED}/receipt.changed"
      ;;
    unknown)
      cp -- "${MUTATED}/receipt.oci.v1" "${MUTATED}/receipt.changed"
      printf '%s\n' expected_safe=true >>"${MUTATED}/receipt.changed"
      ;;
    duplicate)
      awk '{ print } /^authority=/ { print }' "${MUTATED}/receipt.oci.v1" \
        >"${MUTATED}/receipt.changed"
      ;;
    authority)
      awk '$0 == "authority=none" { print "authority=trusted"; next } { print }' \
        "${MUTATED}/receipt.oci.v1" >"${MUTATED}/receipt.changed"
      ;;
    profile-locator)
      awk '/^profile_commit=/ {
        print "profile_commit=0000000000000000000000000000000000000000"; next
      } { print }' "${MUTATED}/receipt.oci.v1" >"${MUTATED}/receipt.changed"
      ;;
  esac
  mv -- "${MUTATED}/receipt.changed" "${MUTATED}/receipt.oci.v1"
  chmod 0400 -- "${MUTATED}/receipt.oci.v1"
  case "${receipt_mutation}" in
    reorder) expected_receipt_error='receipt field order or value is invalid' ;;
    unknown|duplicate) expected_receipt_error='receipt does not have the exact field count' ;;
    authority) expected_receipt_error='receipt field order or value is invalid' ;;
    profile-locator) expected_receipt_error='receipt field order or value is invalid' ;;
  esac
  assert_candidate_refused "receipt-${receipt_mutation}" \
    "${expected_receipt_error}" "${MUTATED}"
done

MUTATED="$(copy_candidate both-markers)"
printf '%s\n' incomplete-candidate >"${MUTATED}/INCOMPLETE"
chmod 0400 -- "${MUTATED}/INCOMPLETE"
assert_candidate_refused both-markers 'candidate contains an unexpected entry' "${MUTATED}"

MUTATED="$(copy_candidate no-marker)"
rm -- "${MUTATED}/COMPLETE"
assert_candidate_refused no-marker 'candidate is missing one or more required entries' "${MUTATED}"

prepare_semantic_mutant invalid-index-json
printf '%s\n' '{not-json}' >"${MUTATED}/objects/index.json"
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused invalid-index-json \
  'index JSON does not bind the expected ARM64/v8 manifest and named source assertions' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant multi-document-index-json
printf '%s\n' '{}' >>"${MUTATED}/objects/index.json"
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused multi-document-index-json \
  'index JSON does not bind the expected ARM64/v8 manifest and named source assertions' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant multi-document-manifest-json
printf '%s\n' '{}' >>"${MUTATED}/objects/manifest.json"
write_index "${MUTATED}"
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused multi-document-manifest-json \
  'manifest JSON does not bind the expected config and compressed layer descriptors' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant multi-document-config-json
printf '%s\n' '{}' >>"${MUTATED}/objects/config.json"
write_manifest "${MUTATED}"
write_index "${MUTATED}"
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused multi-document-config-json \
  'config JSON does not bind the expected platform, version, and one DiffID' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant platform-mismatch
write_index "${MUTATED}" '' '' windows arm64 v8
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused platform-mismatch \
  'index JSON does not bind the expected ARM64/v8 manifest and named source assertions' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant variant-mismatch
write_index "${MUTATED}" '' '' linux arm64 v7
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused variant-mismatch \
  'index JSON does not bind the expected ARM64/v8 manifest and named source assertions' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant manifest-link-mismatch
write_index "${MUTATED}" \
  0000000000000000000000000000000000000000000000000000000000000000 \
  "$(file_size "${MUTATED}/objects/manifest.json")" linux arm64 v8
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused manifest-link-mismatch \
  'index JSON does not bind the expected ARM64/v8 manifest and named source assertions' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant config-link-mismatch
write_manifest "${MUTATED}" \
  0000000000000000000000000000000000000000000000000000000000000000 \
  "$(file_size "${MUTATED}/objects/config.json")"
write_index "${MUTATED}"
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused config-link-mismatch \
  'manifest JSON does not bind the expected config and compressed layer descriptors' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant layer-link-mismatch
write_manifest "${MUTATED}" '' '' \
  0000000000000000000000000000000000000000000000000000000000000000 \
  "$(file_size "${MUTATED}/objects/layer-01.tar.gz")"
write_index "${MUTATED}"
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused layer-link-mismatch \
  'manifest JSON does not bind the expected config and compressed layer descriptors' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant truncated-gzip
head -c -8 -- "${MUTATED}/objects/layer-01.tar.gz" \
  >"${MUTATED}/objects/layer.changed"
mv -- "${MUTATED}/objects/layer.changed" "${MUTATED}/objects/layer-01.tar.gz"
write_manifest "${MUTATED}"
write_index "${MUTATED}"
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused truncated-gzip \
  'compressed layer is not one accepted gzip byte stream within the time bound' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant trailing-gzip
printf '%s' trailing >>"${MUTATED}/objects/layer-01.tar.gz"
write_manifest "${MUTATED}"
write_index "${MUTATED}"
finish_semantic_mutant "${SYNTHETIC_DIFF_ID}"
assert_candidate_refused trailing-gzip \
  'compressed layer is not one accepted gzip byte stream within the time bound' \
  "${MUTATED}" "${MUTATED_PROFILE}"

prepare_semantic_mutant diff-id-mismatch
readonly ZERO_DIFF_ID=sha256:0000000000000000000000000000000000000000000000000000000000000000
write_config "${MUTATED}" "${ZERO_DIFF_ID}"
write_manifest "${MUTATED}"
write_index "${MUTATED}"
finish_semantic_mutant "${ZERO_DIFF_ID}"
assert_candidate_refused diff-id-mismatch \
  'uncompressed layer DiffID does not match the profile' \
  "${MUTATED}" "${MUTATED_PROFILE}"

# Exercise the same production bound logic at a cheaper scale in an isolated
# verifier copy. The production script's exact 512 MiB constant is asserted;
# only that one line is changed to 1 MiB in the disposable copy.
prepare_semantic_mutant decompression-bomb-bound
dd if=/dev/zero bs=1048576 count=1 status=none | gzip -n -c \
  >"${TEMPORARY_ROOT}/one-mebibyte.gz"
: >"${MUTATED}/objects/layer-01.tar.gz"
for ((_index = 1; _index <= 2; _index += 1)); do
  dd if="${TEMPORARY_ROOT}/one-mebibyte.gz" \
    of="${MUTATED}/objects/layer-01.tar.gz" oflag=append conv=notrunc status=none
done
write_config "${MUTATED}" "${ZERO_DIFF_ID}"
write_manifest "${MUTATED}"
write_index "${MUTATED}"
finish_semantic_mutant "${ZERO_DIFF_ID}"
grep -Fxq 'readonly MAXIMUM_UNCOMPRESSED_LAYER_BYTES=536870912' "${VERIFIER}" ||
  fail_contract 'production verifier does not retain the reviewed 512 MiB expansion bound'
SMALL_BOUND_VERIFIER="${TEMPORARY_ROOT}/verify-oci-small-bound.sh"
readonly SMALL_BOUND_VERIFIER
sed 's/^readonly MAXIMUM_UNCOMPRESSED_LAYER_BYTES=536870912$/readonly MAXIMUM_UNCOMPRESSED_LAYER_BYTES=1048576/' \
  "${VERIFIER}" >"${SMALL_BOUND_VERIFIER}"
chmod 0755 -- "${SMALL_BOUND_VERIFIER}"
[[ "$(grep -Fc 'MAXIMUM_UNCOMPRESSED_LAYER_BYTES=1048576' "${SMALL_BOUND_VERIFIER}")" -eq 1 ]] ||
  fail_contract 'isolated small-bound verifier rewrite was not exact'
assert_refused decompression-bomb-bound \
  'uncompressed layer exceeds the byte or time bound' \
  "${SMALL_BOUND_VERIFIER}" --profile "${MUTATED_PROFILE}" \
  --externally-expected-profile-sha256 "$(file_sha256 "${MUTATED_PROFILE}")" \
  --externally-expected-profile-repository "${TEST_PROFILE_REPOSITORY}" \
  --externally-expected-profile-commit "${TEST_PROFILE_COMMIT}" \
  --externally-expected-profile-path "${TEST_PROFILE_REPOSITORY_PATH}" \
  --candidate "${MUTATED}"

if [[ "$(id -u)" -eq 0 ]]; then
  assert_refused root-acquisition 'networked candidate acquisition must not run as root' \
    "${ACQUIRER}" --profile "${CANONICAL_PROFILE}" \
    --output "${OUTPUT_ROOT}/contract-root-must-not-exist" \
    --acknowledge-networked-candidate-only
else
  # The networked acquirer alone owns the canonical profile and output-root
  # policy. Each refusal below happens before its first curl invocation.
  assert_refused synthetic-profile-acquisition \
    'profile must be the canonical v2 profile' \
    "${ACQUIRER}" --profile "${TEST_PROFILE}" \
    --output "${OUTPUT_ROOT}/contract-must-not-exist" \
    --acknowledge-networked-candidate-only

  mkdir -p -- "${OUTPUT_ROOT}"
  created_output="${OUTPUT_ROOT}/contract-existing-${BASHPID}"
  mkdir -m 0700 -- "${created_output}"
  assert_refused existing-output 'output already exists' \
    "${ACQUIRER}" --profile "${CANONICAL_PROFILE}" \
    --output "${created_output}" \
    --acknowledge-networked-candidate-only

  # Copy the scripts into a disposable repository and change only the pinned
  # curl path. The fake returns a known token, then fails the first object
  # transport. This proves the real acquirer does not put that token in argv,
  # diagnostics, retained candidate files, or a receipt.
  FAKE_REPOSITORY="${TEMPORARY_ROOT}/fake-repository"
  FAKE_SCRIPTS="${FAKE_REPOSITORY}/scripts"
  FAKE_PROFILE_DIRECTORY="${FAKE_REPOSITORY}/packaging/evaluation-targets"
  FAKE_CURL="${FAKE_REPOSITORY}/fake-curl"
  FAKE_ACQUIRER="${FAKE_SCRIPTS}/acquire-omarchy-ubuntu-oci-candidate.sh"
  readonly FAKE_REPOSITORY FAKE_SCRIPTS FAKE_PROFILE_DIRECTORY
  readonly FAKE_CURL FAKE_ACQUIRER
  mkdir -p -- "${FAKE_SCRIPTS}" "${FAKE_PROFILE_DIRECTORY}"
  chmod 0700 -- "${FAKE_REPOSITORY}" "${FAKE_REPOSITORY}/packaging" \
    "${FAKE_PROFILE_DIRECTORY%/*}" "${FAKE_PROFILE_DIRECTORY}" "${FAKE_SCRIPTS}"
  cp -- "${CANONICAL_PROFILE}" "${FAKE_PROFILE_DIRECTORY}/$(basename -- "${CANONICAL_PROFILE}")"
  cp -- "${SCRIPT_DIRECTORY}/verify-omarchy-evaluation-target-profile.sh" \
    "${VERIFIER}" "${FAKE_SCRIPTS}/"
  sed "s|^readonly CURL=/usr/bin/curl$|readonly CURL=${FAKE_CURL}|" \
    "${ACQUIRER}" >"${FAKE_ACQUIRER}"
  chmod 0755 -- "${FAKE_ACQUIRER}" "${FAKE_SCRIPTS}/"*.sh
  # The following single-quoted lines are source for the disposable fake.
  # shellcheck disable=SC2016
  {
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'set -euo pipefail' \
      ': "${FAKE_CURL_LOG:?}" "${FAKE_CURL_MODE:?}" "${FAKE_CURL_SENTINEL:?}"' \
      'if [[ "${1:-}" == --version ]]; then' \
      '  printf "%s\n" "curl 8.4.0 synthetic-contract"' \
      '  exit 0' \
      'fi' \
      '{ printf "%s\n" call; printf "%q\n" "$@"; } >>"${FAKE_CURL_LOG}"' \
      'if [[ " $* " == *auth.docker.io/token* ]]; then' \
      '  if [[ "${FAKE_CURL_MODE}" == interrupt ]]; then' \
      '    : >"${FAKE_CURL_SENTINEL}"' \
      "    trap 'exit 130' HUP INT TERM" \
      '    while :; do sleep 1; done' \
      '  fi' \
      '  metadata=' \
      '  for argument in "$@"; do' \
      '    if [[ "${argument}" == %output\{* ]]; then' \
      '      metadata="${argument#*\{}"' \
      '      metadata="${metadata%%\}*}"' \
      '    fi' \
      '  done' \
      '  [[ -n "${metadata}" ]]' \
      '  printf "200\n" >"${metadata}"' \
      '  printf "{\"token\":\"%s\"}" "${FAKE_REGISTRY_TOKEN:?}"' \
      '  exit 0' \
      'fi' \
      'exit 22'
  } >"${FAKE_CURL}"
  chmod 0755 -- "${FAKE_CURL}"

  FAKE_LOG="${TEMPORARY_ROOT}/fake-curl.argv"
  FAKE_SENTINEL="${TEMPORARY_ROOT}/fake-curl.sentinel"
  FAKE_TOKEN=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._
  readonly FAKE_LOG FAKE_SENTINEL FAKE_TOKEN
  FAKE_PROFILE="${FAKE_PROFILE_DIRECTORY}/$(basename -- "${CANONICAL_PROFILE}")"
  FAKE_OUTPUT_ROOT="${FAKE_REPOSITORY}/target/omarchy-evaluation-input-observations"
  FAKE_FAILED_OUTPUT="${FAKE_OUTPUT_ROOT}/token-redaction"
  readonly FAKE_PROFILE FAKE_OUTPUT_ROOT FAKE_FAILED_OUTPUT
  set +e
  FAKE_CURL_LOG="${FAKE_LOG}" \
  FAKE_CURL_MODE=transport-failure \
  FAKE_CURL_SENTINEL="${FAKE_SENTINEL}" \
  FAKE_REGISTRY_TOKEN="${FAKE_TOKEN}" \
    "${FAKE_ACQUIRER}" --profile "${FAKE_PROFILE}" \
    --output "${FAKE_FAILED_OUTPUT}" \
    --acknowledge-networked-candidate-only \
    >"${TEMPORARY_ROOT}/fake-acquirer.output" 2>&1
  fake_status="$?"
  set -e
  [[ "${fake_status}" -eq 1 ]] ||
    fail_contract "fake transport failure returned status ${fake_status}"
  [[ -f "${FAKE_FAILED_OUTPUT}/INCOMPLETE" && \
    ! -e "${FAKE_FAILED_OUTPUT}/COMPLETE" && \
    ! -e "${FAKE_FAILED_OUTPUT}/receipt.oci.v1" ]] ||
    fail_contract 'failed acquisition did not retain only an incomplete candidate state'
  if grep -aRFq -- "${FAKE_TOKEN}" \
    "${TEMPORARY_ROOT}/fake-acquirer.output" "${FAKE_LOG}" "${FAKE_FAILED_OUTPUT}"; then
    fail_contract 'registry bearer token escaped into argv, output, or retained files'
  fi

  # Interrupt a second fake token request as one process group. The acquirer
  # must return 130 and leave an explicit incomplete state, never COMPLETE.
  : >"${FAKE_LOG}"
  rm -f -- "${FAKE_SENTINEL}"
  FAKE_INTERRUPTED_OUTPUT="${FAKE_OUTPUT_ROOT}/interrupted"
  readonly FAKE_INTERRUPTED_OUTPUT
  setsid env \
    FAKE_CURL_LOG="${FAKE_LOG}" \
    FAKE_CURL_MODE=interrupt \
    FAKE_CURL_SENTINEL="${FAKE_SENTINEL}" \
    FAKE_REGISTRY_TOKEN="${FAKE_TOKEN}" \
    "${FAKE_ACQUIRER}" --profile "${FAKE_PROFILE}" \
    --output "${FAKE_INTERRUPTED_OUTPUT}" \
    --acknowledge-networked-candidate-only \
    >"${TEMPORARY_ROOT}/interrupted-acquirer.output" 2>&1 &
  interrupted_pid="$!"
  sentinel_seen=false
  for ((_attempt = 1; _attempt <= 100; _attempt += 1)); do
    if [[ -e "${FAKE_SENTINEL}" ]]; then
      sentinel_seen=true
      break
    fi
    sleep 0.02
  done
  [[ "${sentinel_seen}" == true ]] || {
    kill -TERM -- "-${interrupted_pid}" 2>/dev/null || true
    fail_contract 'fake curl did not reach the interruptible token request'
  }
  kill -TERM -- "-${interrupted_pid}"
  set +e
  wait "${interrupted_pid}"
  interrupted_status="$?"
  set -e
  [[ "${interrupted_status}" -eq 130 ]] ||
    fail_contract "interrupted acquisition returned status ${interrupted_status}"
  [[ -f "${FAKE_INTERRUPTED_OUTPUT}/INCOMPLETE" && \
    ! -e "${FAKE_INTERRUPTED_OUTPUT}/COMPLETE" && \
    ! -e "${FAKE_INTERRUPTED_OUTPUT}/receipt.oci.v1" ]] ||
    fail_contract 'interrupted acquisition did not retain an incomplete-only state'
fi

grep -Fq 'if (( EUID == 0 )); then' "${ACQUIRER}" ||
  fail_contract 'acquirer does not retain the explicit root predicate'
grep -Fq "fail 'networked candidate acquisition must not run as root'" \
  "${ACQUIRER}" || fail_contract 'acquirer does not retain the explicit root refusal'
grep -Fq 'readonly CURL=/usr/bin/curl' "${ACQUIRER}" ||
  fail_contract 'acquirer does not pin the curl program path'
for secrecy_control in \
  'set +x' \
  'ulimit -c 0' \
  '-u SSLKEYLOGFILE' \
  'Authorization: Bearer' \
  '/proc/self/fd/'; do
  grep -Fq -- "${secrecy_control}" "${ACQUIRER}" ||
    fail_contract "acquirer is missing bearer-token secrecy control: ${secrecy_control}"
done
if grep -Eiq 'printf[^\n]*(bearer|token)|receipt[^\n]*(bearer|token)' "${ACQUIRER}"; then
  fail_contract 'acquirer has an apparent bearer-token output or receipt path'
fi
grep -Eq 'trap .*(EXIT|INT|TERM)' "${ACQUIRER}" ||
  fail_contract 'acquirer does not have an auditable interruption cleanup trap'
grep -Fq 'set -o noclobber' "${ACQUIRER}" ||
  fail_contract 'acquirer does not use exclusive marker creation'
# This asserts the pinned variable invocation text rather than expanding it.
# shellcheck disable=SC2016
grep -Fq '${MV} -T --no-clobber --' "${ACQUIRER}" ||
  fail_contract 'acquirer does not use no-clobber object publication'

printf '%s\n' 'offline Omarchy Ubuntu OCI candidate contract passed'
