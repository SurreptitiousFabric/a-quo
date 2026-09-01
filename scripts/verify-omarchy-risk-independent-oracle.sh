#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
fixture_dir="${1:-${repo_root}/fixtures/omarchy-plugin-risk-v1-independent}"
manifest="${fixture_dir}/oracle-manifest.json"

fail() {
  printf 'independent risk oracle: %s\n' "$*" >&2
  exit 1
}

for command in basename cmp cut find jq mktemp rm sha256sum sort tr wc; do
  command -v "${command}" >/dev/null 2>&1 || fail "required command is unavailable: ${command}"
done

files=(
  local-policy.json
  operation-assessment.json
  policy-result.json
  previous-native-reports.json
  publisher-evidence-new.json
  publisher-evidence-old.json
  structural-record-new.json
  structural-record-old.json
  update-delta.json
)

expected_inventory="$(printf '%s\n' "${files[@]}" oracle-manifest.json | LC_ALL=C sort)"
actual_inventory="$(find "${fixture_dir}" -maxdepth 1 -type f -name '*.json' -printf '%f\n' | LC_ALL=C sort)"
[[ "${actual_inventory}" == "${expected_inventory}" ]] || fail "JSON inventory differs from the closed manifest"

temporary_dir="$(mktemp -d)"
trap 'rm -rf -- "${temporary_dir}"' EXIT

canonicalize() {
  LC_ALL=C jq -j -S -c . "$1"
}

digest() {
  sha256sum "$1" | cut -d' ' -f1
}

json() {
  LC_ALL=C jq -cer "$1" "$2"
}

assert_equal() {
  local description="$1"
  local observed="$2"
  local expected="$3"
  [[ "${observed}" == "${expected}" ]] || fail "${description}: expected ${expected}, observed ${observed}"
}

canonicalize "${manifest}" >"${temporary_dir}/oracle-manifest.json"
cmp -s "${manifest}" "${temporary_dir}/oracle-manifest.json" || fail "oracle-manifest.json is not canonical"

for name in "${files[@]}"; do
  path="${fixture_dir}/${name}"
  canonicalize "${path}" >"${temporary_dir}/${name}"
  cmp -s "${path}" "${temporary_dir}/${name}" || fail "${name} is not canonical"

  expected_size="$(LC_ALL=C jq -cer --arg name "${name}" '.files[$name].size' "${manifest}")"
  observed_size="$(wc -c <"${path}" | tr -d '[:space:]')"
  assert_equal "${name} size" "${observed_size}" "${expected_size}"

  expected_sha256="$(LC_ALL=C jq -cer --arg name "${name}" '.files[$name].sha256' "${manifest}")"
  assert_equal "${name} SHA-256" "$(digest "${path}")" "${expected_sha256}"

  if [[ "${name}" != "previous-native-reports.json" ]]; then
    expected_schema="$(LC_ALL=C jq -cer --arg name "${name}" '.files[$name].schema' "${manifest}")"
    assert_equal "${name} schema" "$(json '.schema' "${path}")" "${expected_schema}"
  fi
done

old_publisher_sha256="$(digest "${fixture_dir}/publisher-evidence-old.json")"
publisher_sha256="$(digest "${fixture_dir}/publisher-evidence-new.json")"
old_structural_sha256="$(digest "${fixture_dir}/structural-record-old.json")"
structural_sha256="$(digest "${fixture_dir}/structural-record-new.json")"
delta_sha256="$(digest "${fixture_dir}/update-delta.json")"
policy_sha256="$(digest "${fixture_dir}/local-policy.json")"
result_sha256="$(digest "${fixture_dir}/policy-result.json")"

delta="${fixture_dir}/update-delta.json"
result="${fixture_dir}/policy-result.json"
assessment="${fixture_dir}/operation-assessment.json"
previous_reports="${fixture_dir}/previous-native-reports.json"

assert_equal "delta previous publisher binding" "$(json '.previous_publisher_evidence_sha256' "${delta}")" "${old_publisher_sha256}"
assert_equal "delta current publisher binding" "$(json '.publisher_evidence_sha256' "${delta}")" "${publisher_sha256}"
assert_equal "delta previous structural binding" "$(json '.previous_structural_record_sha256' "${delta}")" "${old_structural_sha256}"
assert_equal "delta current structural binding" "$(json '.structural_record_sha256' "${delta}")" "${structural_sha256}"

for record in "${result}" "${assessment}"; do
  assert_equal "$(basename "${record}") publisher binding" "$(json '.publisher_evidence_sha256' "${record}")" "${publisher_sha256}"
  assert_equal "$(basename "${record}") structural binding" "$(json '.structural_record_sha256' "${record}")" "${structural_sha256}"
  assert_equal "$(basename "${record}") delta binding" "$(json '.update_delta_sha256' "${record}")" "${delta_sha256}"
  assert_equal "$(basename "${record}") policy binding" "$(json '.policy_sha256' "${record}")" "${policy_sha256}"
done
assert_equal "assessment result binding" "$(json '.policy_result_sha256' "${assessment}")" "${result_sha256}"

for selector in '.operation_id' '.action' '.enablement' '.subject' '.native_reports'; do
  assert_equal "result/assessment ${selector}" "$(json "${selector}" "${result}")" "$(json "${selector}" "${assessment}")"
done
assert_equal "current publisher/structural subject" "$(json '.subject' "${fixture_dir}/publisher-evidence-new.json")" "$(json '.subject' "${fixture_dir}/structural-record-new.json")"
assert_equal "current publisher/delta subject" "$(json '.subject' "${fixture_dir}/publisher-evidence-new.json")" "$(json '.subject' "${delta}")"
assert_equal "previous publisher/structural subject" "$(json '.subject' "${fixture_dir}/publisher-evidence-old.json")" "$(json '.subject' "${fixture_dir}/structural-record-old.json")"
assert_equal "previous publisher/delta subject" "$(json '.subject' "${fixture_dir}/publisher-evidence-old.json")" "$(json '.previous_subject' "${delta}")"

assert_equal "previous native report binding" "$(json '.[0]' "${previous_reports}")" "$(json '.providers[0] | {integration_status:"complete",native_report_schema:"urn:example:oracle-report:v1",native_report_sha256:.previous_native_report_sha256,native_report_size:1024,provider_id:.provider_id}' "${delta}")"
assert_equal "current native report digest" "$(json '.native_reports[0].native_report_sha256' "${result}")" "$(json '.providers[0].current_native_report_sha256' "${delta}")"

expected_action="$(json '.expected.action' "${manifest}")"
expected_decision="$(json '.expected.decision' "${manifest}")"
expected_operation_id="$(json '.expected.operation_id' "${manifest}")"
assert_equal "expected action" "$(json '.action' "${result}")" "${expected_action}"
assert_equal "expected operation ID" "$(json '.operation_id' "${result}")" "${expected_operation_id}"
assert_equal "expected decision" "$(json '.decision' "${result}")" "${expected_decision}"

jq -e '.reasons | any(.code == "interactive_approval_required" and .disposition == "require_consent" and .provider_id == null)' "${result}" >/dev/null || fail "mandatory interactive-approval reason is absent"
derived_decision="$(jq -r 'if any(.reasons[]; .disposition == "block") then "block" else "require_consent" end' "${result}")"
assert_equal "independently derived decision" "$(json '.decision' "${result}")" "${derived_decision}"

printf 'independent risk oracle: verified %d canonical records and joined bindings\n' "${#files[@]}"
