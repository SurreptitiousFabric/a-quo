#!/usr/bin/env bash

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_directory
repository_root="$(cd -- "${script_directory}/.." && pwd -P)"
readonly repository_root
cd -- "${repository_root}"

failure=0

report_failure() {
  printf 'documentation check: %s\n' "$*" >&2
  failure=1
}

markdown_without_fences() {
  awk '
    function leading_marker_count(text, marker, count) {
      count = 0
      while (substr(text, count + 1, 1) == marker) {
        count++
      }
      return count
    }

    function leading_space_count(text, count) {
      count = 0
      while (substr(text, count + 1, 1) == " ") {
        count++
      }
      return count
    }

    {
      indentation = leading_space_count($0)
      candidate = substr($0, indentation + 1)

      if (fence != "") {
        marker_count = leading_marker_count(candidate, fence)
        remainder = substr(candidate, marker_count + 1)
        if (indentation <= 3 && marker_count >= fence_length && remainder ~ /^[ \t]*$/) {
          fence = ""
          fence_length = 0
        }
        print ""
        next
      }

      marker = substr(candidate, 1, 1)
      if (marker == "`" || marker == "~") {
        marker_count = leading_marker_count(candidate, marker)
        remainder = substr(candidate, marker_count + 1)
        if (indentation <= 3 && marker_count >= 3 &&
            (marker != "`" || remainder !~ /`/)) {
          fence = marker
          fence_length = marker_count
          print ""
          next
        }
      }

      print
    }
  ' "$1"
}

mapfile -t markdown_files < <(
  git ls-files --cached --others --exclude-standard -- '*.md' | sort -u
)

markdown_records() {
  local pattern="$1"
  local match_only="${2:-false}"
  local document
  local record

  for document in "${markdown_files[@]}"; do
    if [[ "${match_only}" == true ]]; then
      while IFS= read -r record; do
        printf '%s:%s\n' "${document}" "${record}"
      done < <(
        markdown_without_fences "${document}" |
          grep -noE -- "${pattern}" || true
      )
    else
      while IFS= read -r record; do
        printf '%s:%s\n' "${document}" "${record}"
      done < <(
        markdown_without_fences "${document}" |
          grep -nE -- "${pattern}" || true
      )
    fi
  done
}

reference_records() {
  local document
  local record

  for document in "${markdown_files[@]}"; do
    while IFS= read -r record; do
      printf '%s:%s\n' "${document}" "${record}"
    done < <(
      markdown_without_fences "${document}" |
        awk '
          {
            if (pending_line != 0) {
              continuation = $0
              sub(/^[ \t]*/, "", continuation)
              if (continuation != "") {
                print pending_line ":" continuation
                pending_line = 0
                next
              }
              print pending_line ":"
              pending_line = 0
            }

            if (match($0, /^[[:space:]]{0,3}\[[^][]+\]:[[:space:]]*/)) {
              target = substr($0, RLENGTH + 1)
              if (target == "") {
                pending_line = NR
              } else {
                print NR ":" target
              }
            }
          }

          END {
            if (pending_line != 0) {
              print pending_line ":"
            }
          }
        '
    )
  done
}

if ((${#markdown_files[@]} == 0)); then
  report_failure 'no tracked or pending Markdown files found'
fi

readonly -a required_documents=(
  README.md
  docs/DOCUMENTATION.md
  docs/EVIDENCE.md
  docs/MATURITY.md
  docs/MATURITY-AUDIT.md
  docs/PACKAGING.md
  docs/ROADMAP.md
  docs/THREAT-MODEL.md
)

for document in "${required_documents[@]}"; do
  [[ -f "${document}" ]] || report_failure "missing required document: ${document}"
done

for document in README.md CONTRIBUTING.md SECURITY.md docs/*.md; do
  h1_count="$(markdown_without_fences "${document}" | sed -n '/^# /p' | wc -l)"
  if [[ "${h1_count}" != 1 ]]; then
    report_failure "${document} must contain exactly one level-one heading"
  fi
done

for document in docs/*.md; do
  [[ "${document}" == docs/DOCUMENTATION.md ]] && continue
  basename="${document##*/}"
  if ! markdown_without_fences docs/DOCUMENTATION.md |
    grep -F -- "](${basename})" >/dev/null; then
    report_failure "${document} has no entry in docs/DOCUMENTATION.md"
  fi
done

for required_heading in \
  '## Central journey' \
  '## Current support boundary' \
  '## What verification says' \
  '## Quick start from source' \
  '## Documentation'; do
  if ! markdown_without_fences README.md |
    grep -Fx -- "${required_heading}" >/dev/null; then
    report_failure "README.md is missing required heading: ${required_heading}"
  fi
done

for required_link in \
  'docs/DOCUMENTATION.md' \
  'docs/EVIDENCE.md' \
  'docs/MATURITY-AUDIT.md' \
  'docs/PACKAGING.md' \
  'docs/THREAT-MODEL.md'; do
  if ! markdown_without_fences README.md |
    grep -F -- "${required_link}" >/dev/null; then
    report_failure "README.md is missing required authority link: ${required_link}"
  fi
done

readme_lines="$(wc -l <README.md)"
if ((readme_lines > 500)); then
  report_failure "README.md exceeds its 500-line product-entry-point bound"
fi

chronology_pattern='https://github\.com/SurreptitiousFabric/a-quo/actions/runs/|(^|[^[:alnum:]_-])[Rr]un[[:space:]]+[[:punct:]]?[0-9]{8,}|(^|[^[:alnum:]_-])[Aa]rtifact[[:space:]]+[[:punct:]]?[0-9]{7,}'
readonly chronology_pattern
chronology="$({
  for document in "${markdown_files[@]}"; do
    case "${document}" in
      README.md | docs/*.md) ;;
      *) continue ;;
    esac
    [[ "${document}" == docs/EVIDENCE.md ]] && continue
    while IFS= read -r record; do
      printf '%s:%s\n' "${document}" "${record}"
    done < <(
      markdown_without_fences "${document}" |
        grep -nE -- "${chronology_pattern}" || true
    )
  done
})"
if [[ -n "${chronology}" ]]; then
  report_failure 'dated workflow-run chronology exists outside docs/EVIDENCE.md'
  printf '%s\n' "${chronology}" >&2
fi

slugify() {
  local heading="$1"
  heading="${heading,,}"
  heading="${heading//\`/}"
  heading="${heading//\*/}"
  printf '%s\n' "${heading}" |
    sed -E \
      -e 's/<[^>]*>//g' \
      -e 's/\[([^][]*)\]\([^)]*\)/\1/g' \
      -e 's/[^[:alnum:] _-]//g' \
      -e 's/[[:space:]]+/-/g' \
      -e 's/^-+//' \
      -e 's/-+$//'
}

documentation_tmp_directory="$(mktemp -d)"
readonly documentation_tmp_directory
trap 'rm -rf -- "${documentation_tmp_directory}"' EXIT
anchor_index="${documentation_tmp_directory}/anchors"
readonly anchor_index
: >"${anchor_index}"

declare -A heading_occurrences=()
while IFS= read -r heading_record; do
  document="${heading_record%%:*}"
  remainder="${heading_record#*:}"
  remainder="${remainder#*:}"
  heading="${remainder#* }"
  base_slug="$(slugify "${heading}")"
  [[ -n "${base_slug}" ]] || continue
  occurrence_key="${document}|${base_slug}"
  occurrence="${heading_occurrences[${occurrence_key}]:-0}"
  slug="${base_slug}"
  if ((occurrence > 0)); then
    slug="${base_slug}-${occurrence}"
  fi
  heading_occurrences["${occurrence_key}"]="$((occurrence + 1))"
  absolute_document="$(realpath -e -- "${document}")"
  printf '%s|%s\n' "${absolute_document}" "${slug}" >>"${anchor_index}"
done < <(markdown_records '^#{1,6} ')

link_count=0

check_link_target() {
  local source_document="$1"
  local source_line="$2"
  local target="$3"
  local fragment
  local target_path
  local resolved_target

  target="${target#"${target%%[![:space:]]*}"}"
  if [[ "${target}" == \<* ]]; then
    target="${target#<}"
    target="${target%%>*}"
  else
    target="${target%%[[:space:]]*}"
  fi
  link_count="$((link_count + 1))"

  case "${target}" in
    http://* | https://* | mailto:* | data:*)
      return
      ;;
  esac

  fragment=''
  target_path="${target}"
  if [[ "${target}" == *'#'* ]]; then
    fragment="${target#*#}"
    target_path="${target%%#*}"
  fi

  if [[ -z "${target_path}" ]]; then
    resolved_target="$(realpath -e -- "${source_document}")"
  else
    resolved_target="$(realpath -m -- "$(dirname -- "${source_document}")/${target_path}")"
  fi

  case "${resolved_target}" in
    "${repository_root}" | "${repository_root}"/*) ;;
    *)
      report_failure "${source_document}:${source_line} escapes the repository: ${target}"
      return
      ;;
  esac

  if [[ ! -e "${resolved_target}" ]]; then
    report_failure "${source_document}:${source_line} has missing local target: ${target}"
    return
  fi

  if [[ -n "${fragment}" ]] &&
    ! grep -Fqx -- "${resolved_target}|${fragment}" "${anchor_index}"; then
    report_failure "${source_document}:${source_line} has missing local anchor: ${target}"
  fi
}

while IFS= read -r link_record; do
  source_document="${link_record%%:*}"
  remainder="${link_record#*:}"
  source_line="${remainder%%:*}"
  link_token="${remainder#*:}"
  target="${link_token#](}"
  target="${target%)}"
  check_link_target "${source_document}" "${source_line}" "${target}"
done < <(
  markdown_records '\]\([^)]*\)' true
)

while IFS= read -r reference_record; do
  source_document="${reference_record%%:*}"
  remainder="${reference_record#*:}"
  source_line="${remainder%%:*}"
  target="${remainder#*:}"
  if [[ -z "${target//[[:space:]]/}" ]]; then
    report_failure "${source_document}:${source_line} has missing reference destination"
    continue
  fi
  check_link_target "${source_document}" "${source_line}" "${target}"
done < <(
  reference_records
)

if ((failure != 0)); then
  exit 1
fi

printf 'documentation checks passed (%d Markdown files, %d link destinations)\n' \
  "${#markdown_files[@]}" "${link_count}"
