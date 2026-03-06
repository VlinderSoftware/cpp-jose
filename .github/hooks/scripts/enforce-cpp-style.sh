#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
repo_root="$(cd -- "${script_dir}/../../.." >/dev/null 2>&1 && pwd)"
CPP_JOSE_BOOTSTRAP_AUTO_CHECK=0
if ! source "${repo_root}/bootstrap"; then
    printf '{"decision":"block","reason":"Hook bootstrap failed","systemMessage":"Unable to load bootstrap script: %s/bootstrap"}\n' "$repo_root"
    exit 0
fi

if ! hookBootstrapCheckTools; then
    printf '{"decision":"block","reason":"Hook bootstrap failed","systemMessage":"Required tools are missing. On Linux, jq is mandatory; clang-format and clang-tidy are required."}\n'
    exit 0
fi

payload="$(cat)"

# Best-effort extraction helpers that work with or without jq.
get_json_value() {
    local expr="$1"
    if command -v jq >/dev/null 2>&1; then
        jq -r "$expr // empty" <<<"$payload"
    else
        echo ""
    fi
}

event_name="$(get_json_value '.hookEventName')"
if [[ -z "$event_name" ]]; then
    event_name="$(get_json_value '.hook_event_name')"
fi

if [[ "$event_name" == "SessionStart" ]]; then
    cat <<'JSON'
{
  "continue": true,
  "systemMessage": "C++ style enforcement is active: use C++20/C++23, Allman braces (namespace braces on same line), Vlinder naming rules, and keep OpenSSL/CNG-specific code confined to backend-specific files."
}
JSON
    exit 0
fi

if [[ "$event_name" != "PostToolUse" ]]; then
    cat <<'JSON'
{
  "continue": true
}
JSON
    exit 0
fi

tool_name="$(get_json_value '.toolName')"
if [[ -z "$tool_name" ]]; then
    tool_name="$(get_json_value '.tool_name')"
fi

case "$tool_name" in
    apply_patch|create_file|edit_file|write_file)
        ;;
    *)
        cat <<'JSON'
{
  "continue": true
}
JSON
        exit 0
        ;;
esac

extract_paths_with_jq() {
    jq -r '
      [
        .. | objects | .filePath?,
        .. | objects | .path?,
        .. | objects | .new_path?,
        .. | objects | .old_path?
      ]
      | flatten
      | .[]
      | select(type == "string")
    ' <<<"$payload" | sed '/^$/d' || true
}

extract_paths_without_jq() {
    printf '%s\n' "$payload" | grep -Eo '(/[A-Za-z0-9._/\-]+\.[A-Za-z0-9_]+)' || true
}

if command -v jq >/dev/null 2>&1; then
    candidate_paths="$(extract_paths_with_jq)"
else
    candidate_paths="$(extract_paths_without_jq)"
fi

cpp_files="$(printf '%s\n' "$candidate_paths" | grep -E '\.c[^./]*$|\.h[^./]*$' | sort -u || true)"
if [[ -z "$cpp_files" ]]; then
    cat <<'JSON'
{
  "continue": true
}
JSON
    exit 0
fi

if ! command -v clang-format >/dev/null 2>&1; then
    cat <<'JSON'
{
  "decision": "block",
  "reason": "clang-format is required for C++ style enforcement but is not available in PATH.",
  "systemMessage": "Install clang-format or adjust the hook if your environment uses a different formatter command."
}
JSON
    exit 0
fi

if ! command -v clang-tidy >/dev/null 2>&1; then
        cat <<'JSON'
{
    "decision": "block",
    "reason": "clang-tidy is required for C++ style enforcement but is not available in PATH.",
    "systemMessage": "Install clang-tidy or adjust the hook if your environment uses a different linter command."
}
JSON
        exit 0
fi

format_violations=()
while IFS= read -r file_path; do
    [[ -z "$file_path" ]] && continue
    [[ ! -f "$file_path" ]] && continue

    if ! clang-format --dry-run --Werror "$file_path" >/dev/null 2>&1; then
        format_violations+=("$file_path")
    fi
done <<<"$cpp_files"

compile_db_dir=""
for candidate in "$PWD/build" "$PWD"; do
    if [[ -f "$candidate/compile_commands.json" ]]; then
        compile_db_dir="$candidate"
        break
    fi
done

tidy_violations=()
while IFS= read -r file_path; do
    [[ -z "$file_path" ]] && continue
    [[ ! -f "$file_path" ]] && continue

    if [[ -n "$compile_db_dir" ]]; then
        if ! clang-tidy -p "$compile_db_dir" --quiet --warnings-as-errors='*' "$file_path" >/dev/null 2>&1; then
            tidy_violations+=("$file_path")
        fi
    else
        if ! clang-tidy --quiet --warnings-as-errors='*' "$file_path" -- -std=c++20 -I"$PWD/include" -I"$PWD/src" >/dev/null 2>&1; then
            tidy_violations+=("$file_path")
        fi
    fi
done <<<"$cpp_files"

if [[ ${#format_violations[@]} -eq 0 && ${#tidy_violations[@]} -eq 0 ]]; then
    cat <<'JSON'
{
  "continue": true
}
JSON
    exit 0
fi

message="C++ style check failed."
if [[ ${#format_violations[@]} -gt 0 ]]; then
    message+=" clang-format violations in:"
    for file in "${format_violations[@]}"; do
        message+=" ${file};"
    done
fi
if [[ ${#tidy_violations[@]} -gt 0 ]]; then
    message+=" clang-tidy violations in:"
    for file in "${tidy_violations[@]}"; do
        message+=" ${file};"
    done
fi
message+=" Fix the listed files before continuing."

escaped_message="${message//"/\\"}"
printf '{"decision":"block","reason":"C++ style check failed","systemMessage":"%s"}\n' "$escaped_message"
