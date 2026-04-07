#!/usr/bin/env bash
set -euo pipefail

check_only=0
for arg in "$@"; do
    case "${arg}" in
        --check-only | -CheckOnly) check_only=1 ;;
        *) echo "Unknown argument: ${arg}" >&2; exit 1 ;;
    esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="${script_dir}"

while [[ ! -f "${repo_root}/CMakeLists.txt" ]]; do
    parent="$(dirname "${repo_root}")"
    if [[ "${parent}" == "${repo_root}" ]]; then
        echo "Unable to locate repository root (CMakeLists.txt not found in parent chain)." >&2
        exit 1
    fi
    repo_root="${parent}"
done

if ! command -v clang-format >/dev/null 2>&1; then
    echo "Unable to locate clang-format. Ensure it is installed and available in PATH." >&2
    exit 1
fi

roots=(
    "${repo_root}/src"
    "${repo_root}/include"
    "${repo_root}/tests"
    "${repo_root}/examples"
)

find_args=()
for root in "${roots[@]}"; do
    if [[ -d "${root}" ]]; then
        find_args+=("${root}")
    fi
done

if [[ ${#find_args[@]} -eq 0 ]]; then
    echo "No source directories found to format."
    exit 0
fi

mapfile -t files < <(
    find "${find_args[@]}" -type f \( \
        -name "*.c" -o -name "*.cc" -o -name "*.cpp" -o -name "*.cxx" -o \
        -name "*.h" -o -name "*.hh" -o -name "*.hpp" -o -name "*.hxx" -o \
        -name "*.ipp" -o -name "*.inl" \
    \) | LC_ALL=C sort
)

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No C/C++ files found to format."
    exit 0
fi

echo "Using clang-format: $(command -v clang-format)"
echo "Files discovered: ${#files[@]}"

# Use --output-replacements-xml to detect whether a file needs reformatting
# without passing the formatted content through the shell (which would mangle
# multi-byte UTF-8 in comments/string literals on some locales).
# clang-format emits a self-closing <replacements/> tag when the file is already
# formatted; otherwise it emits one or more <replacement ...> elements.
needs_formatting=()
for file in "${files[@]}"; do
    xml="$(clang-format --style=file --output-replacements-xml "${file}")"
    if echo "${xml}" | grep -q '<replacement '; then
        rel="${file#${repo_root}/}"
        needs_formatting+=("${rel}")
    fi
done

if [[ ${#needs_formatting[@]} -eq 0 ]]; then
    echo "All files already match clang-format output."
    exit 0
fi

if [[ ${check_only} -eq 1 ]]; then
    echo "Files requiring formatting:"
    for rel in "${needs_formatting[@]}"; do
        echo " - ${rel}"
    done
    exit 1
fi

# Reformat in place.
for file in "${files[@]}"; do
    clang-format -i --style=file "${file}"
done

echo "Reformatted ${#needs_formatting[@]} file(s):"
for rel in "${needs_formatting[@]}"; do
    echo "  ${rel}"
done
exit 0
