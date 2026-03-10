#!/usr/bin/env bash
set -euo pipefail

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

check_only=0
if [[ "${1:-}" == "--check" ]]; then
    check_only=1
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

if [[ ${check_only} -eq 1 ]]; then
    needs_formatting=0
    for file in "${files[@]}"; do
        if ! diff -u "${file}" <(clang-format --style=file "${file}") >/dev/null; then
            rel="${file#${repo_root}/}"
            echo "Needs formatting: ${rel}"
            needs_formatting=1
        fi
    done

    if [[ ${needs_formatting} -ne 0 ]]; then
        exit 1
    fi

    echo "All checked files already match clang-format output."
    exit 0
fi

for file in "${files[@]}"; do
    clang-format -i --style=file "${file}"
done

echo "Formatted ${#files[@]} files."
