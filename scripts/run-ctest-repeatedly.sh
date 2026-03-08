#!/usr/bin/env bash
set -euo pipefail

COUNT=128
TEST_DIR="build/baseline-openssl"
CONFIG="Debug"
REGEX=""

print_usage() {
    cat <<'USAGE'
Usage: run-ctest-repeatedly.sh [options]

Options:
  -n, --count N       Number of iterations (default: 128)
  -d, --test-dir DIR  CTest directory (default: build/baseline-openssl)
  -c, --config CFG    CTest config (default: Debug)
  -r, --regex REGEX   Optional ctest -R filter
  -h, --help          Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--count)
            COUNT="$2"
            shift 2
            ;;
        -d|--test-dir)
            TEST_DIR="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG="$2"
            shift 2
            ;;
        -r|--regex)
            REGEX="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            print_usage >&2
            exit 2
            ;;
    esac
done

if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [[ "$COUNT" -lt 1 ]]; then
    echo "Invalid count: $COUNT (must be integer >= 1)" >&2
    exit 2
fi

resolve_ctest() {
    if command -v ctest >/dev/null 2>&1; then
        command -v ctest
        return 0
    fi

    local vs_ctest="/c/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/ctest.exe"
    if [[ -x "$vs_ctest" ]]; then
        printf '%s\n' "$vs_ctest"
        return 0
    fi

    return 1
}

if [[ ! -d "$TEST_DIR" ]]; then
    echo "Test directory not found: $TEST_DIR" >&2
    exit 2
fi

if ! CTEST_PATH="$(resolve_ctest)"; then
    echo "Unable to locate ctest." >&2
    exit 2
fi

echo "Using ctest: $CTEST_PATH"
echo "Running tests $COUNT times"
echo "Test directory: $TEST_DIR"
echo "Configuration: $CONFIG"
if [[ -n "$REGEX" ]]; then
    echo "Regex filter: $REGEX"
fi

overall_start="$(date +%s)"

for ((i=1; i<=COUNT; i++)); do
    echo
    echo "=== Iteration $i/$COUNT ==="

    args=(--test-dir "$TEST_DIR" -C "$CONFIG" --output-on-failure)
    if [[ -n "$REGEX" ]]; then
        args+=(-R "$REGEX")
    fi

    iteration_start="$(date +%s)"
    if ! "$CTEST_PATH" "${args[@]}"; then
        iteration_elapsed="$(( $(date +%s) - iteration_start ))"
        echo "Iteration $i failed after ${iteration_elapsed}s." >&2
        exit 1
    fi

    iteration_elapsed="$(( $(date +%s) - iteration_start ))"
    echo "Iteration $i passed in ${iteration_elapsed}s."
done

overall_elapsed="$(( $(date +%s) - overall_start ))"
echo
echo "All $COUNT iterations passed in ${overall_elapsed}s."
