#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PASS=0
FAIL=0
ERRORS=()

run_test() {
    local name="$1"
    local script="$2"
    printf "  %-40s " "${name}..."
    if bash "${script}" "${PROJECT_ROOT}" > /tmp/test_output_$$ 2>&1; then
        echo "PASS"
        (( PASS++ )) || true
    else
        echo "FAIL"
        (( FAIL++ )) || true
        ERRORS+=("${name}: $(tail -5 /tmp/test_output_$$)")
    fi
    rm -f /tmp/test_output_$$
}

echo ""
echo "Running VPS Hardening Suite tests"
echo "=================================="
echo ""

run_test "ShellCheck compliance"    "${SCRIPT_DIR}/test_shellcheck.sh"
run_test "Bash syntax validation"   "${SCRIPT_DIR}/test_syntax.sh"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if (( FAIL > 0 )); then
    echo ""
    echo "Failures:"
    for err in "${ERRORS[@]}"; do
        echo "  - ${err}"
    done
    exit 1
fi

echo ""
echo "All tests passed."
