#!/usr/bin/env bash
# Usage: ./test_shellcheck.sh [project_root]
set -euo pipefail

PROJECT_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if ! command -v shellcheck &>/dev/null; then
    echo "shellcheck not installed. Install with: apt-get install shellcheck"
    echo "SKIP: shellcheck not available — install it for full compliance checking"
    exit 0
fi

FAIL=0
while IFS= read -r -d '' file; do
    if ! shellcheck -S warning -x "${file}" 2>&1; then
        (( FAIL++ )) || true
    fi
done < <(find "${PROJECT_ROOT}" -name "*.sh" -not -path "*/.git/*" -print0)

if (( FAIL > 0 )); then
    echo "ShellCheck found issues in ${FAIL} file(s)"
    exit 1
fi

echo "ShellCheck: all scripts pass"
