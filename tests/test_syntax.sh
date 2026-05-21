#!/usr/bin/env bash
# Usage: ./test_syntax.sh [project_root]
set -euo pipefail

PROJECT_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

FAIL=0
CHECKED=0

while IFS= read -r -d '' file; do
    if ! bash -n "${file}" 2>&1; then
        echo "Syntax error in: ${file}"
        (( FAIL++ )) || true
    fi
    (( CHECKED++ )) || true
done < <(find "${PROJECT_ROOT}" -name "*.sh" -not -path "*/.git/*" -print0)

echo "Checked ${CHECKED} scripts"

if (( FAIL > 0 )); then
    echo "Syntax errors in ${FAIL} file(s)"
    exit 1
fi

echo "Syntax check: all scripts pass"
