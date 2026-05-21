#!/usr/bin/env bash
# =============================================================================
# lib/common.sh — Compatibility shim; sources all lib components
# =============================================================================
# Every module in the suite sources THIS file and continues to work unchanged.
# Actual implementation has been split into focused files under lib/:
#
#   lib/logging.sh    — colours, log_*, print_banner, show_progress, summary
#   lib/helpers.sh    — paths, constants, system/network checks, state mgmt
#   lib/backups.sh    — backup_file, restore_file, list_backups, run_with_log
#   lib/validation.sh — post-install validators and post_module_verify()
# =============================================================================

[[ -n "${_VPS_HARDENING_COMMON_LOADED:-}" ]] && return 0
readonly _VPS_HARDENING_COMMON_LOADED=1

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly LIB_DIR="${PROJECT_ROOT}/lib"

# shellcheck source=lib/logging.sh
source "${LIB_DIR}/logging.sh"
# shellcheck source=lib/helpers.sh
source "${LIB_DIR}/helpers.sh"
# shellcheck source=lib/backups.sh
source "${LIB_DIR}/backups.sh"
# shellcheck source=lib/validation.sh
source "${LIB_DIR}/validation.sh"
