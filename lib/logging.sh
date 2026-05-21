#!/usr/bin/env bash
# =============================================================================
# lib/logging.sh — ANSI colours, log functions, banner, progress bar, summary
# =============================================================================
# Sourced by lib/common.sh (and optionally directly by any module).
# Provides all terminal-output primitives; writes a copy to $LOG_FILE.
# =============================================================================

[[ -n "${_VPS_LOGGING_LOADED:-}" ]] && return 0
readonly _VPS_LOGGING_LOADED=1

set -euo pipefail

# =============================================================================
# ANSI COLOR & FORMATTING CONSTANTS  (exported for subshells)
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
RESET='\033[0m'

export RED GREEN YELLOW BLUE CYAN MAGENTA WHITE BOLD RESET

# =============================================================================
# LOGGING INFRASTRUCTURE
# =============================================================================
# All log_* functions write to both stdout (with colour) and $LOG_FILE (plain).
# LOG_DIR and LOG_FILE must be set before sourcing this file (helpers.sh does
# this), or they will fall back to /var/log/vps-hardening defaults.

# _ensure_log_dir — creates LOG_DIR and LOG_FILE if they are absent.
_ensure_log_dir() {
    local log_dir="${LOG_DIR:-/var/log/vps-hardening}"
    local log_file="${LOG_FILE:-${log_dir}/install.log}"

    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" 2>/dev/null || true
    fi
    if [[ ! -f "$log_file" ]]; then
        touch "$log_file" 2>/dev/null || true
    fi
}

# _log_raw(level, color, msg) — internal: writes one log line to stdout + file.
_log_raw() {
    local level="$1"
    local color="$2"
    local msg="$3"
    local log_file="${LOG_FILE:-/var/log/vps-hardening/install.log}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    _ensure_log_dir

    # Coloured line to terminal
    printf "${color}[%-7s]${RESET} %s %s\n" "$level" "$timestamp" "$msg"

    # Plain-text line to log file (strip any embedded colour codes)
    printf "[%-7s] %s %s\n" "$level" "$timestamp" "$msg" \
        | sed 's/\x1b\[[0-9;]*m//g' >> "$log_file" 2>/dev/null || true
}

# log_info(msg) — informational message (blue)
log_info() {
    _log_raw "INFO" "${BLUE}" "$*"
}

# log_success(msg) — operation completed successfully (green)
log_success() {
    _log_raw "OK" "${GREEN}" "$*"
}

# log_warning(msg) — non-fatal warning that needs attention (yellow)
log_warning() {
    _log_raw "WARN" "${YELLOW}" "$*"
}

# log_error(msg) — fatal or serious error (red)
log_error() {
    _log_raw "ERROR" "${RED}" "$*"
}

# log_section(title) — prominent bordered section header for major phases.
log_section() {
    local title="$1"
    local log_file="${LOG_FILE:-/var/log/vps-hardening/install.log}"
    local line
    local width
    width=$(( $(tput cols 2>/dev/null || echo 72) < 72 ? $(tput cols 2>/dev/null || echo 72) : 72 ))
    line="$(printf '═%.0s' $(seq 1 "$width"))"

    echo ""
    printf "${CYAN}${BOLD}╔%s╗${RESET}\n" "$line"
    local pad=$(( (width - ${#title}) / 2 ))
    printf "${CYAN}${BOLD}║%*s%s%*s║${RESET}\n" \
        "$pad" "" "$title" "$(( width - pad - ${#title} ))" ""
    printf "${CYAN}${BOLD}╚%s╝${RESET}\n" "$line"
    echo ""

    _ensure_log_dir
    printf "\n=== %s ===\n" "$title" >> "$log_file" 2>/dev/null || true
}

# log_step(n, total, msg) — prints "Step N/TOTAL: msg" for multi-step operations.
log_step() {
    local n="$1"
    local total="$2"
    local msg="$3"
    printf "${BOLD}${WHITE}  ▸ Step %s/%s:${RESET} %s\n" "$n" "$total" "$msg"
    _log_raw "STEP" "${WHITE}" "($n/$total) $msg"
}

# =============================================================================
# BANNER
# =============================================================================

# print_banner() — ASCII art banner displayed at startup.
print_banner() {
    printf "${CYAN}"
    cat << 'BANNER'

 ██╗   ██╗██████╗ ███████╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗███╗   ██╗ ██████╗
 ██║   ██║██╔══██╗██╔════╝    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║████╗  ██║██╔════╝
 ██║   ██║██████╔╝███████╗    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 ╚██╗ ██╔╝██╔═══╝ ╚════██║    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╗██║██║   ██║
  ╚████╔╝ ██║     ███████║    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██║██║ ╚████║╚██████╔╝
   ╚═══╝  ╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝

BANNER
    printf "${RESET}"
    printf "${BOLD}${WHITE}         VPS Hardening Suite  •  Maximiliano Arango  •  2025${RESET}\n"
    printf "${MAGENTA}         Automated security hardening for production Linux servers${RESET}\n"
    echo ""
}

# =============================================================================
# UI HELPERS
# =============================================================================

# show_progress(current, total, label)
# Prints a block-character progress bar to stdout.
show_progress() {
    local current="$1"
    local total="$2"
    local label="${3:-}"
    local bar_width=40
    local filled=$(( current * bar_width / total ))
    local empty=$(( bar_width - filled ))

    local bar=""
    bar+="${GREEN}"
    bar+="$(printf '█%.0s' $(seq 1 "$filled"))"
    bar+="${RESET}${WHITE}"
    bar+="$(printf '░%.0s' $(seq 1 "$empty"))"
    bar+="${RESET}"

    printf "\r  [%s] %3d%%  %s" "$bar" "$(( current * 100 / total ))" "$label"

    if (( current >= total )); then
        printf "\n"
    fi
}

# print_summary_table(title, key1, val1, key2, val2, ...)
# Prints a formatted two-column table. Pass key-value pairs as alternating args.
print_summary_table() {
    local title="$1"
    shift
    local items=("$@")

    # Find the longest key for column alignment
    local max_key=0
    local i
    for (( i=0; i<${#items[@]}; i+=2 )); do
        local k="${items[$i]}"
        (( ${#k} > max_key )) && max_key=${#k}
    done

    local col_w=$(( max_key + 2 ))
    local sep
    sep="$(printf '─%.0s' $(seq 1 $(( col_w + 36 ))))"

    echo ""
    printf "${BOLD}${CYAN}  %s${RESET}\n" "$title"
    printf "  ${CYAN}┌%s┐${RESET}\n" "$sep"

    for (( i=0; i<${#items[@]}; i+=2 )); do
        local key="${items[$i]}"
        local val="${items[$i+1]:-N/A}"
        printf "  ${CYAN}│${RESET}  ${BOLD}%-*s${RESET} ${CYAN}│${RESET}  ${WHITE}%-30s${RESET}  ${CYAN}│${RESET}\n" \
            "$max_key" "$key" "$val"
    done

    printf "  ${CYAN}└%s┘${RESET}\n" "$sep"
    echo ""
}
