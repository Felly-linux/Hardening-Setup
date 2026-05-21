#!/usr/bin/env bash
# =============================================================================
# lib/common.sh — Shared library for VPS Hardening Suite
# =============================================================================
# This file is sourced by every script in the project. It provides:
#   - ANSI color constants for terminal output
#   - Logging functions (info, success, warning, error, section header)
#   - System inspection helpers (root check, command/service/package checks)
#   - Network helpers (port in use, find free port, wait for port)
#   - File helpers (backup, run with log)
#   - State management (save/get key-value pairs in JSON)
#   - UI helpers (banner, progress bar, summary table)
#   - OS detection and public IP resolution
# =============================================================================
# Usage: source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# =============================================================================

# Guard against double-sourcing
[[ -n "${_VPS_HARDENING_COMMON_LOADED:-}" ]] && return 0
readonly _VPS_HARDENING_COMMON_LOADED=1

# =============================================================================
# GLOBAL PATHS & CONSTANTS
# =============================================================================

# Resolve the project root relative to this file's location.
# lib/common.sh lives at PROJECT_ROOT/lib/, so go one level up.
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Runtime state file – written atomically via save_state / read by get_state
readonly STATE_FILE="/var/lib/vps-hardening/state.json"

# Central log directory and log file used by all log_* functions
readonly LOG_DIR="/var/log/vps-hardening"
readonly LOG_FILE="${LOG_DIR}/install.log"

# Backup directory where backup_file() stores original copies
readonly BACKUP_DIR="${PROJECT_ROOT}/backups"

# =============================================================================
# PORT / SERVICE CONSTANTS  (single source of truth for the whole suite)
# =============================================================================
readonly PORT_CROWDSEC_LAPI=6767       # Moved from 8080 to avoid conflicts
readonly PORT_PROMETHEUS=9090
readonly PORT_GRAFANA=3000
readonly PORT_NODE_EXPORTER=9100
readonly PORT_CADVISOR=8081
readonly PORT_LOKI=3100
readonly PORT_PROMTAIL=9080

# Docker network shared by all monitoring containers
readonly DOCKER_MONITORING_NETWORK="monitoring"

# =============================================================================
# ANSI COLOR & FORMATTING CONSTANTS
# =============================================================================
# These are exported so subshells and sourced scripts inherit them.

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
# The log file is created on first use if it doesn't exist yet.

# _ensure_log_dir — creates LOG_DIR and LOG_FILE if they are absent.
_ensure_log_dir() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" 2>/dev/null || true
    fi
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE" 2>/dev/null || true
    fi
}

# _log_raw(level, color, msg)
# Internal helper: writes a single log line to stdout + log file.
_log_raw() {
    local level="$1"
    local color="$2"
    local msg="$3"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    _ensure_log_dir

    # Coloured output to terminal
    printf "${color}[%-7s]${RESET} %s %s\n" "$level" "$timestamp" "$msg"

    # Plain-text line to log file (strip any colour codes that might be present in msg)
    printf "[%-7s] %s %s\n" "$level" "$timestamp" "$msg" \
        | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE" 2>/dev/null || true
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

# log_section(title) — prints a prominent bordered section header.
# Used at the beginning of each major phase.
log_section() {
    local title="$1"
    local line
    # Build a line of '═' characters matching terminal width (max 72)
    local width
    width=$(( $(tput cols 2>/dev/null || echo 72) < 72 ? $(tput cols 2>/dev/null || echo 72) : 72 ))
    line="$(printf '═%.0s' $(seq 1 "$width"))"

    echo ""
    printf "${CYAN}${BOLD}╔%s╗${RESET}\n" "$line"
    # Centre the title
    local pad=$(( (width - ${#title}) / 2 ))
    printf "${CYAN}${BOLD}║%*s%s%*s║${RESET}\n" \
        "$pad" "" "$title" "$(( width - pad - ${#title} ))" ""
    printf "${CYAN}${BOLD}╚%s╝${RESET}\n" "$line"
    echo ""

    _ensure_log_dir
    printf "\n=== %s ===\n" "$title" >> "$LOG_FILE" 2>/dev/null || true
}

# log_step(n, total, msg) — prints "Step N/TOTAL: msg" for multi-step operations
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

# print_banner() — ASCII art banner displayed at startup
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
    printf "${BOLD}${WHITE}         VPS Hardening Suite  •  Urpe Integral Services  •  2025${RESET}\n"
    printf "${MAGENTA}         Automated security hardening for production Linux servers${RESET}\n"
    echo ""
}

# =============================================================================
# INTERACTIVE PROMPTS
# =============================================================================

# confirm(question) — Ask a yes/no question.
# Returns 0 (true) for yes, 1 (false) for no.
# In non-interactive mode (NONINTERACTIVE=1), defaults to yes.
confirm() {
    local question="$1"
    local default="${2:-y}"  # optional second arg for default: 'y' or 'n'

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        log_info "Non-interactive mode: auto-confirming '$question'"
        return 0
    fi

    local prompt
    if [[ "$default" == "y" ]]; then
        prompt="${question} [Y/n]: "
    else
        prompt="${question} [y/N]: "
    fi

    while true; do
        printf "${BOLD}${WHITE}%s${RESET}" "$prompt"
        read -r answer
        case "${answer,,}" in
            y|yes|"")
                [[ "$default" == "n" && -z "$answer" ]] && return 1
                return 0
                ;;
            n|no)
                return 1
                ;;
            *)
                printf "${YELLOW}Please answer 'y' or 'n'.${RESET}\n"
                ;;
        esac
    done
}

# ask(question, default_value) — Prompt for a string value.
# Echoes the entered value. If user presses Enter with no input, returns default.
ask() {
    local question="$1"
    local default="${2:-}"
    local answer

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        echo "$default"
        return 0
    fi

    if [[ -n "$default" ]]; then
        printf "${BOLD}${WHITE}%s${RESET} [default: ${CYAN}%s${RESET}]: " "$question" "$default"
    else
        printf "${BOLD}${WHITE}%s${RESET}: " "$question"
    fi

    read -r answer
    echo "${answer:-$default}"
}

# ask_password(question) — Prompt for a password without echo.
# Echoes the entered password.
ask_password() {
    local question="$1"
    local password

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        # Generate a random password in non-interactive mode
        password="$(openssl rand -base64 24 2>/dev/null || tr -dc 'A-Za-z0-9@#$%' < /dev/urandom | head -c 20)"
        echo "$password"
        return 0
    fi

    printf "${BOLD}${WHITE}%s${RESET}: " "$question"
    read -rs password
    echo ""  # newline after silent input
    echo "$password"
}

# =============================================================================
# SYSTEM CHECKS
# =============================================================================

# check_root() — Exits with error if the current user is not root.
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# command_exists(cmd) — Returns 0 if 'cmd' is found in PATH, 1 otherwise.
command_exists() {
    command -v "$1" &>/dev/null
}

# service_running(name) — Returns 0 if the named systemd service is active.
service_running() {
    local name="$1"
    systemctl is-active --quiet "$name" 2>/dev/null
}

# service_enabled(name) — Returns 0 if the named systemd service is enabled.
service_enabled() {
    local name="$1"
    systemctl is-enabled --quiet "$name" 2>/dev/null
}

# package_installed(pkg) — Returns 0 if the apt package is installed.
package_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
}

# =============================================================================
# NETWORK HELPERS
# =============================================================================

# port_in_use(port) — Returns 0 if the given TCP port is currently bound.
port_in_use() {
    local port="$1"
    # ss is preferred; fall back to netstat if not available
    if command_exists ss; then
        ss -tlnp 2>/dev/null | grep -q ":${port}\b"
    elif command_exists netstat; then
        netstat -tlnp 2>/dev/null | grep -q ":${port}\b"
    else
        # Last resort: try to bind the port with /dev/tcp
        (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null
    fi
}

# find_free_port(start_port) — Returns the first unused TCP port >= start_port.
find_free_port() {
    local port="${1:-8080}"
    while port_in_use "$port"; do
        (( port++ ))
        if (( port > 65535 )); then
            log_error "No free port found starting from ${1}"
            return 1
        fi
    done
    echo "$port"
}

# =============================================================================
# FILE HELPERS
# =============================================================================

# backup_file(path) — Copies a file to BACKUP_DIR with a timestamp suffix.
# Idempotent: if the backup already exists for today, it is not overwritten.
# Returns the backup path.
backup_file() {
    local src="$1"
    if [[ ! -f "$src" ]]; then
        log_warning "backup_file: source does not exist: $src"
        return 0
    fi

    mkdir -p "$BACKUP_DIR"

    local filename
    filename="$(basename "$src")"
    local timestamp
    timestamp="$(date '+%Y%m%d_%H%M%S')"
    local dest="${BACKUP_DIR}/${filename}.${timestamp}.bak"

    cp -p "$src" "$dest"
    log_success "Backed up: $src → $dest"
    echo "$dest"
}

# run_with_log(label, cmd...) — Runs a command, streaming output to the log file.
# On failure, prints the last 20 lines of log output.
run_with_log() {
    local label="$1"
    shift
    local cmd=("$@")

    _ensure_log_dir
    log_info "Running: ${cmd[*]}"

    local rc=0
    "${cmd[@]}" >> "$LOG_FILE" 2>&1 || rc=$?

    if [[ $rc -ne 0 ]]; then
        log_error "Command failed (exit $rc): ${cmd[*]}"
        log_error "Last log lines:"
        tail -20 "$LOG_FILE" | while IFS= read -r line; do
            printf "  ${RED}│${RESET} %s\n" "$line"
        done
        return $rc
    fi
    return 0
}

# =============================================================================
# SERVICE WAIT HELPERS
# =============================================================================

# wait_for_service(name, max_wait_seconds)
# Polls systemd service status until active or timeout.
wait_for_service() {
    local name="$1"
    local max_wait="${2:-60}"
    local elapsed=0
    local interval=2

    log_info "Waiting for service '${name}' to become active (max ${max_wait}s)..."

    while ! service_running "$name"; do
        if (( elapsed >= max_wait )); then
            log_error "Timed out waiting for service '${name}' after ${max_wait}s"
            return 1
        fi
        sleep "$interval"
        (( elapsed += interval ))
        printf "  ${YELLOW}⟳${RESET} Waiting... ${elapsed}s / ${max_wait}s\r"
    done

    printf "\n"
    log_success "Service '${name}' is active."
}

# wait_for_port(port, max_wait_seconds)
# Polls until a TCP port is accepting connections or timeout.
wait_for_port() {
    local port="$1"
    local max_wait="${2:-60}"
    local elapsed=0
    local interval=2

    log_info "Waiting for port ${port} to open (max ${max_wait}s)..."

    while ! (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; do
        if (( elapsed >= max_wait )); then
            log_error "Timed out waiting for port ${port} after ${max_wait}s"
            return 1
        fi
        sleep "$interval"
        (( elapsed += interval ))
        printf "  ${YELLOW}⟳${RESET} Waiting for port ${port}... ${elapsed}s / ${max_wait}s\r"
    done

    printf "\n"
    log_success "Port ${port} is open."
}

# =============================================================================
# STATE MANAGEMENT
# =============================================================================
# State is stored as a flat JSON object: { "key": "value", ... }
# jq is required for reliable JSON handling.

# _ensure_state_file() — Creates the state file and its parent directory.
_ensure_state_file() {
    local state_dir
    state_dir="$(dirname "$STATE_FILE")"
    if [[ ! -d "$state_dir" ]]; then
        mkdir -p "$state_dir" 2>/dev/null || true
    fi
    if [[ ! -f "$STATE_FILE" ]]; then
        echo '{}' > "$STATE_FILE" 2>/dev/null || true
    fi
}

# save_state(key, value) — Writes or updates a key in the JSON state file.
save_state() {
    local key="$1"
    local value="$2"

    _ensure_state_file

    if command_exists jq; then
        local tmp
        tmp="$(mktemp)"
        jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$STATE_FILE" > "$tmp" \
            && mv "$tmp" "$STATE_FILE"
    else
        # Fallback: sed-based update (less robust, but jq should be installed)
        log_warning "jq not found; using sed fallback for state management"
        if grep -q "\"${key}\"" "$STATE_FILE" 2>/dev/null; then
            sed -i "s|\"${key}\":[[:space:]]*\"[^\"]*\"|\"${key}\": \"${value}\"|g" "$STATE_FILE"
        else
            # Append before closing brace
            sed -i "s|}$/,\n  \"${key}\": \"${value}\"\n}/" "$STATE_FILE" 2>/dev/null \
                || echo "{\"${key}\": \"${value}\"}" > "$STATE_FILE"
        fi
    fi
}

# get_state(key) — Reads a value from the JSON state file. Echoes the value.
# Returns empty string if key doesn't exist.
get_state() {
    local key="$1"

    _ensure_state_file

    if command_exists jq; then
        jq -r --arg k "$key" '.[$k] // empty' "$STATE_FILE" 2>/dev/null || true
    else
        grep -oP "\"${key}\":\s*\"\K[^\"]*" "$STATE_FILE" 2>/dev/null || true
    fi
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

# =============================================================================
# OS DETECTION
# =============================================================================
# Sets global variables: OS_ID, OS_VERSION, OS_CODENAME

# detect_os() — Reads /etc/os-release and populates OS_* globals.
detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_CODENAME="${VERSION_CODENAME:-unknown}"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
        OS_CODENAME="unknown"
        log_warning "Cannot read /etc/os-release; OS detection failed."
    fi

    export OS_ID OS_VERSION OS_CODENAME
    log_info "Detected OS: ${OS_ID} ${OS_VERSION} (${OS_CODENAME})"
}

# is_ubuntu() — Returns 0 if running on Ubuntu.
is_ubuntu() {
    [[ "${OS_ID:-}" == "ubuntu" ]]
}

# is_debian() — Returns 0 if running on Debian.
is_debian() {
    [[ "${OS_ID:-}" == "debian" ]]
}

# =============================================================================
# NETWORK — PUBLIC IP
# =============================================================================

# get_server_ip() — Returns the primary public IPv4 address.
# Tries multiple services; falls back to the primary interface address.
get_server_ip() {
    local ip=""

    # Try public IP services in order
    for service in \
        "https://api.ipify.org" \
        "https://ifconfig.me/ip" \
        "https://ipecho.net/plain" \
        "https://icanhazip.com"
    do
        ip="$(curl -sf --max-time 5 "$service" 2>/dev/null || true)"
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done

    # Fallback: default route interface address
    ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)"
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi

    echo "127.0.0.1"
}

# =============================================================================
# IDEMPOTENCY HELPERS
# =============================================================================

# module_completed(name) — Returns 0 if the given module name is marked done
# in the state file. Used to skip already-completed modules.
module_completed() {
    local name="$1"
    local status
    status="$(get_state "module_${name}" 2>/dev/null || echo "")"
    [[ "$status" == "completed" ]]
}

# mark_module_complete(name) — Marks a module as completed in the state file.
mark_module_complete() {
    local name="$1"
    save_state "module_${name}" "completed"
    save_state "module_${name}_time" "$(date --iso-8601=seconds)"
    log_success "Module '${name}' marked as completed."
}

# require_module(name) — Exits with error if a prerequisite module is not done.
require_module() {
    local name="$1"
    if ! module_completed "$name"; then
        log_error "Required module '${name}' has not been completed."
        log_error "Please run module '${name}' first."
        exit 1
    fi
}

# =============================================================================
# MISC UTILITIES
# =============================================================================

# generate_password(length) — Generates a random alphanumeric+symbol password.
generate_password() {
    local length="${1:-24}"
    # Use openssl if available (preferred); fall back to /dev/urandom
    if command_exists openssl; then
        openssl rand -base64 48 | tr -dc 'A-Za-z0-9@#$%^&*' | head -c "$length"
    else
        tr -dc 'A-Za-z0-9@#$%^&*' < /dev/urandom | head -c "$length"
    fi
    echo ""  # ensure trailing newline
}

# trim(string) — Strips leading and trailing whitespace.
trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    echo "$s"
}

# version_gte(v1, v2) — Returns 0 if version v1 >= v2.
# Compares dot-separated version strings.
version_gte() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# =============================================================================
# Initialise log directory on source
# =============================================================================
_ensure_log_dir
_ensure_state_file
