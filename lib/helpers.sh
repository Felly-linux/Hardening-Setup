#!/usr/bin/env bash
# =============================================================================
# lib/helpers.sh — Global paths, constants, system checks, network helpers,
#                  OS detection, state management, and prompt utilities
# =============================================================================
# Depends on lib/logging.sh (sourced internally below).
# =============================================================================

[[ -n "${_VPS_HELPERS_LOADED:-}" ]] && return 0
readonly _VPS_HELPERS_LOADED=1

set -euo pipefail

# Source logging so _ensure_log_dir and log_* are available
_HELPERS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=logging.sh
source "${_HELPERS_LIB_DIR}/logging.sh"
unset _HELPERS_LIB_DIR

# =============================================================================
# GLOBAL PATHS  (derived from PROJECT_ROOT set by common.sh or self-computed)
# =============================================================================
# PROJECT_ROOT is declared readonly by common.sh; if helpers.sh is sourced
# directly we compute it ourselves, but only when it is not already set.
if [[ -z "${PROJECT_ROOT:-}" ]]; then
    readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

readonly STATE_FILE="/var/lib/vps-hardening/state.json"
readonly LOG_DIR="/var/log/vps-hardening"
readonly LOG_FILE="${LOG_DIR}/install.log"
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
# OS DETECTION
# =============================================================================
# Sets and exports global variables: OS_ID, OS_VERSION, OS_CODENAME

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

# version_gte(v1, v2) — Returns 0 if version v1 >= v2 (dot-separated strings).
version_gte() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# =============================================================================
# INTERACTIVE PROMPTS
# =============================================================================

# confirm(question, [default]) — Ask a yes/no question.
# Returns 0 (true) for yes, 1 (false) for no.
# In non-interactive mode (NONINTERACTIVE=1), defaults to yes.
confirm() {
    local question="$1"
    local default="${2:-y}"  # optional second arg: 'y' or 'n'

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

    local answer
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
# Echoes the entered value; returns default when user presses Enter.
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
# Echoes the entered password (auto-generates in non-interactive mode).
ask_password() {
    local question="$1"
    local password

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
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
# Returns empty string if the key doesn't exist.
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
# IDEMPOTENCY HELPERS
# =============================================================================

# module_completed(name) — Returns 0 if the given module name is marked done.
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
# Initialise on source
# =============================================================================
_ensure_log_dir
_ensure_state_file
