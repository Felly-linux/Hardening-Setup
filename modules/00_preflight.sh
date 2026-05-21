#!/usr/bin/env bash
# =============================================================================
# modules/00_preflight.sh — Pre-flight checks
# =============================================================================
# Verifies that the system meets all requirements before the hardening suite
# makes any changes. Saves detected environment details to the state file so
# later modules can make informed decisions.
#
# Checks performed:
#   1.  OS compatibility (Ubuntu 20.04+ or Debian 11+)
#   2.  Root privileges
#   3.  Internet connectivity
#   4.  Minimum free disk space (20 GB)
#   5.  Minimum RAM (1 GB)
#   6.  Already-installed services (Docker, Fail2Ban, CrowdSec, UFW)
#   7.  Port conflict detection for every service in our stack
#
# Exported state keys:
#   preflight_passed        — "yes" / "no"
#   existing_docker         — "yes" / "no"
#   existing_fail2ban       — "yes" / "no"
#   existing_crowdsec       — "yes" / "no"
#   existing_ufw            — "yes" / "no"
#   port_conflict_<port>    — service name or "free"
# =============================================================================
set -euo pipefail

# Guard double-source
[[ -n "${_MODULE_PREFLIGHT_LOADED:-}" ]] && return 0
readonly _MODULE_PREFLIGHT_LOADED=1

# ---------------------------------------------------------------------------
# run_preflight — Main entry point called by install.sh
# ---------------------------------------------------------------------------
run_preflight() {
    log_section "PRE-FLIGHT CHECKS"

    local failures=0
    local warnings=0

    log_step 1 7 "Checking OS compatibility"
    _check_os || (( failures++ )) || true

    log_step 2 7 "Verifying root privileges"
    _check_root_priv || (( failures++ )) || true

    log_step 3 7 "Testing internet connectivity"
    _check_internet || (( failures++ )) || true

    log_step 4 7 "Checking free disk space (minimum 20 GB)"
    _check_disk_space || (( warnings++ )) || true

    log_step 5 7 "Checking available RAM (minimum 1 GB)"
    _check_ram || (( warnings++ )) || true

    log_step 6 7 "Detecting already-installed services"
    _detect_installed_services

    log_step 7 7 "Scanning for port conflicts"
    _scan_port_conflicts || (( warnings++ )) || true

    # --- Summary ---
    echo ""
    if (( failures > 0 )); then
        log_error "Pre-flight FAILED with ${failures} critical error(s)."
        log_error "Resolve the issues above and re-run the installer."
        save_state "preflight_passed" "no"
        return 1
    fi

    if (( warnings > 0 )); then
        log_warning "Pre-flight passed with ${warnings} warning(s). Review the output above."
    else
        log_success "All pre-flight checks passed."
    fi

    save_state "preflight_passed" "yes"
    save_state "preflight_time" "$(date --iso-8601=seconds)"
}

# ---------------------------------------------------------------------------
# _check_os — Verifies Ubuntu 20.04+ or Debian 11+
# ---------------------------------------------------------------------------
_check_os() {
    detect_os  # populates OS_ID, OS_VERSION, OS_CODENAME (from common.sh)

    case "$OS_ID" in
        ubuntu)
            local major
            major="${OS_VERSION%%.*}"
            if (( major < 20 )); then
                log_error "Ubuntu ${OS_VERSION} is too old. Minimum required: Ubuntu 20.04."
                return 1
            fi
            log_success "OS: Ubuntu ${OS_VERSION} (${OS_CODENAME}) — supported."
            ;;
        debian)
            local major
            major="${OS_VERSION%%.*}"
            if (( major < 11 )); then
                log_error "Debian ${OS_VERSION} is too old. Minimum required: Debian 11."
                return 1
            fi
            log_success "OS: Debian ${OS_VERSION} (${OS_CODENAME}) — supported."
            ;;
        *)
            log_error "Unsupported OS: '${OS_ID}'. This suite supports Ubuntu 20.04+ and Debian 11+ only."
            return 1
            ;;
    esac

    save_state "os_id"       "$OS_ID"
    save_state "os_version"  "$OS_VERSION"
    save_state "os_codename" "$OS_CODENAME"
}

# ---------------------------------------------------------------------------
# _check_root_priv — Confirms script is running as UID 0
# ---------------------------------------------------------------------------
_check_root_priv() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "Not running as root (EUID=${EUID}). Re-run with: sudo $0"
        return 1
    fi
    log_success "Running as root."
}

# ---------------------------------------------------------------------------
# _check_internet — Pings 8.8.8.8 and tries HTTPS to confirm connectivity
# ---------------------------------------------------------------------------
_check_internet() {
    # ICMP ping
    if ping -c 2 -W 5 8.8.8.8 &>/dev/null; then
        log_success "Internet connectivity: OK (ping 8.8.8.8)"
    else
        log_warning "Ping to 8.8.8.8 failed. Trying HTTP fallback..."
        if curl -sf --max-time 10 https://www.google.com &>/dev/null; then
            log_success "Internet connectivity: OK (HTTPS fallback)"
        else
            log_error "No internet connectivity detected."
            log_error "This installer requires internet access to download packages."
            return 1
        fi
    fi

    # Also verify DNS resolution
    if host google.com &>/dev/null || nslookup google.com &>/dev/null 2>&1; then
        log_success "DNS resolution: OK"
    else
        log_warning "DNS resolution may be broken. Package installation might fail."
    fi
}

# ---------------------------------------------------------------------------
# _check_disk_space — Verifies at least 20 GB free on /
# ---------------------------------------------------------------------------
_check_disk_space() {
    local min_gb=20
    local available_kb
    available_kb="$(df -k / | awk 'NR==2 {print $4}')"
    local available_gb=$(( available_kb / 1024 / 1024 ))

    if (( available_gb < min_gb )); then
        log_warning "Low disk space: ${available_gb} GB free on / (recommended: ${min_gb} GB)"
        log_warning "You may run out of space during installation."
        # Warning only — do not abort
        return 0
    fi

    log_success "Disk space: ${available_gb} GB free on / — sufficient."
    save_state "disk_free_gb" "$available_gb"
}

# ---------------------------------------------------------------------------
# _check_ram — Verifies at least 1 GB of total RAM
# ---------------------------------------------------------------------------
_check_ram() {
    local min_mb=1024
    local total_mb
    total_mb="$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)"

    if (( total_mb < min_mb )); then
        log_warning "Low RAM: ${total_mb} MB total (recommended: ${min_mb} MB)"
        log_warning "The monitoring stack may struggle on this machine."
        # Warning only — do not abort
        return 0
    fi

    log_success "RAM: ${total_mb} MB total — sufficient."
    save_state "ram_total_mb" "$total_mb"
}

# ---------------------------------------------------------------------------
# _detect_installed_services — Records which of our target services are already
# present so that installer modules can skip installation if appropriate.
# ---------------------------------------------------------------------------
_detect_installed_services() {
    local -A services=(
        ["docker"]="docker"
        ["fail2ban"]="fail2ban"
        ["crowdsec"]="crowdsec"
        ["ufw"]="ufw"
    )

    for name in "${!services[@]}"; do
        local pkg="${services[$name]}"
        if package_installed "$pkg" || command_exists "$pkg"; then
            log_info "  Detected existing: ${name}"
            save_state "existing_${name}" "yes"
        else
            log_info "  Not installed: ${name}"
            save_state "existing_${name}" "no"
        fi
    done

    # Docker-specific: also check daemon is running
    if command_exists docker && service_running docker; then
        log_info "  Docker daemon is running."
        save_state "docker_running" "yes"
    else
        save_state "docker_running" "no"
    fi
}

# ---------------------------------------------------------------------------
# _scan_port_conflicts — Checks every port used by our stack for conflicts
# ---------------------------------------------------------------------------
_scan_port_conflicts() {
    # Map of port → service name (using our constants from common.sh)
    local -a port_service_pairs=(
        "${PORT_GRAFANA}:Grafana"
        "${PORT_PROMETHEUS}:Prometheus"
        "${PORT_NODE_EXPORTER}:Node-Exporter"
        "${PORT_CADVISOR}:cAdvisor"
        "${PORT_LOKI}:Loki"
        "${PORT_PROMTAIL}:Promtail"
        "${PORT_CROWDSEC_LAPI}:CrowdSec-LAPI"
        "8080:Port-8080-default-CrowdSec"
        "22:SSH-default"
        "80:HTTP"
        "443:HTTPS"
    )

    local conflict_count=0

    printf "\n  ${BOLD}%-10s  %-30s  %-20s${RESET}\n" "PORT" "EXPECTED SERVICE" "STATUS"
    printf "  %s\n" "────────────────────────────────────────────────────────────"

    for pair in "${port_service_pairs[@]}"; do
        local port="${pair%%:*}"
        local svc="${pair#*:}"
        local status_str
        local status_color

        if port_in_use "$port"; then
            # Identify which process owns the port
            local owner
            owner="$(ss -tlnp 2>/dev/null | awk -v p=":${port}" '$0 ~ p {print $NF}' | grep -oP '"[^"]+"' | head -1 | tr -d '"' || echo "unknown")"
            status_str="IN USE (${owner:-unknown})"
            status_color="$YELLOW"
            save_state "port_conflict_${port}" "${owner:-in-use}"
            (( conflict_count++ )) || true
        else
            status_str="free"
            status_color="$GREEN"
            save_state "port_conflict_${port}" "free"
        fi

        printf "  ${BOLD}%-10s${RESET}  %-30s  ${status_color}%-20s${RESET}\n" \
            "$port" "$svc" "$status_str"
    done

    echo ""

    if (( conflict_count > 0 )); then
        log_warning "${conflict_count} port conflict(s) detected."
        log_warning "The installer will attempt to remap conflicting ports automatically."
        log_warning "Specifically: if port 8080 is busy, CrowdSec will use port ${PORT_CROWDSEC_LAPI}."
        # Not a hard failure — individual modules handle remapping
        save_state "port_conflicts_count" "$conflict_count"
        return 0
    fi

    log_success "No port conflicts detected."
    save_state "port_conflicts_count" "0"
}
