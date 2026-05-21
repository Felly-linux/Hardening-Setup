#!/usr/bin/env bash
# =============================================================================
# modules/sysctl.sh — Kernel parameter hardening
# =============================================================================
# THREAT MODEL:
#   Mitigates: IP spoofing, SYN flood, ICMP redirect attacks, kernel pointer
#              leaks, ASLR bypass, core dumps containing secrets
#   Attack surface reduced: Network stack, kernel information disclosure
#   Operational impact: Disables IP forwarding (re-enable for Docker hosts
#                       via SYSCTL_IP_FORWARD=yes)
#   Can break: Docker networking if ip_forward disabled; VirtualBox if
#              kernel hardening applied on desktop; some ptrace-based debuggers
#   Compatible with: Ubuntu 20.04+, Debian 11+
# =============================================================================
set -euo pipefail

# Guard against double-sourcing
[[ -n "${_MODULE_SYSCTL_LOADED:-}" ]] && return 0
readonly _MODULE_SYSCTL_LOADED=1

# Source common library if not already loaded
if [[ -z "${_VPS_HARDENING_COMMON_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "${SCRIPT_DIR}/../lib/common.sh"
fi

# =============================================================================
# Profile variables with safe defaults
# =============================================================================
SYSCTL_NETWORK_HARDENING="${SYSCTL_NETWORK_HARDENING:-yes}"
SYSCTL_KERNEL_HARDENING="${SYSCTL_KERNEL_HARDENING:-yes}"
SYSCTL_FS_HARDENING="${SYSCTL_FS_HARDENING:-yes}"
SYSCTL_DISABLE_IPV6="${SYSCTL_DISABLE_IPV6:-no}"
SYSCTL_IP_FORWARD="${SYSCTL_IP_FORWARD:-no}"
SYSCTL_DISABLE_CORE_DUMPS="${SYSCTL_DISABLE_CORE_DUMPS:-no}"
DRY_RUN="${DRY_RUN:-0}"

# =============================================================================
# run_sysctl — Public entry point
# =============================================================================
run_sysctl() {
    log_section "KERNEL PARAMETER HARDENING (sysctl)"

    local total_steps=3
    local step=0

    (( step++ )) && log_step "$step" "$total_steps" "Deploying sysctl configuration files"
    _sysctl_deploy_configs

    (( step++ )) && log_step "$step" "$total_steps" "Applying sysctl settings"
    _sysctl_apply

    (( step++ )) && log_step "$step" "$total_steps" "Validating applied settings"
    _sysctl_validate

    log_success "Kernel parameter hardening complete."
    mark_module_complete "sysctl"
}

# =============================================================================
# _sysctl_deploy_configs — Copy config files to /etc/sysctl.d/
# =============================================================================
_sysctl_deploy_configs() {
    local src_dir="${PROJECT_ROOT}/configs/sysctl"
    local dst_dir="/etc/sysctl.d"

    if [[ ! -d "$src_dir" ]]; then
        log_error "sysctl config source directory not found: ${src_dir}"
        return 1
    fi

    # --- Network hardening ---
    if [[ "${SYSCTL_NETWORK_HARDENING}" == "yes" ]]; then
        local net_src="${src_dir}/99-hardening-network.conf"
        local net_dst="${dst_dir}/99-hardening-network.conf"
        _sysctl_deploy_file "$net_src" "$net_dst" "network hardening"

        # Apply IP forward override inside the deployed file
        if [[ "${SYSCTL_IP_FORWARD}" == "yes" ]]; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log_info "[DRY-RUN] Would set net.ipv4.ip_forward=1 in ${net_dst}"
            else
                log_info "Enabling IP forwarding (SYSCTL_IP_FORWARD=yes)"
                # Ensure the override is present; add if absent, replace if present
                if grep -q "^net.ipv4.ip_forward" "$net_dst" 2>/dev/null; then
                    sed -i 's|^net\.ipv4\.ip_forward\s*=.*|net.ipv4.ip_forward = 1|' "$net_dst"
                else
                    printf '\n# IP forwarding enabled via SYSCTL_IP_FORWARD=yes\nnet.ipv4.ip_forward = 1\n' >> "$net_dst"
                fi
                log_success "IP forwarding enabled in ${net_dst}"
            fi
        fi

        # Apply IPv6 disable override
        if [[ "${SYSCTL_DISABLE_IPV6}" == "yes" ]]; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log_info "[DRY-RUN] Would add net.ipv6.conf.all.disable_ipv6=1 to ${net_dst}"
            else
                log_info "Disabling IPv6 (SYSCTL_DISABLE_IPV6=yes)"
                if grep -q "^net.ipv6.conf.all.disable_ipv6" "$net_dst" 2>/dev/null; then
                    sed -i 's|^net\.ipv6\.conf\.all\.disable_ipv6\s*=.*|net.ipv6.conf.all.disable_ipv6 = 1|' "$net_dst"
                else
                    printf '\n# IPv6 disabled via SYSCTL_DISABLE_IPV6=yes\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1\n' >> "$net_dst"
                fi
                log_success "IPv6 disabled in ${net_dst}"
            fi
        fi
    else
        log_info "SYSCTL_NETWORK_HARDENING=no — skipping network config"
    fi

    # --- Kernel hardening ---
    if [[ "${SYSCTL_KERNEL_HARDENING}" == "yes" ]]; then
        local kern_src="${src_dir}/99-hardening-kernel.conf"
        local kern_dst="${dst_dir}/99-hardening-kernel.conf"
        _sysctl_deploy_file "$kern_src" "$kern_dst" "kernel hardening"
    else
        log_info "SYSCTL_KERNEL_HARDENING=no — skipping kernel config"
    fi

    # --- Filesystem hardening ---
    if [[ "${SYSCTL_FS_HARDENING}" == "yes" ]]; then
        local fs_src="${src_dir}/99-hardening-fs.conf"
        local fs_dst="${dst_dir}/99-hardening-fs.conf"
        _sysctl_deploy_file "$fs_src" "$fs_dst" "filesystem hardening"
    else
        log_info "SYSCTL_FS_HARDENING=no — skipping filesystem config"
    fi

    # --- Core dumps (separate concern from FS hardening) ---
    if [[ "${SYSCTL_DISABLE_CORE_DUMPS}" == "yes" ]]; then
        _sysctl_disable_core_dumps
    fi
}

# =============================================================================
# _sysctl_deploy_file — Idempotent file deploy with backup
# Arguments: src dst label
# =============================================================================
_sysctl_deploy_file() {
    local src="$1"
    local dst="$2"
    local label="$3"

    if [[ ! -f "$src" ]]; then
        log_error "Source config not found: ${src}"
        return 1
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would deploy ${label}: ${src} → ${dst}"
        return 0
    fi

    # Idempotency check: skip if destination already has identical content
    if [[ -f "$dst" ]]; then
        if diff -q "$src" "$dst" &>/dev/null; then
            log_info "${label} already up to date: ${dst}"
            return 0
        fi
        # Backup the existing file before overwriting
        backup_file "$dst" >> "$LOG_FILE" 2>&1 || true
    fi

    cp -p "$src" "$dst"
    chmod 644 "$dst"
    log_success "Deployed ${label}: ${dst}"
}

# =============================================================================
# _sysctl_disable_core_dumps — Write limits.conf to suppress core dumps
# =============================================================================
_sysctl_disable_core_dumps() {
    local limits_file="/etc/security/limits.d/99-no-coredumps.conf"

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would write core dump limits to ${limits_file}"
        return 0
    fi

    if [[ -f "$limits_file" ]]; then
        # Check if already configured
        if grep -q "^\\* .* core .* 0" "$limits_file" 2>/dev/null; then
            log_info "Core dumps already disabled via ${limits_file}"
            return 0
        fi
        backup_file "$limits_file" >> "$LOG_FILE" 2>&1 || true
    fi

    cat > "$limits_file" << 'EOF'
# /etc/security/limits.d/99-no-coredumps.conf
# Disable core dumps to prevent memory leaks of sensitive data
# Deployed by VPS Hardening Suite (SYSCTL_DISABLE_CORE_DUMPS=yes)
*    hard    core    0
*    soft    core    0
EOF
    chmod 644 "$limits_file"
    log_success "Core dumps disabled via ${limits_file}"
}

# =============================================================================
# _sysctl_apply — Run sysctl --system to activate all /etc/sysctl.d/ files
# =============================================================================
_sysctl_apply() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would run: sysctl --system"
        return 0
    fi

    log_info "Loading all sysctl parameters (sysctl --system)..."
    if sysctl --system >> "$LOG_FILE" 2>&1; then
        log_success "sysctl --system completed successfully."
    else
        log_warning "sysctl --system reported errors; check ${LOG_FILE} for details."
    fi
}

# =============================================================================
# _sysctl_validate — Spot-check a sample of expected values
# =============================================================================
_sysctl_validate() {
    local all_ok=1

    # Build list of expected parameter=value pairs based on enabled settings
    local -a checks=()

    if [[ "${SYSCTL_NETWORK_HARDENING}" == "yes" ]]; then
        checks+=(
            "net.ipv4.tcp_syncookies=1"
            "net.ipv4.conf.all.rp_filter=1"
            "net.ipv4.conf.all.accept_redirects=0"
            "net.ipv4.icmp_echo_ignore_broadcasts=1"
        )
        if [[ "${SYSCTL_IP_FORWARD}" == "yes" ]]; then
            checks+=("net.ipv4.ip_forward=1")
        else
            checks+=("net.ipv4.ip_forward=0")
        fi
    fi

    if [[ "${SYSCTL_KERNEL_HARDENING}" == "yes" ]]; then
        checks+=(
            "kernel.dmesg_restrict=1"
            "kernel.kptr_restrict=2"
            "kernel.randomize_va_space=2"
            "kernel.sysrq=0"
        )
    fi

    if [[ "${SYSCTL_FS_HARDENING}" == "yes" ]]; then
        checks+=(
            "fs.protected_hardlinks=1"
            "fs.protected_symlinks=1"
            "fs.suid_dumpable=0"
        )
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would validate ${#checks[@]} sysctl parameters"
        return 0
    fi

    log_info "Validating ${#checks[@]} sysctl parameters..."

    for check in "${checks[@]}"; do
        local param="${check%%=*}"
        local expected="${check##*=}"
        local actual
        actual="$(sysctl -n "$param" 2>/dev/null || echo "ERROR")"

        # Normalize: strip spaces
        actual="${actual// /}"
        expected="${expected// /}"

        if [[ "$actual" == "$expected" ]]; then
            log_success "  OK: ${param} = ${actual}"
        else
            log_warning "  MISMATCH: ${param} expected=${expected} actual=${actual}"
            all_ok=0
        fi
    done

    if [[ "$all_ok" -eq 1 ]]; then
        log_success "All sysctl validations passed."
    else
        log_warning "Some sysctl parameters did not match expected values."
        log_warning "Check ${LOG_FILE} and verify /etc/sysctl.d/ files are correct."
    fi
}
