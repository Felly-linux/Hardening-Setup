#!/usr/bin/env bash
# =============================================================================
# modules/system.sh — System base hardening
# =============================================================================
# Performs foundational system hardening before any application-level modules
# run. This module is intentionally idempotent: every step checks whether it
# has already been applied before making changes.
#
# Steps:
#   1.  apt update + full upgrade
#   2.  Install essential tooling packages
#   3.  Set system timezone
#   4.  Set hostname
#   5.  Configure NTP via systemd-timesyncd
#   6.  Disable unnecessary services (Bluetooth, CUPS, Avahi, etc.)
#   7.  Apply hardened sysctl kernel parameters
#   8.  Configure automatic security updates (unattended-upgrades)
#   9.  Set /tmp as a separate mount with noexec,nosuid options
#  10.  Configure core dump limits
#
# State keys written:
#   system_timezone   — timezone that was configured
#   system_hostname   — hostname that was set
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_SYSTEM_LOADED:-}" ]] && return 0
readonly _MODULE_SYSTEM_LOADED=1

# Source common library if not already loaded
if [[ -z "${_VPS_HARDENING_COMMON_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "${SCRIPT_DIR}/../lib/common.sh"
fi

# =============================================================================
# Profile variables with safe defaults
# =============================================================================
DRY_RUN="${DRY_RUN:-0}"

# ---------------------------------------------------------------------------
# run_system — Main entry point
# ---------------------------------------------------------------------------
run_system() {
    log_section "SYSTEM BASE HARDENING"

    log_step 1 10 "Updating package lists and upgrading installed packages"
    _system_update_packages

    log_step 2 10 "Installing essential tools"
    _system_install_tools

    log_step 3 10 "Configuring timezone"
    _system_set_timezone

    log_step 4 10 "Configuring hostname"
    _system_set_hostname

    log_step 5 10 "Configuring NTP (systemd-timesyncd)"
    _system_configure_ntp

    log_step 6 10 "Disabling unnecessary system services"
    _system_disable_services

    log_step 7 10 "Applying kernel hardening parameters (sysctl)"
    _system_apply_sysctl

    log_step 8 10 "Configuring automatic security updates"
    _system_configure_auto_updates

    log_step 9 10 "Hardening /tmp filesystem options"
    _system_harden_tmp

    log_step 10 10 "Configuring core dump restrictions"
    _system_configure_coredumps

    log_success "System base hardening complete."
    mark_module_complete "system"
}

# ---------------------------------------------------------------------------
# _system_update_packages — apt update + full upgrade
# ---------------------------------------------------------------------------
_system_update_packages() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would run: apt-get update && apt-get upgrade -y"
        return 0
    fi

    log_info "Running apt-get update..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >> "$LOG_FILE" 2>&1

    log_info "Running apt-get upgrade..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        >> "$LOG_FILE" 2>&1

    log_success "Packages updated and upgraded."
}

# ---------------------------------------------------------------------------
# _system_install_tools — Install the set of essential utilities
# ---------------------------------------------------------------------------
_system_install_tools() {
    local packages=(
        # Networking
        curl wget net-tools nmap iputils-ping dnsutils iproute2
        # Version control / build
        git build-essential
        # Compression
        unzip zip tar
        # JSON / YAML / scripting
        jq
        # Security
        gnupg2 ca-certificates apt-transport-https
        # Monitoring & diagnostics
        htop iftop iotop sysstat lsof strace tcpdump
        # Editors
        vim nano
        # Misc
        lsb-release software-properties-common rsync screen tmux
        # Required by other modules
        ufw fail2ban
        # Auto-update support
        unattended-upgrades apt-listchanges
    )

    log_info "Installing ${#packages[@]} packages..."

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would install: ${packages[*]}"
        return 0
    fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "${packages[@]}" >> "$LOG_FILE" 2>&1

    log_success "All essential packages installed."
}

# ---------------------------------------------------------------------------
# _system_set_timezone — Interactively or default to UTC
# ---------------------------------------------------------------------------
_system_set_timezone() {
    local current_tz
    current_tz="$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "UTC")"

    log_info "Current timezone: ${current_tz}"

    local tz
    tz="$(ask "Set timezone (leave blank to keep '${current_tz}')" "$current_tz")"
    tz="$(trim "$tz")"

    # Validate timezone
    if [[ -n "$tz" && -f "/usr/share/zoneinfo/${tz}" ]]; then
        if [[ "${DRY_RUN}" == "1" ]]; then
            log_info "[DRY-RUN] Would set timezone to: ${tz}"
        else
            timedatectl set-timezone "$tz" >> "$LOG_FILE" 2>&1
            log_success "Timezone set to: ${tz}"
            save_state "system_timezone" "$tz"
        fi
    elif [[ "$tz" == "$current_tz" ]]; then
        log_info "Timezone unchanged: ${tz}"
        if [[ "${DRY_RUN}" != "1" ]]; then
            save_state "system_timezone" "$tz"
        fi
    else
        log_warning "Invalid timezone '${tz}'. Keeping current: ${current_tz}"
        if [[ "${DRY_RUN}" != "1" ]]; then
            save_state "system_timezone" "$current_tz"
        fi
    fi
}

# ---------------------------------------------------------------------------
# _system_set_hostname — Ask for and set the system hostname
# ---------------------------------------------------------------------------
_system_set_hostname() {
    local current_hostname
    current_hostname="$(hostname)"

    log_info "Current hostname: ${current_hostname}"

    local new_hostname
    new_hostname="$(ask "Set hostname (leave blank to keep '${current_hostname}')" "$current_hostname")"
    new_hostname="$(trim "$new_hostname")"

    # Validate: only letters, numbers, hyphens; max 63 chars
    if [[ "$new_hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] \
       && [[ "$new_hostname" != "$current_hostname" ]]; then
        if [[ "${DRY_RUN}" == "1" ]]; then
            log_info "[DRY-RUN] Would set hostname to: ${new_hostname}"
        else
            hostnamectl set-hostname "$new_hostname" >> "$LOG_FILE" 2>&1

            # Update /etc/hosts to reflect new hostname
            if grep -q "127.0.1.1" /etc/hosts; then
                sed -i "s/127\.0\.1\.1.*/127.0.1.1\t${new_hostname}/" /etc/hosts
            else
                echo "127.0.1.1	${new_hostname}" >> /etc/hosts
            fi

            log_success "Hostname set to: ${new_hostname}"
            save_state "system_hostname" "$new_hostname"
        fi
    else
        log_info "Hostname unchanged: ${current_hostname}"
        if [[ "${DRY_RUN}" != "1" ]]; then
            save_state "system_hostname" "$current_hostname"
        fi
    fi
}

# ---------------------------------------------------------------------------
# _system_configure_ntp — Enable and configure systemd-timesyncd
# ---------------------------------------------------------------------------
_system_configure_ntp() {
    local ntp_conf="/etc/systemd/timesyncd.conf"

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would write NTP config to ${ntp_conf} and restart systemd-timesyncd"
        return 0
    fi

    backup_file "$ntp_conf" >> "$LOG_FILE" 2>&1 || true

    cat > "$ntp_conf" << 'EOF'
# /etc/systemd/timesyncd.conf — configured by VPS Hardening Suite
[Time]
# Primary and fallback NTP servers
NTP=0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org
FallbackNTP=ntp.ubuntu.com time.cloudflare.com
# Polling intervals (seconds)
PollIntervalMinSecs=32
PollIntervalMaxSecs=2048
EOF

    systemctl enable systemd-timesyncd >> "$LOG_FILE" 2>&1
    systemctl restart systemd-timesyncd >> "$LOG_FILE" 2>&1

    log_success "NTP configured and timesyncd restarted."

    # Verify sync (may take a few seconds to establish)
    timedatectl status 2>/dev/null | grep -E "NTP|synchronized" | while IFS= read -r line; do
        log_info "  ${line}"
    done
}

# ---------------------------------------------------------------------------
# _system_disable_services — Stop and disable unneeded services
# ---------------------------------------------------------------------------
_system_disable_services() {
    local unnecessary_services=(
        bluetooth          # No Bluetooth on servers
        cups               # Printing — not needed
        cups-browsed       # Print discovery
        avahi-daemon       # mDNS/ZeroConf — security risk
        ModemManager       # Mobile broadband — not needed on servers
        apport             # Ubuntu crash reporter
        whoopsie           # Ubuntu error reporting to Canonical
        snapd              # Snap daemon (optional, comment out if snaps needed)
    )

    for svc in "${unnecessary_services[@]}"; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null \
           && systemctl list-unit-files "${svc}.service" | grep -q "${svc}"; then
            if service_running "$svc"; then
                log_info "  Stopping and disabling: ${svc}"
                if [[ "${DRY_RUN}" == "1" ]]; then
                    log_info "[DRY-RUN] Would stop and disable service: ${svc}"
                else
                    systemctl stop "$svc" >> "$LOG_FILE" 2>&1 || true
                    systemctl disable "$svc" >> "$LOG_FILE" 2>&1 || true
                    systemctl mask "$svc" >> "$LOG_FILE" 2>&1 || true
                fi
            else
                log_info "  Already stopped/disabled: ${svc}"
            fi
        fi
    done

    log_success "Unnecessary services disabled."
}

# ---------------------------------------------------------------------------
# _system_apply_sysctl — Write and apply hardened kernel parameters
# ---------------------------------------------------------------------------
_system_apply_sysctl() {
    local sysctl_file="/etc/sysctl.d/99-vps-hardening.conf"

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would write sysctl config to ${sysctl_file} and run sysctl --system"
        return 0
    fi

    # Backup existing file if present
    [[ -f "$sysctl_file" ]] && backup_file "$sysctl_file"

    cat > "$sysctl_file" << 'EOF'
# =============================================================================
# /etc/sysctl.d/99-vps-hardening.conf
# Kernel hardening parameters applied by VPS Hardening Suite
# =============================================================================

# ---------------------------------------------------------------------------
# Network: IP Forwarding (required by Docker and NAT)
# ---------------------------------------------------------------------------
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0

# ---------------------------------------------------------------------------
# Network: Anti-spoofing (Reverse Path Filtering)
# ---------------------------------------------------------------------------
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ---------------------------------------------------------------------------
# Network: Disable source routing (prevents routing table manipulation)
# ---------------------------------------------------------------------------
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# ---------------------------------------------------------------------------
# Network: SYN flood protection
# ---------------------------------------------------------------------------
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# ---------------------------------------------------------------------------
# Network: ICMP security
# ---------------------------------------------------------------------------
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ---------------------------------------------------------------------------
# Network: Disable ICMP redirect acceptance
# ---------------------------------------------------------------------------
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ---------------------------------------------------------------------------
# IPv6: Keep enabled but disable router advertisements
# ---------------------------------------------------------------------------
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# ---------------------------------------------------------------------------
# Kernel: Restrict dmesg to root
# ---------------------------------------------------------------------------
kernel.dmesg_restrict = 1

# ---------------------------------------------------------------------------
# Kernel: Restrict ptrace to processes with CAP_SYS_PTRACE
# ---------------------------------------------------------------------------
kernel.yama.ptrace_scope = 1

# ---------------------------------------------------------------------------
# Kernel: Restrict kernel pointer exposure
# ---------------------------------------------------------------------------
kernel.kptr_restrict = 2

# ---------------------------------------------------------------------------
# Kernel: Randomize virtual address space (ASLR)
# ---------------------------------------------------------------------------
kernel.randomize_va_space = 2

# ---------------------------------------------------------------------------
# Kernel: Restrict kernel log access
# ---------------------------------------------------------------------------
kernel.printk = 3 4 1 3

# ---------------------------------------------------------------------------
# Kernel: Disable magic SysRq key
# ---------------------------------------------------------------------------
kernel.sysrq = 0

# ---------------------------------------------------------------------------
# Kernel: Protect hard links and symlinks
# ---------------------------------------------------------------------------
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# ---------------------------------------------------------------------------
# Filesystem: Restrict core dump file creation
# ---------------------------------------------------------------------------
fs.suid_dumpable = 0

# ---------------------------------------------------------------------------
# Network: TCP performance and memory tuning
# ---------------------------------------------------------------------------
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
EOF

    # Apply immediately
    sysctl --system >> "$LOG_FILE" 2>&1

    log_success "Kernel parameters applied from ${sysctl_file}"
}

# ---------------------------------------------------------------------------
# _system_configure_auto_updates — Enable unattended security updates
# ---------------------------------------------------------------------------
_system_configure_auto_updates() {
    local auto_conf="/etc/apt/apt.conf.d/20auto-upgrades"
    local unattended_conf="/etc/apt/apt.conf.d/50unattended-upgrades"

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would write ${auto_conf} and ${unattended_conf}"
        log_info "[DRY-RUN] Would enable and restart unattended-upgrades service"
        return 0
    fi

    # Write apt auto-upgrade triggers
    cat > "$auto_conf" << 'EOF'
// /etc/apt/apt.conf.d/20auto-upgrades — configured by VPS Hardening Suite
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    # Write comprehensive unattended-upgrades config
    cat > "$unattended_conf" << 'EOF'
// /etc/apt/apt.conf.d/50unattended-upgrades
// Configured by VPS Hardening Suite
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

// Packages to never auto-update (kernel, SSH, databases)
Unattended-Upgrade::Package-Blacklist {
    "linux-image-*";
    "openssh-server";
};

// Auto-remove unused packages after upgrade
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Reboot automatically if required (at 3 AM)
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";

// Email notifications for problems
// Unattended-Upgrade::Mail "admin@example.com";
// Unattended-Upgrade::MailOnlyOnError "true";

// Log to syslog
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

    systemctl enable unattended-upgrades >> "$LOG_FILE" 2>&1
    systemctl restart unattended-upgrades >> "$LOG_FILE" 2>&1 || true

    log_success "Automatic security updates configured."
}

# ---------------------------------------------------------------------------
# _system_harden_tmp — Remount /tmp with security options
# ---------------------------------------------------------------------------
_system_harden_tmp() {
    # Only apply if /tmp is not already a separate partition / tmpfs
    local fstab="/etc/fstab"

    if mount | grep -q " /tmp "; then
        log_info "/tmp already mounted separately. Checking options..."
        # If mounted but without noexec, remount
        if ! mount | grep " /tmp " | grep -q "noexec"; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log_info "[DRY-RUN] Would remount /tmp with noexec,nosuid,nodev"
            else
                mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null \
                    && log_success "/tmp remounted with noexec,nosuid,nodev" \
                    || log_warning "Could not remount /tmp with hardened options"
            fi
        else
            log_info "/tmp already has noexec option. Skipping."
        fi
    else
        # /tmp is on root partition — add tmpfs entry if not already in fstab
        if ! grep -q "^tmpfs /tmp" "$fstab" 2>/dev/null; then
            if [[ "${DRY_RUN}" == "1" ]]; then
                log_info "[DRY-RUN] Would add tmpfs /tmp entry to ${fstab} and run mount -a"
            else
                backup_file "$fstab"
                echo "tmpfs /tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=512m 0 0" >> "$fstab"
                mount -a 2>/dev/null && log_success "/tmp tmpfs entry added to fstab and mounted." \
                    || log_warning "Added /tmp to fstab; will apply on next boot."
            fi
        else
            log_info "/tmp tmpfs already in fstab. Skipping."
        fi
    fi
}

# ---------------------------------------------------------------------------
# _system_configure_coredumps — Disable core dumps for setuid processes
# ---------------------------------------------------------------------------
_system_configure_coredumps() {
    local limits_file="/etc/security/limits.d/99-disable-coredumps.conf"

    if [[ -f "$limits_file" ]]; then
        log_info "Core dump limits already configured."
        return 0
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would write ${limits_file} to disable core dumps"
        log_info "[DRY-RUN] Would run: sysctl -w fs.suid_dumpable=0"
        return 0
    fi

    cat > "$limits_file" << 'EOF'
# /etc/security/limits.d/99-disable-coredumps.conf
# Disable core dumps system-wide to prevent memory leaks of sensitive data
*    hard    core    0
*    soft    core    0
EOF
    log_success "Core dumps disabled via /etc/security/limits.d/"

    # Also set via sysctl (belt-and-suspenders)
    sysctl -w fs.suid_dumpable=0 >> "$LOG_FILE" 2>&1 || true
}
