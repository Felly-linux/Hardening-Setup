#!/usr/bin/env bash
# =============================================================================
# modules/05_fail2ban.sh — Fail2Ban intrusion prevention
# =============================================================================
# Installs and configures Fail2Ban to detect and block brute-force attempts
# against SSH, web applications, and other services.
#
# Architecture:
#   fail2ban.conf   — Upstream defaults (never edited directly)
#   jail.conf       — Upstream jail definitions (never edited directly)
#   jail.local      — Our overrides (created by this module)
#   filter.d/       — Custom filter definitions (we may add some)
#   action.d/       — Notification actions
#
# Jails configured:
#   sshd            — SSH brute force (uses correct port from state)
#   recidive        — Bans IPs that trigger multiple jails repeatedly
#   nginx-http-auth — Optional, if nginx is installed
#   nginx-botsearch — Optional, if nginx is installed
#   crowdsec        — Optional integration if CrowdSec is installed
#
# Steps:
#   1.  Install fail2ban
#   2.  Backup existing config
#   3.  Write jail.local
#   4.  Write custom filter if needed
#   5.  Set up whitelist from user input
#   6.  Start + enable service
#   7.  Verify status
#
# State keys written:
#   fail2ban_installed  — "yes"
#   fail2ban_whitelist  — comma-separated whitelisted IPs
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_FAIL2BAN_LOADED:-}" ]] && return 0
readonly _MODULE_FAIL2BAN_LOADED=1

# ---------------------------------------------------------------------------
# run_fail2ban — Main entry point
# ---------------------------------------------------------------------------
run_fail2ban() {
    log_section "FAIL2BAN CONFIGURATION"

    log_step 1 6 "Installing Fail2Ban"
    _fail2ban_install

    log_step 2 6 "Backing up existing configuration"
    _fail2ban_backup

    log_step 3 6 "Writing jail.local configuration"
    _fail2ban_write_config

    log_step 4 6 "Configuring whitelist IPs"
    _fail2ban_configure_whitelist

    log_step 5 6 "Starting and enabling Fail2Ban service"
    _fail2ban_enable

    log_step 6 6 "Verifying Fail2Ban status"
    _fail2ban_verify

    log_success "Fail2Ban configured and running."
    save_state "fail2ban_installed" "yes"
}

# ---------------------------------------------------------------------------
# _fail2ban_install — Install fail2ban and dependencies
# ---------------------------------------------------------------------------
_fail2ban_install() {
    if package_installed fail2ban; then
        log_info "Fail2Ban is already installed."
        return 0
    fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        fail2ban \
        python3-systemd \
        >> "$LOG_FILE" 2>&1

    log_success "Fail2Ban installed."
}

# ---------------------------------------------------------------------------
# _fail2ban_backup — Backup existing jail.local if present
# ---------------------------------------------------------------------------
_fail2ban_backup() {
    local conf_files=(
        "/etc/fail2ban/jail.local"
        "/etc/fail2ban/jail.conf"
    )

    for f in "${conf_files[@]}"; do
        [[ -f "$f" ]] && backup_file "$f" || true
    done
}

# ---------------------------------------------------------------------------
# _fail2ban_write_config — Generate /etc/fail2ban/jail.local
# ---------------------------------------------------------------------------
_fail2ban_write_config() {
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "2222")"

    local whitelist
    whitelist="$(get_state "fail2ban_whitelist" 2>/dev/null || echo "127.0.0.1")"

    # Determine if nginx is installed
    local nginx_enabled="false"
    if command_exists nginx || package_installed nginx; then
        nginx_enabled="true"
        log_info "Nginx detected — enabling nginx jails."
    fi

    cat > /etc/fail2ban/jail.local << EOF
# =============================================================================
# /etc/fail2ban/jail.local — VPS Hardening Suite configuration
# Generated: $(date --iso-8601=seconds)
# =============================================================================
# This file overrides settings from jail.conf.
# After changes: sudo systemctl reload fail2ban
# =============================================================================

[DEFAULT]
# ---------------------------------------------------------------------------
# Global settings (applied to all jails unless overridden)
# ---------------------------------------------------------------------------

# Ignore these IPs — never ban them (your management IPs, localhost)
ignoreip = ${whitelist} 127.0.0.0/8 ::1

# Ban duration in seconds (-1 = permanent)
bantime  = 3600

# Time window to count failures in (seconds)
findtime = 600

# Number of failures before banning
maxretry = 5

# Backend for log file monitoring
# systemd: read from journald (preferred on modern systemd systems)
# auto:    try pyinotify → gamin → polling
backend = systemd

# Use iptables-allports action by default
banaction = iptables-multiport
banaction_allports = iptables-allports

# Use UFW if available and iptables is not
# banaction = ufw

# Enable DNS lookups (set to warn/no to improve performance)
usedns = warn

# Encoding of log files
encoding = UTF-8

# Enable/disable all jails globally
enabled = false

# Send email notifications (uncomment and configure to enable)
# action = %(action_mwl)s
# destemail = admin@example.com
# sender = fail2ban@%(fq-hostname)s

# ---------------------------------------------------------------------------
# Journal backend settings
# ---------------------------------------------------------------------------
[sshd]
enabled  = true
port     = ${ssh_port}
protocol = tcp
filter   = sshd
# systemd journal backend — no logpath needed
backend  = systemd
# More aggressive settings for SSH
maxretry = 3
bantime  = 7200
findtime = 300
# Log all matches for debugging
logencoding = auto

# ---------------------------------------------------------------------------
# Recidive jail: re-bans IPs that get banned repeatedly across jails
# A second line of defence against persistent attackers
# ---------------------------------------------------------------------------
[recidive]
enabled   = true
filter    = recidive
# Read from fail2ban's own log
logpath   = /var/log/fail2ban.log
# If an IP gets banned 3 times in 12h, ban it for 1 week
maxretry  = 3
findtime  = 43200
bantime   = 604800

EOF

    # Append nginx jails if nginx is installed
    if [[ "$nginx_enabled" == "true" ]]; then
        cat >> /etc/fail2ban/jail.local << 'NGINX_JAILS'
# ---------------------------------------------------------------------------
# Nginx jails (active only because nginx was detected)
# ---------------------------------------------------------------------------
[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime  = 600

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 86400

NGINX_JAILS
        log_info "Nginx fail2ban jails added."
    fi

    log_success "jail.local written for SSH port ${ssh_port}."

    # Write a custom fail2ban filter for enhanced SSH detection
    _fail2ban_write_custom_filter
}

# ---------------------------------------------------------------------------
# _fail2ban_write_custom_filter — Enhanced SSH filter to catch more patterns
# ---------------------------------------------------------------------------
_fail2ban_write_custom_filter() {
    local filter_file="/etc/fail2ban/filter.d/sshd-enhanced.conf"

    if [[ -f "$filter_file" ]]; then
        log_info "Custom sshd filter already exists."
        return 0
    fi

    cat > "$filter_file" << 'EOF'
# /etc/fail2ban/filter.d/sshd-enhanced.conf
# Enhanced SSH filter for Fail2Ban — catches additional attack patterns
# VPS Hardening Suite

[INCLUDES]
before = common.conf

[Definition]
_daemon = sshd

failregex = ^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error|failed) for .* from <HOST>( via \S+)?\s*$
            ^%(__prefix_line)s(?:error: PAM: )?User not known to the underlying authentication module for .* from <HOST>\s*$
            ^%(__prefix_line)sFailed \S+ for (?P<cond>invalid user )?(?P<user>(?P<cond2>(?:(?! from ).)*)|.+?) from <HOST>(?: port \d+)?(?: ssh\d*)?(?(cond): |(?:(?(cond2):| from \S+ port \d+ ssh\d*))\s*$)
            ^%(__prefix_line)sROOT LOGIN REFUSED.* FROM <HOST>\s*$
            ^%(__prefix_line)s[iI](?:llegal|nvalid) user .* from <HOST>(?: port \d+)?\s*$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because not listed in AllowUsers\s*$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because listed in DenyUsers\s*$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because not in any group\s*$
            ^%(__prefix_line)srefused connect from \S+ \(<HOST>\)\s*$
            ^%(__prefix_line)sReceived disconnect from <HOST>: 3: .*: Auth fail$
            ^%(__prefix_line)sUser .+ not allowed because shell \S+ does not exist\s*$
            ^%(__prefix_line)sUser .+ not allowed because shell \S+ is not executable\s*$
            ^%(__prefix_line)s(?:error: )?Could not get shadow information for \S+\s*$
            ^%(__prefix_line)smaximum authentication attempts exceeded for .* from <HOST>(?: port \d+)?(?: ssh\d*)?\s*$
            ^%(__prefix_line)spam_unix\(sshd:auth\):\s+authentication failure;\s*logname=\S*\s+uid=\d+\s+euid=\d+\s+tty=\S*\s+ruser=\S*\s+rhost=<HOST>(?:\s+user=.*)?\s*$
            ^%(__prefix_line)sConnection (?:closed|reset) by (?:authenticating|invalid) user .* <HOST> port \d+ \[preauth\]\s*$
            ^%(__prefix_line)sDisconnected from invalid user .* <HOST> port \d+ \[preauth\]\s*$
            ^%(__prefix_line)sDisconnected from user .* <HOST> port \d+\s*$
            ^%(__prefix_line)sDisconnected from authenticating user .* <HOST> port \d+ \[preauth\]\s*$

ignoreregex =
EOF

    log_success "Enhanced SSH filter written."
}

# ---------------------------------------------------------------------------
# _fail2ban_configure_whitelist — Ask user for IPs to never ban
# ---------------------------------------------------------------------------
_fail2ban_configure_whitelist() {
    log_info "Configure IP whitelist (IPs that will never be banned)."
    log_info "Always includes: 127.0.0.1, ::1"
    echo ""

    local extra_ips
    extra_ips="$(ask "Additional IPs/CIDRs to whitelist (space-separated, blank for none)" "")"
    extra_ips="$(trim "$extra_ips")"

    local whitelist="127.0.0.1 127.0.0.0/8 ::1"
    if [[ -n "$extra_ips" ]]; then
        whitelist="${whitelist} ${extra_ips}"
        log_success "Whitelist: ${whitelist}"
    fi

    # Update jail.local with the whitelist
    sed -i "s|^ignoreip = .*|ignoreip = ${whitelist}|" /etc/fail2ban/jail.local
    save_state "fail2ban_whitelist" "${whitelist}"
}

# ---------------------------------------------------------------------------
# _fail2ban_enable — Start and enable fail2ban
# ---------------------------------------------------------------------------
_fail2ban_enable() {
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1

    wait_for_service "fail2ban" 30
}

# ---------------------------------------------------------------------------
# _fail2ban_verify — Confirm jails are active
# ---------------------------------------------------------------------------
_fail2ban_verify() {
    # Give fail2ban a moment to fully initialize
    sleep 3

    log_info "Active Fail2Ban jails:"
    echo ""

    local status_output
    status_output="$(fail2ban-client status 2>/dev/null || echo "fail2ban not responding yet")"

    echo "$status_output" | while IFS= read -r line; do
        printf "  ${CYAN}│${RESET} %s\n" "$line"
    done

    echo ""

    # Check each expected jail
    for jail in sshd recidive; do
        if fail2ban-client status "$jail" &>/dev/null; then
            local banned
            banned="$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")"
            log_success "Jail '${jail}': active (currently banned: ${banned})"
        else
            log_warning "Jail '${jail}': not running (may still be initializing)"
        fi
    done
}
