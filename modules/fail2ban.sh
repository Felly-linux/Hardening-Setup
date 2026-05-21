#!/usr/bin/env bash
# =============================================================================
# modules/fail2ban.sh — Fail2Ban intrusion prevention
# =============================================================================
# THREAT MODEL:
#   Mitigates: SSH brute force, credential stuffing, web auth brute force,
#              persistent attackers (recidive jail), nginx bots/scanners
#   Attack surface reduced: Authentication endpoints; blocks IPs at iptables
#                           after threshold violations
#   Operational impact: Legitimate users locked out after too many failed
#                       attempts; whitelist your management IPs
#   Can break: Monitoring systems that poll SSH; automated login tools
#   Note: Operates alongside CrowdSec (defense in depth — each bans
#         independently; both lists are authoritative)
#   Compatible with: Ubuntu 20.04+, Debian 11+
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_FAIL2BAN_LOADED:-}" ]] && return 0
readonly _MODULE_FAIL2BAN_LOADED=1

if [[ -z "${_VPS_HARDENING_COMMON_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "${SCRIPT_DIR}/../lib/common.sh"
fi

# =============================================================================
# Profile variables with safe defaults
# =============================================================================
FAIL2BAN_SSH_MAXRETRY="${FAIL2BAN_SSH_MAXRETRY:-3}"
FAIL2BAN_SSH_BANTIME="${FAIL2BAN_SSH_BANTIME:-7200}"
FAIL2BAN_SSH_FINDTIME="${FAIL2BAN_SSH_FINDTIME:-300}"
FAIL2BAN_WHITELIST_IPS="${FAIL2BAN_WHITELIST_IPS:-}"

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
# _fail2ban_install
# ---------------------------------------------------------------------------
_fail2ban_install() {
    if package_installed fail2ban; then
        log_info "Fail2Ban already installed."
        return 0
    fi
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would install fail2ban + python3-systemd."
        return 0
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        fail2ban python3-systemd >> "$LOG_FILE" 2>&1
    log_success "Fail2Ban installed."
}

# ---------------------------------------------------------------------------
# _fail2ban_backup
# ---------------------------------------------------------------------------
_fail2ban_backup() {
    [[ "${DRY_RUN:-0}" == "1" ]] && return 0
    local conf_files=("/etc/fail2ban/jail.local" "/etc/fail2ban/jail.conf")
    for f in "${conf_files[@]}"; do
        [[ -f "$f" ]] && backup_file "$f" || true
    done
}

# ---------------------------------------------------------------------------
# _fail2ban_write_config — Generate jail.local using profile vars
# ---------------------------------------------------------------------------
_fail2ban_write_config() {
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "${SSH_PORT:-22}")"

    local whitelist="127.0.0.1 127.0.0.0/8 ::1"
    if [[ -n "${FAIL2BAN_WHITELIST_IPS}" ]]; then
        whitelist="${whitelist} ${FAIL2BAN_WHITELIST_IPS}"
    fi

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would write /etc/fail2ban/jail.local (SSH port=${ssh_port}, maxretry=${FAIL2BAN_SSH_MAXRETRY}, bantime=${FAIL2BAN_SSH_BANTIME}s)."
        return 0
    fi

    local nginx_enabled="false"
    if command_exists nginx || package_installed nginx; then
        nginx_enabled="true"
        log_info "Nginx detected — enabling nginx jails."
    fi

    cat > /etc/fail2ban/jail.local << EOF
# =============================================================================
# /etc/fail2ban/jail.local — VPS Hardening Suite
# Generated: $(date --iso-8601=seconds)
# Profile: ${PROFILE_NAME:-manual}
# =============================================================================

[DEFAULT]
ignoreip = ${whitelist}
bantime  = 3600
findtime = 600
maxretry = 5
backend = systemd
banaction = iptables-multiport
banaction_allports = iptables-allports
usedns = warn
encoding = UTF-8
enabled = false

[sshd]
enabled  = true
port     = ${ssh_port}
protocol = tcp
filter   = sshd
backend  = systemd
maxretry = ${FAIL2BAN_SSH_MAXRETRY}
bantime  = ${FAIL2BAN_SSH_BANTIME}
findtime = ${FAIL2BAN_SSH_FINDTIME}

[recidive]
enabled   = true
filter    = recidive
logpath   = /var/log/fail2ban.log
maxretry  = 3
findtime  = 43200
bantime   = 604800

EOF

    if [[ "$nginx_enabled" == "true" ]]; then
        cat >> /etc/fail2ban/jail.local << 'NGINX_JAILS'
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

    log_success "jail.local written (SSH port ${ssh_port}, maxretry ${FAIL2BAN_SSH_MAXRETRY}, bantime ${FAIL2BAN_SSH_BANTIME}s)."
    _fail2ban_write_custom_filter
}

# ---------------------------------------------------------------------------
# _fail2ban_write_custom_filter — Enhanced SSH pattern matching
# ---------------------------------------------------------------------------
_fail2ban_write_custom_filter() {
    local filter_file="/etc/fail2ban/filter.d/sshd-enhanced.conf"
    [[ -f "$filter_file" ]] && { log_info "Custom sshd filter already exists."; return 0; }

    cat > "$filter_file" << 'EOF'
# /etc/fail2ban/filter.d/sshd-enhanced.conf — VPS Hardening Suite

[INCLUDES]
before = common.conf

[Definition]
_daemon = sshd

failregex = ^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error|failed) for .* from <HOST>( via \S+)?\s*$
            ^%(__prefix_line)sFailed \S+ for (?P<cond>invalid user )?(?P<user>(?P<cond2>(?:(?! from ).)*)|.+?) from <HOST>(?: port \d+)?(?: ssh\d*)?(?(cond): |(?:(?(cond2):| from \S+ port \d+ ssh\d*))\s*$)
            ^%(__prefix_line)sROOT LOGIN REFUSED.* FROM <HOST>\s*$
            ^%(__prefix_line)s[iI](?:llegal|nvalid) user .* from <HOST>(?: port \d+)?\s*$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because not listed in AllowUsers\s*$
            ^%(__prefix_line)smaximum authentication attempts exceeded for .* from <HOST>(?: port \d+)?(?: ssh\d*)?\s*$
            ^%(__prefix_line)spam_unix\(sshd:auth\):\s+authentication failure;\s*logname=\S*\s+uid=\d+\s+euid=\d+\s+tty=\S*\s+ruser=\S*\s+rhost=<HOST>(?:\s+user=.*)?\s*$
            ^%(__prefix_line)sDisconnected from (?:invalid|authenticating) user .* <HOST> port \d+ \[preauth\]\s*$

ignoreregex =
EOF

    log_success "Enhanced SSH filter written."
}

# ---------------------------------------------------------------------------
# _fail2ban_configure_whitelist — Apply FAIL2BAN_WHITELIST_IPS or prompt
# ---------------------------------------------------------------------------
_fail2ban_configure_whitelist() {
    [[ "${DRY_RUN:-0}" == "1" ]] && return 0

    local whitelist="127.0.0.1 127.0.0.0/8 ::1"

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        if [[ -n "${FAIL2BAN_WHITELIST_IPS}" ]]; then
            whitelist="${whitelist} ${FAIL2BAN_WHITELIST_IPS}"
        fi
    else
        log_info "Configure IP whitelist (IPs that will never be banned)."
        log_info "Always includes: 127.0.0.1, ::1"
        local extra_ips
        extra_ips="$(ask "Additional IPs/CIDRs to whitelist (space-separated, blank for none)" "${FAIL2BAN_WHITELIST_IPS:-}")"
        extra_ips="$(trim "$extra_ips")"
        [[ -n "$extra_ips" ]] && whitelist="${whitelist} ${extra_ips}"
    fi

    sed -i "s|^ignoreip = .*|ignoreip = ${whitelist}|" /etc/fail2ban/jail.local
    save_state "fail2ban_whitelist" "${whitelist}"
    log_success "Whitelist configured: ${whitelist}"
}

# ---------------------------------------------------------------------------
# _fail2ban_enable
# ---------------------------------------------------------------------------
_fail2ban_enable() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would enable + restart fail2ban."
        return 0
    fi
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    wait_for_service "fail2ban" 30
}

# ---------------------------------------------------------------------------
# _fail2ban_verify
# ---------------------------------------------------------------------------
_fail2ban_verify() {
    [[ "${DRY_RUN:-0}" == "1" ]] && return 0
    sleep 3

    log_info "Active Fail2Ban jails:"
    fail2ban-client status 2>/dev/null | while IFS= read -r line; do
        printf "  ${CYAN}│${RESET} %s\n" "$line"
    done
    echo ""

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
