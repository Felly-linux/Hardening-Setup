#!/usr/bin/env bash
# =============================================================================
# modules/ssh.sh — SSH daemon hardening
# =============================================================================
# THREAT MODEL:
#   Mitigates: Brute-force logins, credential stuffing, MITM via weak ciphers,
#              lateral movement via agent forwarding, root login abuse
#   Attack surface reduced: Authentication attack surface, cipher downgrade
#   Operational impact: Password auth disabled (requires SSH key); port changes
#                       require UFW update and client config update
#   Can break: CI/CD pipelines using password auth; tools using agent forwarding
#   Compatible with: Ubuntu 20.04+, Debian 11+ (OpenSSH 8.x+)
# =============================================================================
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# DANGER: Misconfiguring SSH can permanently lock you out of your server.
# Safety checks: (1) sshd -t validation before apply, (2) confirmation gate
# before restart, (3) key check before disabling password auth.
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
set -euo pipefail

[[ -n "${_MODULE_SSH_LOADED:-}" ]] && return 0
readonly _MODULE_SSH_LOADED=1

if [[ -z "${_VPS_HARDENING_COMMON_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "${SCRIPT_DIR}/../lib/common.sh"
fi

# =============================================================================
# Profile variables with safe defaults
# =============================================================================
SSH_PORT="${SSH_PORT:-22}"
SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN:-no}"
SSH_PASSWORD_AUTH="${SSH_PASSWORD_AUTH:-no}"
SSH_MAX_AUTH_TRIES="${SSH_MAX_AUTH_TRIES:-3}"
SSH_MAX_SESSIONS="${SSH_MAX_SESSIONS:-3}"
SSH_ALLOW_TCP_FORWARDING="${SSH_ALLOW_TCP_FORWARDING:-no}"
SSH_ALLOW_AGENT_FORWARDING="${SSH_ALLOW_AGENT_FORWARDING:-no}"

# ---------------------------------------------------------------------------
# run_ssh — Main entry point
# ---------------------------------------------------------------------------
run_ssh() {
    log_section "SSH HARDENING"

    printf "\n${RED}${BOLD}  ╔══════════════════════════════════════════════════════════════╗${RESET}\n"
    printf "${RED}${BOLD}  ║  WARNING: SSH misconfiguration can lock you out permanently!  ║${RESET}\n"
    printf "${RED}${BOLD}  ║  Make sure you have an out-of-band access method ready!       ║${RESET}\n"
    printf "${RED}${BOLD}  ╚══════════════════════════════════════════════════════════════╝${RESET}\n\n"

    if [[ "${NONINTERACTIVE:-0}" != "1" ]]; then
        if ! confirm "Continue with SSH hardening?"; then
            log_info "SSH hardening skipped by user."
            return 0
        fi
    fi

    log_step 1 8 "Selecting SSH port"
    local ssh_port
    ssh_port="$(_ssh_choose_port)"
    save_state "ssh_port" "$ssh_port"

    log_step 2 8 "Backing up original sshd_config"
    [[ "${DRY_RUN:-0}" != "1" ]] && backup_file "/etc/ssh/sshd_config"

    log_step 3 8 "Generating hardened sshd_config"
    _ssh_write_config "$ssh_port"

    log_step 4 8 "Validating SSH configuration"
    [[ "${DRY_RUN:-0}" != "1" ]] && _ssh_validate_config

    log_step 5 8 "Installing SSH login banner"
    [[ "${DRY_RUN:-0}" != "1" ]] && _ssh_install_banner

    log_step 6 8 "Regenerating host keys (if needed)"
    [[ "${DRY_RUN:-0}" != "1" ]] && _ssh_harden_host_keys

    log_step 7 8 "Safety confirmation"
    [[ "${DRY_RUN:-0}" != "1" ]] && _ssh_safety_confirmation "$ssh_port"

    log_step 8 8 "Restarting SSH daemon"
    _ssh_restart

    log_success "SSH hardening complete. New port: ${ssh_port}"
    save_state "ssh_hardened" "yes"

    printf "\n${GREEN}${BOLD}  SSH service restarted successfully on port ${ssh_port}.${RESET}\n"
    printf "  Connect with: ${CYAN}ssh -p ${ssh_port} $(get_state "admin_user" 2>/dev/null || echo "user")@$(get_state "server_ip" 2>/dev/null || hostname -I | awk '{print $1}')${RESET}\n\n"
}

# ---------------------------------------------------------------------------
# _ssh_choose_port — Use profile SSH_PORT or prompt
# ---------------------------------------------------------------------------
_ssh_choose_port() {
    local port

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        port="${SSH_PORT}"
        log_info "Using profile SSH port: ${port}"
        echo "$port"
        return 0
    fi

    local default_port="${SSH_PORT}"

    while true; do
        port="$(ask "SSH port" "$default_port")"
        port="$(trim "$port")"

        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            log_warning "Port must be a number."
            continue
        fi

        if (( port < 1 || port > 65535 )); then
            log_warning "Port must be between 1 and 65535."
            continue
        fi

        if (( port < 1024 )); then
            log_warning "Using a privileged port (< 1024). Ensure sshd can bind to it."
        fi

        if port_in_use "$port"; then
            local owner
            owner="$(ss -tlnp 2>/dev/null | awk -v p=":${port}" '$0 ~ p {print $NF}' | head -1 || echo "unknown")"
            if echo "$owner" | grep -qi "sshd"; then
                log_info "Port ${port} is already used by sshd — reconfiguring."
                break
            else
                log_warning "Port ${port} is in use by: ${owner}"
                if confirm "Use this port anyway?"; then
                    break
                fi
            fi
        else
            break
        fi
    done

    echo "$port"
}

# ---------------------------------------------------------------------------
# _ssh_write_config — Generate /etc/ssh/sshd_config using profile vars
# ---------------------------------------------------------------------------
_ssh_write_config() {
    local port="$1"

    # Password auth: profile default, but override if no SSH key configured
    local password_auth_line
    local ssh_key_set
    ssh_key_set="$(get_state "admin_ssh_key_set" 2>/dev/null || echo "no")"

    if [[ "${SSH_PASSWORD_AUTH}" == "yes" ]]; then
        password_auth_line="PasswordAuthentication yes"
        save_state "ssh_password_auth" "yes"
        log_info "Profile: password authentication enabled."
    elif [[ "$ssh_key_set" == "yes" ]]; then
        password_auth_line="PasswordAuthentication no"
        save_state "ssh_password_auth" "no"
        log_info "SSH key detected → disabling password authentication."
    else
        password_auth_line="PasswordAuthentication yes"
        save_state "ssh_password_auth" "yes"
        log_warning "No SSH key detected → keeping password authentication enabled."
        log_warning "Run the users module first and add an SSH key to disable password auth."
    fi

    # TCP forwarding — profile controlled; interactive only if not set
    local tcp_forwarding="${SSH_ALLOW_TCP_FORWARDING}"
    local agent_forwarding="${SSH_ALLOW_AGENT_FORWARDING}"

    if [[ "${NONINTERACTIVE:-0}" != "1" && "${SSH_ALLOW_TCP_FORWARDING}" == "no" ]]; then
        if confirm "Allow TCP forwarding? (needed for tunnels/port forwarding)" "n"; then
            tcp_forwarding="yes"
        fi
    fi

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would write /etc/ssh/sshd_config (port=${port}, PasswordAuth=${password_auth_line##* }, TCPFwd=${tcp_forwarding})"
        return 0
    fi

    cat > /etc/ssh/sshd_config << EOF
# =============================================================================
# /etc/ssh/sshd_config — Hardened by VPS Hardening Suite
# Generated: $(date --iso-8601=seconds)
# Profile: ${PROFILE_NAME:-manual}
# DO NOT EDIT MANUALLY — re-run the hardening suite to make changes
# =============================================================================

Port ${port}
AddressFamily any

# Authentication
PermitRootLogin ${SSH_PERMIT_ROOT_LOGIN}
${password_auth_line}
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
IgnoreRhosts yes
HostbasedAuthentication no
KbdInteractiveAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes
MaxAuthTries ${SSH_MAX_AUTH_TRIES}
MaxStartups 10:30:60

# Session limits
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions ${SSH_MAX_SESSIONS}

# Forwarding (hardened)
AllowAgentForwarding ${agent_forwarding}
AllowTcpForwarding ${tcp_forwarding}
X11Forwarding no
PermitTunnel no
GatewayPorts no

# Environment
PermitUserEnvironment no
PermitUserRC no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE
PrintLastLog yes

# Banner
Banner /etc/ssh/banner

# Cryptographic algorithms (strong modern only)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Host keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
StrictModes yes
EOF

    log_success "New sshd_config written for port ${port}."
}

# ---------------------------------------------------------------------------
# _ssh_validate_config — Run sshd -t before applying
# ---------------------------------------------------------------------------
_ssh_validate_config() {
    log_info "Validating /etc/ssh/sshd_config with 'sshd -t'..."
    local validation_output
    if validation_output="$(sshd -t 2>&1)"; then
        log_success "sshd config validation: PASSED"
    else
        log_error "sshd config validation: FAILED"
        echo "$validation_output" | while IFS= read -r line; do
            printf "  ${RED}│${RESET} %s\n" "$line"
        done
        log_warning "Restoring original sshd_config from backup..."
        local latest_backup
        latest_backup="$(find "$BACKUP_DIR" -name 'sshd_config*.bak' | sort | tail -1)"
        if [[ -n "$latest_backup" && -f "$latest_backup" ]]; then
            cp "$latest_backup" /etc/ssh/sshd_config
            log_success "Original sshd_config restored."
        fi
        return 1
    fi
}

# ---------------------------------------------------------------------------
# _ssh_install_banner
# ---------------------------------------------------------------------------
_ssh_install_banner() {
    local banner_src="${PROJECT_ROOT}/configs/sshd/banner"
    local banner_dest="/etc/ssh/banner"

    if [[ -f "$banner_src" ]]; then
        cp "$banner_src" "$banner_dest"
        log_success "SSH banner installed from: ${banner_src}"
    else
        cat > "$banner_dest" << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║                    *** AUTHORIZED ACCESS ONLY ***                    ║
║                                                                      ║
║  This system is the property of the organization. Unauthorized       ║
║  access or use is strictly prohibited and may be subject to civil    ║
║  and criminal penalties.                                             ║
║                                                                      ║
║  All connections are monitored and logged. By continuing you         ║
║  consent to monitoring of your session.                              ║
║                                                                      ║
║  Disconnect IMMEDIATELY if you are not an authorized user.           ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
        log_success "Default SSH banner installed."
    fi
}

# ---------------------------------------------------------------------------
# _ssh_harden_host_keys — Remove weak keys, ensure ed25519 + RSA-4096
# ---------------------------------------------------------------------------
_ssh_harden_host_keys() {
    for weak_key in /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub \
                    /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_ecdsa_key.pub; do
        if [[ -f "$weak_key" ]]; then
            rm -f "$weak_key"
            log_info "Removed weak host key: ${weak_key}"
        fi
    done

    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
        log_success "Generated new ed25519 host key."
    fi

    if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
        ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
        log_success "Generated new RSA-4096 host key."
    else
        local rsa_bits
        rsa_bits="$(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key 2>/dev/null | awk '{print $1}' || echo "0")"
        if (( rsa_bits < 4096 )); then
            log_warning "RSA host key is ${rsa_bits} bits. Regenerating at 4096."
            ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
        fi
    fi

    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
    chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

    if [[ -f /etc/ssh/moduli ]]; then
        awk '$5 >= 3071' /etc/ssh/moduli > /tmp/moduli.filtered
        if [[ -s /tmp/moduli.filtered ]]; then
            mv /tmp/moduli.filtered /etc/ssh/moduli
            log_success "Removed weak Diffie-Hellman moduli (< 3072 bits)."
        else
            rm /tmp/moduli.filtered
        fi
    fi
}

# ---------------------------------------------------------------------------
# _ssh_safety_confirmation — Gate before restart
# ---------------------------------------------------------------------------
_ssh_safety_confirmation() {
    local new_port="$1"
    local server_ip
    server_ip="$(get_state "server_ip" 2>/dev/null || hostname -I | awk '{print $1}')"
    local admin_user
    admin_user="$(get_state "admin_user" 2>/dev/null || echo "admin")"

    printf "\n"
    printf "${YELLOW}${BOLD}  ╔══════════════════════════════════════════════════════════════════════╗\n"
    printf "  ║  CRITICAL: DO NOT RESTART SSH WITHOUT TESTING FIRST              ║\n"
    printf "  ╠══════════════════════════════════════════════════════════════════════╣\n"
    printf "  ║  1. Open a NEW terminal window.                                    ║\n"
    printf "  ║  2. Connect: ssh -p %d -i ~/.ssh/id_ed25519 %s@%s\n" \
           "$new_port" "$admin_user" "$server_ip"
    printf "  ║  3. If login succeeds, return here and press Enter.                ║\n"
    printf "  ║  4. If it FAILS, type 'n' to abort and restore old config.         ║\n"
    printf "  ╚══════════════════════════════════════════════════════════════════════╝${RESET}\n\n"

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        log_warning "Non-interactive mode: skipping SSH test confirmation."
        return 0
    fi

    if ! confirm "Have you successfully tested the new SSH connection on port ${new_port}?"; then
        log_warning "SSH restart aborted by user. Restoring original sshd_config..."
        local latest_backup
        latest_backup="$(find "$BACKUP_DIR" -name 'sshd_config*.bak' | sort | tail -1)"
        if [[ -n "$latest_backup" && -f "$latest_backup" ]]; then
            cp "$latest_backup" /etc/ssh/sshd_config
            log_success "Original sshd_config restored."
        fi
        save_state "ssh_hardened" "aborted"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# _ssh_restart — Reload (graceful) or restart sshd
# ---------------------------------------------------------------------------
_ssh_restart() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would reload/restart SSH service."
        return 0
    fi

    local ssh_service
    if systemctl cat ssh.service &>/dev/null 2>&1; then
        ssh_service="ssh"
    elif systemctl cat sshd.service &>/dev/null 2>&1; then
        ssh_service="sshd"
    else
        ssh_service="ssh"
    fi

    log_info "Restarting SSH service: ${ssh_service}"
    if systemctl reload "$ssh_service" >> "$LOG_FILE" 2>&1; then
        log_success "SSH service reloaded gracefully."
    else
        systemctl restart "$ssh_service" >> "$LOG_FILE" 2>&1
        log_success "SSH service restarted."
    fi

    wait_for_service "$ssh_service" 15
}
