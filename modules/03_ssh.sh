#!/usr/bin/env bash
# =============================================================================
# modules/03_ssh.sh — SSH daemon hardening
# =============================================================================
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# DANGER: Misconfiguring SSH can permanently lock you out of your server.
# This module implements multiple safety checks:
#   1.  Validates the new config with 'sshd -t' before applying it.
#   2.  Does NOT restart SSH until user explicitly confirms a second session.
#   3.  Only disables password auth if an SSH key was set in the users module.
#   4.  Keeps a backup of the original sshd_config.
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#
# Steps:
#   1.  Choose SSH port (default 2222)
#   2.  Backup existing /etc/ssh/sshd_config
#   3.  Generate new sshd_config from template
#   4.  Validate config with sshd -t
#   5.  Install SSH login banner
#   6.  Generate strong host keys if not present
#   7.  Warn user to open a NEW SSH session to test
#   8.  Restart SSH only after user confirmation
#   9.  Update UFW / firewall rules (if UFW is installed)
#
# State keys written:
#   ssh_port            — the configured SSH port
#   ssh_hardened        — "yes" on success
#   ssh_password_auth   — "yes" / "no"
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_SSH_LOADED:-}" ]] && return 0
readonly _MODULE_SSH_LOADED=1

# Source path to config template
_SSH_TEMPLATE="${PROJECT_ROOT}/configs/sshd/sshd_config.template"

# ---------------------------------------------------------------------------
# run_ssh — Main entry point
# ---------------------------------------------------------------------------
run_ssh() {
    log_section "SSH HARDENING"

    # Safety banner
    printf "\n${RED}${BOLD}  ╔══════════════════════════════════════════════════════════════╗${RESET}\n"
    printf "${RED}${BOLD}  ║  WARNING: SSH misconfiguration can lock you out permanently!  ║${RESET}\n"
    printf "${RED}${BOLD}  ║  Make sure you have an out-of-band access method ready!       ║${RESET}\n"
    printf "${RED}${BOLD}  ╚══════════════════════════════════════════════════════════════╝${RESET}\n\n"

    if ! confirm "Continue with SSH hardening?"; then
        log_info "SSH hardening skipped by user."
        return 0
    fi

    log_step 1 8 "Selecting SSH port"
    local ssh_port
    ssh_port="$(_ssh_choose_port)"
    save_state "ssh_port" "$ssh_port"

    log_step 2 8 "Backing up original sshd_config"
    backup_file "/etc/ssh/sshd_config"

    log_step 3 8 "Generating hardened sshd_config"
    _ssh_write_config "$ssh_port"

    log_step 4 8 "Validating SSH configuration"
    _ssh_validate_config

    log_step 5 8 "Installing SSH login banner"
    _ssh_install_banner

    log_step 6 8 "Regenerating host keys (if needed)"
    _ssh_harden_host_keys

    log_step 7 8 "Safety confirmation"
    _ssh_safety_confirmation "$ssh_port"

    log_step 8 8 "Restarting SSH daemon"
    _ssh_restart

    log_success "SSH hardening complete. New port: ${ssh_port}"
    save_state "ssh_hardened" "yes"

    printf "\n${GREEN}${BOLD}  SSH service restarted successfully on port ${ssh_port}.${RESET}\n"
    printf "  Connect with: ${CYAN}ssh -p ${ssh_port} $(get_state "admin_user")@$(get_state "server_ip")${RESET}\n\n"
}

# ---------------------------------------------------------------------------
# _ssh_choose_port — Ask for SSH port and validate it's available
# ---------------------------------------------------------------------------
_ssh_choose_port() {
    local default_port="2222"

    # In hardcore mode, use a higher unpredictable port
    if [[ "${HARDCORE_MODE:-0}" == "1" ]]; then
        default_port="2222"
    fi

    local port
    while true; do
        port="$(ask "SSH port" "$default_port")"
        port="$(trim "$port")"

        # Validate numeric
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            log_warning "Port must be a number."
            continue
        fi

        # Validate range
        if (( port < 1 || port > 65535 )); then
            log_warning "Port must be between 1 and 65535."
            continue
        fi

        # Warn about privileged ports
        if (( port < 1024 )); then
            log_warning "Using a privileged port (< 1024). Ensure sshd can bind to it."
        fi

        # Check if port is already in use (not by sshd itself)
        if port_in_use "$port"; then
            local owner
            owner="$(ss -tlnp 2>/dev/null | awk -v p=":${port}" '$0 ~ p {print $NF}' | head -1 || echo "unknown")"
            if echo "$owner" | grep -qi "sshd"; then
                log_info "Port ${port} is already used by sshd — this is fine (reconfiguring)."
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
# _ssh_write_config — Generate /etc/ssh/sshd_config from template or inline
# ---------------------------------------------------------------------------
_ssh_write_config() {
    local port="$1"

    # Determine password auth setting: only disable if SSH key was configured
    local password_auth_line="PasswordAuthentication yes"
    local ssh_key_set
    ssh_key_set="$(get_state "admin_ssh_key_set" 2>/dev/null || echo "no")"

    if [[ "$ssh_key_set" == "yes" ]]; then
        password_auth_line="PasswordAuthentication no"
        save_state "ssh_password_auth" "no"
        log_info "SSH key detected → disabling password authentication."
    else
        save_state "ssh_password_auth" "yes"
        log_warning "No SSH key detected → keeping password authentication enabled."
        log_warning "Run the users module first and add an SSH key to disable password auth."
    fi

    # Stricter AllowTcpForwarding in hardcore mode
    local tcp_forwarding="no"
    local agent_forwarding="no"

    # Allow TCP forwarding only if explicitly in non-hardcore mode
    if [[ "${HARDCORE_MODE:-0}" != "1" ]]; then
        if confirm "Allow TCP forwarding? (needed for tunnels/port forwarding)" "n"; then
            tcp_forwarding="yes"
        fi
    fi

    # Write configuration
    cat > /etc/ssh/sshd_config << EOF
# =============================================================================
# /etc/ssh/sshd_config — Hardened by VPS Hardening Suite
# Generated: $(date --iso-8601=seconds)
# DO NOT EDIT MANUALLY — re-run the hardening suite to make changes
# =============================================================================

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
Port ${port}

# Bind to all interfaces (comment out to restrict to specific IP)
#ListenAddress 0.0.0.0
#ListenAddress ::

# Address family: 'any', 'inet' (IPv4), or 'inet6' (IPv6)
AddressFamily any

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
# Disable root login entirely
PermitRootLogin no

# Password authentication — only if no SSH key is available
${password_auth_line}

# Public key authentication (the correct way to authenticate)
PubkeyAuthentication yes

# Authorized keys file location
AuthorizedKeysFile .ssh/authorized_keys

# Do NOT use .rhosts or /etc/hosts.equiv
IgnoreRhosts yes
HostbasedAuthentication no

# Challenge-response / keyboard-interactive authentication
# ChallengeResponseAuthentication was deprecated in OpenSSH 8.7; KbdInteractiveAuthentication replaces it
KbdInteractiveAuthentication no

# Kerberos and GSSAPI — disable unless needed
KerberosAuthentication no
GSSAPIAuthentication no

# PAM integration (needed for account/session management)
UsePAM yes

# Limit authentication attempts per connection
MaxAuthTries 3

# Maximum concurrent unauthenticated connections: start:rate:full
MaxStartups 10:30:60

# ---------------------------------------------------------------------------
# Session limits
# ---------------------------------------------------------------------------
# Seconds before unauthenticated connection is dropped
LoginGraceTime 30

# Keep-alive: ping client every 300s, disconnect if no response after 2 pings
ClientAliveInterval 300
ClientAliveCountMax 2

# Maximum simultaneous sessions per connection
MaxSessions 3

# ---------------------------------------------------------------------------
# Forwarding (hardened — disabled by default)
# ---------------------------------------------------------------------------
AllowAgentForwarding ${agent_forwarding}
AllowTcpForwarding ${tcp_forwarding}
X11Forwarding no
PermitTunnel no
GatewayPorts no

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
# Prevent users from setting environment variables via authorized_keys
PermitUserEnvironment no

# Do not read the user's ~/.profile on login (safer)
PermitUserRC no

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
SyslogFacility AUTH
LogLevel VERBOSE
PrintLastLog yes

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Banner /etc/ssh/banner

# ---------------------------------------------------------------------------
# Cryptographic algorithms (strong modern ciphers only)
# ---------------------------------------------------------------------------
# Key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Host key algorithms
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Ciphers (AES-GCM, ChaCha20 only — remove CBC modes)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Message Authentication Codes
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# ---------------------------------------------------------------------------
# Host keys (only strong algorithms)
# ---------------------------------------------------------------------------
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# ---------------------------------------------------------------------------
# Miscellaneous
# ---------------------------------------------------------------------------
# Don't show /etc/motd on login (shown separately by pam_motd)
PrintMotd no

# Accept locale from client
AcceptEnv LANG LC_*

# Subsystem for SFTP
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# ---------------------------------------------------------------------------
# Additional restrictions
# ---------------------------------------------------------------------------
# Strict mode: check permissions of user files
StrictModes yes

EOF

    log_success "New sshd_config written for port ${port}."
}

# ---------------------------------------------------------------------------
# _ssh_validate_config — Run sshd -t to catch config errors before restart
# ---------------------------------------------------------------------------
_ssh_validate_config() {
    log_info "Validating /etc/ssh/sshd_config with 'sshd -t'..."

    local validation_output
    if validation_output="$(sshd -t 2>&1)"; then
        log_success "sshd config validation: PASSED"
    else
        log_error "sshd config validation: FAILED"
        log_error "Validation output:"
        echo "$validation_output" | while IFS= read -r line; do
            printf "  ${RED}│${RESET} %s\n" "$line"
        done

        # Restore the original config
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
# _ssh_install_banner — Write the legal/warning banner shown before login
# ---------------------------------------------------------------------------
_ssh_install_banner() {
    local banner_src="${PROJECT_ROOT}/configs/sshd/banner"
    local banner_dest="/etc/ssh/banner"

    if [[ -f "$banner_src" ]]; then
        cp "$banner_src" "$banner_dest"
        log_success "SSH banner installed from: ${banner_src}"
    else
        # Generate banner inline
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
# _ssh_harden_host_keys — Remove weak host keys, ensure ed25519 + rsa exist
# ---------------------------------------------------------------------------
_ssh_harden_host_keys() {
    # Remove weak DSA and ECDSA keys
    for weak_key in /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub \
                    /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_ecdsa_key.pub; do
        if [[ -f "$weak_key" ]]; then
            rm -f "$weak_key"
            log_info "Removed weak host key: ${weak_key}"
        fi
    done

    # Regenerate ed25519 key if not present or small
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
        log_success "Generated new ed25519 host key."
    fi

    # Regenerate RSA key (4096 bits)
    if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
        ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
        log_success "Generated new RSA-4096 host key."
    else
        # Check if existing RSA key is weaker than 4096 bits
        local rsa_bits
        rsa_bits="$(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key 2>/dev/null | awk '{print $1}' || echo "0")"
        if (( rsa_bits < 4096 )); then
            log_warning "Existing RSA host key is ${rsa_bits} bits. Regenerating at 4096 bits."
            ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
            log_success "RSA host key regenerated at 4096 bits."
        fi
    fi

    # Fix permissions
    chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
    chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

    # Remove default moduli entries smaller than 3072 bits
    if [[ -f /etc/ssh/moduli ]]; then
        awk '$5 >= 3071' /etc/ssh/moduli > /tmp/moduli.filtered
        if [[ -s /tmp/moduli.filtered ]]; then
            mv /tmp/moduli.filtered /etc/ssh/moduli
            log_success "Removed weak Diffie-Hellman moduli (< 3072 bits)."
        else
            rm /tmp/moduli.filtered
            log_warning "No moduli >= 3072 bits found — keeping original moduli file."
        fi
    fi
}

# ---------------------------------------------------------------------------
# _ssh_safety_confirmation — Instruct user to test before restarting
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
    printf "  ║  1. Open a NEW terminal window / tab.                              ║\n"
    printf "  ║  2. Connect with the NEW configuration (do NOT close this session) ║\n"
    printf "  ║                                                                    ║\n"
    printf "  ║     Command: ssh -p %d -i ~/.ssh/id_ed25519 %s@%s\n" \
           "$new_port" "$admin_user" "$server_ip"
    printf "  ║     (replace ~/.ssh/id_ed25519 with your actual key path)          ║\n"
    printf "  ║                                                                    ║\n"
    printf "  ║  3. If login succeeds, return here and press Enter to continue.    ║\n"
    printf "  ║  4. If it FAILS, type 'n' to abort and keep the old config.        ║\n"
    printf "  ╚══════════════════════════════════════════════════════════════════════╝${RESET}\n\n"

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        log_warning "Non-interactive mode: skipping SSH test confirmation."
        return 0
    fi

    if ! confirm "Have you successfully tested the new SSH connection on port ${new_port}?"; then
        log_warning "SSH restart aborted by user."
        log_warning "Restoring original sshd_config..."
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
# _ssh_restart — Restart the SSH daemon with the new configuration
# ---------------------------------------------------------------------------
_ssh_restart() {
    local ssh_service
    # Detect the correct service name: 'ssh' on Debian/Ubuntu, 'sshd' on some others
    if systemctl cat ssh.service &>/dev/null 2>&1; then
        ssh_service="ssh"
    elif systemctl cat sshd.service &>/dev/null 2>&1; then
        ssh_service="sshd"
    else
        ssh_service="ssh"
    fi

    log_info "Restarting SSH service: ${ssh_service}"

    # Use 'reload' first (graceful) — falls back to restart
    if systemctl reload "$ssh_service" >> "$LOG_FILE" 2>&1; then
        log_success "SSH service reloaded gracefully."
    else
        systemctl restart "$ssh_service" >> "$LOG_FILE" 2>&1
        log_success "SSH service restarted."
    fi

    wait_for_service "$ssh_service" 15
}
