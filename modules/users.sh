#!/usr/bin/env bash
# =============================================================================
# modules/users.sh — User management & password policy
# =============================================================================
# Creates an admin user with strong credentials, configures sudo access,
# installs SSH keys, and enforces a PAM password policy.
#
# Steps:
#   1.  Ask for admin username (default: admin)
#   2.  Create user if not existing
#   3.  Add user to sudo group
#   4.  Ask for SSH public key → add to authorized_keys
#   5.  Set strong password policy in PAM
#   6.  Optional: configure passwordless sudo
#   7.  Disable root password login
#   8.  Set secure umask
#
# State keys written:
#   admin_user          — the configured admin username
#   admin_ssh_key_set   — "yes" if an SSH key was configured
#   sudo_nopasswd       — "yes" if passwordless sudo was configured
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_USERS_LOADED:-}" ]] && return 0
readonly _MODULE_USERS_LOADED=1

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
# run_users — Main entry point
# ---------------------------------------------------------------------------
run_users() {
    log_section "USER MANAGEMENT"

    log_step 1 7 "Configuring admin user"
    local admin_user
    admin_user="$(_users_create_admin)"
    if [[ "${DRY_RUN}" != "1" ]]; then
        save_state "admin_user" "$admin_user"
    fi

    log_step 2 7 "Configuring SSH public key authentication"
    _users_configure_ssh_key "$admin_user"

    log_step 3 7 "Applying PAM password policy"
    _users_set_password_policy

    log_step 4 7 "Configuring sudo access"
    _users_configure_sudo "$admin_user"

    log_step 5 7 "Disabling root password login"
    _users_disable_root_password

    log_step 6 7 "Setting secure umask system-wide"
    _users_set_umask

    log_step 7 7 "Configuring login security limits"
    _users_login_security

    log_success "User management complete. Admin user: ${admin_user}"

    printf "\n${YELLOW}${BOLD}  IMPORTANT:${RESET}${YELLOW} Make sure you have tested SSH key login as '${admin_user}'\n"
    printf "  before the SSH module disables password authentication!${RESET}\n\n"

    mark_module_complete "users"
}

# ---------------------------------------------------------------------------
# _users_create_admin — Create or verify the admin user. Returns username.
# ---------------------------------------------------------------------------
_users_create_admin() {
    local default_user="admin"
    local username
    username="$(ask "Admin username" "$default_user")"
    username="$(trim "$username")"

    # Validate: no spaces, no special chars
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{1,31}$ ]]; then
        log_warning "Invalid username '${username}'. Using '${default_user}' instead."
        username="$default_user"
    fi

    if id "$username" &>/dev/null; then
        log_info "User '${username}' already exists."
    else
        log_info "Creating user '${username}'..."
        if [[ "${DRY_RUN}" == "1" ]]; then
            log_info "[DRY-RUN] Would create user '${username}' with home directory and bash shell"
        else
            # Create user with home directory, bash shell, no password initially
            useradd -m -s /bin/bash -c "VPS Admin (created by hardening suite)" "$username"
            log_success "User '${username}' created."

            # Set a password interactively
            log_info "Set a strong password for '${username}':"
            passwd "$username"
        fi
    fi

    # Ensure the user is in the sudo group
    if id "$username" &>/dev/null && ! groups "$username" | grep -qw sudo; then
        if [[ "${DRY_RUN}" == "1" ]]; then
            log_info "[DRY-RUN] Would add '${username}' to sudo group"
        else
            usermod -aG sudo "$username"
            log_success "User '${username}' added to sudo group."
        fi
    else
        log_info "User '${username}' is already in sudo group (or user not yet created in DRY_RUN)."
    fi

    # Ensure home directory has correct permissions
    if id "$username" &>/dev/null; then
        if [[ "${DRY_RUN}" == "1" ]]; then
            log_info "[DRY-RUN] Would set /home/${username} permissions to 750"
        else
            chmod 750 "/home/${username}" 2>/dev/null || true
            chown "${username}:${username}" "/home/${username}" 2>/dev/null || true
        fi
    fi

    echo "$username"
}

# ---------------------------------------------------------------------------
# _users_configure_ssh_key — Install an SSH public key for the admin user
# ---------------------------------------------------------------------------
_users_configure_ssh_key() {
    local username="$1"
    local home_dir
    home_dir="$(getent passwd "$username" 2>/dev/null | cut -d: -f6 || echo "/home/${username}")"
    local ssh_dir="${home_dir}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would create ${ssh_dir} (700) and manage ${auth_keys}"
        return 0
    fi

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "${username}:${username}" "$ssh_dir"

    # Check if authorized_keys already has entries
    if [[ -f "$auth_keys" && -s "$auth_keys" ]]; then
        log_info "authorized_keys already contains key(s)."
        if confirm "Add another SSH public key?"; then
            _users_add_ssh_key "$username" "$auth_keys"
        fi
    else
        log_info "No SSH keys configured yet for '${username}'."
        printf "\n  ${YELLOW}TIP: If you don't add an SSH key now, the SSH module will NOT disable\n"
        printf "  password authentication (for safety).${RESET}\n\n"

        if confirm "Add an SSH public key for user '${username}'? (highly recommended)"; then
            _users_add_ssh_key "$username" "$auth_keys"
        else
            log_warning "No SSH key added. Password authentication will remain enabled."
            save_state "admin_ssh_key_set" "no"
            return 0
        fi
    fi

    save_state "admin_ssh_key_set" "yes"
}

# ---------------------------------------------------------------------------
# _users_add_ssh_key — Read a public key and append it to authorized_keys
# ---------------------------------------------------------------------------
_users_add_ssh_key() {
    local username="$1"
    local auth_keys="$2"

    printf "\n  ${BOLD}Paste your SSH public key (starts with 'ssh-rsa', 'ssh-ed25519', etc.):${RESET}\n  > "
    local pubkey
    read -r pubkey

    # Basic validation
    if [[ "$pubkey" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519|sk-ecdsa-sha2-nistp256) ]]; then
        # Check for duplicate
        if [[ -f "$auth_keys" ]] && grep -qF "$pubkey" "$auth_keys" 2>/dev/null; then
            log_info "Key already present in authorized_keys."
        else
            echo "$pubkey" >> "$auth_keys"
            chmod 600 "$auth_keys"
            chown "${username}:${username}" "$auth_keys"
            log_success "SSH public key added for user '${username}'."
        fi
    else
        log_warning "Key doesn't look like a valid SSH public key. Skipping."
        log_warning "Expected format: ssh-ed25519 AAAA... comment"
        save_state "admin_ssh_key_set" "no"
        return 0
    fi
}

# ---------------------------------------------------------------------------
# _users_set_password_policy — Configure PAM for strong passwords
# ---------------------------------------------------------------------------
_users_set_password_policy() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would install libpam-pwquality"
        log_info "[DRY-RUN] Would write /etc/security/pwquality.conf"
        log_info "[DRY-RUN] Would update /etc/pam.d/common-password with pam_pwquality"
        log_info "[DRY-RUN] Would update /etc/login.defs with PASS_MAX_DAYS=90, SHA512"
        return 0
    fi

    # Install pwquality library
    DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality >> "$LOG_FILE" 2>&1

    local pwquality_conf="/etc/security/pwquality.conf"
    backup_file "$pwquality_conf" || true

    cat > "$pwquality_conf" << 'EOF'
# /etc/security/pwquality.conf — VPS Hardening Suite password policy
# Minimum password length
minlen = 14
# Minimum number of digits
dcredit = -1
# Minimum number of uppercase characters
ucredit = -1
# Minimum number of lowercase characters
lcredit = -1
# Minimum number of other (special) characters
ocredit = -1
# Minimum number of character classes in new password
minclass = 3
# Number of characters that must differ from old password
difok = 8
# Reject passwords containing the username
usercheck = 1
# Check password against a dictionary
dictcheck = 1
# Maximum consecutive same characters
maxrepeat = 3
# Maximum consecutive same class characters
maxclassrepeat = 4
# Reject if it contains a word longer than 3 chars from user's info
gecoscheck = 1
EOF

    # Configure PAM common-password to enforce the policy
    local pam_password="/etc/pam.d/common-password"
    backup_file "$pam_password" || true

    # Check if pam_pwquality is already in the file
    if ! grep -q "pam_pwquality" "$pam_password" 2>/dev/null; then
        # Insert pwquality before pam_unix
        sed -i '/pam_unix.so/i password        requisite                       pam_pwquality.so retry=3 enforce_for_root' \
            "$pam_password"
        log_success "PAM password quality module configured."
    else
        log_info "pam_pwquality already configured in ${pam_password}."
    fi

    # Set password expiry policy via /etc/login.defs
    local login_defs="/etc/login.defs"
    backup_file "$login_defs" || true

    # Update PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE
    for setting in \
        "PASS_MAX_DAYS 90" \
        "PASS_MIN_DAYS 1" \
        "PASS_WARN_AGE 14" \
        "ENCRYPT_METHOD SHA512" \
        "SHA_CRYPT_MIN_ROUNDS 5000"
    do
        local key="${setting%% *}"
        local val="${setting##* }"
        if grep -q "^${key}" "$login_defs"; then
            sed -i "s|^${key}.*|${key}\t${val}|" "$login_defs"
        else
            echo "${key}	${val}" >> "$login_defs"
        fi
    done

    log_success "Password policy applied: min 14 chars, max 90 days, SHA512 hashing."
}

# ---------------------------------------------------------------------------
# _users_configure_sudo — Optionally set up passwordless sudo
# ---------------------------------------------------------------------------
_users_configure_sudo() {
    local username="$1"
    local sudoers_drop="/etc/sudoers.d/${username}-hardening"

    if [[ -f "$sudoers_drop" ]]; then
        log_info "sudoers drop-in for '${username}' already exists."
        return 0
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would write sudoers drop-in: ${sudoers_drop}"
        return 0
    fi

    if confirm "Configure passwordless sudo for '${username}'? (convenient but less secure)" "n"; then
        cat > "$sudoers_drop" << EOF
# Sudoers drop-in created by VPS Hardening Suite
# Grants ${username} passwordless sudo access
${username} ALL=(ALL) NOPASSWD: ALL
EOF
        chmod 440 "$sudoers_drop"
        # Verify the sudoers file is syntactically correct
        visudo -c -f "$sudoers_drop" >> "$LOG_FILE" 2>&1 \
            && log_success "Passwordless sudo configured for '${username}'." \
            || { rm -f "$sudoers_drop"; log_warning "sudoers validation failed; passwordless sudo NOT configured."; }
        save_state "sudo_nopasswd" "yes"
    else
        # Require password but allow full sudo
        cat > "$sudoers_drop" << EOF
# Sudoers drop-in created by VPS Hardening Suite
${username} ALL=(ALL) ALL
EOF
        chmod 440 "$sudoers_drop"
        visudo -c -f "$sudoers_drop" >> "$LOG_FILE" 2>&1 \
            && log_success "Sudo access configured for '${username}' (password required)." \
            || { rm -f "$sudoers_drop"; log_warning "sudoers validation failed; sudo entry not added."; }
        save_state "sudo_nopasswd" "no"
    fi
}

# ---------------------------------------------------------------------------
# _users_disable_root_password — Lock root password and disable root shell
# ---------------------------------------------------------------------------
_users_disable_root_password() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would lock root password (passwd -l root)"
        log_info "[DRY-RUN] Would optionally set root shell to /usr/sbin/nologin"
        log_info "[DRY-RUN] Would truncate /etc/securetty to disable console root login"
        return 0
    fi

    # Lock root password (ssh login with password will fail; key login still works)
    passwd -l root >> "$LOG_FILE" 2>&1
    log_success "Root password locked."

    # Change root shell to nologin to prevent direct root sessions
    # (keeps ability to 'sudo -i' for those with sudo rights)
    if confirm "Change root shell to /usr/sbin/nologin? (prevents direct root login)" "y"; then
        chsh -s /usr/sbin/nologin root >> "$LOG_FILE" 2>&1
        log_success "Root shell set to /usr/sbin/nologin."
    else
        log_info "Root shell unchanged."
    fi

    # Disable root login via /etc/pam.d/login
    local pam_login="/etc/pam.d/login"
    if ! grep -q "pam_securetty" "$pam_login" 2>/dev/null; then
        log_info "pam_securetty already handled by PAM."
    fi

    # Ensure root is not in the TTY allowlist
    : > /etc/securetty  # Empty securetty disables all direct tty root logins
    log_success "Root console login disabled via /etc/securetty."
}

# ---------------------------------------------------------------------------
# _users_set_umask — Set a stricter default umask
# ---------------------------------------------------------------------------
_users_set_umask() {
    local profile_file="/etc/profile.d/99-secure-umask.sh"

    if [[ -f "$profile_file" ]]; then
        log_info "Secure umask already configured."
        return 0
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would write ${profile_file} with umask 027"
        log_info "[DRY-RUN] Would update UMASK in /etc/login.defs"
        return 0
    fi

    cat > "$profile_file" << 'EOF'
#!/bin/sh
# /etc/profile.d/99-secure-umask.sh — VPS Hardening Suite
# Set default umask to 027: owner full, group read+execute, others nothing
umask 027
EOF
    chmod 644 "$profile_file"
    log_success "Secure umask (027) configured via /etc/profile.d/"

    # Also update /etc/login.defs
    local login_defs="/etc/login.defs"
    if grep -q "^UMASK" "$login_defs"; then
        sed -i 's/^UMASK.*/UMASK\t027/' "$login_defs"
    else
        echo "UMASK	027" >> "$login_defs"
    fi
}

# ---------------------------------------------------------------------------
# _users_login_security — Configure login failure limits and account lockout
# ---------------------------------------------------------------------------
_users_login_security() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would install libpam-faillock"
        log_info "[DRY-RUN] Would configure pam_faillock in /etc/pam.d/common-auth (5 failures → 15 min lockout)"
        log_info "[DRY-RUN] Would set LOGIN_RETRIES=5, LOGIN_TIMEOUT=60 in /etc/login.defs"
        return 0
    fi

    # Configure PAM tally for account lockout after repeated failures
    DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-faillock >> "$LOG_FILE" 2>&1 || true

    local pam_auth="/etc/pam.d/common-auth"
    backup_file "$pam_auth" || true

    # Add faillock if not already present
    if ! grep -q "pam_faillock" "$pam_auth" 2>/dev/null; then
        # Insert faillock preauth before pam_unix, and authfail after
        sed -i '/^auth.*pam_unix/i auth    required                        pam_faillock.so preauth silent audit deny=5 unlock_time=900' \
            "$pam_auth"
        sed -i '/^auth.*pam_unix/a auth    [default=die]                   pam_faillock.so authfail audit deny=5 unlock_time=900' \
            "$pam_auth"
        log_success "Account lockout configured: 5 failures → 15 min lockout."
    else
        log_info "pam_faillock already configured."
    fi

    # Configure /etc/login.defs login retry limit
    local login_defs="/etc/login.defs"
    if grep -q "^LOGIN_RETRIES" "$login_defs"; then
        sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES\t5/' "$login_defs"
    else
        echo "LOGIN_RETRIES	5" >> "$login_defs"
    fi

    if grep -q "^LOGIN_TIMEOUT" "$login_defs"; then
        sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT\t60/' "$login_defs"
    else
        echo "LOGIN_TIMEOUT	60" >> "$login_defs"
    fi
}
