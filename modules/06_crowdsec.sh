#!/usr/bin/env bash
# =============================================================================
# modules/06_crowdsec.sh — CrowdSec collaborative intrusion prevention
# =============================================================================
# CrowdSec is a modern, collaborative IPS that uses a crowd-sourced threat
# intelligence database to block known malicious IPs across the community.
#
# Architecture:
#   CrowdSec agent  — reads logs, detects attacks, calls LAPI
#   LAPI (Local API)— coordinator between agents and bouncers
#   Bouncer         — enforces bans (iptables-based)
#   cscli           — management CLI
#
# Port strategy:
#   Default LAPI port is 8080. If port 8080 is in use, we reconfigure
#   to use our non-conflicting port: 6767 (PORT_CROWDSEC_LAPI constant).
#
# Collections installed:
#   crowdsecurity/linux   — base Linux detection rules
#   crowdsecurity/sshd    — SSH brute force detection
#   crowdsecurity/nginx   — Optional, if nginx is installed
#
# Steps:
#   1.  Check port 8080 availability
#   2.  Add CrowdSec APT repository
#   3.  Install crowdsec and crowdsec-firewall-bouncer-iptables
#   4.  Configure LAPI port if needed
#   5.  Install collections
#   6.  Start and enable services
#   7.  Register with crowdsec LAPI
#   8.  Verify installation
#
# State keys written:
#   crowdsec_installed  — "yes"
#   crowdsec_lapi_port  — the configured LAPI port
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_CROWDSEC_LOADED:-}" ]] && return 0
readonly _MODULE_CROWDSEC_LOADED=1

# The LAPI port we want to use (from common.sh constant)
_CROWDSEC_TARGET_PORT="${PORT_CROWDSEC_LAPI}"  # 6767

# ---------------------------------------------------------------------------
# run_crowdsec — Main entry point
# ---------------------------------------------------------------------------
run_crowdsec() {
    log_section "CROWDSEC INSTALLATION"

    log_step 1 8 "Checking port availability"
    local lapi_port
    lapi_port="$(_crowdsec_determine_port)"

    log_step 2 8 "Adding CrowdSec APT repository"
    _crowdsec_add_repo

    log_step 3 8 "Installing CrowdSec and firewall bouncer"
    _crowdsec_install

    log_step 4 8 "Configuring LAPI port: ${lapi_port}"
    _crowdsec_configure_port "$lapi_port"

    log_step 5 8 "Installing threat intelligence collections"
    _crowdsec_install_collections

    log_step 6 8 "Starting CrowdSec services"
    _crowdsec_start_services

    log_step 7 8 "Configuring firewall bouncer"
    _crowdsec_configure_bouncer "$lapi_port"

    log_step 8 8 "Verifying CrowdSec installation"
    _crowdsec_verify

    save_state "crowdsec_installed" "yes"
    save_state "crowdsec_lapi_port" "$lapi_port"

    log_success "CrowdSec installed and configured on LAPI port ${lapi_port}."
}

# ---------------------------------------------------------------------------
# _crowdsec_determine_port — Check if 8080 is free; use 6767 otherwise
# ---------------------------------------------------------------------------
_crowdsec_determine_port() {
    if port_in_use 8080; then
        log_warning "Port 8080 is in use. CrowdSec LAPI will be configured on port ${_CROWDSEC_TARGET_PORT}."
        echo "${_CROWDSEC_TARGET_PORT}"
    else
        log_info "Port 8080 is free, but using ${_CROWDSEC_TARGET_PORT} to avoid future conflicts."
        echo "${_CROWDSEC_TARGET_PORT}"
    fi
}

# ---------------------------------------------------------------------------
# _crowdsec_add_repo — Add the official CrowdSec APT repository
# ---------------------------------------------------------------------------
_crowdsec_add_repo() {
    if [[ -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]] \
       || [[ -f /etc/apt/sources.list.d/crowdsec.list ]]; then
        log_info "CrowdSec repository already configured."
        return 0
    fi

    log_info "Adding CrowdSec repository..."

    # Download and install the repo setup script
    local setup_script
    setup_script="$(mktemp /tmp/crowdsec_install.XXXXXX.sh)"
    trap 'rm -f "$setup_script"' RETURN

    if curl -sf https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh \
            -o "$setup_script"; then
        bash "$setup_script" >> "$LOG_FILE" 2>&1
        log_success "CrowdSec repository added via packagecloud."
    else
        # Fallback: add manually using GPG key and sources.list entry
        log_warning "Failed to fetch repo script; trying manual method..."
        _crowdsec_add_repo_manual
    fi

    apt-get update -qq >> "$LOG_FILE" 2>&1
}

# ---------------------------------------------------------------------------
# _crowdsec_add_repo_manual — Manual fallback GPG + sources.list method
# ---------------------------------------------------------------------------
_crowdsec_add_repo_manual() {
    local keyring_path="/usr/share/keyrings/crowdsec-archive-keyring.gpg"

    # Download GPG key
    curl -sf "https://packagecloud.io/crowdsec/crowdsec/gpgkey" \
        | gpg --dearmor -o "$keyring_path"

    chmod 644 "$keyring_path"

    # Add sources.list entry
    local arch
    arch="$(dpkg --print-architecture)"
    local codename="${OS_CODENAME:-$(lsb_release -cs 2>/dev/null || echo focal)}"

    cat > /etc/apt/sources.list.d/crowdsec.list << EOF
# CrowdSec repository — added by VPS Hardening Suite
deb [arch=${arch} signed-by=${keyring_path}] https://packagecloud.io/crowdsec/crowdsec/ubuntu ${codename} main
deb-src [arch=${arch} signed-by=${keyring_path}] https://packagecloud.io/crowdsec/crowdsec/ubuntu ${codename} main
EOF

    log_success "CrowdSec repository added manually."
}

# ---------------------------------------------------------------------------
# _crowdsec_install — Install crowdsec and the firewall bouncer
# ---------------------------------------------------------------------------
_crowdsec_install() {
    if command_exists cscli && command_exists crowdsec; then
        log_info "CrowdSec is already installed."
        # Still install bouncer if missing
        if ! command_exists crowdsec-firewall-bouncer; then
            log_info "Installing firewall bouncer..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                crowdsec-firewall-bouncer-iptables >> "$LOG_FILE" 2>&1
        fi
        return 0
    fi

    log_info "Installing CrowdSec and firewall bouncer..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        crowdsec \
        crowdsec-firewall-bouncer-iptables \
        >> "$LOG_FILE" 2>&1

    log_success "CrowdSec packages installed."
}

# ---------------------------------------------------------------------------
# _crowdsec_configure_port — Update LAPI listen URI to use our target port
# ---------------------------------------------------------------------------
_crowdsec_configure_port() {
    local target_port="$1"
    local config_file="/etc/crowdsec/config.yaml"

    if [[ ! -f "$config_file" ]]; then
        log_error "CrowdSec config not found: ${config_file}"
        return 1
    fi

    backup_file "$config_file"

    # Check current listen_uri
    local current_uri
    current_uri="$(grep -oP "listen_uri:\s*\K[^\s]+" "$config_file" 2>/dev/null | head -1 || echo "")"

    local target_uri="127.0.0.1:${target_port}"

    if [[ "$current_uri" == "$target_uri" ]]; then
        log_info "CrowdSec LAPI already configured on ${target_uri}."
        return 0
    fi

    log_info "Reconfiguring LAPI from '${current_uri}' to '${target_uri}'..."

    # Use sed to update the listen_uri (handles indented YAML lines)
    sed -i "s|listen_uri:.*|listen_uri: ${target_uri}|" "$config_file"

    # Also update the local_api_credentials.yaml if it exists
    local creds_file="/etc/crowdsec/local_api_credentials.yaml"
    if [[ -f "$creds_file" ]]; then
        backup_file "$creds_file"
        sed -i "s|url:.*localhost:[0-9]*|url: http://127.0.0.1:${target_port}|g" "$creds_file"
        sed -i "s|url:.*127\.0\.0\.1:[0-9]*|url: http://127.0.0.1:${target_port}|g" "$creds_file"
        log_info "Updated local API credentials URL to port ${target_port}."
    fi

    log_success "CrowdSec LAPI configured on port ${target_port}."
}

# ---------------------------------------------------------------------------
# _crowdsec_install_collections — Install threat detection rules
# ---------------------------------------------------------------------------
_crowdsec_install_collections() {
    # Ensure cscli is available
    if ! command_exists cscli; then
        log_warning "cscli not found; skipping collection installation."
        return 0
    fi

    # Update Hub index first
    log_info "Updating CrowdSec Hub index..."
    cscli hub update >> "$LOG_FILE" 2>&1 || true

    # Base collections (always install)
    local base_collections=(
        "crowdsecurity/linux"
        "crowdsecurity/sshd"
        "crowdsecurity/linux-lpe"     # Linux privilege escalation
    )

    log_info "Installing base collections..."
    for collection in "${base_collections[@]}"; do
        if cscli collections list 2>/dev/null | grep -q "${collection##*/}"; then
            log_info "  Already installed: ${collection}"
        else
            cscli collections install "$collection" >> "$LOG_FILE" 2>&1 \
                && log_success "  Installed: ${collection}" \
                || log_warning "  Failed to install: ${collection}"
        fi
    done

    # Optional: nginx collection
    if command_exists nginx || package_installed nginx; then
        log_info "Nginx detected — installing nginx CrowdSec collection..."
        cscli collections install crowdsecurity/nginx >> "$LOG_FILE" 2>&1 \
            && log_success "  Installed: crowdsecurity/nginx" \
            || log_warning "  Failed to install nginx collection."
    else
        if confirm "Install nginx CrowdSec collection? (useful if you plan to install nginx)" "n"; then
            cscli collections install crowdsecurity/nginx >> "$LOG_FILE" 2>&1 || true
        fi
    fi

    # Optional: docker collection
    if command_exists docker; then
        log_info "Docker detected — installing docker CrowdSec collection..."
        cscli collections install crowdsecurity/docker >> "$LOG_FILE" 2>&1 \
            && log_success "  Installed: crowdsecurity/docker" \
            || true
    fi

    # Apply hub upgrade (install latest versions)
    cscli hub upgrade >> "$LOG_FILE" 2>&1 || true

    log_success "CrowdSec collections installed."
}

# ---------------------------------------------------------------------------
# _crowdsec_start_services — Enable and start crowdsec
# ---------------------------------------------------------------------------
_crowdsec_start_services() {
    systemctl enable crowdsec >> "$LOG_FILE" 2>&1
    systemctl restart crowdsec >> "$LOG_FILE" 2>&1

    wait_for_service "crowdsec" 45
    log_success "CrowdSec service started."
}

# ---------------------------------------------------------------------------
# _crowdsec_configure_bouncer — Set up firewall bouncer to call our LAPI port
# ---------------------------------------------------------------------------
_crowdsec_configure_bouncer() {
    local lapi_port="$1"
    local bouncer_config="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"

    if [[ ! -f "$bouncer_config" ]]; then
        log_warning "Bouncer config not found at ${bouncer_config}. Skipping bouncer config."
        return 0
    fi

    backup_file "$bouncer_config"

    # Update the API URL to point to our LAPI port
    sed -i "s|api_url:.*|api_url: http://127.0.0.1:${lapi_port}/|" "$bouncer_config"

    # Register the bouncer with the LAPI (generates an API key)
    log_info "Registering firewall bouncer with CrowdSec LAPI..."
    local bouncer_name="firewall-bouncer-$(hostname -s)"

    # Delete old registration if exists (idempotent)
    cscli bouncers delete "$bouncer_name" >> "$LOG_FILE" 2>&1 || true

    local api_key
    api_key="$(cscli bouncers add "$bouncer_name" --output raw 2>/dev/null \
        | grep -oP '[a-f0-9]{64}' | head -1 || echo "")"

    if [[ -n "$api_key" ]]; then
        # Update bouncer config with the API key
        sed -i "s|api_key:.*|api_key: ${api_key}|" "$bouncer_config"
        log_success "Bouncer registered with API key."
    else
        log_warning "Could not auto-register bouncer. You may need to run:"
        log_warning "  cscli bouncers add my-bouncer"
        log_warning "  and update ${bouncer_config} with the key."
    fi

    # Enable and start the bouncer
    systemctl enable crowdsec-firewall-bouncer >> "$LOG_FILE" 2>&1 || true
    systemctl restart crowdsec-firewall-bouncer >> "$LOG_FILE" 2>&1 || true
    wait_for_service "crowdsec-firewall-bouncer" 20 || log_warning "Bouncer may not have started; check logs."
}

# ---------------------------------------------------------------------------
# _crowdsec_verify — Confirm CrowdSec is working correctly
# ---------------------------------------------------------------------------
_crowdsec_verify() {
    # Wait for CrowdSec to be fully ready
    sleep 3

    log_info "CrowdSec machine list:"
    echo ""
    cscli machines list 2>/dev/null | while IFS= read -r line; do
        printf "  ${CYAN}│${RESET} %s\n" "$line"
    done

    echo ""
    log_info "Installed collections:"
    cscli collections list 2>/dev/null | head -20 | while IFS= read -r line; do
        printf "  ${CYAN}│${RESET} %s\n" "$line"
    done

    echo ""
    log_info "Active bouncers:"
    cscli bouncers list 2>/dev/null | while IFS= read -r line; do
        printf "  ${CYAN}│${RESET} %s\n" "$line"
    done

    echo ""

    # Quick health check
    if cscli metrics 2>/dev/null | head -5 | grep -q "crowdsec"; then
        log_success "CrowdSec is healthy and processing events."
    else
        log_warning "CrowdSec metrics not yet available (may still be initializing)."
    fi
}
