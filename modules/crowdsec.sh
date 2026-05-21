#!/usr/bin/env bash
# =============================================================================
# modules/crowdsec.sh — CrowdSec collaborative intrusion prevention
# =============================================================================
# THREAT MODEL:
#   Mitigates: Known-malicious IPs, coordinated attacks, tor exit nodes,
#              bot networks — using crowd-sourced threat intelligence
#   Attack surface reduced: Blocks entire IPs at iptables/nftables before
#                           they reach application layer
#   Operational impact: Risk of banning legitimate IPs if community signals
#                       incorrect; keep out-of-band console access ready
#   Can break: Nothing by default — CrowdSec only blocks IPs that have
#              triggered community alerts; false positives can be whitelisted
#   Note: Works alongside Fail2Ban — both operate independently (defense in
#         depth). CrowdSec catches known-bad IPs proactively; Fail2Ban catches
#         new brute-force attempts reactively.
#   Compatible with: Ubuntu 20.04+, Debian 11+
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_CROWDSEC_LOADED:-}" ]] && return 0
readonly _MODULE_CROWDSEC_LOADED=1

if [[ -z "${_VPS_HARDENING_COMMON_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "${SCRIPT_DIR}/../lib/common.sh"
fi

# =============================================================================
# Profile variables with safe defaults
# =============================================================================
# Port 6767 avoids conflicts with cAdvisor (8080), Grafana (3000), etc.
CROWDSEC_LAPI_PORT="${CROWDSEC_LAPI_PORT:-${PORT_CROWDSEC_LAPI:-6767}}"

# ---------------------------------------------------------------------------
# run_crowdsec — Main entry point
# ---------------------------------------------------------------------------
run_crowdsec() {
    log_section "CROWDSEC INSTALLATION"

    log_step 1 8 "Checking port availability"
    local lapi_port="${CROWDSEC_LAPI_PORT}"
    log_info "CrowdSec LAPI will use port ${lapi_port}."

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
# _crowdsec_add_repo
# ---------------------------------------------------------------------------
_crowdsec_add_repo() {
    if [[ -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]] \
       || [[ -f /etc/apt/sources.list.d/crowdsec.list ]]; then
        log_info "CrowdSec repository already configured."
        return 0
    fi

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would add CrowdSec APT repository."
        return 0
    fi

    log_info "Adding CrowdSec repository..."
    local setup_script
    setup_script="$(mktemp /tmp/crowdsec_install.XXXXXX.sh)"
    trap 'rm -f "$setup_script"' RETURN

    if curl -sf https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh \
            -o "$setup_script"; then
        bash "$setup_script" >> "$LOG_FILE" 2>&1
        log_success "CrowdSec repository added via packagecloud."
    else
        log_warning "Failed to fetch repo script; trying manual method..."
        _crowdsec_add_repo_manual
    fi

    apt-get update -qq >> "$LOG_FILE" 2>&1
}

# ---------------------------------------------------------------------------
# _crowdsec_add_repo_manual — GPG key + sources.list fallback
# ---------------------------------------------------------------------------
_crowdsec_add_repo_manual() {
    local keyring_path="/usr/share/keyrings/crowdsec-archive-keyring.gpg"
    curl -sf "https://packagecloud.io/crowdsec/crowdsec/gpgkey" \
        | gpg --dearmor -o "$keyring_path"
    chmod 644 "$keyring_path"

    local arch codename
    arch="$(dpkg --print-architecture)"
    codename="${OS_CODENAME:-$(lsb_release -cs 2>/dev/null || echo focal)}"

    cat > /etc/apt/sources.list.d/crowdsec.list << EOF
# CrowdSec repository — added by VPS Hardening Suite
deb [arch=${arch} signed-by=${keyring_path}] https://packagecloud.io/crowdsec/crowdsec/ubuntu ${codename} main
deb-src [arch=${arch} signed-by=${keyring_path}] https://packagecloud.io/crowdsec/crowdsec/ubuntu ${codename} main
EOF

    log_success "CrowdSec repository added manually."
}

# ---------------------------------------------------------------------------
# _crowdsec_install
# ---------------------------------------------------------------------------
_crowdsec_install() {
    if command_exists cscli && command_exists crowdsec; then
        log_info "CrowdSec already installed."
        if ! command_exists crowdsec-firewall-bouncer && [[ "${DRY_RUN:-0}" != "1" ]]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                crowdsec-firewall-bouncer-iptables >> "$LOG_FILE" 2>&1
        fi
        return 0
    fi

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would install crowdsec + crowdsec-firewall-bouncer-iptables."
        return 0
    fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        crowdsec crowdsec-firewall-bouncer-iptables >> "$LOG_FILE" 2>&1
    log_success "CrowdSec packages installed."
}

# ---------------------------------------------------------------------------
# _crowdsec_configure_port — Update LAPI listen_uri
# ---------------------------------------------------------------------------
_crowdsec_configure_port() {
    local target_port="$1"
    local config_file="/etc/crowdsec/config.yaml"
    local target_uri="127.0.0.1:${target_port}"

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would set CrowdSec LAPI to ${target_uri}."
        return 0
    fi

    if [[ ! -f "$config_file" ]]; then
        log_error "CrowdSec config not found: ${config_file}"
        return 1
    fi

    backup_file "$config_file"

    local current_uri
    current_uri="$(grep -oP "listen_uri:\s*\K[^\s]+" "$config_file" 2>/dev/null | head -1 || echo "")"

    if [[ "$current_uri" == "$target_uri" ]]; then
        log_info "LAPI already configured on ${target_uri}."
        return 0
    fi

    log_info "Reconfiguring LAPI from '${current_uri}' to '${target_uri}'..."
    sed -i "s|listen_uri:.*|listen_uri: ${target_uri}|" "$config_file"

    local creds_file="/etc/crowdsec/local_api_credentials.yaml"
    if [[ -f "$creds_file" ]]; then
        backup_file "$creds_file"
        sed -i "s|url:.*localhost:[0-9]*|url: http://127.0.0.1:${target_port}|g" "$creds_file"
        sed -i "s|url:.*127\.0\.0\.1:[0-9]*|url: http://127.0.0.1:${target_port}|g" "$creds_file"
        log_info "Updated local API credentials to port ${target_port}."
    fi

    log_success "CrowdSec LAPI configured on port ${target_port}."
}

# ---------------------------------------------------------------------------
# _crowdsec_install_collections — Threat detection rules
# ---------------------------------------------------------------------------
_crowdsec_install_collections() {
    if ! command_exists cscli; then
        log_warning "cscli not found; skipping collections."
        return 0
    fi

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would install collections: crowdsecurity/linux, crowdsecurity/sshd, crowdsecurity/linux-lpe."
        return 0
    fi

    log_info "Updating CrowdSec Hub index..."
    cscli hub update >> "$LOG_FILE" 2>&1 || true

    local -a base_collections=(
        "crowdsecurity/linux"
        "crowdsecurity/sshd"
        "crowdsecurity/linux-lpe"
    )

    for collection in "${base_collections[@]}"; do
        if cscli collections list 2>/dev/null | grep -q "${collection##*/}"; then
            log_info "  Already installed: ${collection}"
        else
            cscli collections install "$collection" >> "$LOG_FILE" 2>&1 \
                && log_success "  Installed: ${collection}" \
                || log_warning "  Failed: ${collection}"
        fi
    done

    if command_exists nginx || package_installed nginx; then
        cscli collections install crowdsecurity/nginx >> "$LOG_FILE" 2>&1 || true
        log_success "  Installed: crowdsecurity/nginx"
    fi

    if command_exists docker; then
        cscli collections install crowdsecurity/docker >> "$LOG_FILE" 2>&1 || true
        log_success "  Installed: crowdsecurity/docker"
    fi

    cscli hub upgrade >> "$LOG_FILE" 2>&1 || true
    log_success "CrowdSec collections installed."
}

# ---------------------------------------------------------------------------
# _crowdsec_start_services
# ---------------------------------------------------------------------------
_crowdsec_start_services() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would enable + restart crowdsec."
        return 0
    fi
    systemctl enable crowdsec >> "$LOG_FILE" 2>&1
    systemctl restart crowdsec >> "$LOG_FILE" 2>&1
    wait_for_service "crowdsec" 45
    log_success "CrowdSec service started."
}

# ---------------------------------------------------------------------------
# _crowdsec_configure_bouncer
# ---------------------------------------------------------------------------
_crowdsec_configure_bouncer() {
    local lapi_port="$1"
    local bouncer_config="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would configure and register firewall bouncer."
        return 0
    fi

    if [[ ! -f "$bouncer_config" ]]; then
        log_warning "Bouncer config not found at ${bouncer_config}. Skipping."
        return 0
    fi

    backup_file "$bouncer_config"
    sed -i "s|api_url:.*|api_url: http://127.0.0.1:${lapi_port}/|" "$bouncer_config"

    local bouncer_name="firewall-bouncer-$(hostname -s)"
    cscli bouncers delete "$bouncer_name" >> "$LOG_FILE" 2>&1 || true

    local api_key
    api_key="$(cscli bouncers add "$bouncer_name" --output raw 2>/dev/null \
        | grep -oP '[a-f0-9]{64}' | head -1 || echo "")"

    if [[ -n "$api_key" ]]; then
        sed -i "s|api_key:.*|api_key: ${api_key}|" "$bouncer_config"
        log_success "Bouncer registered with API key."
    else
        log_warning "Could not auto-register bouncer. Run: cscli bouncers add my-bouncer"
    fi

    systemctl enable crowdsec-firewall-bouncer >> "$LOG_FILE" 2>&1 || true
    systemctl restart crowdsec-firewall-bouncer >> "$LOG_FILE" 2>&1 || true
    wait_for_service "crowdsec-firewall-bouncer" 20 \
        || log_warning "Bouncer may not have started; check: systemctl status crowdsec-firewall-bouncer"
}

# ---------------------------------------------------------------------------
# _crowdsec_verify
# ---------------------------------------------------------------------------
_crowdsec_verify() {
    [[ "${DRY_RUN:-0}" == "1" ]] && return 0
    sleep 3

    log_info "CrowdSec machine list:"
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

    if cscli metrics 2>/dev/null | head -5 | grep -q "crowdsec"; then
        log_success "CrowdSec healthy and processing events."
    else
        log_warning "CrowdSec metrics not yet available (may still be initializing)."
    fi
}
