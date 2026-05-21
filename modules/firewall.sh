#!/usr/bin/env bash
# =============================================================================
# modules/firewall.sh — UFW Firewall configuration
# =============================================================================
# THREAT MODEL:
#   Mitigates: Unrestricted inbound connections, port scanning, exposure of
#              internal services, container traffic bypassing host rules
#   Attack surface reduced: All inbound traffic except explicitly permitted ports
#   Operational impact: Enabling UFW during active session can drop connection
#                       if SSH port is not allowed first
#   Can break: Any service listening on a port not in UFW_ALLOW_PORTS; Docker
#              NAT requires DOCKER-USER chain (handled here)
#   Compatible with: Ubuntu 20.04+, Debian 11+
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_FIREWALL_LOADED:-}" ]] && return 0
readonly _MODULE_FIREWALL_LOADED=1

if [[ -z "${_VPS_HARDENING_COMMON_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "${SCRIPT_DIR}/../lib/common.sh"
fi

# =============================================================================
# Profile variables with safe defaults
# =============================================================================
# Space-separated list of ports/proto to open (e.g. "22 80/tcp 443")
UFW_ALLOW_PORTS="${UFW_ALLOW_PORTS:-"${SSH_PORT:-22}"}"
UFW_MONITORING_LOCALHOST_ONLY="${UFW_MONITORING_LOCALHOST_ONLY:-yes}"

# ---------------------------------------------------------------------------
# run_firewall — Main entry point
# ---------------------------------------------------------------------------
run_firewall() {
    log_section "FIREWALL CONFIGURATION (UFW)"

    log_step 1 9 "Installing UFW"
    _firewall_install_ufw

    log_step 2 9 "Resetting UFW to clean state"
    _firewall_reset

    log_step 3 9 "Setting default policies"
    _firewall_set_defaults

    log_step 4 9 "Adding SSH rule"
    _firewall_add_ssh

    log_step 5 9 "Configuring profile-defined ports"
    _firewall_profile_ports

    log_step 6 9 "Configuring monitoring stack rules"
    _firewall_configure_monitoring

    log_step 7 9 "Adding interactive custom rules"
    _firewall_custom_ports

    log_step 8 9 "Configuring Docker compatibility"
    _firewall_docker_compat

    log_step 9 9 "Enabling UFW"
    _firewall_enable

    log_success "UFW firewall configured and enabled."
    save_state "firewall_enabled" "yes"

    echo ""
    log_info "Current UFW rules:"
    ufw status verbose 2>&1 | while IFS= read -r line; do
        printf "  %s\n" "$line"
    done
}

# ---------------------------------------------------------------------------
# _firewall_install_ufw
# ---------------------------------------------------------------------------
_firewall_install_ufw() {
    if command_exists ufw; then
        log_info "UFW already installed."
        return 0
    fi
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would install UFW."
        return 0
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw >> "$LOG_FILE" 2>&1
    log_success "UFW installed."
}

# ---------------------------------------------------------------------------
# _firewall_reset
# ---------------------------------------------------------------------------
_firewall_reset() {
    local ufw_status
    ufw_status="$(ufw status 2>/dev/null | head -1)"

    if echo "$ufw_status" | grep -qi "active"; then
        log_warning "UFW is currently active with existing rules."
        if [[ "${NONINTERACTIVE:-0}" != "1" ]]; then
            if ! confirm "Reset all UFW rules and start fresh?" "y"; then
                log_info "Keeping existing UFW rules. Adding to them instead."
                return 0
            fi
        fi
    fi

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would disable + reset UFW rules."
        return 0
    fi

    ufw --force disable >> "$LOG_FILE" 2>&1 || true
    ufw --force reset  >> "$LOG_FILE" 2>&1
    log_success "UFW rules reset to clean state."
}

# ---------------------------------------------------------------------------
# _firewall_set_defaults
# ---------------------------------------------------------------------------
_firewall_set_defaults() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would set: deny incoming, allow outgoing, deny forward."
        return 0
    fi

    ufw default deny incoming  >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    ufw default deny forward   >> "$LOG_FILE" 2>&1

    local ufw_defaults="/etc/default/ufw"
    if [[ -f "$ufw_defaults" ]]; then
        backup_file "$ufw_defaults" >> "$LOG_FILE" 2>&1 || true
        sed -i 's/^IPV6=.*/IPV6=yes/' "$ufw_defaults"
        log_info "IPv6 support enabled in UFW."
    fi

    log_success "Default policies: deny incoming, allow outgoing, deny forward."
}

# ---------------------------------------------------------------------------
# _firewall_add_ssh — Always allow SSH port before anything else
# ---------------------------------------------------------------------------
_firewall_add_ssh() {
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "${SSH_PORT:-22}")"

    local ssh_whitelist="${FAIL2BAN_WHITELIST_IPS:-}"

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would rate-limit SSH on port ${ssh_port}."
        return 0
    fi

    if [[ -n "$ssh_whitelist" ]]; then
        for ip in $ssh_whitelist; do
            ufw allow from "$ip" to any port "$ssh_port" proto tcp \
                comment "SSH from trusted source" >> "$LOG_FILE" 2>&1 || true
        done
        log_success "SSH (port ${ssh_port}) allowed from whitelist: ${ssh_whitelist}"
    fi

    ufw limit "${ssh_port}/tcp" comment "SSH rate-limited" >> "$LOG_FILE" 2>&1
    log_success "SSH (port ${ssh_port}) rate-limited."

    if [[ "$ssh_port" != "22" ]]; then
        log_warning "Temporarily keeping port 22 open. Remove after confirming new SSH works."
        ufw allow 22/tcp comment "TEMPORARY: remove after testing new SSH port" >> "$LOG_FILE" 2>&1
    fi
}

# ---------------------------------------------------------------------------
# _firewall_profile_ports — Open ports declared in UFW_ALLOW_PORTS
# ---------------------------------------------------------------------------
_firewall_profile_ports() {
    if [[ -z "${UFW_ALLOW_PORTS}" ]]; then
        log_info "No additional ports in profile (UFW_ALLOW_PORTS is empty)."
        return 0
    fi

    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "${SSH_PORT:-22}")"

    for port_spec in ${UFW_ALLOW_PORTS}; do
        local bare_port="${port_spec%%/*}"
        # Skip SSH port — already handled above
        [[ "$bare_port" == "$ssh_port" ]] && continue
        [[ "$bare_port" == "22" ]] && continue

        if [[ "${DRY_RUN:-0}" == "1" ]]; then
            log_info "[DRY-RUN] Would open port ${port_spec}."
            continue
        fi

        ufw allow "${port_spec}" comment "Profile: ${PROFILE_NAME:-manual}" >> "$LOG_FILE" 2>&1 \
            && log_success "Opened port ${port_spec}." \
            || log_warning "Failed to add rule for port ${port_spec}."
    done
}

# ---------------------------------------------------------------------------
# _firewall_configure_monitoring — Monitoring ports localhost+Docker only
# ---------------------------------------------------------------------------
_firewall_configure_monitoring() {
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would restrict monitoring ports to localhost + Docker networks."
        return 0
    fi

    local restrict_to_localhost="${UFW_MONITORING_LOCALHOST_ONLY}"

    if [[ "${NONINTERACTIVE:-0}" != "1" ]]; then
        if ! confirm "Restrict monitoring ports to localhost only? (recommended)" "y"; then
            restrict_to_localhost="no"
        fi
    fi

    if [[ "$restrict_to_localhost" == "yes" ]]; then
        local -a monitoring_ports=(
            "${PORT_GRAFANA}:Grafana"
            "${PORT_PROMETHEUS}:Prometheus"
            "${PORT_NODE_EXPORTER}:Node Exporter"
            "${PORT_CADVISOR}:cAdvisor"
            "${PORT_LOKI}:Loki"
            "${PORT_PROMTAIL}:Promtail"
        )
        for entry in "${monitoring_ports[@]}"; do
            local port="${entry%%:*}"
            local svc="${entry#*:}"
            ufw allow from 127.0.0.1 to any port "$port" comment "${svc} (localhost)" >> "$LOG_FILE" 2>&1
            ufw allow from 172.16.0.0/12 to any port "$port" comment "${svc} (Docker)" >> "$LOG_FILE" 2>&1
        done
        log_success "Monitoring ports restricted to localhost and Docker networks."
    else
        log_warning "Monitoring ports left unrestricted (user choice). Consider a reverse proxy with auth."
    fi
}

# ---------------------------------------------------------------------------
# _firewall_custom_ports — Interactive extra rules (skipped in non-interactive)
# ---------------------------------------------------------------------------
_firewall_custom_ports() {
    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        log_info "Non-interactive mode: skipping custom port prompts."
        return 0
    fi

    if ! confirm "Add any other custom firewall rules?" "n"; then
        return 0
    fi

    while true; do
        local port_spec
        port_spec="$(ask "Port/proto to open (e.g. '8443', '1194/udp', 'done' to finish)" "done")"
        port_spec="$(trim "$port_spec")"
        [[ "$port_spec" == "done" || -z "$port_spec" ]] && break

        local comment source
        comment="$(ask "Description for this rule" "custom")"
        source="$(ask "Source IP/CIDR (blank = any)" "")"

        if [[ "${DRY_RUN:-0}" == "1" ]]; then
            log_info "[DRY-RUN] Would open port ${port_spec} from '${source:-any}' (${comment})."
            continue
        fi

        if [[ -n "$source" ]]; then
            ufw allow from "$source" to any port "${port_spec%%/*}" comment "$comment" >> "$LOG_FILE" 2>&1 \
                && log_success "Rule added: from ${source} → port ${port_spec} (${comment})" \
                || log_warning "Failed to add rule for port ${port_spec}"
        else
            ufw allow "$port_spec" comment "$comment" >> "$LOG_FILE" 2>&1 \
                && log_success "Rule added: port ${port_spec} (${comment})" \
                || log_warning "Failed to add rule for port ${port_spec}"
        fi
    done
}

# ---------------------------------------------------------------------------
# _firewall_docker_compat — DOCKER-USER chain to preserve UFW authority
# ---------------------------------------------------------------------------
_firewall_docker_compat() {
    local after_rules="/etc/ufw/after.rules"

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would add DOCKER-USER iptables rules to ${after_rules}."
        return 0
    fi

    backup_file "$after_rules" >> "$LOG_FILE" 2>&1 || true

    if grep -q "BEGIN DOCKER-UFW" "$after_rules" 2>/dev/null; then
        log_info "Docker UFW compatibility rules already present."
        return 0
    fi

    cat >> "$after_rules" << 'DOCKER_RULES'

# BEGIN DOCKER-UFW
# UFW authority over Docker traffic via DOCKER-USER chain.
# Docker calls this chain before its own DOCKER chain — rules here
# execute first and can RETURN or DROP traffic before Docker processes it.
*filter
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-USER -i docker0 -j ACCEPT
-A DOCKER-USER -o docker0 -j ACCEPT
-A DOCKER-USER -i br-+ -j ACCEPT
-A DOCKER-USER -o br-+ -j ACCEPT
COMMIT
# END DOCKER-UFW
DOCKER_RULES

    log_success "Docker UFW compatibility rules added (DOCKER-USER chain)."
}

# ---------------------------------------------------------------------------
# _firewall_enable
# ---------------------------------------------------------------------------
_firewall_enable() {
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "${SSH_PORT:-22}")"

    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log_info "[DRY-RUN] Would enable UFW (SSH port ${ssh_port} would remain open)."
        return 0
    fi

    if ! ufw show added 2>/dev/null | grep -q "$ssh_port"; then
        log_warning "SSH port ${ssh_port} not found in UFW rules. Adding safety rule..."
        ufw allow "${ssh_port}/tcp" comment "SSH safety rule" >> "$LOG_FILE" 2>&1
    fi

    printf "${YELLOW}${BOLD}  Enabling UFW. SSH port ${ssh_port} will remain open.${RESET}\n"
    ufw --force enable >> "$LOG_FILE" 2>&1
    log_success "UFW enabled."
}
