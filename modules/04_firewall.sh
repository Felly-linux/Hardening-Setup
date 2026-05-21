#!/usr/bin/env bash
# =============================================================================
# modules/04_firewall.sh — UFW Firewall configuration
# =============================================================================
# Configures UFW (Uncomplicated Firewall) with a defense-in-depth ruleset:
#   - Default deny inbound, allow outbound
#   - SSH with rate limiting (via ufw limit)
#   - Optional web server ports (80/443)
#   - Optional custom ports
#   - Docker-compatible configuration (does not break Docker iptables rules)
#   - Monitoring stack ports (restricted to localhost by default)
#   - Full IPv6 support
#
# Steps:
#   1.  Install UFW
#   2.  Reset to clean defaults
#   3.  Set default policies
#   4.  Add SSH rule with rate limiting
#   5.  Interactively add web / database / custom ports
#   6.  Add monitoring stack rules
#   7.  Configure Docker-compatible UFW settings
#   8.  Enable UFW
#   9.  Print final status
#
# State keys written:
#   firewall_enabled        — "yes"
#   firewall_web_server     — "yes" / "no"
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_FIREWALL_LOADED:-}" ]] && return 0
readonly _MODULE_FIREWALL_LOADED=1

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

    log_step 5 9 "Configuring web server rules"
    _firewall_configure_web

    log_step 6 9 "Configuring monitoring stack rules"
    _firewall_configure_monitoring

    log_step 7 9 "Adding custom port rules"
    _firewall_custom_ports

    log_step 8 9 "Configuring Docker compatibility"
    _firewall_docker_compat

    log_step 9 9 "Enabling UFW"
    _firewall_enable

    log_success "UFW firewall configured and enabled."
    save_state "firewall_enabled" "yes"

    # Show final status
    echo ""
    log_info "Current UFW rules:"
    ufw status verbose 2>&1 | while IFS= read -r line; do
        printf "  %s\n" "$line"
    done
}

# ---------------------------------------------------------------------------
# _firewall_install_ufw — Install ufw if not present
# ---------------------------------------------------------------------------
_firewall_install_ufw() {
    if command_exists ufw; then
        log_info "UFW already installed."
    else
        DEBIAN_FRONTEND=noninteractive apt-get install -y ufw >> "$LOG_FILE" 2>&1
        log_success "UFW installed."
    fi
}

# ---------------------------------------------------------------------------
# _firewall_reset — Reset UFW to defaults (non-destructively with confirmation)
# ---------------------------------------------------------------------------
_firewall_reset() {
    local ufw_status
    ufw_status="$(ufw status 2>/dev/null | head -1)"

    if echo "$ufw_status" | grep -qi "active"; then
        log_warning "UFW is currently active with existing rules."
        log_warning "These rules will be reset. Make sure SSH access is preserved."

        if ! confirm "Reset all UFW rules and start fresh?" "y"; then
            log_info "Keeping existing UFW rules. Adding to them instead."
            return 0
        fi
    fi

    # Disable UFW before resetting to avoid lockout
    ufw --force disable >> "$LOG_FILE" 2>&1 || true
    ufw --force reset  >> "$LOG_FILE" 2>&1
    log_success "UFW rules reset to clean state."
}

# ---------------------------------------------------------------------------
# _firewall_set_defaults — Default deny inbound, allow outbound
# ---------------------------------------------------------------------------
_firewall_set_defaults() {
    ufw default deny incoming  >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    ufw default deny forward   >> "$LOG_FILE" 2>&1

    # Enable IPv6 in /etc/default/ufw
    local ufw_defaults="/etc/default/ufw"
    if [[ -f "$ufw_defaults" ]]; then
        backup_file "$ufw_defaults" >> "$LOG_FILE" 2>&1 || true
        sed -i 's/^IPV6=.*/IPV6=yes/' "$ufw_defaults"
        log_info "IPv6 support enabled in UFW."
    fi

    log_success "Default policies: deny incoming, allow outgoing, deny forward."
}

# ---------------------------------------------------------------------------
# _firewall_add_ssh — Allow SSH with rate limiting
# ---------------------------------------------------------------------------
_firewall_add_ssh() {
    # Read SSH port from state (set by ssh module) or ask
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "")"

    if [[ -z "$ssh_port" ]]; then
        ssh_port="$(ask "SSH port to allow" "2222")"
        ssh_port="$(trim "$ssh_port")"
    else
        log_info "Using SSH port from state: ${ssh_port}"
    fi

    # Ask about whitelisted IPs for SSH
    echo ""
    log_info "You can restrict SSH access to specific IP addresses."
    log_info "Leave blank to allow SSH from any IP (with rate limiting)."

    local ssh_source
    ssh_source="$(ask "Source IP or CIDR for SSH access (blank = any)" "")"
    ssh_source="$(trim "$ssh_source")"

    if [[ -n "$ssh_source" ]]; then
        # Validate CIDR/IP format
        if [[ "$ssh_source" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]] \
           || [[ "$ssh_source" =~ : ]]; then
            ufw allow from "$ssh_source" to any port "$ssh_port" proto tcp comment "SSH from trusted source" >> "$LOG_FILE" 2>&1
            log_success "SSH (port ${ssh_port}) allowed from: ${ssh_source}"
        else
            log_warning "Invalid IP/CIDR '${ssh_source}'. Allowing SSH from any IP instead."
            # Use 'ufw limit' for rate limiting against brute force
            ufw limit "${ssh_port}/tcp" comment "SSH rate-limited" >> "$LOG_FILE" 2>&1
            log_success "SSH (port ${ssh_port}) rate-limited from any source."
        fi
    else
        # Rate limit SSH from all sources
        ufw limit "${ssh_port}/tcp" comment "SSH rate-limited" >> "$LOG_FILE" 2>&1
        log_success "SSH (port ${ssh_port}) rate-limited from any source."
    fi

    # Also allow standard port 22 if it's different (for current session safety)
    if [[ "$ssh_port" != "22" ]]; then
        log_warning "Temporarily keeping port 22 open during configuration."
        log_warning "You should remove this rule after confirming new SSH works."
        ufw allow 22/tcp comment "TEMPORARY: remove after testing new SSH port" >> "$LOG_FILE" 2>&1
    fi
}

# ---------------------------------------------------------------------------
# _firewall_configure_web — Optionally open HTTP/HTTPS ports
# ---------------------------------------------------------------------------
_firewall_configure_web() {
    echo ""

    if confirm "Does this server run a web server? (open ports 80 and 443)" "n"; then
        ufw allow 80/tcp  comment "HTTP"  >> "$LOG_FILE" 2>&1
        ufw allow 443/tcp comment "HTTPS" >> "$LOG_FILE" 2>&1
        log_success "Ports 80 (HTTP) and 443 (HTTPS) opened."
        save_state "firewall_web_server" "yes"

        # Also open for IPv6
        ufw allow in on any to any port 80  proto tcp comment "HTTP IPv6"  >> "$LOG_FILE" 2>&1 || true
        ufw allow in on any to any port 443 proto tcp comment "HTTPS IPv6" >> "$LOG_FILE" 2>&1 || true
    else
        log_info "Web server ports not opened."
        save_state "firewall_web_server" "no"
    fi

    # Optional database ports (restricted to localhost by default)
    if confirm "Open database ports? (MySQL/PostgreSQL — localhost only)" "n"; then
        ufw allow from 127.0.0.1 to any port 3306 proto tcp comment "MySQL (localhost)" >> "$LOG_FILE" 2>&1
        ufw allow from 127.0.0.1 to any port 5432 proto tcp comment "PostgreSQL (localhost)" >> "$LOG_FILE" 2>&1
        log_success "Database ports opened for localhost only."
    fi
}

# ---------------------------------------------------------------------------
# _firewall_configure_monitoring — Add rules for monitoring stack
# ---------------------------------------------------------------------------
_firewall_configure_monitoring() {
    echo ""
    log_info "Configuring monitoring stack firewall rules."
    log_info "By default, monitoring ports are restricted to localhost (127.0.0.1)."

    if confirm "Restrict monitoring ports to localhost only? (recommended)" "y"; then
        local monitoring_ports=(
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
            # Allow from Docker bridge network too
            ufw allow from 172.16.0.0/12 to any port "$port" comment "${svc} (Docker)" >> "$LOG_FILE" 2>&1
            log_info "  ${svc} (port ${port}): localhost + Docker networks."
        done

        log_success "Monitoring ports restricted to localhost and Docker networks."
    else
        # Allow from anywhere (user chose to expose them)
        local access_cidr
        access_cidr="$(ask "Source CIDR for monitoring access (blank = any)" "")"

        local monitoring_ports=(
            "${PORT_GRAFANA}" "${PORT_PROMETHEUS}" "${PORT_NODE_EXPORTER}"
            "${PORT_CADVISOR}" "${PORT_LOKI}" "${PORT_PROMTAIL}"
        )

        for port in "${monitoring_ports[@]}"; do
            if [[ -n "$access_cidr" ]]; then
                ufw allow from "$access_cidr" to any port "$port" comment "Monitoring" >> "$LOG_FILE" 2>&1
            else
                ufw allow "$port/tcp" comment "Monitoring" >> "$LOG_FILE" 2>&1
            fi
        done

        log_warning "Monitoring ports opened to: ${access_cidr:-any IP}"
    fi
}

# ---------------------------------------------------------------------------
# _firewall_custom_ports — Let user add additional ports
# ---------------------------------------------------------------------------
_firewall_custom_ports() {
    echo ""

    if ! confirm "Add any other custom firewall rules?" "n"; then
        log_info "No custom rules added."
        return 0
    fi

    while true; do
        local port_spec
        port_spec="$(ask "Port/protocol to open (e.g. '8443', '1194/udp', 'done' to finish)" "done")"
        port_spec="$(trim "$port_spec")"

        [[ "$port_spec" == "done" || -z "$port_spec" ]] && break

        local comment
        comment="$(ask "Description for this rule" "custom")"

        local source
        source="$(ask "Source IP/CIDR (blank = any)" "")"

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
# _firewall_docker_compat — Prevent UFW from breaking Docker networking
# ---------------------------------------------------------------------------
_firewall_docker_compat() {
    # Docker adds its own iptables rules and UFW can interfere with container
    # networking if we're not careful. The standard approach is to tell Docker
    # NOT to modify iptables (via daemon.json) and instead use UFW for all
    # rules — but that's complex and breaks NAT. Instead we use the UFW-Docker
    # approach: configure /etc/ufw/after.rules to allow Docker traffic.

    local after_rules="/etc/ufw/after.rules"
    backup_file "$after_rules" >> "$LOG_FILE" 2>&1 || true

    # Check if Docker compat block already added
    if grep -q "BEGIN DOCKER-UFW" "$after_rules" 2>/dev/null; then
        log_info "Docker UFW compatibility rules already present."
        return 0
    fi

    # Append Docker-compatible rules using the DOCKER-USER chain.
    # Docker creates DOCKER-USER chain in the filter table's FORWARD hook.
    # Rules in DOCKER-USER run before Docker's own DOCKER chain, so UFW
    # can control which traffic reaches containers.
    # We allow traffic on docker0 and br-* (bridge networks) so containers
    # can reach each other and the internet via NAT.
    cat >> "$after_rules" << 'DOCKER_RULES'

# BEGIN DOCKER-UFW
# Allow Docker bridge network traffic to pass through iptables FORWARD.
# Uses the DOCKER-USER chain which Docker creates and calls before its own rules.
*filter

# Allow established/related connections (stateful firewall)
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow traffic in/out of docker0 bridge (default Docker bridge)
-A DOCKER-USER -i docker0 -j ACCEPT
-A DOCKER-USER -o docker0 -j ACCEPT

# Allow traffic in/out of custom Docker bridge networks (br-*)
-A DOCKER-USER -i br-+ -j ACCEPT
-A DOCKER-USER -o br-+ -j ACCEPT

COMMIT
# END DOCKER-UFW
DOCKER_RULES

    log_success "Docker UFW compatibility rules added."
}

# ---------------------------------------------------------------------------
# _firewall_enable — Enable UFW with confirmation of SSH rule
# ---------------------------------------------------------------------------
_firewall_enable() {
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "2222")"

    # Final check: make sure SSH rule is present
    if ! ufw show added 2>/dev/null | grep -q "$ssh_port"; then
        log_warning "SSH port ${ssh_port} may not be in UFW rules!"
        log_warning "Adding it now as a safety measure..."
        ufw allow "${ssh_port}/tcp" comment "SSH safety rule" >> "$LOG_FILE" 2>&1
    fi

    echo ""
    printf "${YELLOW}${BOLD}  About to enable UFW. Your current SSH port (${ssh_port}) will remain open.${RESET}\n"
    printf "  ${YELLOW}If you get locked out, use your VPS provider's console to disable UFW:${RESET}\n"
    printf "  ${CYAN}  sudo ufw disable${RESET}\n\n"

    if [[ "${NONINTERACTIVE:-0}" == "1" ]]; then
        ufw --force enable >> "$LOG_FILE" 2>&1
    else
        ufw --force enable >> "$LOG_FILE" 2>&1
    fi

    log_success "UFW enabled."
}
