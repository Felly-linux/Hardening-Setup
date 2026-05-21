#!/usr/bin/env bash
# =============================================================================
# lib/validation.sh — Post-install verification functions
# =============================================================================
# Provides granular validators and a dispatcher (post_module_verify) that
# runs the appropriate checks for each module after installation.
# Depends on lib/logging.sh (log_*) and lib/helpers.sh (command_exists, etc.)
# =============================================================================

[[ -n "${_VPS_VALIDATION_LOADED:-}" ]] && return 0
readonly _VPS_VALIDATION_LOADED=1

set -euo pipefail

# =============================================================================
# INDIVIDUAL VALIDATORS
# =============================================================================

# validate_sshd_config() — Runs `sshd -t` to check the SSH daemon config.
# Returns 0 on success, 1 on failure. Logs the result.
validate_sshd_config() {
    log_info "Validating sshd configuration..."
    if sshd -t 2>/dev/null; then
        log_success "sshd config is valid."
        return 0
    else
        local err
        err="$(sshd -t 2>&1 || true)"
        log_error "sshd config validation failed: ${err}"
        return 1
    fi
}

# validate_sysctl_value(key, expected) — Checks that `sysctl -n key` equals
# the expected string. Logs PASS or FAIL.
validate_sysctl_value() {
    local key="$1"
    local expected="$2"
    local actual

    actual="$(sysctl -n "$key" 2>/dev/null || true)"
    if [[ "$actual" == "$expected" ]]; then
        log_success "sysctl check PASS: ${key} = ${actual}"
        return 0
    else
        log_error "sysctl check FAIL: ${key} expected='${expected}' actual='${actual}'"
        return 1
    fi
}

# validate_ufw_active() — Checks that ufw reports "Status: active".
validate_ufw_active() {
    log_info "Checking ufw status..."
    if command_exists ufw && ufw status 2>/dev/null | grep -q "^Status: active"; then
        log_success "ufw is active."
        return 0
    else
        log_error "ufw is not active or not installed."
        return 1
    fi
}

# validate_service_active(name) — Verifies a systemd service is active.
validate_service_active() {
    local name="$1"
    log_info "Checking service '${name}'..."
    if systemctl is-active --quiet "$name" 2>/dev/null; then
        log_success "Service '${name}' is active."
        return 0
    else
        log_error "Service '${name}' is NOT active."
        return 1
    fi
}

# validate_docker_daemon() — Runs `docker info` and checks for a usable daemon.
# Logs an informational note when experimental mode is not enabled.
validate_docker_daemon() {
    log_info "Validating Docker daemon..."
    if ! command_exists docker; then
        log_error "docker command not found."
        return 1
    fi

    local info
    if ! info="$(docker info 2>&1)"; then
        log_error "docker info failed: ${info}"
        return 1
    fi

    log_success "Docker daemon is reachable."

    # Informational: report whether experimental mode is on
    if echo "$info" | grep -qi "experimental: true"; then
        log_info "Docker experimental mode: enabled."
    else
        log_info "Docker experimental mode: disabled (not required)."
    fi

    return 0
}

# check_dependencies(dep1 dep2 ...) — Verifies all listed commands are in PATH.
# Returns 0 only if every dependency is present; logs any missing ones.
check_dependencies() {
    local missing=()
    local dep

    for dep in "$@"; do
        if ! command_exists "$dep"; then
            log_error "Missing dependency: ${dep}"
            missing+=("$dep")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        log_error "Install missing dependencies before continuing: ${missing[*]}"
        return 1
    fi

    log_success "All dependencies present: $*"
    return 0
}

# =============================================================================
# MODULE DISPATCHER
# =============================================================================

# post_module_verify(module_id) — Runs the appropriate validation suite for the
# given module name after installation. Extend the case statement as new
# modules are added to the suite.
post_module_verify() {
    local module_id="$1"
    local rc=0

    log_section "Post-install verification: ${module_id}"

    case "$module_id" in
        ssh|ssh-hardening)
            validate_sshd_config || rc=1
            validate_service_active sshd || validate_service_active ssh || rc=1
            ;;
        ufw|firewall)
            validate_ufw_active || rc=1
            ;;
        sysctl|kernel-hardening)
            validate_sysctl_value "net.ipv4.ip_forward" "0" || rc=1
            validate_sysctl_value "kernel.dmesg_restrict" "1" || rc=1
            validate_sysctl_value "net.ipv4.conf.all.rp_filter" "1" || rc=1
            validate_sysctl_value "net.ipv4.conf.all.accept_redirects" "0" || rc=1
            validate_sysctl_value "net.ipv4.conf.all.send_redirects" "0" || rc=1
            validate_sysctl_value "net.ipv4.tcp_syncookies" "1" || rc=1
            ;;
        fail2ban)
            validate_service_active fail2ban || rc=1
            ;;
        docker)
            validate_docker_daemon || rc=1
            validate_service_active docker || rc=1
            ;;
        crowdsec)
            validate_service_active crowdsec || rc=1
            ;;
        monitoring|prometheus|grafana)
            validate_service_active prometheus || rc=1
            validate_service_active grafana-server || rc=1
            ;;
        wazuh)
            validate_service_active wazuh-agent \
                || validate_service_active wazuh-manager || rc=1
            ;;
        suricata)
            validate_service_active suricata || rc=1
            ;;
        *)
            log_warning "No specific validation defined for module '${module_id}'. Skipping."
            ;;
    esac

    if (( rc == 0 )); then
        log_success "Verification PASSED for module '${module_id}'."
    else
        log_error "Verification FAILED for module '${module_id}'. Review the errors above."
    fi

    return $rc
}
