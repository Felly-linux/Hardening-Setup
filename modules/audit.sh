#!/usr/bin/env bash
# =============================================================================
# modules/audit.sh — System call and file access auditing
# =============================================================================
# THREAT MODEL:
#   Mitigates: Insider threats, privilege escalation detection, rootkit
#              persistence, lateral movement, compliance requirements
#   Attack surface reduced: Undetected privileged operations, log tampering
#   Operational impact: Small CPU overhead (~1-3%); generates audit logs
#                       in /var/log/audit/; use ausearch/aureport to query
#   Can break: Systems with very high syscall rates (heavy database servers)
#   Compatible with: Ubuntu 20.04+, Debian 11+
#   Note: AUDITD_ENABLED must be yes in profile to activate this module
# =============================================================================
set -euo pipefail

# Guard against double-sourcing
[[ -n "${_MODULE_AUDIT_LOADED:-}" ]] && return 0
readonly _MODULE_AUDIT_LOADED=1

# Source common library if not already loaded
if [[ -z "${_VPS_HARDENING_COMMON_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "${SCRIPT_DIR}/../lib/common.sh"
fi

# =============================================================================
# Profile variables with safe defaults
# =============================================================================
AUDITD_ENABLED="${AUDITD_ENABLED:-no}"
AUDITD_RULES_LEVEL="${AUDITD_RULES_LEVEL:-standard}"
DRY_RUN="${DRY_RUN:-0}"

# =============================================================================
# run_audit — Public entry point
# =============================================================================
run_audit() {
    log_section "SYSTEM CALL AND FILE ACCESS AUDITING (auditd)"

    # Respect the profile opt-in
    if [[ "${AUDITD_ENABLED}" != "yes" ]]; then
        log_info "auditd disabled in profile (AUDITD_ENABLED=no), skipping."
        return 0
    fi

    local total_steps=5
    local step=0

    (( step++ )) && log_step "$step" "$total_steps" "Installing auditd packages"
    _audit_install

    (( step++ )) && log_step "$step" "$total_steps" "Backing up existing audit rules"
    _audit_backup_rules

    (( step++ )) && log_step "$step" "$total_steps" "Deploying hardening rules (level: ${AUDITD_RULES_LEVEL})"
    _audit_deploy_rules

    (( step++ )) && log_step "$step" "$total_steps" "Enabling and starting auditd service"
    _audit_enable_service

    (( step++ )) && log_step "$step" "$total_steps" "Validating loaded rules"
    _audit_validate

    log_success "Auditd hardening complete (rules level: ${AUDITD_RULES_LEVEL})."
    log_info "Query audit events with: ausearch -k <key>  |  aureport --summary"
    mark_module_complete "audit"
}

# =============================================================================
# _audit_install — Ensure auditd and audispd-plugins are present
# =============================================================================
_audit_install() {
    local packages=(auditd audispd-plugins)
    local missing=()

    for pkg in "${packages[@]}"; do
        if ! package_installed "$pkg"; then
            missing+=("$pkg")
        fi
    done

    if [[ "${#missing[@]}" -eq 0 ]]; then
        log_info "auditd packages already installed."
        return 0
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would install: ${missing[*]}"
        return 0
    fi

    log_info "Installing: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "${missing[@]}" >> "$LOG_FILE" 2>&1
    log_success "auditd packages installed."
}

# =============================================================================
# _audit_backup_rules — Back up /etc/audit/rules.d/ before any changes
# =============================================================================
_audit_backup_rules() {
    local rules_dir="/etc/audit/rules.d"

    if [[ ! -d "$rules_dir" ]]; then
        log_info "Audit rules directory does not exist yet: ${rules_dir}"
        return 0
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would backup all files in ${rules_dir}"
        return 0
    fi

    local backed_up=0
    while IFS= read -r -d '' rulefile; do
        backup_file "$rulefile" >> "$LOG_FILE" 2>&1 || true
        (( backed_up++ )) || true
    done < <(find "$rules_dir" -maxdepth 1 -type f -name "*.rules" -print0 2>/dev/null)

    if [[ "$backed_up" -gt 0 ]]; then
        log_success "Backed up ${backed_up} existing rule file(s) from ${rules_dir}"
    else
        log_info "No existing rule files to back up in ${rules_dir}"
    fi
}

# =============================================================================
# _audit_deploy_rules — Copy hardening.rules and optionally add paranoid rules
# =============================================================================
_audit_deploy_rules() {
    local src_rules="${PROJECT_ROOT}/configs/audit/hardening.rules"
    local dst_rules="/etc/audit/rules.d/hardening.rules"
    local rules_dir="/etc/audit/rules.d"

    if [[ ! -f "$src_rules" ]]; then
        log_error "Source audit rules not found: ${src_rules}"
        return 1
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would deploy: ${src_rules} → ${dst_rules}"
        if [[ "${AUDITD_RULES_LEVEL}" == "paranoid" ]]; then
            log_info "[DRY-RUN] Would append paranoid extra rules to ${dst_rules}"
        fi
        return 0
    fi

    # Ensure the rules directory exists
    mkdir -p "$rules_dir"

    # Idempotency: only copy if content differs (paranoid addition may change this below)
    local needs_update=0
    if [[ ! -f "$dst_rules" ]]; then
        needs_update=1
    else
        if ! diff -q "$src_rules" "$dst_rules" &>/dev/null; then
            needs_update=1
        fi
    fi

    if [[ "$needs_update" -eq 1 ]]; then
        cp -p "$src_rules" "$dst_rules"
        chmod 640 "$dst_rules"
        log_success "Deployed audit rules: ${dst_rules}"
    else
        log_info "Audit rules already up to date: ${dst_rules}"
    fi

    # --- Paranoid additional rules ---
    if [[ "${AUDITD_RULES_LEVEL}" == "paranoid" ]]; then
        _audit_add_paranoid_rules "$dst_rules"
    fi
}

# =============================================================================
# _audit_add_paranoid_rules — Append high-volume rules for paranoid level
# These generate significant audit log volume. Use only when required.
# =============================================================================
_audit_add_paranoid_rules() {
    local dst_rules="$1"
    local paranoid_marker="# BEGIN PARANOID RULES"

    # Idempotency: only append if marker is not already present
    if grep -q "$paranoid_marker" "$dst_rules" 2>/dev/null; then
        log_info "Paranoid rules already present in ${dst_rules}"
        return 0
    fi

    log_info "Appending paranoid-level rules to ${dst_rules}"

    cat >> "$dst_rules" << 'PARANOID_RULES'

# BEGIN PARANOID RULES
# =============================================================================
# Paranoid extra rules (AUDITD_RULES_LEVEL=paranoid)
# WARNING: These generate high audit log volume. Not suitable for
# high-throughput servers without adequate storage and log rotation.
# =============================================================================

# Audit ALL execve calls (every program execution) — very high volume
-a always,exit -F arch=b64 -S execve -k exec_all
-a always,exit -F arch=b32 -S execve -k exec_all

# Watch entire /etc/ tree for write/attribute changes
-w /etc/ -p wa -k etc_changes

# Module insertion and removal
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_unload

# Finit_module and init_module syscalls (module loading via syscall)
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b32 -S init_module -S finit_module -k module_load

# END PARANOID RULES
PARANOID_RULES

    chmod 640 "$dst_rules"
    log_success "Paranoid rules appended to ${dst_rules}"
}

# =============================================================================
# _audit_enable_service — Enable and start auditd
# =============================================================================
_audit_enable_service() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would enable and start auditd service"
        log_info "[DRY-RUN] Would run: augenrules --load  (or service auditd reload)"
        return 0
    fi

    # Enable at boot
    systemctl enable auditd >> "$LOG_FILE" 2>&1 || true

    # Load the rules — prefer augenrules (compiles rules.d/ into a single file)
    if command_exists augenrules; then
        log_info "Loading rules via augenrules --load..."
        if augenrules --load >> "$LOG_FILE" 2>&1; then
            log_success "augenrules --load succeeded."
        else
            log_warning "augenrules --load failed; falling back to service reload."
            service auditd reload >> "$LOG_FILE" 2>&1 || true
        fi
    else
        log_info "augenrules not found; using service auditd reload..."
        service auditd reload >> "$LOG_FILE" 2>&1 || true
    fi

    # Ensure auditd is running
    if service_running auditd; then
        log_success "auditd is running."
    else
        log_info "Starting auditd..."
        systemctl start auditd >> "$LOG_FILE" 2>&1
        if service_running auditd; then
            log_success "auditd started successfully."
        else
            log_error "auditd failed to start. Check: journalctl -u auditd"
            return 1
        fi
    fi
}

# =============================================================================
# _audit_validate — Confirm that audit rules are loaded
# =============================================================================
_audit_validate() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would validate: auditctl -l shows rules loaded"
        return 0
    fi

    if ! command_exists auditctl; then
        log_warning "auditctl not found; cannot validate loaded rules."
        return 0
    fi

    local rule_count
    rule_count="$(auditctl -l 2>/dev/null | grep -v "^No rules" | grep -c "." || echo "0")"

    if [[ "$rule_count" -gt 0 ]]; then
        log_success "Audit rules loaded: ${rule_count} rule(s) active."
        log_info "Preview of loaded rules:"
        auditctl -l 2>/dev/null | head -20 | while IFS= read -r line; do
            log_info "  ${line}"
        done
    else
        # auditctl -l returns "No rules" or empty when nothing is loaded
        local raw_output
        raw_output="$(auditctl -l 2>/dev/null || true)"
        if echo "$raw_output" | grep -qi "no rules"; then
            log_warning "auditctl reports no rules loaded. Rules may load after a service restart."
        else
            log_warning "Could not determine rule count. Output: ${raw_output}"
        fi
    fi
}
