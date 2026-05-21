#!/usr/bin/env bash
# =============================================================================
# modules/permissions.sh — Filesystem permission hardening
# =============================================================================
# THREAT MODEL:
#   Mitigates: /tmp-based malware execution (noexec), SUID binary privilege
#              escalation, world-writable directory abuse, umask-weak file creation
#   Attack surface reduced: Local privilege escalation vectors
#   Operational impact: /tmp noexec may break some build tools (npm, pip, cmake)
#                       and installer scripts that write executables to /tmp.
#                       Test carefully on development machines.
#   Can break: Build systems, some package managers if PERMISSIONS_TMP_NOEXEC=yes
#   Compatible with: Ubuntu 20.04+, Debian 11+
# =============================================================================
set -euo pipefail

# Guard against double-sourcing
[[ -n "${_MODULE_PERMISSIONS_LOADED:-}" ]] && return 0
readonly _MODULE_PERMISSIONS_LOADED=1

# Source common library if not already loaded
if [[ -z "${_VPS_HARDENING_COMMON_LOADED:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "${SCRIPT_DIR}/../lib/common.sh"
fi

# =============================================================================
# Profile variables with safe defaults
# =============================================================================
PERMISSIONS_TMP_NOEXEC="${PERMISSIONS_TMP_NOEXEC:-yes}"
PERMISSIONS_UMASK="${PERMISSIONS_UMASK:-027}"
PERMISSIONS_AUDIT_SUID="${PERMISSIONS_AUDIT_SUID:-yes}"
DRY_RUN="${DRY_RUN:-0}"

# Persistent storage for audit results
readonly _HARDENING_STATE_DIR="/var/lib/vps-hardening"

# =============================================================================
# run_permissions — Public entry point
# =============================================================================
run_permissions() {
    log_section "FILESYSTEM PERMISSION HARDENING"

    local total_steps=4
    local step=0

    (( step++ )) && log_step "$step" "$total_steps" "/tmp noexec enforcement"
    _permissions_tmp_noexec

    (( step++ )) && log_step "$step" "$total_steps" "System-wide umask hardening"
    _permissions_umask

    (( step++ )) && log_step "$step" "$total_steps" "SUID/SGID binary audit"
    _permissions_audit_suid

    (( step++ )) && log_step "$step" "$total_steps" "World-writable directory scan"
    _permissions_world_writable

    log_success "Filesystem permission hardening complete."
    mark_module_complete "permissions"
}

# =============================================================================
# _permissions_tmp_noexec — Mount /tmp with noexec,nodev,nosuid
# =============================================================================
_permissions_tmp_noexec() {
    if [[ "${PERMISSIONS_TMP_NOEXEC}" != "yes" ]]; then
        log_info "PERMISSIONS_TMP_NOEXEC=no — skipping /tmp hardening"
        return 0
    fi

    local mount_unit="/etc/systemd/system/tmp.mount"

    # --- Idempotency: check if /tmp already mounted with noexec ---
    if _tmp_has_noexec; then
        log_info "/tmp already mounted with noexec. Skipping."
        # Still ensure our unit file is in place for persistence
        if [[ ! -f "$mount_unit" ]]; then
            _write_tmp_mount_unit "$mount_unit"
        fi
        return 0
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        log_info "[DRY-RUN] Would create ${mount_unit} with noexec,nodev,nosuid options"
        log_info "[DRY-RUN] Would run: systemctl daemon-reload && mount -o remount /tmp"
        return 0
    fi

    # Write the systemd override unit
    _write_tmp_mount_unit "$mount_unit"

    # Reload systemd to pick up the new unit
    systemctl daemon-reload >> "$LOG_FILE" 2>&1

    # Attempt to remount /tmp immediately (if it is already a separate mount)
    if mount | grep -q " /tmp "; then
        log_info "Remounting /tmp with hardened options..."
        if mount -o remount,mode=1777,strictatime,noexec,nodev,nosuid /tmp 2>/dev/null; then
            log_success "/tmp remounted with noexec,nodev,nosuid."
        else
            log_warning "Could not remount /tmp immediately. Will take effect after next boot/mount."
        fi
    else
        # /tmp is on root partition — enable the unit so it mounts at boot
        systemctl enable tmp.mount >> "$LOG_FILE" 2>&1 || true
        log_info "/tmp is on root partition; tmp.mount unit enabled for next boot."
        log_warning "Reboot or run 'systemctl start tmp.mount' to apply noexec immediately."
    fi

    # Validate
    if _tmp_has_noexec; then
        log_success "/tmp noexec is active."
    else
        log_warning "/tmp noexec not yet active (may require reboot)."
    fi
}

# _tmp_has_noexec — Returns 0 if /tmp is currently mounted with noexec
_tmp_has_noexec() {
    grep -q " /tmp " /proc/mounts 2>/dev/null \
        && grep " /tmp " /proc/mounts 2>/dev/null | grep -q "noexec"
}

# _write_tmp_mount_unit — Write the systemd tmp.mount override
_write_tmp_mount_unit() {
    local unit_file="$1"

    # Backup if it already exists (user may have customised it)
    if [[ -f "$unit_file" ]]; then
        backup_file "$unit_file" >> "$LOG_FILE" 2>&1 || true
    fi

    cat > "$unit_file" << 'EOF'
# /etc/systemd/system/tmp.mount
# Override for /tmp — deployed by VPS Hardening Suite (permissions module)
# Mounts /tmp as a tmpfs with hardened options to block malware execution.
# Options explanation:
#   noexec  — binaries cannot be directly executed from /tmp
#   nodev   — device files in /tmp have no effect
#   nosuid  — setuid/setgid bits on files in /tmp are ignored
#   mode=1777 — sticky bit; only owner can delete their own files
#   strictatime — required by some legacy tools; atime updates on read
[Unit]
Description=Temporary Directory (/tmp) — hardened
Documentation=man:hier(7)
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid,size=512m

[Install]
WantedBy=local-fs.target
EOF
    chmod 644 "$unit_file"
    log_success "Written: ${unit_file}"
}

# =============================================================================
# _permissions_umask — Write /etc/profile.d/hardening-umask.sh
# =============================================================================
_permissions_umask() {
    if [[ -z "${PERMISSIONS_UMASK:-}" ]]; then
        log_info "PERMISSIONS_UMASK not set — skipping umask configuration"
        return 0
    fi

    local umask_file="/etc/profile.d/hardening-umask.sh"
    local target_umask="${PERMISSIONS_UMASK}"

    # Idempotency: check if file already contains the same umask
    if [[ -f "$umask_file" ]]; then
        if grep -q "umask ${target_umask}" "$umask_file" 2>/dev/null; then
            log_info "umask ${target_umask} already configured in ${umask_file}"
            return 0
        fi
        # Content differs — backup before overwriting
        if [[ "${DRY_RUN}" == "1" ]]; then
            log_info "[DRY-RUN] Would update umask in ${umask_file} to ${target_umask}"
            return 0
        fi
        backup_file "$umask_file" >> "$LOG_FILE" 2>&1 || true
    else
        if [[ "${DRY_RUN}" == "1" ]]; then
            log_info "[DRY-RUN] Would write ${umask_file} with umask ${target_umask}"
            return 0
        fi
    fi

    cat > "$umask_file" << EOF
#!/bin/sh
# /etc/profile.d/hardening-umask.sh
# System-wide umask — deployed by VPS Hardening Suite (permissions module)
# umask ${target_umask}: owner full, group read+execute, others nothing
# Effect on new files: 640 (rw-r-----)
# Effect on new dirs:  750 (rwxr-x---)
umask ${target_umask}
EOF
    chmod 644 "$umask_file"
    log_success "umask ${target_umask} configured via ${umask_file}"

    # Also update /etc/login.defs for login sessions
    local login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        if grep -q "^UMASK" "$login_defs"; then
            sed -i "s|^UMASK.*|UMASK\t${target_umask}|" "$login_defs"
        else
            printf 'UMASK\t%s\n' "$target_umask" >> "$login_defs"
        fi
        log_info "UMASK updated in /etc/login.defs"
    fi
}

# =============================================================================
# _permissions_audit_suid — Find SUID/SGID binaries and report changes
# =============================================================================
_permissions_audit_suid() {
    if [[ "${PERMISSIONS_AUDIT_SUID}" != "yes" ]]; then
        log_info "PERMISSIONS_AUDIT_SUID=no — skipping SUID audit"
        return 0
    fi

    # Ensure state directory exists (audit is read-only, so runs regardless of DRY_RUN)
    mkdir -p "$_HARDENING_STATE_DIR" 2>/dev/null || true

    local today
    today="$(date +%Y%m%d)"
    local audit_file="${_HARDENING_STATE_DIR}/suid_audit_${today}.txt"
    local prev_audit
    prev_audit="$(find "$_HARDENING_STATE_DIR" -maxdepth 1 -name "suid_audit_*.txt" \
        ! -name "suid_audit_${today}.txt" -type f 2>/dev/null | sort -r | head -1 || true)"

    log_info "Scanning filesystem for SUID/SGID binaries..."
    log_info "Results → ${audit_file}"

    # Run the scan (read-only — runs even in DRY_RUN)
    {
        printf "# SUID/SGID audit — %s\n" "$(date --iso-8601=seconds)"
        printf "# Host: %s\n" "$(hostname)"
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort
    } > "$audit_file"

    local suid_count
    suid_count="$(grep -c "^/" "$audit_file" 2>/dev/null || echo "0")"
    log_info "Found ${suid_count} SUID/SGID binaries."

    # --- Diff against previous audit ---
    if [[ -n "$prev_audit" && -f "$prev_audit" ]]; then
        log_info "Comparing against previous audit: $(basename "$prev_audit")"

        # Extract just the file paths (skip comment lines starting with #)
        local new_entries
        new_entries="$(
            comm -13 \
                <(grep "^/" "$prev_audit" 2>/dev/null | sort) \
                <(grep "^/" "$audit_file"  2>/dev/null | sort) \
            || true
        )"

        local removed_entries
        removed_entries="$(
            comm -23 \
                <(grep "^/" "$prev_audit" 2>/dev/null | sort) \
                <((grep "^/" "$audit_file"  2>/dev/null | sort)) \
            || true
        )"

        if [[ -n "$new_entries" ]]; then
            log_warning "NEW SUID/SGID binaries detected since last audit:"
            while IFS= read -r entry; do
                [[ -n "$entry" ]] && log_warning "  [+NEW] ${entry}"
            done <<< "$new_entries"
        else
            log_success "No new SUID/SGID binaries since last audit."
        fi

        if [[ -n "$removed_entries" ]]; then
            log_info "SUID/SGID binaries removed since last audit:"
            while IFS= read -r entry; do
                [[ -n "$entry" ]] && log_info "  [-REM] ${entry}"
            done <<< "$removed_entries"
        fi
    else
        log_info "No previous audit found; this is the baseline. Compare on next run."
    fi

    log_success "SUID/SGID audit saved: ${audit_file}"
    log_info "NOTE: No binaries were removed. Review manually and use 'chmod u-s' to strip SUID if needed."
}

# =============================================================================
# _permissions_world_writable — Find and report world-writable directories
# =============================================================================
_permissions_world_writable() {
    log_info "Scanning for world-writable directories (without sticky bit)..."

    # -perm -0002: world-writable bit set
    # ! -perm -1000: sticky bit NOT set
    # Directories with sticky bit (like /tmp, /var/tmp) are acceptable
    local ww_dirs
    ww_dirs="$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | sort || true)"

    if [[ -z "$ww_dirs" ]]; then
        log_success "No world-writable directories without sticky bit found."
        return 0
    fi

    local count
    count="$(printf '%s\n' "$ww_dirs" | grep -c "." 2>/dev/null || echo "0")"

    log_warning "${count} world-writable director(ies) without sticky bit found:"
    while IFS= read -r dir; do
        [[ -n "$dir" ]] && log_warning "  [WW] ${dir}"
    done <<< "$ww_dirs"

    log_warning "World-writable directories allow any local user to write/overwrite files."
    log_warning "Review the above list. To add sticky bit: chmod +t <directory>"
    log_warning "To remove world-write: chmod o-w <directory>"
    log_warning "No automatic changes have been made."
}
