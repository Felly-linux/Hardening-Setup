#!/usr/bin/env bash
# =============================================================================
# lib/backups.sh — File backup/restore helpers and logged command runner
# =============================================================================
# Depends on lib/logging.sh and lib/helpers.sh (BACKUP_DIR, LOG_FILE).
# =============================================================================

[[ -n "${_VPS_BACKUPS_LOADED:-}" ]] && return 0
readonly _VPS_BACKUPS_LOADED=1

set -euo pipefail

# =============================================================================
# BACKUP / RESTORE HELPERS
# =============================================================================

# backup_file(path) — Copies a file to BACKUP_DIR with a timestamp suffix.
# Idempotent: each call creates a uniquely-timestamped copy.
# Returns (echoes) the destination backup path.
backup_file() {
    local src="$1"
    local backup_dir="${BACKUP_DIR:-/tmp/vps-hardening-backups}"

    if [[ ! -f "$src" ]]; then
        log_warning "backup_file: source does not exist: $src"
        return 0
    fi

    mkdir -p "$backup_dir"

    local filename
    filename="$(basename "$src")"
    local timestamp
    timestamp="$(date '+%Y%m%d_%H%M%S')"
    local dest="${backup_dir}/${filename}.${timestamp}.bak"

    cp -p "$src" "$dest"
    # Sidecar records the original absolute path for restore_file_auto
    echo "$src" > "${dest}.orig"

    log_success "Backed up: $src → $dest"
    echo "$dest"
}

# restore_file_auto(backup_path) — Restores a backup to its original location
# by reading the .orig sidecar written by backup_file.
restore_file_auto() {
    local backup_path="$1"
    local sidecar="${backup_path}.orig"

    if [[ ! -f "$backup_path" ]]; then
        log_error "restore_file_auto: backup not found: $backup_path"
        return 1
    fi

    if [[ ! -f "$sidecar" ]]; then
        log_warning "restore_file_auto: no .orig sidecar for ${backup_path}"
        log_warning "Cannot determine original path. Skipping."
        return 1
    fi

    local original_path
    original_path="$(cat "$sidecar")"

    restore_file "$backup_path" "$original_path"
    echo "$original_path"
}

# restore_file(backup_path, target_path) — Copies a backup back to its original
# location. Performs a safety backup of the current target before overwriting.
restore_file() {
    local backup_path="$1"
    local target_path="$2"

    if [[ ! -f "$backup_path" ]]; then
        log_error "restore_file: backup does not exist: $backup_path"
        return 1
    fi

    # Safety: back up whatever is currently at the target before clobbering it
    if [[ -f "$target_path" ]]; then
        local safety_dest
        safety_dest="$(backup_file "$target_path")"
        log_info "Safety backup of current target created: $safety_dest"
    fi

    local target_dir
    target_dir="$(dirname "$target_path")"
    mkdir -p "$target_dir"

    cp -p "$backup_path" "$target_path"
    log_success "Restored: $backup_path → $target_path"
}

# list_backups([module_name]) — Lists backup files in BACKUP_DIR.
# When module_name is provided, filters to files whose names begin with that prefix.
list_backups() {
    local module_prefix="${1:-}"
    local backup_dir="${BACKUP_DIR:-/tmp/vps-hardening-backups}"

    if [[ ! -d "$backup_dir" ]]; then
        log_warning "Backup directory does not exist: $backup_dir"
        return 0
    fi

    if [[ -n "$module_prefix" ]]; then
        find "$backup_dir" -maxdepth 1 -name "${module_prefix}*" -type f | sort
    else
        find "$backup_dir" -maxdepth 1 -name "*.bak" -type f | sort
    fi
}

# =============================================================================
# LOGGED COMMAND RUNNER
# =============================================================================

# run_with_log(label, cmd...) — Runs a command, streaming output to LOG_FILE.
# On failure, prints the last 20 lines of log output to stderr.
run_with_log() {
    local label="$1"
    shift
    local cmd=("$@")
    local log_file="${LOG_FILE:-/var/log/vps-hardening/install.log}"

    _ensure_log_dir
    log_info "Running: ${cmd[*]}"

    local rc=0
    "${cmd[@]}" >> "$log_file" 2>&1 || rc=$?

    if [[ $rc -ne 0 ]]; then
        log_error "Command failed (exit $rc): ${cmd[*]}"
        log_error "Last log lines:"
        tail -20 "$log_file" | while IFS= read -r line; do
            printf "  ${RED}│${RESET} %s\n" "$line"
        done
        return $rc
    fi
    return 0
}
