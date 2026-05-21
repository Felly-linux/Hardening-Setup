#!/usr/bin/env bash
# =============================================================================
# install.sh — Linux Hardening Framework
# =============================================================================
# Profile-driven, idempotent, validated security hardening for Linux servers.
#
# Usage:
#   sudo bash install.sh --profile vps
#   sudo bash install.sh --profile paranoid --dry-run
#   sudo bash install.sh --profile docker-host --module ssh --module firewall
#   sudo bash install.sh --audit-only
#   sudo bash install.sh --rollback ssh
#
# Options:
#   --profile NAME          Load profiles/NAME.conf (required unless using menu)
#   --dry-run               Print all actions; make zero changes to the system
#   --audit-only            Run validation checks only; produce a score report
#   --module NAME           Override profile module selection (repeatable)
#   --skip-module NAME      Skip a module (repeatable)
#   --force                 Re-run modules already marked complete
#   --rollback MODULE       Restore backed-up config files for a module
#   --report json|text      Print execution summary in specified format
#   --non-interactive       Skip all prompts; use profile defaults
#   --list-profiles         List available profiles and exit
#   --help                  Show this help
#
# Profiles: vps, docker-host, homelab, desktop, paranoid
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Bootstrap: resolve project root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT="$SCRIPT_DIR"
export LIB_DIR="${PROJECT_ROOT}/lib"

# Load shared library
if [[ ! -f "${LIB_DIR}/common.sh" ]]; then
    echo "FATAL: ${LIB_DIR}/common.sh not found" >&2
    exit 1
fi
# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
PROFILE_NAME=""
DRY_RUN=0
AUDIT_ONLY=0
FORCE_REINSTALL=0
NONINTERACTIVE=0
ROLLBACK_MODULE=""
REPORT_FORMAT=""
declare -a SELECTED_MODULES=()
declare -a SKIP_MODULES=()
declare -a MODULE_RESULTS=()   # "module:status:duration"

export DRY_RUN NONINTERACTIVE

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    local args=("$@")
    local i=0
    while (( i < ${#args[@]} )); do
        local arg="${args[$i]}"
        case "$arg" in
            --profile)
                (( i++ )); PROFILE_NAME="${args[$i]:-}"
                ;;
            --profile=*)
                PROFILE_NAME="${arg#--profile=}"
                ;;
            --dry-run)
                DRY_RUN=1; export DRY_RUN
                ;;
            --audit-only)
                AUDIT_ONLY=1
                ;;
            --force)
                FORCE_REINSTALL=1
                ;;
            --non-interactive)
                NONINTERACTIVE=1; export NONINTERACTIVE
                ;;
            --module)
                (( i++ )); SELECTED_MODULES+=("${args[$i]:-}")
                ;;
            --module=*)
                SELECTED_MODULES+=("${arg#--module=}")
                ;;
            --skip-module)
                (( i++ )); SKIP_MODULES+=("${args[$i]:-}")
                ;;
            --skip-module=*)
                SKIP_MODULES+=("${arg#--skip-module=}")
                ;;
            --rollback)
                (( i++ )); ROLLBACK_MODULE="${args[$i]:-}"
                ;;
            --rollback=*)
                ROLLBACK_MODULE="${arg#--rollback=}"
                ;;
            --report)
                (( i++ )); REPORT_FORMAT="${args[$i]:-text}"
                ;;
            --report=*)
                REPORT_FORMAT="${arg#--report=}"
                ;;
            --list-profiles)
                _list_profiles
                exit 0
                ;;
            --help|-h)
                _show_usage
                exit 0
                ;;
            *)
                log_warning "Unknown argument: ${arg}"
                ;;
        esac
        (( i++ ))
    done
}

_show_usage() {
    cat << 'EOF'
Linux Hardening Framework

Usage:
  sudo bash install.sh [OPTIONS]

Options:
  --profile NAME          Load profiles/NAME.conf
  --dry-run               Print actions, make no changes
  --audit-only            Run validation checks, output score
  --module NAME           Override profile module list (repeatable)
  --skip-module NAME      Skip a module (repeatable)
  --force                 Re-run completed modules
  --rollback MODULE       Restore backed-up configs for a module
  --report json|text      Output execution summary
  --non-interactive       No prompts, use profile defaults
  --list-profiles         List available profiles
  --help                  Show this help

Profiles:
  vps           SSH + UFW + Fail2Ban + CrowdSec + sysctl hardening
  docker-host   VPS profile + Docker daemon hardening + monitoring stack
  homelab       Relaxed settings for trusted home network environments
  desktop       Minimal: UFW + sysctl + filesystem permissions only
  paranoid      All modules, strictest settings — high breakage risk

Examples:
  sudo bash install.sh --profile vps
  sudo bash install.sh --profile paranoid --dry-run
  sudo bash install.sh --profile docker-host --skip-module monitoring
  sudo bash install.sh --audit-only
  sudo bash install.sh --rollback ssh

EOF
}

_list_profiles() {
    local profiles_dir="${PROJECT_ROOT}/profiles"
    echo ""
    printf "  %-20s %s\n" "PROFILE" "DESCRIPTION"
    printf "  %-20s %s\n" "───────" "───────────"
    for conf in "${profiles_dir}"/*.conf; do
        [[ -f "$conf" ]] || continue
        local name
        name="$(basename "$conf" .conf)"
        local desc
        desc="$(grep '^PROFILE_DESC=' "$conf" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "")"
        printf "  %-20s %s\n" "$name" "$desc"
    done
    echo ""
}

# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------
load_profile() {
    local name="$1"
    local profile_file="${PROJECT_ROOT}/profiles/${name}.conf"

    if [[ ! -f "$profile_file" ]]; then
        log_error "Profile not found: ${profile_file}"
        log_error "Available profiles:"
        _list_profiles
        exit 1
    fi

    # shellcheck source=/dev/null
    source "$profile_file"
    log_success "Profile loaded: ${name}"

    # If --module flags were given, they override profile's ENABLED_MODULES
    if (( ${#SELECTED_MODULES[@]} > 0 )); then
        ENABLED_MODULES="${SELECTED_MODULES[*]}"
        log_info "Module override: ${ENABLED_MODULES}"
    fi

    # Apply --skip-module flags
    for skipped in "${SKIP_MODULES[@]:-}"; do
        ENABLED_MODULES="${ENABLED_MODULES//$skipped/}"
        log_info "Skipping module: ${skipped}"
    done
}

# ---------------------------------------------------------------------------
# Module registry — all available modules in execution order
# ---------------------------------------------------------------------------
# Format: "id:script_path:display_name"
declare -a MODULE_REGISTRY=(
    "preflight:modules/preflight.sh:Pre-flight checks"
    "system:modules/system.sh:System hardening base"
    "users:modules/users.sh:User management"
    "ssh:modules/ssh.sh:SSH hardening"
    "firewall:modules/firewall.sh:Firewall (UFW)"
    "fail2ban:modules/fail2ban.sh:Fail2Ban"
    "crowdsec:modules/crowdsec.sh:CrowdSec"
    "sysctl:modules/sysctl.sh:Kernel parameter hardening"
    "audit:modules/audit.sh:System call auditing (auditd)"
    "permissions:modules/permissions.sh:Filesystem permissions"
    "docker:modules/docker.sh:Docker Engine"
    "monitoring:modules/monitoring.sh:Monitoring stack"
)

_module_id()     { echo "${1%%:*}"; }
_module_script() { local s="${1#*:}"; echo "${s%%:*}"; }
_module_name()   { echo "${1##*:}"; }

# ---------------------------------------------------------------------------
# Module execution
# ---------------------------------------------------------------------------
run_module() {
    local entry="$1"
    local id script name
    id="$(_module_id "$entry")"
    script="$(_module_script "$entry")"
    name="$(_module_name "$entry")"

    # Idempotency check
    if [[ "$FORCE_REINSTALL" -eq 0 ]] && module_completed "$id"; then
        log_info "Module '${name}' already completed. (--force to re-run)"
        MODULE_RESULTS+=("${id}:skipped:0")
        return 0
    fi

    local script_path="${PROJECT_ROOT}/${script}"
    if [[ ! -f "$script_path" ]]; then
        log_error "Module script not found: ${script_path}"
        MODULE_RESULTS+=("${id}:missing:0")
        return 1
    fi

    log_section "MODULE: ${name}"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_info "[DRY-RUN] Would execute module: ${name}"
        MODULE_RESULTS+=("${id}:dry-run:0")
        return 0
    fi

    # shellcheck source=/dev/null
    source "$script_path"

    local func="run_${id}"
    if ! declare -f "$func" > /dev/null 2>&1; then
        log_error "Module '${id}' does not define function '${func}'"
        MODULE_RESULTS+=("${id}:error:0")
        return 1
    fi

    local start_time
    start_time="$(date +%s)"
    local rc=0
    "$func" || rc=$?
    local elapsed=$(( $(date +%s) - start_time ))

    if [[ $rc -ne 0 ]]; then
        log_error "Module '${name}' failed (exit ${rc})"
        save_state "module_${id}" "failed"
        MODULE_RESULTS+=("${id}:failed:${elapsed}")
        return $rc
    fi

    mark_module_complete "$id"
    MODULE_RESULTS+=("${id}:completed:${elapsed}")
    return 0
}

run_enabled_modules() {
    local enabled_list="${ENABLED_MODULES:-}"
    if [[ -z "$enabled_list" ]]; then
        log_warning "No modules enabled. Set ENABLED_MODULES in your profile."
        return 0
    fi

    log_info "Modules to run: ${enabled_list}"

    for entry in "${MODULE_REGISTRY[@]}"; do
        local id
        id="$(_module_id "$entry")"
        # shellcheck disable=SC2076
        if [[ " ${enabled_list} " =~ " ${id} " ]]; then
            run_module "$entry"
        fi
    done
}

# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------
do_rollback() {
    local module="$1"
    log_section "ROLLBACK: ${module}"

    local backups
    backups="$(list_backups "$module" 2>/dev/null || true)"

    if [[ -z "$backups" ]]; then
        log_warning "No backups found for module: ${module}"
        log_info "Backup location: ${BACKUP_DIR}/"
        ls -la "${BACKUP_DIR}/" 2>/dev/null | grep -v "^total" || log_info "(backup directory empty)"
        return 1
    fi

    echo ""
    log_info "Available backups for '${module}':"
    echo "$backups" | while IFS= read -r line; do
        printf "  %s\n" "$line"
    done

    echo ""
    log_info "Restoring backups for module: ${module}"

    while IFS= read -r backup_file; do
        local original
        original="$(restore_file_auto "$backup_file" 2>/dev/null || true)"
        if [[ -n "$original" ]]; then
            log_success "Restored: ${backup_file} → ${original}"
        fi
    done <<< "$backups"

    # Clear the module's completed state
    save_state "module_${module}" ""
    log_success "Rollback complete for module: ${module}"
    log_warning "You may need to restart affected services manually."
}

# ---------------------------------------------------------------------------
# Audit-only mode
# ---------------------------------------------------------------------------
run_audit_only() {
    log_section "AUDIT MODE — No changes will be made"

    local score=0
    local total=0
    local results=()

    _audit_check() {
        local name="$1"
        local check_cmd="$2"
        (( total++ )) || true

        local output
        if output="$(eval "$check_cmd" 2>/dev/null)"; then
            log_success "[PASS] ${name}"
            (( score++ )) || true
            results+=("PASS:${name}")
        else
            log_warning "[FAIL] ${name}"
            results+=("FAIL:${name}")
        fi
    }

    echo ""
    log_info "Running security audit checks..."
    echo ""

    # SSH checks
    _audit_check "SSH: PasswordAuthentication disabled" \
        "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config"
    _audit_check "SSH: PermitRootLogin disabled" \
        "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"
    _audit_check "SSH: MaxAuthTries <= 3" \
        "awk '/^MaxAuthTries/{if(\$2<=3)exit 0; exit 1}' /etc/ssh/sshd_config"

    # Firewall checks
    _audit_check "UFW: active" \
        "ufw status 2>/dev/null | grep -q '^Status: active'"
    _audit_check "UFW: default deny incoming" \
        "ufw status verbose 2>/dev/null | grep -q 'Default: deny (incoming)'"

    # Fail2Ban checks
    _audit_check "Fail2Ban: service running" \
        "systemctl is-active --quiet fail2ban"
    _audit_check "Fail2Ban: sshd jail active" \
        "fail2ban-client status sshd 2>/dev/null | grep -q 'Jail Status'"

    # sysctl checks
    _audit_check "Sysctl: TCP SYN cookies enabled" \
        "[[ \"\$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)\" == '1' ]]"
    _audit_check "Sysctl: ICMP redirect acceptance disabled" \
        "[[ \"\$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)\" == '0' ]]"
    _audit_check "Sysctl: ASLR fully enabled (randomize_va_space=2)" \
        "[[ \"\$(sysctl -n kernel.randomize_va_space 2>/dev/null)\" == '2' ]]"
    _audit_check "Sysctl: dmesg restricted" \
        "[[ \"\$(sysctl -n kernel.dmesg_restrict 2>/dev/null)\" == '1' ]]"
    _audit_check "Sysctl: kernel pointer restriction" \
        "[[ \"\$(sysctl -n kernel.kptr_restrict 2>/dev/null)\" -ge 1 ]]"

    # /tmp noexec
    _audit_check "Filesystem: /tmp mounted noexec" \
        "mount | grep -E '^tmpfs on /tmp ' | grep -q 'noexec'"

    # Auto-updates
    _audit_check "System: unattended-upgrades installed" \
        "dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'"

    # CrowdSec (optional)
    _audit_check "CrowdSec: service running" \
        "systemctl is-active --quiet crowdsec"

    echo ""
    local pct=0
    (( total > 0 )) && pct=$(( score * 100 / total ))

    local score_color="$RED"
    (( pct >= 50 )) && score_color="$YELLOW"
    (( pct >= 75 )) && score_color="$GREEN"

    printf "\n  ${BOLD}Hardening Score: ${score_color}%d/%d (%.0f%%)${RESET}\n\n" \
        "$score" "$total" "$pct"

    if [[ "$REPORT_FORMAT" == "json" ]]; then
        _output_json_audit "${results[@]}" "$score" "$total"
    fi
}

_output_json_audit() {
    local -a results=("${@:1:$(($#-2))}")
    local score="${@: -2:1}"
    local total="${@: -1}"

    local pct=0
    (( total > 0 )) && pct=$(( score * 100 / total ))

    printf '{\n'
    printf '  "audit_time": "%s",\n' "$(date --iso-8601=seconds)"
    printf '  "score": %d,\n' "$score"
    printf '  "total": %d,\n' "$total"
    printf '  "percentage": %d,\n' "$pct"
    printf '  "checks": [\n'
    local first=1
    for result in "${results[@]}"; do
        local status="${result%%:*}"
        local name="${result#*:}"
        [[ "$first" -eq 0 ]] && printf ',\n'
        printf '    {"check": "%s", "status": "%s"}' "$name" "$status"
        first=0
    done
    printf '\n  ]\n'
    printf '}\n'
}

# ---------------------------------------------------------------------------
# Execution summary report
# ---------------------------------------------------------------------------
print_execution_report() {
    if [[ "${REPORT_FORMAT:-}" == "json" ]]; then
        _report_json
    else
        _report_text
    fi
}

_report_text() {
    log_section "EXECUTION SUMMARY"
    echo ""
    printf "  %-30s %-12s %s\n" "MODULE" "STATUS" "DURATION"
    printf "  %-30s %-12s %s\n" "──────" "──────" "────────"

    for result in "${MODULE_RESULTS[@]:-}"; do
        local id="${result%%:*}"
        local rest="${result#*:}"
        local status="${rest%%:*}"
        local duration="${rest#*:}"

        local color="$WHITE"
        case "$status" in
            completed)  color="$GREEN" ;;
            failed)     color="$RED" ;;
            skipped)    color="$YELLOW" ;;
            dry-run)    color="$CYAN" ;;
            missing)    color="$RED" ;;
        esac

        printf "  %-30s ${color}%-12s${RESET} %ss\n" "$id" "$status" "$duration"
    done

    echo ""

    # Access info
    local server_ip
    server_ip="$(get_state "server_ip" 2>/dev/null || echo "unknown")"
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "${SSH_PORT:-22}")"

    print_summary_table "Access Information" \
        "SSH"         "ssh -p ${ssh_port} admin@${server_ip}" \
        "Grafana"     "http://${server_ip}:${PORT_GRAFANA}  (SSH tunnel)" \
        "Prometheus"  "http://${server_ip}:${PORT_PROMETHEUS}  (SSH tunnel)" \
        "Loki"        "http://${server_ip}:${PORT_LOKI}  (via Grafana)" \
        "Log file"    "$LOG_FILE" \
        "State file"  "$STATE_FILE"
}

_report_json() {
    printf '{\n'
    printf '  "execution_time": "%s",\n' "$(date --iso-8601=seconds)"
    printf '  "profile": "%s",\n' "${PROFILE_NAME:-none}"
    printf '  "dry_run": %s,\n' "$( [[ "$DRY_RUN" -eq 1 ]] && echo true || echo false )"
    printf '  "modules": [\n'

    local first=1
    for result in "${MODULE_RESULTS[@]:-}"; do
        local id="${result%%:*}"
        local rest="${result#*:}"
        local status="${rest%%:*}"
        local duration="${rest#*:}"

        [[ "$first" -eq 0 ]] && printf ',\n'
        printf '    {"module": "%s", "status": "%s", "duration_seconds": %s}' \
            "$id" "$status" "$duration"
        first=0
    done

    printf '\n  ]\n'
    printf '}\n'
}

# ---------------------------------------------------------------------------
# Interactive menu helpers
# ---------------------------------------------------------------------------

# _module_status_symbol(id) — Returns a colored symbol for module state
_module_status_symbol() {
    local id="$1"
    local state
    state="$(get_state "module_${id}" 2>/dev/null || echo "")"
    case "$state" in
        completed) printf "${GREEN}✔${RESET}" ;;
        failed)    printf "${RED}✖${RESET}" ;;
        *)         printf "${WHITE}·${RESET}" ;;
    esac
}

# _show_module_list(enabled_modules_str) — Prints module list with status symbols
_show_module_list() {
    local enabled="$1"
    echo ""
    printf "  ${BOLD}%-4s %-14s %-28s %s${RESET}\n" "#" "MODULE" "DESCRIPTION" "STATUS"
    printf "  %-4s %-14s %-28s %s\n"   "─" "──────" "───────────" "──────"
    local n=1
    for entry in "${MODULE_REGISTRY[@]}"; do
        local id script name
        id="$(_module_id "$entry")"
        name="$(_module_name "$entry")"
        local enabled_mark="  "
        # shellcheck disable=SC2076
        if [[ " $enabled " =~ " $id " ]]; then
            enabled_mark="${CYAN}▶${RESET} "
        else
            enabled_mark="${WHITE}  ${RESET}"
        fi
        local sym
        sym="$(_module_status_symbol "$id")"
        printf "  ${enabled_mark}${BOLD}%2d)${RESET} %-14s %-28s %s\n" \
            "$n" "$id" "$name" "$sym"
        (( n++ ))
    done
    echo ""
    printf "  ${GREEN}✔${RESET} = completed   ${WHITE}·${RESET} = pending   ${RED}✖${RESET} = failed\n"
}

# _pick_custom_modules() — Interactive module selector; sets ENABLED_MODULES
_pick_custom_modules() {
    local -a toggled=()

    # Start with all modules off; user toggles them on
    for entry in "${MODULE_REGISTRY[@]}"; do
        toggled+=("0")
    done
    # preflight always on
    toggled[0]="1"

    while true; do
        clear 2>/dev/null || true
        echo ""
        printf "  ${BOLD}${WHITE}Custom Module Selection${RESET}  (preflight always runs)\n"
        printf "  ${CYAN}Toggle modules on/off by number. Enter 0 to confirm.${RESET}\n"
        echo ""
        printf "  ${BOLD}%-4s %-3s %-14s %s${RESET}\n" "#" "ON?" "MODULE" "DESCRIPTION"
        printf "  %-4s %-3s %-14s %s\n"   "─" "───" "──────" "───────────"

        local n=1
        for entry in "${MODULE_REGISTRY[@]}"; do
            local id name sym
            id="$(_module_id "$entry")"
            name="$(_module_name "$entry")"
            sym="$(_module_status_symbol "$id")"
            local on="${toggled[$((n-1))]}"
            local toggle_str
            if [[ "$on" == "1" ]]; then
                toggle_str="${GREEN}[ON] ${RESET}"
            else
                toggle_str="${WHITE}[   ]${RESET}"
            fi
            printf "  ${BOLD}%2d)${RESET} %s %-14s %-28s %s\n" \
                "$n" "$toggle_str" "$id" "$name" "$sym"
            (( n++ ))
        done

        echo ""
        local choice
        choice="$(ask "Toggle module # (0 = done)" "0")"

        if [[ "$choice" == "0" || -z "$choice" ]]; then
            break
        fi

        if (( choice >= 1 && choice <= ${#MODULE_REGISTRY[@]} )); then
            local idx=$(( choice - 1 ))
            local entry_id
            entry_id="$(_module_id "${MODULE_REGISTRY[$idx]}")"
            if [[ "$entry_id" == "preflight" ]]; then
                log_warning "preflight cannot be disabled."
            elif [[ "${toggled[$idx]}" == "1" ]]; then
                toggled[$idx]="0"
            else
                toggled[$idx]="1"
            fi
        fi
    done

    # Build ENABLED_MODULES from selections
    ENABLED_MODULES=""
    local n=1
    for entry in "${MODULE_REGISTRY[@]}"; do
        local id
        id="$(_module_id "$entry")"
        if [[ "${toggled[$((n-1))]}" == "1" ]]; then
            ENABLED_MODULES="${ENABLED_MODULES} ${id}"
        fi
        (( n++ ))
    done
    ENABLED_MODULES="$(echo "$ENABLED_MODULES" | xargs)"   # trim
    export ENABLED_MODULES
}

# _confirm_run(profile, modules, dry_run) — Show run summary and confirm
_confirm_run() {
    local profile="$1"
    local modules="$2"
    local dry="$3"

    echo ""
    printf "  ${BOLD}══════════════════════════════════════════${RESET}\n"
    if [[ "$dry" == "1" ]]; then
        printf "  ${BOLD}${CYAN}  DRY-RUN — No changes will be made${RESET}\n"
    fi
    printf "  ${BOLD}  Profile  :${RESET} %s\n" "$profile"
    printf "  ${BOLD}  Modules  :${RESET} %s\n" "$modules"
    printf "  ${BOLD}══════════════════════════════════════════${RESET}\n"
    echo ""

    confirm "Proceed?" "y"
}

# ---------------------------------------------------------------------------
# Interactive main menu (when no --profile given)
# ---------------------------------------------------------------------------
show_main_menu() {
    while true; do
        clear 2>/dev/null || true
        print_banner

        local profiles_dir="${PROJECT_ROOT}/profiles"
        echo ""
        printf "  ${BOLD}${WHITE}MAIN MENU${RESET}\n\n"

        local i=1
        local -a profile_names=()
        for conf in "${profiles_dir}"/*.conf; do
            [[ -f "$conf" ]] || continue
            local pname
            pname="$(basename "$conf" .conf)"
            local pdesc
            pdesc="$(grep '^PROFILE_DESC=' "$conf" 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "")"
            printf "  ${BOLD}%2d)${RESET} ${CYAN}%-20s${RESET} %s\n" "$i" "$pname" "$pdesc"
            profile_names+=("$pname")
            (( i++ ))
        done

        echo ""
        printf "  ${BOLD}%2d)${RESET} ${MAGENTA}custom${RESET}               Pick individual modules\n" "$i";  local opt_custom=$i; (( i++ ))
        printf "  ${BOLD}%2d)${RESET} ${YELLOW}audit-only${RESET}           Security score check, no changes\n" "$i"; local opt_audit=$i; (( i++ ))
        printf "  ${BOLD}%2d)${RESET} ${WHITE}status${RESET}               Show module completion status\n" "$i"; local opt_status=$i; (( i++ ))
        printf "  ${BOLD}%2d)${RESET} Exit\n" "$i"; local opt_exit=$i
        echo ""

        local choice
        choice="$(ask "Select option" "1")"

        local total_profiles=${#profile_names[@]}

        if (( choice >= 1 && choice <= total_profiles )); then
            # Profile selected
            local selected_profile="${profile_names[$((choice-1))]}"
            PROFILE_NAME="$selected_profile"
            load_profile "$PROFILE_NAME"

            # Show what will run
            _show_module_list "${ENABLED_MODULES:-}"

            echo ""
            printf "  ${BOLD}Run mode:${RESET}\n"
            printf "  ${BOLD}r)${RESET} Run (make changes)\n"
            printf "  ${BOLD}d)${RESET} Dry-run (preview only)\n"
            printf "  ${BOLD}b)${RESET} Back\n"
            echo ""
            local run_mode
            run_mode="$(ask "Mode" "r")"

            case "${run_mode,,}" in
                d|dry|dry-run)
                    DRY_RUN=1; export DRY_RUN
                    log_info "DRY-RUN MODE enabled."
                    ;;
                b|back)
                    DRY_RUN=0; export DRY_RUN
                    continue
                    ;;
            esac

            if ! _confirm_run "$PROFILE_NAME" "${ENABLED_MODULES:-}" "$DRY_RUN"; then
                DRY_RUN=0; export DRY_RUN
                continue
            fi

            run_enabled_modules
            print_execution_report
            echo ""
            read -rp "  Press Enter to return to menu..."
            DRY_RUN=0; export DRY_RUN

        elif (( choice == opt_custom )); then
            # Custom module picker
            PROFILE_NAME="custom"
            _pick_custom_modules

            if [[ -z "${ENABLED_MODULES:-}" ]]; then
                log_warning "No modules selected."
                read -rp "  Press Enter to continue..."
                continue
            fi

            echo ""
            printf "  ${BOLD}Run mode:${RESET}\n"
            printf "  ${BOLD}r)${RESET} Run   ${BOLD}d)${RESET} Dry-run   ${BOLD}b)${RESET} Back\n"
            echo ""
            local run_mode
            run_mode="$(ask "Mode" "r")"

            case "${run_mode,,}" in
                d|dry|dry-run)
                    DRY_RUN=1; export DRY_RUN
                    ;;
                b|back)
                    DRY_RUN=0; export DRY_RUN
                    continue
                    ;;
            esac

            if ! _confirm_run "custom" "${ENABLED_MODULES}" "$DRY_RUN"; then
                DRY_RUN=0; export DRY_RUN
                continue
            fi

            run_enabled_modules
            print_execution_report
            echo ""
            read -rp "  Press Enter to return to menu..."
            DRY_RUN=0; export DRY_RUN

        elif (( choice == opt_audit )); then
            run_audit_only
            echo ""
            read -rp "  Press Enter to return to menu..."

        elif (( choice == opt_status )); then
            clear 2>/dev/null || true
            echo ""
            printf "  ${BOLD}${WHITE}Module Status${RESET}\n"
            _show_module_list "$(for e in "${MODULE_REGISTRY[@]}"; do _module_id "$e"; done | tr '\n' ' ')"
            echo ""
            read -rp "  Press Enter to return to menu..."

        elif (( choice == opt_exit )); then
            log_info "Exiting."
            exit 0

        else
            log_warning "Invalid choice: ${choice}"
        fi
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    check_root
    _ensure_log_dir
    _ensure_state_file
    detect_os

    local server_ip
    server_ip="$(get_server_ip)"
    save_state "server_ip" "$server_ip"

    if [[ -n "$ROLLBACK_MODULE" ]]; then
        do_rollback "$ROLLBACK_MODULE"
        exit 0
    fi

    if [[ "$AUDIT_ONLY" -eq 1 ]]; then
        run_audit_only
        [[ -n "$REPORT_FORMAT" ]] && print_execution_report
        exit 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_info "DRY-RUN MODE: No changes will be made to this system."
        echo ""
    fi

    if [[ -n "$PROFILE_NAME" ]]; then
        print_banner
        load_profile "$PROFILE_NAME"
        run_enabled_modules
        print_execution_report
        [[ -n "$REPORT_FORMAT" ]] && print_execution_report
    else
        show_main_menu
    fi
}

main "$@"
