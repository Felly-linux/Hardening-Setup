#!/usr/bin/env bash
# =============================================================================
# install.sh — Main interactive installer for VPS Hardening Suite
# =============================================================================
# This is the entry point for the entire hardening suite.
#
# Usage:
#   sudo ./install.sh [OPTIONS]
#
# Options:
#   --mode=basic|intermediate|hardcore|custom
#       basic        : modules 1,2,3,4 (system, SSH, UFW, Fail2Ban)
#       intermediate : modules 1-7 (adds CrowdSec, Docker, Monitoring)
#       hardcore     : all modules with stricter SSH/firewall settings
#       custom       : user selects individual modules
#
#   --non-interactive
#       Skip all interactive prompts; use defaults everywhere.
#
#   --skip-module=NAME
#       Skip a specific module by name (can be repeated).
#       Names: preflight, system, users, ssh, firewall, fail2ban,
#              crowdsec, docker, monitoring
#
#   --force
#       Re-run modules even if they are already marked complete.
#
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve script directory and project root
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT="$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Source shared library (must exist)
# ---------------------------------------------------------------------------
if [[ ! -f "${PROJECT_ROOT}/lib/common.sh" ]]; then
    echo "FATAL: lib/common.sh not found at ${PROJECT_ROOT}/lib/common.sh" >&2
    exit 1
fi
# shellcheck source=lib/common.sh
source "${PROJECT_ROOT}/lib/common.sh"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
INSTALL_MODE="menu"          # default: show interactive menu
NONINTERACTIVE=0             # exported, consumed by common.sh confirm()
FORCE_REINSTALL=0            # re-run completed modules
declare -a SKIP_MODULES=()   # list of module names to skip
HARDCORE_MODE=0              # extra-strict settings flag

parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --mode=*)
                INSTALL_MODE="${arg#--mode=}"
                ;;
            --non-interactive)
                NONINTERACTIVE=1
                export NONINTERACTIVE
                ;;
            --skip-module=*)
                SKIP_MODULES+=("${arg#--skip-module=}")
                ;;
            --force)
                FORCE_REINSTALL=1
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_warning "Unknown argument: $arg"
                ;;
        esac
    done

    if [[ "$INSTALL_MODE" == "hardcore" ]]; then
        HARDCORE_MODE=1
        export HARDCORE_MODE
    fi
}

show_usage() {
    cat << 'EOF'
VPS Hardening Suite — Installer

Usage:
  sudo ./install.sh [OPTIONS]

Options:
  --mode=basic|intermediate|hardcore|custom
  --non-interactive      Use defaults, no prompts
  --skip-module=NAME     Skip a module (repeatable)
  --force                Re-run already-completed modules
  --help                 Show this help

Modes:
  basic        System update, SSH, UFW, Fail2Ban
  intermediate + CrowdSec, Docker, Monitoring stack
  hardcore     All modules, strictest security settings
  custom       Pick modules interactively

EOF
}

# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------
# Each entry: "id:script_name:display_name"
declare -a MODULE_REGISTRY=(
    "preflight:modules/00_preflight.sh:Pre-flight checks"
    "system:modules/01_system.sh:System hardening base"
    "users:modules/02_users.sh:User management"
    "ssh:modules/03_ssh.sh:SSH hardening"
    "firewall:modules/04_firewall.sh:Firewall (UFW)"
    "fail2ban:modules/05_fail2ban.sh:Fail2Ban"
    "crowdsec:modules/06_crowdsec.sh:CrowdSec"
    "docker:modules/07_docker.sh:Docker"
    "monitoring:modules/08_monitoring.sh:Monitoring stack"
)

# Helper: get field from registry entry
_module_id()   { echo "${1%%:*}"; }
_module_script() { local s="${1#*:}"; echo "${s%%:*}"; }
_module_name() { echo "${1##*:}"; }

# is_module_skipped(id) — Returns 0 if the module is in the skip list.
is_module_skipped() {
    local id="$1"
    for skipped in "${SKIP_MODULES[@]:-}"; do
        [[ "$skipped" == "$id" ]] && return 0
    done
    return 1
}

# run_module(registry_entry) — Sources the module script and calls its main
# function. Handles idempotency check, skip check, and error trapping.
run_module() {
    local entry="$1"
    local id script name
    id="$(_module_id "$entry")"
    script="$(_module_script "$entry")"
    name="$(_module_name "$entry")"

    # Check if skipped
    if is_module_skipped "$id"; then
        log_warning "Skipping module: ${name} (--skip-module=${id})"
        return 0
    fi

    # Idempotency: skip if already complete (unless --force)
    if [[ "$FORCE_REINSTALL" -eq 0 ]] && module_completed "$id"; then
        log_info "Module '${name}' already completed. Skipping. (use --force to re-run)"
        return 0
    fi

    local script_path="${PROJECT_ROOT}/${script}"
    if [[ ! -f "$script_path" ]]; then
        log_error "Module script not found: ${script_path}"
        return 1
    fi

    log_section "MODULE: ${name}"

    # Source the module script — it registers its functions but doesn't run them
    # shellcheck source=/dev/null
    source "$script_path"

    # Each module exposes a function named run_<id>()
    local func="run_${id}"
    if ! declare -f "$func" > /dev/null 2>&1; then
        log_error "Module '${id}' does not define function '${func}'"
        return 1
    fi

    # Run with error handling
    local rc=0
    "$func" || rc=$?

    if [[ $rc -ne 0 ]]; then
        log_error "Module '${name}' failed with exit code ${rc}"
        save_state "module_${id}" "failed"
        return $rc
    fi

    mark_module_complete "$id"
    return 0
}

# ---------------------------------------------------------------------------
# Module sets per mode
# ---------------------------------------------------------------------------

# run_modules_by_ids(id1 id2 ...) — Runs only the specified module IDs.
run_modules_by_ids() {
    local ids=("$@")
    for entry in "${MODULE_REGISTRY[@]}"; do
        local id
        id="$(_module_id "$entry")"
        for requested in "${ids[@]}"; do
            if [[ "$id" == "$requested" ]]; then
                run_module "$entry"
                break
            fi
        done
    done
}

run_mode_basic() {
    log_info "Running BASIC mode: system, users, ssh, firewall, fail2ban"
    run_modules_by_ids preflight system users ssh firewall fail2ban
}

run_mode_intermediate() {
    log_info "Running INTERMEDIATE mode: basic + crowdsec, docker, monitoring"
    run_modules_by_ids preflight system users ssh firewall fail2ban crowdsec docker monitoring
}

run_mode_hardcore() {
    log_info "Running HARDCORE mode: all modules + strictest settings"
    # HARDCORE_MODE=1 is already exported; modules check this flag
    run_modules_by_ids preflight system users ssh firewall fail2ban crowdsec docker monitoring
}

run_mode_custom() {
    log_section "CUSTOM MODULE SELECTION"
    echo ""
    printf "  ${BOLD}Available modules:${RESET}\n\n"

    local i=1
    declare -a entries_indexed=()
    for entry in "${MODULE_REGISTRY[@]}"; do
        local id name
        id="$(_module_id "$entry")"
        name="$(_module_name "$entry")"
        local status_marker="  "
        module_completed "$id" && status_marker="${GREEN}✓${RESET}"
        printf "  ${BOLD}%2d)${RESET} [%b] %s  ${CYAN}(%s)${RESET}\n" \
            "$i" "$status_marker" "$name" "$id"
        entries_indexed+=("$entry")
        (( i++ ))
    done

    echo ""
    local selection
    selection="$(ask "Enter module numbers to run (comma/space separated, e.g. 1,2,3)" "")"

    if [[ -z "$selection" ]]; then
        log_warning "No modules selected."
        return 0
    fi

    # Parse the selection
    local selected_ids=()
    IFS=', ' read -ra nums <<< "$selection"
    for num in "${nums[@]}"; do
        local idx=$(( num - 1 ))
        if (( idx >= 0 && idx < ${#entries_indexed[@]} )); then
            selected_ids+=("$(_module_id "${entries_indexed[$idx]}")")
        else
            log_warning "Invalid module number: $num"
        fi
    done

    if [[ ${#selected_ids[@]} -eq 0 ]]; then
        log_warning "No valid modules selected."
        return 0
    fi

    log_info "Selected modules: ${selected_ids[*]}"
    run_modules_by_ids "${selected_ids[@]}"
}

# ---------------------------------------------------------------------------
# Interactive main menu
# ---------------------------------------------------------------------------

show_main_menu() {
    while true; do
        clear 2>/dev/null || true
        print_banner

        echo ""
        printf "  ${BOLD}${WHITE}Main Menu${RESET}\n"
        printf "  ${CYAN}─────────────────────────────────────────────────────${RESET}\n"
        printf "  ${BOLD}  0)${RESET} Full automatic install\n"
        printf "  ${BOLD}  1)${RESET} System update & hardening base\n"
        printf "  ${BOLD}  2)${RESET} SSH hardening\n"
        printf "  ${BOLD}  3)${RESET} Firewall (UFW)\n"
        printf "  ${BOLD}  4)${RESET} Fail2Ban\n"
        printf "  ${BOLD}  5)${RESET} CrowdSec\n"
        printf "  ${BOLD}  6)${RESET} Docker\n"
        printf "  ${BOLD}  7)${RESET} Monitoring stack (Prometheus / Grafana / Loki)\n"
        printf "  ${BOLD}  8)${RESET} Generate documentation\n"
        printf "  ${BOLD}  9)${RESET} Show installation status\n"
        printf "  ${BOLD} 10)${RESET} Exit\n"
        printf "  ${CYAN}─────────────────────────────────────────────────────${RESET}\n"
        echo ""

        local choice
        choice="$(ask "Select option" "0")"

        case "$choice" in
            0)
                menu_full_install
                ;;
            1)
                run_modules_by_ids preflight system
                ;;
            2)
                run_modules_by_ids ssh
                ;;
            3)
                run_modules_by_ids firewall
                ;;
            4)
                run_modules_by_ids fail2ban
                ;;
            5)
                run_modules_by_ids crowdsec
                ;;
            6)
                run_modules_by_ids docker
                ;;
            7)
                run_modules_by_ids monitoring
                ;;
            8)
                generate_documentation
                ;;
            9)
                show_installation_status
                read -rp "  Press Enter to continue..."
                ;;
            10|q|quit|exit)
                log_info "Exiting VPS Hardening Suite."
                exit 0
                ;;
            *)
                log_warning "Invalid option: $choice"
                sleep 1
                ;;
        esac
    done
}

# menu_full_install — Ask which mode to run, then execute it.
menu_full_install() {
    echo ""
    printf "  ${BOLD}Select installation mode:${RESET}\n\n"
    printf "  ${BOLD}  1)${RESET} ${GREEN}basic${RESET}        — System, SSH, UFW, Fail2Ban\n"
    printf "  ${BOLD}  2)${RESET} ${YELLOW}intermediate${RESET} — Basic + CrowdSec, Docker, Monitoring\n"
    printf "  ${BOLD}  3)${RESET} ${RED}hardcore${RESET}     — All modules, strictest settings\n"
    printf "  ${BOLD}  4)${RESET} ${CYAN}custom${RESET}       — Pick individual modules\n"
    echo ""

    local mode_choice
    mode_choice="$(ask "Mode" "2")"

    case "$mode_choice" in
        1|basic)        run_mode_basic ;;
        2|intermediate) run_mode_intermediate ;;
        3|hardcore)
            HARDCORE_MODE=1
            export HARDCORE_MODE
            run_mode_hardcore
            ;;
        4|custom)       run_mode_custom ;;
        *)
            log_warning "Invalid mode; running intermediate."
            run_mode_intermediate
            ;;
    esac

    show_installation_status
    show_access_urls
}

# ---------------------------------------------------------------------------
# Post-install summary
# ---------------------------------------------------------------------------

show_installation_status() {
    log_section "INSTALLATION STATUS"
    echo ""

    for entry in "${MODULE_REGISTRY[@]}"; do
        local id name status_str color
        id="$(_module_id "$entry")"
        name="$(_module_name "$entry")"

        if module_completed "$id"; then
            status_str="COMPLETED"
            color="$GREEN"
        else
            local raw
            raw="$(get_state "module_${id}" 2>/dev/null || true)"
            if [[ "$raw" == "failed" ]]; then
                status_str="FAILED"
                color="$RED"
            else
                status_str="NOT RUN"
                color="$YELLOW"
            fi
        fi

        local completed_time
        completed_time="$(get_state "module_${id}_time" 2>/dev/null || true)"

        printf "  %-40s ${color}%-12s${RESET}  %s\n" \
            "$name" "$status_str" "${completed_time:-}"
    done

    echo ""
}

show_access_urls() {
    local server_ip
    server_ip="$(get_state "server_ip" 2>/dev/null || get_server_ip)"

    local grafana_pass
    grafana_pass="$(get_state "grafana_password" 2>/dev/null || echo "(see state file)")"

    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "22")"

    echo ""
    log_section "ACCESS INFORMATION"
    print_summary_table "Service Access URLs & Credentials" \
        "SSH"              "ssh -p ${ssh_port} admin@${server_ip}" \
        "Grafana"          "http://${server_ip}:${PORT_GRAFANA}  (admin / ${grafana_pass})" \
        "Prometheus"       "http://${server_ip}:${PORT_PROMETHEUS}" \
        "Node Exporter"    "http://${server_ip}:${PORT_NODE_EXPORTER}/metrics" \
        "cAdvisor"         "http://${server_ip}:${PORT_CADVISOR}" \
        "Loki"             "http://${server_ip}:${PORT_LOKI}" \
        "CrowdSec LAPI"    "http://127.0.0.1:${PORT_CROWDSEC_LAPI}" \
        "Log file"         "$LOG_FILE" \
        "State file"       "$STATE_FILE"
    echo ""
}

# ---------------------------------------------------------------------------
# Documentation generator
# ---------------------------------------------------------------------------

generate_documentation() {
    local doc_dir="${PROJECT_ROOT}/docs"
    local doc_file="${doc_dir}/installation_report_$(date +%Y%m%d_%H%M%S).md"

    mkdir -p "$doc_dir"
    log_info "Generating documentation: ${doc_file}"

    local server_ip
    server_ip="$(get_state "server_ip" 2>/dev/null || get_server_ip)"
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "22")"

    {
        echo "# VPS Hardening Suite — Installation Report"
        echo ""
        echo "Generated: $(date --iso-8601=seconds)"
        echo "Server IP: ${server_ip}"
        echo ""
        echo "## Module Status"
        echo ""
        echo "| Module | Status | Completed At |"
        echo "|--------|--------|-------------|"

        for entry in "${MODULE_REGISTRY[@]}"; do
            local id name status_str
            id="$(_module_id "$entry")"
            name="$(_module_name "$entry")"

            if module_completed "$id"; then
                status_str="✅ Completed"
            else
                local raw
                raw="$(get_state "module_${id}" 2>/dev/null || true)"
                [[ "$raw" == "failed" ]] && status_str="❌ Failed" || status_str="⬜ Not Run"
            fi

            local t
            t="$(get_state "module_${id}_time" 2>/dev/null || echo "-")"
            echo "| ${name} | ${status_str} | ${t} |"
        done

        echo ""
        echo "## Access Information"
        echo ""
        echo "| Service | URL / Command |"
        echo "|---------|--------------|"
        echo "| SSH | \`ssh -p ${ssh_port} admin@${server_ip}\` |"
        echo "| Grafana | http://${server_ip}:${PORT_GRAFANA} |"
        echo "| Prometheus | http://${server_ip}:${PORT_PROMETHEUS} |"
        echo "| Node Exporter | http://${server_ip}:${PORT_NODE_EXPORTER}/metrics |"
        echo "| cAdvisor | http://${server_ip}:${PORT_CADVISOR} |"
        echo "| Loki | http://${server_ip}:${PORT_LOKI} |"
        echo ""
        echo "## Firewall Rules"
        echo ""
        echo "\`\`\`"
        ufw status verbose 2>/dev/null || echo "(UFW not active)"
        echo "\`\`\`"
        echo ""
        echo "## Fail2Ban Jails"
        echo ""
        echo "\`\`\`"
        fail2ban-client status 2>/dev/null || echo "(Fail2Ban not active)"
        echo "\`\`\`"
    } > "$doc_file"

    log_success "Documentation written to: ${doc_file}"
}

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

main() {
    # Parse command-line arguments
    parse_args "$@"

    # Must run as root
    check_root

    # Ensure log and state infrastructure is ready
    _ensure_log_dir
    _ensure_state_file

    # Detect OS early; modules will reference OS_ID
    detect_os

    # Store the server IP in state for later reference
    log_info "Detecting public IP..."
    local server_ip
    server_ip="$(get_server_ip)"
    save_state "server_ip" "$server_ip"
    log_info "Server IP: ${server_ip}"

    # Route based on --mode argument
    case "$INSTALL_MODE" in
        basic)
            print_banner
            run_mode_basic
            show_installation_status
            show_access_urls
            ;;
        intermediate)
            print_banner
            run_mode_intermediate
            show_installation_status
            show_access_urls
            ;;
        hardcore)
            print_banner
            run_mode_hardcore
            show_installation_status
            show_access_urls
            ;;
        custom)
            print_banner
            run_mode_custom
            show_installation_status
            show_access_urls
            ;;
        menu|*)
            # Default: interactive menu
            show_main_menu
            ;;
    esac
}

main "$@"
