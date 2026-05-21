#!/usr/bin/env bash
# =============================================================================
# templates/motd.sh — Dynamic login MOTD for VPS Hardening Suite
# =============================================================================
# Displays a rich system status overview on every interactive login.
# No external dependencies beyond standard coreutils, ss, systemctl, docker.
#
# Install:
#   sudo cp templates/motd.sh /etc/update-motd.d/99-vps-monitor
#   sudo chmod +x /etc/update-motd.d/99-vps-monitor
#
# Port reference (used in the monitoring section):
#   Grafana       3000    Prometheus   9090
#   Node Exporter 9100    cAdvisor     8081
#   Loki          3100    Promtail     9080
#   CrowdSec LAPI 6767
# =============================================================================

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
RESET="\e[0m"
BOLD="\e[1m"
DIM="\e[2m"

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
WHITE="\e[97m"
BLUE="\e[34m"
MAGENTA="\e[35m"

# ---------------------------------------------------------------------------
# Bar graph helper
# Usage: bar_graph <used_pct 0-100> <width>
# ---------------------------------------------------------------------------
bar_graph() {
    local pct=$1
    local width=${2:-20}
    local filled=$(( pct * width / 100 ))
    local empty=$(( width - filled ))
    local colour

    if   (( pct >= 90 )); then colour="${RED}"
    elif (( pct >= 70 )); then colour="${YELLOW}"
    else colour="${GREEN}"
    fi

    printf "%s[" "${colour}"
    printf '%0.s#' $(seq 1 $filled)
    printf '%0.s-' $(seq 1 $empty)
    printf "]%s %3d%%" "${RESET}" "${pct}"
}

# ---------------------------------------------------------------------------
# Divider
# ---------------------------------------------------------------------------
divider() {
    printf "${DIM}%s${RESET}\n" "──────────────────────────────────────────────────────"
}

# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
OS=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
KERNEL=$(uname -r)
ARCH=$(uname -m)

# ---------------------------------------------------------------------------
# Uptime & load
# ---------------------------------------------------------------------------
UPTIME_RAW=$(uptime -p 2>/dev/null || uptime)
LOAD=$(awk '{print $1","$2","$3}' /proc/loadavg)
LOAD1=$(echo "$LOAD"  | cut -d, -f1)
LOAD5=$(echo "$LOAD"  | cut -d, -f2)
LOAD15=$(echo "$LOAD" | cut -d, -f3)
CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)

# ---------------------------------------------------------------------------
# Memory (from /proc/meminfo for accuracy, no free -m needed)
# ---------------------------------------------------------------------------
MEM_TOTAL_KB=$(grep MemTotal  /proc/meminfo | awk '{print $2}')
MEM_AVAIL_KB=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
MEM_USED_KB=$(( MEM_TOTAL_KB - MEM_AVAIL_KB ))
MEM_TOTAL_MB=$(( MEM_TOTAL_KB / 1024 ))
MEM_USED_MB=$(( MEM_USED_KB  / 1024 ))
MEM_PCT=0
(( MEM_TOTAL_KB > 0 )) && MEM_PCT=$(( MEM_USED_KB * 100 / MEM_TOTAL_KB ))

# Swap
SWAP_TOTAL_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
SWAP_FREE_KB=$(grep  SwapFree  /proc/meminfo | awk '{print $2}')
SWAP_USED_KB=$(( SWAP_TOTAL_KB - SWAP_FREE_KB ))
SWAP_USED_MB=$(( SWAP_USED_KB  / 1024 ))
SWAP_TOTAL_MB=$(( SWAP_TOTAL_KB / 1024 ))
SWAP_PCT=0
(( SWAP_TOTAL_KB > 0 )) && SWAP_PCT=$(( SWAP_USED_KB * 100 / SWAP_TOTAL_KB ))

# ---------------------------------------------------------------------------
# Disk usage (root fs)
# ---------------------------------------------------------------------------
DISK_INFO=$(df -h / | awk 'NR==2 {print $2,$3,$5}')
DISK_TOTAL=$(echo "$DISK_INFO" | awk '{print $1}')
DISK_USED=$(echo  "$DISK_INFO" | awk '{print $2}')
DISK_PCT_RAW=$(echo "$DISK_INFO" | awk '{print $3}' | tr -d '%')
DISK_PCT=${DISK_PCT_RAW:-0}

# ---------------------------------------------------------------------------
# Last login
# ---------------------------------------------------------------------------
LAST_LOGIN=$(last -n 2 -F "$USER" 2>/dev/null | grep -v "^$USER.*still" | awk 'NR==1{
    printf "%s %s %s %s %s", $3,$4,$5,$6,$7
}')

# ---------------------------------------------------------------------------
# Active sessions
# ---------------------------------------------------------------------------
SESSIONS=$(who | wc -l)
CURRENT_IP=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()')

# ---------------------------------------------------------------------------
# Fail2Ban stats (today's bans)
# ---------------------------------------------------------------------------
F2B_BANS="N/A"
if command -v fail2ban-client &>/dev/null; then
    F2B_BANS=$(fail2ban-client status 2>/dev/null | grep -oP 'Jail list:\s+\K.*' | tr ',' '\n' | while read jail; do
        jail=$(echo "$jail" | xargs)
        fail2ban-client status "$jail" 2>/dev/null | grep 'Currently banned:' | awk '{sum+=$NF} END{print sum}'
    done | awk '{sum+=$1} END{print sum}')
    F2B_BANS=${F2B_BANS:-0}
fi

# ---------------------------------------------------------------------------
# UFW status
# ---------------------------------------------------------------------------
UFW_STATUS="inactive"
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | awk 'NR==1{print $2}')
fi

# ---------------------------------------------------------------------------
# Network — listening ports count
# ---------------------------------------------------------------------------
OPEN_PORTS=$(ss -tlnp 2>/dev/null | grep -c LISTEN || echo "?")

# ---------------------------------------------------------------------------
# Docker containers
# ---------------------------------------------------------------------------
DOCKER_RUNNING="N/A"
if command -v docker &>/dev/null; then
    DOCKER_RUNNING=$(docker ps -q 2>/dev/null | wc -l)
fi

# ---------------------------------------------------------------------------
# Monitoring service status
# ---------------------------------------------------------------------------
_svc_status() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        printf "${GREEN}running${RESET}"
    else
        printf "${RED}stopped${RESET}"
    fi
}

# Systemd service states for security services
CROWDSEC_SVC=$( _svc_status crowdsec   )
FAIL2BAN_SVC=$( _svc_status fail2ban   )
UFW_SVC=$(      _svc_status ufw        )

# Check Docker-based monitoring stack containers
_container_status() {
    local name="$1"
    if docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null | grep -q "^running$"; then
        printf "${GREEN}running${RESET}"
    else
        printf "${RED}stopped${RESET}"
    fi
}
PROMETHEUS_SVC=$( _container_status prometheus 2>/dev/null || printf "${DIM}N/A${RESET}" )
GRAFANA_SVC=$(    _container_status grafana    2>/dev/null || printf "${DIM}N/A${RESET}" )
LOKI_SVC=$(       _container_status loki       2>/dev/null || printf "${DIM}N/A${RESET}" )

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
printf "\n"
printf "${BOLD}${CYAN}  ██╗   ██╗██████╗ ███████╗${RESET}\n"
printf "${BOLD}${CYAN}  ██║   ██║██╔══██╗██╔════╝${RESET}  %s\n" "${HOSTNAME}"
printf "${BOLD}${CYAN}  ██║   ██║██████╔╝███████╗${RESET}  ${DIM}${OS}${RESET}\n"
printf "${BOLD}${CYAN}  ╚██╗ ██╔╝██╔═══╝ ╚════██║${RESET}  ${DIM}Kernel ${KERNEL} (${ARCH})${RESET}\n"
printf "${BOLD}${CYAN}   ╚████╔╝ ██║     ███████║${RESET}\n"
printf "${BOLD}${CYAN}    ╚═══╝  ╚═╝     ╚══════╝${RESET}  ${DIM}vps-hardening-suite${RESET}\n"
printf "\n"

divider

# System info block
printf " ${BOLD}${WHITE}Uptime${RESET}       %s\n" "${UPTIME_RAW}"
printf " ${BOLD}${WHITE}Load avg${RESET}     ${LOAD1}  ${LOAD5}  ${LOAD15}  ${DIM}(1m / 5m / 15m, ${CPU_CORES} cores)${RESET}\n"
printf " ${BOLD}${WHITE}Sessions${RESET}     %s active" "${SESSIONS}"
[[ -n "${CURRENT_IP}" ]] && printf "  ${DIM}(your IP: %s)${RESET}" "${CURRENT_IP}"
printf "\n"
printf " ${BOLD}${WHITE}Last login${RESET}   %s\n" "${LAST_LOGIN:-unknown}"

divider

# Memory
printf " ${BOLD}${WHITE}Memory${RESET}       "
bar_graph "${MEM_PCT}" 24
printf "  ${DIM}%s / %s MB${RESET}\n" "${MEM_USED_MB}" "${MEM_TOTAL_MB}"

# Swap
printf " ${BOLD}${WHITE}Swap${RESET}         "
bar_graph "${SWAP_PCT}" 24
printf "  ${DIM}%s / %s MB${RESET}\n" "${SWAP_USED_MB}" "${SWAP_TOTAL_MB}"

# Disk
printf " ${BOLD}${WHITE}Disk  (/)${RESET}    "
bar_graph "${DISK_PCT}" 24
printf "  ${DIM}%s / %s${RESET}\n" "${DISK_USED}" "${DISK_TOTAL}"

divider

# Security
printf " ${BOLD}${MAGENTA}Security${RESET}\n"
printf "   UFW firewall     %-10s  currently %s\n" "${UFW_STATUS}" "${UFW_SVC}"
printf "   Fail2Ban bans    %-10s  service   %s\n" "${F2B_BANS}" "${FAIL2BAN_SVC}"
printf "   CrowdSec         %s\n"                  "${CROWDSEC_SVC}"
printf "   Listening ports  %s\n"                  "${OPEN_PORTS}"

divider

# Monitoring
printf " ${BOLD}${BLUE}Monitoring${RESET}   Docker containers running: ${DOCKER_RUNNING}\n"
printf "   Prometheus   http://127.0.0.1:9090  %b\n" "${PROMETHEUS_SVC}"
printf "   Grafana      http://127.0.0.1:3000  %b\n" "${GRAFANA_SVC}"
printf "   Loki         http://127.0.0.1:3100  %b\n" "${LOKI_SVC}"
printf "   Node Exp.    http://127.0.0.1:9100/metrics\n"
printf "   cAdvisor     http://127.0.0.1:8081\n"
printf "   CrowdSec     http://127.0.0.1:6767   %b\n" "$(_svc_status crowdsec 2>/dev/null || printf "${DIM}N/A${RESET}")"

divider
printf "\n"
