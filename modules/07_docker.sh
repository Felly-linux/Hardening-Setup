#!/usr/bin/env bash
# =============================================================================
# modules/07_docker.sh — Docker CE installation and hardening
# =============================================================================
# Installs Docker CE from the official Docker APT repository (not the
# distro-packaged version which may be outdated). Applies a hardened
# daemon configuration and creates the shared monitoring Docker network.
#
# Steps:
#   1.  Check if Docker is already installed
#   2.  Remove conflicting old packages (docker.io, podman-docker, etc.)
#   3.  Add Docker's official GPG key
#   4.  Add Docker's APT repository
#   5.  Install docker-ce, docker-ce-cli, containerd.io, plugins
#   6.  Write hardened /etc/docker/daemon.json
#   7.  Add admin user to docker group
#   8.  Create monitoring Docker network
#   9.  Enable and start Docker
#  10.  Verify installation
#
# Security hardening applied:
#   - json-file logging with size limits (prevents disk exhaustion)
#   - live-restore: containers survive daemon restarts
#   - userland-proxy disabled (uses iptables hairpin NAT instead)
#   - icc (inter-container communication) disabled by default
#   - no-new-privileges for containers
#   - seccomp default profile enabled
#
# State keys written:
#   docker_installed        — "yes"
#   docker_version          — installed version
#   docker_admin_user       — user added to docker group
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_DOCKER_LOADED:-}" ]] && return 0
readonly _MODULE_DOCKER_LOADED=1

# ---------------------------------------------------------------------------
# run_docker — Main entry point
# ---------------------------------------------------------------------------
run_docker() {
    log_section "DOCKER INSTALLATION & HARDENING"

    log_step 1  10 "Checking existing Docker installation"
    local already_installed=false
    _docker_check_existing && already_installed=true

    if [[ "$already_installed" == "false" ]]; then
        log_step 2  10 "Removing conflicting packages"
        _docker_remove_old_packages

        log_step 3  10 "Adding Docker GPG key"
        _docker_add_gpg_key

        log_step 4  10 "Adding Docker APT repository"
        _docker_add_repo

        log_step 5  10 "Installing Docker CE and plugins"
        _docker_install_packages
    else
        log_info "Docker already installed — skipping installation steps."
        # Jump ahead to configuration
        for i in 2 3 4 5; do
            show_progress "$i" 10 "Skipping (already installed)"
        done
    fi

    log_step 6  10 "Writing hardened daemon.json"
    _docker_write_daemon_config

    log_step 7  10 "Adding admin user to docker group"
    _docker_add_user_to_group

    log_step 8  10 "Creating monitoring Docker network"
    _docker_create_monitoring_network

    log_step 9  10 "Enabling and starting Docker daemon"
    _docker_enable_service

    log_step 10 10 "Verifying Docker installation"
    _docker_verify

    log_success "Docker configured and running."
    save_state "docker_installed" "yes"
}

# ---------------------------------------------------------------------------
# _docker_check_existing — Returns 0 if Docker is already properly installed
# ---------------------------------------------------------------------------
_docker_check_existing() {
    if command_exists docker && service_running docker; then
        local version
        version="$(docker --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "unknown")"
        log_info "Docker ${version} is already installed and running."
        save_state "docker_version" "$version"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# _docker_remove_old_packages — Remove distro-packaged Docker variants
# ---------------------------------------------------------------------------
_docker_remove_old_packages() {
    local old_packages=(
        docker
        docker-engine
        docker.io
        containerd
        runc
        podman-docker
    )

    log_info "Removing any old/conflicting Docker packages..."

    for pkg in "${old_packages[@]}"; do
        if package_installed "$pkg"; then
            DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" >> "$LOG_FILE" 2>&1 || true
            log_info "  Removed: ${pkg}"
        fi
    done
}

# ---------------------------------------------------------------------------
# _docker_add_gpg_key — Download and install Docker's official GPG signing key
# ---------------------------------------------------------------------------
_docker_add_gpg_key() {
    local keyring="/usr/share/keyrings/docker-archive-keyring.gpg"

    if [[ -f "$keyring" ]]; then
        log_info "Docker GPG keyring already present."
        return 0
    fi

    log_info "Downloading Docker GPG key..."

    mkdir -p /usr/share/keyrings

    # Try to download the key
    if curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
            | gpg --dearmor -o "$keyring" 2>> "$LOG_FILE"; then
        chmod 644 "$keyring"
        log_success "Docker GPG key installed."
    else
        # Try Debian URL as fallback
        local os_id="${OS_ID:-ubuntu}"
        curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" \
            | gpg --dearmor -o "$keyring" 2>> "$LOG_FILE"
        chmod 644 "$keyring"
        log_success "Docker GPG key installed (Debian fallback)."
    fi
}

# ---------------------------------------------------------------------------
# _docker_add_repo — Add Docker's official APT repository
# ---------------------------------------------------------------------------
_docker_add_repo() {
    local sources_file="/etc/apt/sources.list.d/docker.list"

    if [[ -f "$sources_file" ]]; then
        log_info "Docker repository already configured."
        return 0
    fi

    local arch
    arch="$(dpkg --print-architecture)"
    local os_id="${OS_ID:-ubuntu}"
    local codename="${OS_CODENAME:-focal}"

    cat > "$sources_file" << EOF
# Docker official repository — added by VPS Hardening Suite
deb [arch=${arch} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/${os_id} ${codename} stable
EOF

    apt-get update -qq >> "$LOG_FILE" 2>&1
    log_success "Docker repository added for ${os_id}/${codename}."
}

# ---------------------------------------------------------------------------
# _docker_install_packages — Install Docker CE and companion tools
# ---------------------------------------------------------------------------
_docker_install_packages() {
    local packages=(
        docker-ce               # Docker daemon
        docker-ce-cli           # Docker CLI
        containerd.io           # Container runtime
        docker-buildx-plugin    # BuildKit-based builder
        docker-compose-plugin   # `docker compose` (v2)
    )

    log_info "Installing Docker packages: ${packages[*]}"

    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" >> "$LOG_FILE" 2>&1

    local version
    version="$(docker --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "unknown")"
    save_state "docker_version" "$version"
    log_success "Docker CE ${version} installed."
}

# ---------------------------------------------------------------------------
# _docker_write_daemon_config — Write /etc/docker/daemon.json with hardening
# ---------------------------------------------------------------------------
_docker_write_daemon_config() {
    local daemon_conf="/etc/docker/daemon.json"
    mkdir -p /etc/docker

    if [[ -f "$daemon_conf" ]]; then
        backup_file "$daemon_conf"
    fi

    cat > "$daemon_conf" << 'EOF'
{
    "_comment": "VPS Hardening Suite — Docker daemon configuration",

    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3",
        "tag": "{{.Name}}/{{.ID}}"
    },

    "live-restore": true,

    "userland-proxy": false,

    "icc": false,

    "no-new-privileges": true,

    "default-ulimits": {
        "nofile": {
            "Hard": 64000,
            "Name": "nofile",
            "Soft": 64000
        }
    },

    "experimental": false,

    "metrics-addr": "127.0.0.1:9323",

    "max-concurrent-downloads": 3,
    "max-concurrent-uploads": 5,

    "storage-driver": "overlay2",

    "storage-opts": [
        "overlay2.override_kernel_check=true"
    ],

    "default-shm-size": "64m",

    "dns": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],

    "features": {
        "buildkit": true
    }
}
EOF

    log_success "Docker daemon.json written with security hardening."
}

# ---------------------------------------------------------------------------
# _docker_add_user_to_group — Add the admin user to the docker group
# ---------------------------------------------------------------------------
_docker_add_user_to_group() {
    local admin_user
    admin_user="$(get_state "admin_user" 2>/dev/null || echo "")"

    if [[ -z "$admin_user" ]]; then
        admin_user="$(ask "Admin username to add to docker group" "admin")"
        admin_user="$(trim "$admin_user")"
    fi

    if ! id "$admin_user" &>/dev/null; then
        log_warning "User '${admin_user}' does not exist. Skipping docker group assignment."
        return 0
    fi

    if groups "$admin_user" 2>/dev/null | grep -qw docker; then
        log_info "User '${admin_user}' is already in the docker group."
    else
        usermod -aG docker "$admin_user"
        log_success "User '${admin_user}' added to docker group."
        log_warning "NOTE: User must log out and back in for group membership to take effect."
    fi

    save_state "docker_admin_user" "$admin_user"
}

# ---------------------------------------------------------------------------
# _docker_create_monitoring_network — Create the shared monitoring network
# ---------------------------------------------------------------------------
_docker_create_monitoring_network() {
    # Ensure Docker is running before creating networks
    if ! service_running docker; then
        systemctl start docker >> "$LOG_FILE" 2>&1 || true
        wait_for_service docker 30
    fi

    if docker network ls 2>/dev/null | grep -q "\\b${DOCKER_MONITORING_NETWORK}\\b"; then
        log_info "Docker network '${DOCKER_MONITORING_NETWORK}' already exists."
    else
        docker network create \
            --driver bridge \
            --label "managed-by=vps-hardening-suite" \
            --label "purpose=monitoring" \
            "$DOCKER_MONITORING_NETWORK" >> "$LOG_FILE" 2>&1
        log_success "Docker network '${DOCKER_MONITORING_NETWORK}' created."
    fi
}

# ---------------------------------------------------------------------------
# _docker_enable_service — Enable and start Docker, apply daemon config
# ---------------------------------------------------------------------------
_docker_enable_service() {
    systemctl enable docker   >> "$LOG_FILE" 2>&1
    systemctl enable containerd >> "$LOG_FILE" 2>&1

    # Restart to pick up new daemon.json settings
    systemctl restart docker >> "$LOG_FILE" 2>&1

    wait_for_service docker 30
    log_success "Docker daemon started."
}

# ---------------------------------------------------------------------------
# _docker_verify — Run basic verification checks
# ---------------------------------------------------------------------------
_docker_verify() {
    log_info "Docker system info:"
    echo ""

    # Version
    local version
    version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")"
    log_info "  Docker version: ${version}"

    # Compose version
    local compose_version
    compose_version="$(docker compose version --short 2>/dev/null || echo "unavailable")"
    log_info "  Docker Compose v2: ${compose_version}"

    # Storage driver
    local storage_driver
    storage_driver="$(docker info --format '{{.Driver}}' 2>/dev/null || echo "unknown")"
    log_info "  Storage driver: ${storage_driver}"

    # Network list
    echo ""
    log_info "  Docker networks:"
    docker network ls --format "    {{.Name}}\t{{.Driver}}\t{{.Scope}}" 2>/dev/null \
        | while IFS= read -r line; do
            printf "  ${CYAN}│${RESET} %s\n" "$line"
          done

    echo ""

    # Run hello-world to confirm everything works
    log_info "Running hello-world container test..."
    if docker run --rm --pull always hello-world >> "$LOG_FILE" 2>&1; then
        log_success "Docker hello-world: PASSED"
    else
        log_warning "Docker hello-world test failed — Docker may need further configuration."
        log_warning "Check: journalctl -u docker.service -n 50"
    fi
}
