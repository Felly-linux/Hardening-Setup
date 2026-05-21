#!/usr/bin/env bash
# =============================================================================
# modules/08_monitoring.sh — Observability stack deployment
# =============================================================================
# Deploys the full monitoring stack using Docker Compose:
#
#   Prometheus   — metrics collection and alerting engine
#   Node Exporter — host system metrics (CPU, RAM, disk, network)
#   cAdvisor     — Docker container metrics
#   Grafana      — visualisation and dashboards
#   Loki         — log aggregation (PromQL-compatible)
#   Promtail     — log shipper (Docker + system logs)
#
# Deployment directory: /opt/monitoring/
#
# Grafana auto-configuration via REST API:
#   - Prometheus data source
#   - Loki data source
#   - Community dashboards imported by ID
#   - Custom security dashboard
#
# Steps:
#   1.  Ask for Grafana admin password and server IP
#   2.  Create deployment directory
#   3.  Write docker-compose.yml and all configs
#   4.  Start the stack
#   5.  Wait for all containers to be healthy
#   6.  Auto-configure Grafana via API
#   7.  Print access information
#
# State keys written:
#   grafana_password    — the Grafana admin password
#   monitoring_deployed — "yes"
# =============================================================================
set -euo pipefail

[[ -n "${_MODULE_MONITORING_LOADED:-}" ]] && return 0
readonly _MODULE_MONITORING_LOADED=1

# Deployment directory (all config lives here)
readonly _MONITORING_DIR="/opt/monitoring"

# Grafana API retry settings
readonly _GF_API_MAX_RETRIES=30
readonly _GF_API_RETRY_SLEEP=5

# ---------------------------------------------------------------------------
# run_monitoring — Main entry point
# ---------------------------------------------------------------------------
run_monitoring() {
    log_section "MONITORING STACK DEPLOYMENT"

    # Require Docker to be installed first
    if ! command_exists docker || ! service_running docker; then
        log_error "Docker is not installed or not running."
        log_error "Run the Docker module first (module 7)."
        return 1
    fi

    log_step 1 7 "Gathering configuration"
    local grafana_password server_ip
    grafana_password="$(_monitoring_get_grafana_password)"
    server_ip="$(get_state "server_ip" 2>/dev/null || get_server_ip)"
    save_state "grafana_password" "$grafana_password"

    log_step 2 7 "Creating deployment directory"
    _monitoring_setup_directory

    log_step 3 7 "Writing Compose and config files"
    _monitoring_write_all_configs "$grafana_password" "$server_ip"

    log_step 4 7 "Starting monitoring stack"
    _monitoring_start_stack

    log_step 5 7 "Waiting for all services to become healthy"
    _monitoring_wait_for_health

    log_step 6 7 "Auto-configuring Grafana (data sources + dashboards)"
    _monitoring_configure_grafana "$grafana_password"

    log_step 7 7 "Printing access information"
    _monitoring_print_access_info "$grafana_password" "$server_ip"

    save_state "monitoring_deployed" "yes"
    log_success "Monitoring stack deployed successfully."
}

# ---------------------------------------------------------------------------
# _monitoring_get_grafana_password — Ask user or generate a random password
# ---------------------------------------------------------------------------
_monitoring_get_grafana_password() {
    local existing
    existing="$(get_state "grafana_password" 2>/dev/null || echo "")"

    if [[ -n "$existing" ]]; then
        log_info "Using existing Grafana password from state."
        echo "$existing"
        return 0
    fi

    echo ""
    log_info "Set the Grafana admin password (min 8 chars)."
    log_info "Leave blank to generate a random secure password."

    local password
    password="$(ask_password "Grafana admin password (blank = auto-generate)")"

    if [[ -z "$password" || ${#password} -lt 8 ]]; then
        password="$(generate_password 20)"
        log_info "Generated random Grafana password."
    fi

    echo "$password"
}

# ---------------------------------------------------------------------------
# _monitoring_setup_directory — Create /opt/monitoring/ and subdirectories
# ---------------------------------------------------------------------------
_monitoring_setup_directory() {
    mkdir -p "${_MONITORING_DIR}"/{config,data,logs}
    mkdir -p "${_MONITORING_DIR}/config/"{prometheus,grafana,loki,promtail,alertmanager}
    mkdir -p "${_MONITORING_DIR}/data/"{prometheus,grafana,loki}
    mkdir -p "${_MONITORING_DIR}/logs"

    # Fix ownership for Grafana (runs as UID 472)
    chown -R 472:472 "${_MONITORING_DIR}/data/grafana" 2>/dev/null || true
    # Fix ownership for Prometheus (runs as UID 65534)
    chown -R 65534:65534 "${_MONITORING_DIR}/data/prometheus" 2>/dev/null || true

    log_success "Deployment directory created: ${_MONITORING_DIR}"
}

# ---------------------------------------------------------------------------
# _monitoring_write_all_configs — Write docker-compose.yml and service configs
# ---------------------------------------------------------------------------
_monitoring_write_all_configs() {
    local grafana_password="$1"
    local server_ip="$2"

    _monitoring_write_compose     "$grafana_password"
    _monitoring_write_prometheus_config
    _monitoring_write_prometheus_alerts
    _monitoring_write_loki_config
    _monitoring_write_promtail_config "$server_ip"
    _monitoring_write_grafana_provisioning

    log_success "All configuration files written."
}

# ---------------------------------------------------------------------------
# _monitoring_write_compose — Write the Docker Compose manifest
# ---------------------------------------------------------------------------
_monitoring_write_compose() {
    local grafana_password="$1"

    cat > "${_MONITORING_DIR}/docker-compose.yml" << EOF
# =============================================================================
# /opt/monitoring/docker-compose.yml
# VPS Hardening Suite — Full Observability Stack
# Generated: $(date --iso-8601=seconds)
# =============================================================================
# Services:
#   prometheus     — metrics scraping & alerting
#   node-exporter  — host system metrics
#   cadvisor       — container metrics
#   grafana        — dashboards
#   loki           — log aggregation
#   promtail       — log shipping
# =============================================================================

version: "3.9"

networks:
  ${DOCKER_MONITORING_NETWORK}:
    external: true

volumes:
  prometheus_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${_MONITORING_DIR}/data/prometheus
  grafana_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${_MONITORING_DIR}/data/grafana
  loki_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ${_MONITORING_DIR}/data/loki

services:

  # ---------------------------------------------------------------------------
  # Prometheus — Time-series metrics database and alerting engine
  # ---------------------------------------------------------------------------
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    networks:
      - ${DOCKER_MONITORING_NETWORK}
    extra_hosts:
      - "host.docker.internal:host-gateway"
    ports:
      - "127.0.0.1:${PORT_PROMETHEUS}:9090"
    volumes:
      - prometheus_data:/prometheus
      - ./config/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./config/prometheus/alerts.yml:/etc/prometheus/alerts.yml:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--storage.tsdb.retention.size=10GB'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
      - '--query.max-concurrency=20'
    user: "65534:65534"
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:9090/-/healthy"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    labels:
      - "managed-by=vps-hardening-suite"
      - "service=prometheus"

  # ---------------------------------------------------------------------------
  # Node Exporter — Host system metrics
  # ---------------------------------------------------------------------------
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    networks:
      - ${DOCKER_MONITORING_NETWORK}
    ports:
      - "127.0.0.1:${PORT_NODE_EXPORTER}:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
      - /run/systemd/private:/run/systemd/private:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--path.rootfs=/rootfs'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
      - '--collector.systemd'
      - '--collector.processes'
    pid: host
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:9100/metrics"]
      interval: 30s
      timeout: 10s
      retries: 3
    labels:
      - "managed-by=vps-hardening-suite"
      - "service=node-exporter"

  # ---------------------------------------------------------------------------
  # cAdvisor — Docker container resource metrics
  # ---------------------------------------------------------------------------
  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    restart: unless-stopped
    networks:
      - ${DOCKER_MONITORING_NETWORK}
    ports:
      - "127.0.0.1:${PORT_CADVISOR}:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    privileged: true
    devices:
      - /dev/kmsg
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
    labels:
      - "managed-by=vps-hardening-suite"
      - "service=cadvisor"

  # ---------------------------------------------------------------------------
  # Grafana — Visualization and dashboards
  # ---------------------------------------------------------------------------
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    networks:
      - ${DOCKER_MONITORING_NETWORK}
    ports:
      - "0.0.0.0:${PORT_GRAFANA}:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./config/grafana/provisioning:/etc/grafana/provisioning:ro
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: "${grafana_password}"
      GF_SECURITY_SECRET_KEY: "$(generate_password 32)"
      GF_SECURITY_DISABLE_GRAVATAR: "true"
      GF_SECURITY_COOKIE_SECURE: "false"
      GF_SECURITY_STRICT_TRANSPORT_SECURITY: "false"
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_USERS_ALLOW_ORG_CREATE: "false"
      GF_AUTH_DISABLE_LOGIN_FORM: "false"
      GF_AUTH_ANONYMOUS_ENABLED: "false"
      GF_LOG_MODE: "console file"
      GF_LOG_LEVEL: "warn"
      GF_PATHS_LOGS: /var/log/grafana
      GF_PATHS_DATA: /var/lib/grafana
      GF_ANALYTICS_REPORTING_ENABLED: "false"
      GF_ANALYTICS_CHECK_FOR_UPDATES: "false"
      GF_SERVER_ROOT_URL: "%(protocol)s://%(domain)s:%(http_port)s/"
      GF_INSTALL_PLUGINS: "grafana-clock-panel,grafana-simple-json-datasource,grafana-piechart-panel,alexanderzobnin-zabbix-app"
    user: "472"
    healthcheck:
      test: ["CMD-SHELL", "wget --spider -q http://localhost:3000/api/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    labels:
      - "managed-by=vps-hardening-suite"
      - "service=grafana"

  # ---------------------------------------------------------------------------
  # Loki — Log aggregation system
  # ---------------------------------------------------------------------------
  loki:
    image: grafana/loki:latest
    container_name: loki
    restart: unless-stopped
    networks:
      - ${DOCKER_MONITORING_NETWORK}
    ports:
      - "127.0.0.1:${PORT_LOKI}:3100"
    volumes:
      - loki_data:/loki
      - ./config/loki/loki.yml:/etc/loki/loki.yml:ro
    command: -config.file=/etc/loki/loki.yml
    healthcheck:
      test: ["CMD-SHELL", "wget --spider -q http://localhost:3100/ready || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s
    labels:
      - "managed-by=vps-hardening-suite"
      - "service=loki"

  # ---------------------------------------------------------------------------
  # Promtail — Log shipper for Loki
  # ---------------------------------------------------------------------------
  promtail:
    image: grafana/promtail:latest
    container_name: promtail
    restart: unless-stopped
    networks:
      - ${DOCKER_MONITORING_NETWORK}
    ports:
      - "127.0.0.1:${PORT_PROMTAIL}:9080"
    volumes:
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config/promtail/promtail.yml:/etc/promtail/promtail.yml:ro
    command: -config.file=/etc/promtail/promtail.yml
    depends_on:
      loki:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget --spider -q http://localhost:9080/ready || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    labels:
      - "managed-by=vps-hardening-suite"
      - "service=promtail"
EOF

    log_success "docker-compose.yml written."
}

# ---------------------------------------------------------------------------
# _monitoring_write_prometheus_config — scrape configuration
# ---------------------------------------------------------------------------
_monitoring_write_prometheus_config() {
    cat > "${_MONITORING_DIR}/config/prometheus/prometheus.yml" << 'EOF'
# =============================================================================
# Prometheus configuration — VPS Hardening Suite
# =============================================================================

global:
  scrape_interval: 15s
  evaluation_interval: 15s
  scrape_timeout: 10s
  external_labels:
    monitor: 'vps-hardening-suite'
    environment: 'production'

# Alerting configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets: []

# Rules files
rule_files:
  - /etc/prometheus/alerts.yml

# ---------------------------------------------------------------------------
# Scrape configurations
# ---------------------------------------------------------------------------
scrape_configs:

  # Prometheus self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance

  # Host system metrics via Node Exporter
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance

  # Docker container metrics via cAdvisor
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
    metric_relabel_configs:
      # Drop high-cardinality metrics that aren't very useful
      - source_labels: [__name__]
        regex: 'container_tasks_state|container_memory_failures_total'
        action: drop

  # Grafana self-monitoring
  - job_name: 'grafana'
    static_configs:
      - targets: ['grafana:3000']
    metrics_path: /metrics

  # Loki self-monitoring
  - job_name: 'loki'
    static_configs:
      - targets: ['loki:3100']
    metrics_path: /metrics

  # Docker daemon built-in metrics (requires daemon.json metrics-addr: 127.0.0.1:9323)
  # host.docker.internal resolves to the host via extra_hosts in compose
  - job_name: 'docker-daemon'
    static_configs:
      - targets: ['172.17.0.1:9323']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
EOF

    log_success "Prometheus config written."
}

# ---------------------------------------------------------------------------
# _monitoring_write_prometheus_alerts — Security-focused alerting rules
# ---------------------------------------------------------------------------
_monitoring_write_prometheus_alerts() {
    cat > "${_MONITORING_DIR}/config/prometheus/alerts.yml" << 'EOF'
# =============================================================================
# Prometheus alerting rules — VPS Hardening Suite
# Security and availability focused
# =============================================================================

groups:

  - name: availability
    interval: 30s
    rules:
      - alert: InstanceDown
        expr: up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Instance {{ $labels.instance }} down"
          description: "{{ $labels.job }}/{{ $labels.instance }} has been down for more than 2 minutes."

      - alert: HighCPUUsage
        expr: (100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)) > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is {{ printf \"%.1f\" $value }}% for more than 5 minutes."

      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on {{ $labels.instance }}"
          description: "Memory usage is {{ printf \"%.1f\" $value }}%."

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space on {{ $labels.instance }}"
          description: "Only {{ printf \"%.1f\" $value }}% disk space left on {{ $labels.mountpoint }}."

  - name: security
    interval: 60s
    rules:
      - alert: UnusualNetworkConnections
        expr: node_netstat_Tcp_CurrEstab > 500
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Unusually high TCP connections on {{ $labels.instance }}"
          description: "{{ $value }} established TCP connections (threshold: 500)."

      - alert: ContainerKilled
        expr: time() - container_last_seen > 60
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Container {{ $labels.name }} killed"
          description: "Container {{ $labels.name }} has disappeared."

      - alert: ContainerHighCPU
        expr: (sum(rate(container_cpu_usage_seconds_total{name!=""}[3m])) BY (instance, name) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Container {{ $labels.name }} high CPU"
          description: "Container CPU usage is {{ printf \"%.1f\" $value }}%."
EOF

    log_success "Prometheus alert rules written."
}

# ---------------------------------------------------------------------------
# _monitoring_write_loki_config — Loki storage and retention config
# ---------------------------------------------------------------------------
_monitoring_write_loki_config() {
    cat > "${_MONITORING_DIR}/config/loki/loki.yml" << EOF
# =============================================================================
# Loki configuration — VPS Hardening Suite
# =============================================================================

auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096
  log_level: warn

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: loki_index_
        period: 24h

ruler:
  alertmanager_url: http://localhost:9093

storage_config:
  tsdb_shipper:
    active_index_directory: /loki/tsdb-index
    cache_location: /loki/tsdb-cache
    cache_ttl: 24h

limits_config:
  # Retention period for logs (30 days)
  retention_period: 720h
  # Maximum ingestion rate per tenant
  ingestion_rate_mb: 8
  ingestion_burst_size_mb: 16
  max_streams_per_user: 10000
  max_line_size: 65536
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  # Maximum number of label names per series
  max_label_names_per_series: 30

compactor:
  working_directory: /loki/tsdb-compactor
  compaction_interval: 10m
  retention_enabled: true
  retention_delete_delay: 2h
  retention_delete_worker_count: 150
  delete_request_store: filesystem

analytics:
  reporting_enabled: false
EOF

    log_success "Loki config written."
}

# ---------------------------------------------------------------------------
# _monitoring_write_promtail_config — Log shipping configuration
# ---------------------------------------------------------------------------
_monitoring_write_promtail_config() {
    local server_ip="$1"
    local ssh_port
    ssh_port="$(get_state "ssh_port" 2>/dev/null || echo "2222")"

    cat > "${_MONITORING_DIR}/config/promtail/promtail.yml" << EOF
# =============================================================================
# Promtail configuration — VPS Hardening Suite
# Collects: system logs, auth logs, fail2ban, crowdsec, Docker containers
# =============================================================================

server:
  http_listen_port: 9080
  grpc_listen_port: 0
  log_level: warn

positions:
  filename: /tmp/promtail_positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push
    tenant_id: ""
    timeout: 10s
    backoff_config:
      min_period: 100ms
      max_period: 10s
      max_retries: 10

scrape_configs:

  # ---------------------------------------------------------------------------
  # System auth log — SSH, sudo, PAM events
  # ---------------------------------------------------------------------------
  - job_name: auth-log
    static_configs:
      - targets:
          - localhost
        labels:
          job: auth
          host: ${server_ip}
          __path__: /var/log/auth.log
    pipeline_stages:
      - regex:
          expression: '(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<process>\S+): (?P<message>.*)'
      - labels:
          process:

  # ---------------------------------------------------------------------------
  # Syslog
  # ---------------------------------------------------------------------------
  - job_name: syslog
    static_configs:
      - targets:
          - localhost
        labels:
          job: syslog
          host: ${server_ip}
          __path__: /var/log/syslog

  # ---------------------------------------------------------------------------
  # Fail2Ban
  # ---------------------------------------------------------------------------
  - job_name: fail2ban
    static_configs:
      - targets:
          - localhost
        labels:
          job: fail2ban
          host: ${server_ip}
          __path__: /var/log/fail2ban.log
    pipeline_stages:
      - regex:
          expression: '(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (?P<level>\w+)  \[(?P<jail>[^\]]+)\] (?P<action>Ban|Unban|Found|Restore Ban) (?P<ip>\S+)'
      - labels:
          level:
          jail:
          action:

  # ---------------------------------------------------------------------------
  # VPS Hardening Suite own logs
  # ---------------------------------------------------------------------------
  - job_name: vps-hardening
    static_configs:
      - targets:
          - localhost
        labels:
          job: vps-hardening
          host: ${server_ip}
          __path__: /var/log/vps-hardening/*.log

  # ---------------------------------------------------------------------------
  # Docker container logs (all containers)
  # ---------------------------------------------------------------------------
  - job_name: docker-containers
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        regex: '/(.*)'
        target_label: container
      - source_labels: ['__meta_docker_container_log_stream']
        target_label: logstream
      - source_labels: ['__meta_docker_container_label_managed_by']
        target_label: managed_by
    pipeline_stages:
      - docker: {}
EOF

    log_success "Promtail config written."
}

# ---------------------------------------------------------------------------
# _monitoring_write_grafana_provisioning — Data sources + dashboards provisioning
# ---------------------------------------------------------------------------
_monitoring_write_grafana_provisioning() {
    mkdir -p "${_MONITORING_DIR}/config/grafana/provisioning/"{datasources,dashboards,notifiers}

    # Data sources
    cat > "${_MONITORING_DIR}/config/grafana/provisioning/datasources/datasources.yml" << 'EOF'
# Grafana data source provisioning — VPS Hardening Suite
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
    jsonData:
      timeInterval: "15s"
      queryTimeout: "60s"
      httpMethod: POST

  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    editable: true
    jsonData:
      maxLines: 1000
      derivedFields:
        - datasourceUid: ''
          matcherRegex: '(?:^|\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s|$)'
          name: IP Address
          url: ''
EOF

    # Dashboard provisioning config
    cat > "${_MONITORING_DIR}/config/grafana/provisioning/dashboards/dashboards.yml" << 'EOF'
# Grafana dashboard provisioning — VPS Hardening Suite
apiVersion: 1

providers:
  - name: 'VPS Hardening Suite'
    orgId: 1
    folder: 'VPS Monitoring'
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
      foldersFromFilesStructure: true
EOF

    # Copy dashboard JSON files from project into the provisioning path.
    # Grafana reads *.json files from the `path` defined in dashboards.yml,
    # which maps to /etc/grafana/provisioning/dashboards inside the container.
    local dash_src="${PROJECT_ROOT}/docker/grafana/dashboards"
    if [[ -d "$dash_src" ]]; then
        local dash_dest="${_MONITORING_DIR}/config/grafana/provisioning/dashboards"
        cp "${dash_src}/"*.json "$dash_dest/" 2>/dev/null \
            && log_success "Dashboard JSON files copied: $(ls "${dash_dest}/"*.json 2>/dev/null | wc -l) dashboards." \
            || log_warning "No dashboard JSON files found in ${dash_src}."
    fi

    log_success "Grafana provisioning files written."
}

# ---------------------------------------------------------------------------
# _monitoring_start_stack — Run docker compose up
# ---------------------------------------------------------------------------
_monitoring_start_stack() {
    cd "${_MONITORING_DIR}" || return 1

    log_info "Pulling Docker images (this may take a few minutes)..."
    docker compose pull >> "$LOG_FILE" 2>&1

    log_info "Starting monitoring stack..."
    docker compose up -d >> "$LOG_FILE" 2>&1

    log_success "Monitoring stack started."
}

# ---------------------------------------------------------------------------
# _monitoring_wait_for_health — Poll until all containers report healthy
# ---------------------------------------------------------------------------
_monitoring_wait_for_health() {
    local max_wait=300
    local elapsed=0
    local interval=5
    local required_containers=("prometheus" "grafana" "loki" "node-exporter" "cadvisor" "promtail")

    log_info "Waiting for all containers to become healthy (max ${max_wait}s)..."

    while (( elapsed < max_wait )); do
        local all_healthy=true

        for container in "${required_containers[@]}"; do
            local status
            status="$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "absent")"
            if [[ "$status" != "running" ]]; then
                all_healthy=false
                break
            fi
        done

        if [[ "$all_healthy" == "true" ]]; then
            log_success "All containers are running."
            break
        fi

        sleep "$interval"
        (( elapsed += interval ))
        printf "  ${YELLOW}⟳${RESET} Waiting for containers... %ds / %ds\r" "$elapsed" "$max_wait"
    done
    printf "\n"

    if (( elapsed >= max_wait )); then
        log_warning "Some containers may not be fully healthy. Check with: docker compose ps"
        docker compose -f "${_MONITORING_DIR}/docker-compose.yml" ps 2>&1 | while IFS= read -r line; do
            printf "  %s\n" "$line"
        done
    fi

    # Wait specifically for Grafana HTTP endpoint
    wait_for_port "$PORT_GRAFANA" 120 || log_warning "Grafana API not responding yet; continuing..."
}

# ---------------------------------------------------------------------------
# _monitoring_configure_grafana — Auto-configure via REST API
# ---------------------------------------------------------------------------
_monitoring_configure_grafana() {
    local password="$1"
    local base_url="http://localhost:${PORT_GRAFANA}"
    local auth_header="Authorization: Basic $(echo -n "admin:${password}" | base64)"

    # Wait for Grafana API
    log_info "Waiting for Grafana API..."
    local retries=0
    while (( retries < _GF_API_MAX_RETRIES )); do
        local health
        health="$(curl -sf --max-time 5 "${base_url}/api/health" 2>/dev/null | jq -r '.database' 2>/dev/null || echo "")"
        if [[ "$health" == "ok" ]]; then
            log_success "Grafana API is ready."
            break
        fi
        (( retries++ ))
        sleep "$_GF_API_RETRY_SLEEP"
        printf "  ${YELLOW}⟳${RESET} Waiting for Grafana API... (%d/%d)\r" "$retries" "$_GF_API_MAX_RETRIES"
    done
    printf "\n"

    if (( retries >= _GF_API_MAX_RETRIES )); then
        log_warning "Grafana API did not become ready. Skipping auto-configuration."
        return 0
    fi

    # Create 'VPS Monitoring' folder
    log_info "Creating Grafana folder..."
    local folder_uid
    folder_uid="$(curl -sf -X POST "${base_url}/api/folders" \
        -H "$auth_header" \
        -H "Content-Type: application/json" \
        -d '{"title":"VPS Monitoring","uid":"vps-monitoring"}' \
        2>/dev/null | jq -r '.uid' 2>/dev/null || echo "vps-monitoring")"

    # Import community dashboards
    local dashboard_ids=(
        1860    # Node Exporter Full — https://grafana.com/dashboards/1860
        893     # Docker Containers — https://grafana.com/dashboards/893
        13639   # Logs Dashboard (Loki) — https://grafana.com/dashboards/13639
        10619   # Docker Host & Container Overview
        12486   # Node Exporter Full (alternative)
    )

    log_info "Importing Grafana dashboards..."
    for dash_id in "${dashboard_ids[@]}"; do
        _grafana_import_dashboard "$base_url" "$auth_header" "$dash_id" "$folder_uid"
    done

    # Import custom security dashboard (inline)
    _grafana_import_security_dashboard "$base_url" "$auth_header" "$folder_uid"

    log_success "Grafana configuration complete."
}

# ---------------------------------------------------------------------------
# _grafana_import_dashboard — Import a dashboard by community ID
# ---------------------------------------------------------------------------
_grafana_import_dashboard() {
    local base_url="$1"
    local auth_header="$2"
    local dashboard_id="$3"
    local folder_uid="$4"

    # Fetch dashboard JSON from Grafana.com
    local dashboard_json
    dashboard_json="$(curl -sf --max-time 30 \
        "https://grafana.com/api/dashboards/${dashboard_id}/revisions/latest/download" \
        2>/dev/null || echo "")"

    if [[ -z "$dashboard_json" ]]; then
        log_warning "Could not download dashboard ${dashboard_id} from grafana.com."
        return 0
    fi

    # Build import payload
    local import_payload
    import_payload="$(jq -n \
        --argjson dash "$dashboard_json" \
        --arg folder_uid "$folder_uid" \
        '{
            "dashboard": ($dash | .id = null | .uid = null),
            "overwrite": true,
            "folderId": 0,
            "folderUid": $folder_uid,
            "inputs": [
                {"name": "DS_PROMETHEUS", "type": "datasource", "pluginId": "prometheus", "value": "Prometheus"},
                {"name": "DS_LOKI",       "type": "datasource", "pluginId": "loki",       "value": "Loki"}
            ]
        }' 2>/dev/null)"

    if [[ -z "$import_payload" ]]; then
        log_warning "Failed to build import payload for dashboard ${dashboard_id}."
        return 0
    fi

    local result
    result="$(curl -sf --max-time 30 -X POST "${base_url}/api/dashboards/import" \
        -H "$auth_header" \
        -H "Content-Type: application/json" \
        -d "$import_payload" \
        2>/dev/null | jq -r '.status' 2>/dev/null || echo "error")"

    if [[ "$result" == "success" || "$result" == "Name already in use" ]]; then
        log_success "Dashboard ${dashboard_id} imported successfully."
    else
        log_warning "Dashboard ${dashboard_id} import result: ${result}"
    fi
}

# ---------------------------------------------------------------------------
# _grafana_import_security_dashboard — Inline custom security dashboard
# ---------------------------------------------------------------------------
_grafana_import_security_dashboard() {
    local base_url="$1"
    local auth_header="$2"
    local folder_uid="$3"

    local dashboard_json
    dashboard_json='{
        "title": "VPS Security Overview",
        "tags": ["security", "vps-hardening-suite"],
        "timezone": "browser",
        "schemaVersion": 38,
        "version": 1,
        "refresh": "1m",
        "panels": [
            {
                "id": 1,
                "title": "Active Fail2Ban Bans",
                "type": "stat",
                "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
                "targets": [{
                    "expr": "fail2ban_banned_ips_total",
                    "legendFormat": "Banned IPs",
                    "datasource": {"type": "prometheus", "uid": ""}
                }]
            },
            {
                "id": 2,
                "title": "SSH Login Failures (last hour)",
                "type": "stat",
                "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
                "targets": [{
                    "expr": "increase(fail2ban_failed_attempts_total{jail=\"sshd\"}[1h])",
                    "legendFormat": "SSH Failures",
                    "datasource": {"type": "prometheus", "uid": ""}
                }]
            },
            {
                "id": 3,
                "title": "CPU Usage %",
                "type": "timeseries",
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
                "targets": [{
                    "expr": "100 - (avg by(instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
                    "legendFormat": "CPU {{instance}}",
                    "datasource": {"type": "prometheus", "uid": ""}
                }]
            },
            {
                "id": 4,
                "title": "Memory Usage %",
                "type": "timeseries",
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4},
                "targets": [{
                    "expr": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100",
                    "legendFormat": "Memory {{instance}}",
                    "datasource": {"type": "prometheus", "uid": ""}
                }]
            },
            {
                "id": 5,
                "title": "Recent Auth Log Events",
                "type": "logs",
                "gridPos": {"h": 10, "w": 24, "x": 0, "y": 12},
                "targets": [{
                    "expr": "{job=\"auth\"}",
                    "legendFormat": "",
                    "datasource": {"type": "loki", "uid": ""}
                }]
            }
        ]
    }'

    local import_payload
    import_payload="$(jq -n \
        --argjson dash "$dashboard_json" \
        --arg folder_uid "$folder_uid" \
        '{
            "dashboard": ($dash | .id = null),
            "overwrite": true,
            "folderId": 0,
            "folderUid": $folder_uid
        }' 2>/dev/null)"

    curl -sf --max-time 30 -X POST "${base_url}/api/dashboards/import" \
        -H "$auth_header" \
        -H "Content-Type: application/json" \
        -d "$import_payload" >> "$LOG_FILE" 2>&1 || true

    log_success "Custom security dashboard imported."
}

# ---------------------------------------------------------------------------
# _monitoring_print_access_info — Final access summary
# ---------------------------------------------------------------------------
_monitoring_print_access_info() {
    local grafana_password="$1"
    local server_ip="$2"

    echo ""
    log_section "MONITORING STACK — ACCESS INFORMATION"

    print_summary_table "Service URLs" \
        "Grafana"       "http://${server_ip}:${PORT_GRAFANA}  →  admin / ${grafana_password}" \
        "Prometheus"    "http://${server_ip}:${PORT_PROMETHEUS}  (localhost only)" \
        "Node Exporter" "http://${server_ip}:${PORT_NODE_EXPORTER}/metrics  (localhost only)" \
        "cAdvisor"      "http://${server_ip}:${PORT_CADVISOR}  (localhost only)" \
        "Loki"          "http://${server_ip}:${PORT_LOKI}  (localhost only)" \
        "Promtail"      "http://${server_ip}:${PORT_PROMTAIL}  (localhost only)"

    echo ""
    printf "  ${BOLD}Management commands:${RESET}\n"
    printf "  ${CYAN}cd ${_MONITORING_DIR} && docker compose ps${RESET}\n"
    printf "  ${CYAN}cd ${_MONITORING_DIR} && docker compose logs -f grafana${RESET}\n"
    printf "  ${CYAN}cd ${_MONITORING_DIR} && docker compose restart${RESET}\n"
    printf "  ${CYAN}cd ${_MONITORING_DIR} && docker compose down${RESET}\n"
    echo ""
}
