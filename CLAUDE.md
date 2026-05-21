# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Idempotent, modular Bash automation suite that hardens a bare Ubuntu/Debian VPS. Targets: UFW, Fail2Ban, CrowdSec, SSH, Docker, and a Prometheus/Grafana/Loki monitoring stack.

## Running the Installer

```bash
# Interactive menu (default)
sudo bash install.sh

# Non-interactive modes
sudo bash install.sh --mode=basic          # SSH + UFW + Fail2Ban
sudo bash install.sh --mode=intermediate   # + CrowdSec + Docker + Monitoring
sudo bash install.sh --mode=hardcore       # all modules, strictest settings
sudo bash install.sh --mode=custom         # interactive module picker

# Skip a module
sudo bash install.sh --skip-module=crowdsec

# Force re-run of already-completed modules
sudo bash install.sh --force

# Fully headless (CI / agent-driven)
NONINTERACTIVE=1 sudo bash install.sh --mode=intermediate
```

State is persisted in `/var/lib/vps-hardening/state.json`. Completed modules are skipped automatically unless `--force` is passed. To manually reset a module:

```bash
sudo jq 'del(.module_fail2ban, .module_fail2ban_time)' \
    /var/lib/vps-hardening/state.json > /tmp/s.tmp \
    && sudo mv /tmp/s.tmp /var/lib/vps-hardening/state.json
```

## Architecture

### Entry point → modules

`install.sh` sources `lib/common.sh`, then sources each module script on demand. Each module exposes exactly one public function named `run_<id>()` (e.g. `run_fail2ban`). The installer calls that function, checks the exit code, and writes the result to state.

Module registry in `install.sh` (order matters — preflight always runs first):
```
preflight → system → users → ssh → firewall → fail2ban → crowdsec → docker → monitoring
```

### Shared library: `lib/common.sh`

Single source of truth for:
- **Port constants** — `PORT_GRAFANA=3000`, `PORT_PROMETHEUS=9090`, `PORT_LOKI=3100`, `PORT_NODE_EXPORTER=9100`, `PORT_CADVISOR=8081`, `PORT_CROWDSEC_LAPI=6767`
- **State I/O** — `save_state key val`, `get_state key`, `mark_module_complete name`, `module_completed name`
- **Logging** — `log_info`, `log_success`, `log_warning`, `log_error`, `log_section`, `log_step`
- **System checks** — `command_exists`, `service_running`, `package_installed`, `port_in_use`, `check_root`
- **UI helpers** — `confirm`, `ask`, `ask_password`, `show_progress`, `print_summary_table`
- **OS globals** set by `detect_os()` — `OS_ID`, `OS_VERSION`, `OS_CODENAME`

All module scripts source `lib/common.sh` implicitly (it is sourced before any module runs in `install.sh`).

### Monitoring stack

Deployed by `modules/08_monitoring.sh` from `docker/docker-compose.yml` to `/opt/monitoring/`. All services bind to `127.0.0.1` only — never `0.0.0.0`. Access via SSH tunnel:

```bash
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 user@VPS_IP
```

**Node Exporter** uses `network_mode: host` — required for accurate NIC stats. This is intentional.

**cAdvisor** uses `privileged: true` — required for cgroup access. Host port is `8081` (not 8080) to avoid the CrowdSec LAPI default conflict.

**CrowdSec LAPI** listens on `127.0.0.1:6767` — moved from default `0.0.0.0:8080`. If you change this port, update both `/etc/crowdsec/config.yaml` AND `PORT_CROWDSEC_LAPI` in `lib/common.sh`.

**Loki** uses `kvstore: inmemory` and `replication_factor: 1` — mandatory for single-node. Do not change to consul/memberlist unless deploying a cluster.

**DOCKER-USER iptables chain** — Docker bypasses UFW by default. The firewall module inserts rules into `DOCKER-USER` to restore UFW authority. Modifying UFW rules without accounting for this will leave Docker ports exposed.

### Idempotency pattern

Every module checks `module_completed "<id>"` at the start and returns early if already done. Modules that install packages use `package_installed` before calling `apt-get`. Config files are backed up via `backup_file` before modification. All backups land in `./backups/` (gitignored, may contain secrets — never commit).

### HARDCORE_MODE flag

When `--mode=hardcore` is used, `HARDCORE_MODE=1` is exported. Individual modules check this flag to apply stricter settings (e.g., shorter Fail2Ban bantime, more restricted SSH ciphers). Check for `[[ "${HARDCORE_MODE:-0}" == "1" ]]` before adding mode-sensitive logic.

## Adding a New Module

1. Create `modules/NN_name.sh` with `set -euo pipefail` and a `run_name()` function.
2. Add an entry to `MODULE_REGISTRY` in `install.sh`: `"name:modules/NN_name.sh:Display Name"`.
3. Use `require_module <dep>` at the top of `run_name()` if the module has prerequisites.
4. Call `mark_module_complete "name"` at the end on success.
5. Use only functions from `lib/common.sh` for logging, state, and system checks.
