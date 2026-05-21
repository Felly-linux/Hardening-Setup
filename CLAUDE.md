# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Profile-driven, idempotent Bash automation framework that hardens Ubuntu/Debian servers. Targets: UFW, Fail2Ban, CrowdSec, SSH, sysctl kernel params, auditd, filesystem permissions, Docker, and a Prometheus/Grafana/Loki monitoring stack.

## Running the Installer

```bash
# Profile-based (primary interface)
sudo bash install.sh --profile vps
sudo bash install.sh --profile docker-host
sudo bash install.sh --profile paranoid

# Preview without changes
sudo bash install.sh --profile vps --dry-run

# Security audit (read-only score check)
sudo bash install.sh --audit-only

# Module override
sudo bash install.sh --profile vps --module ssh --module firewall
sudo bash install.sh --profile docker-host --skip-module monitoring

# Rollback a module
sudo bash install.sh --rollback ssh

# Fully headless
sudo bash install.sh --profile vps --non-interactive --report json
```

## Tests

```bash
bash tests/run_tests.sh          # all tests
bash tests/test_shellcheck.sh    # ShellCheck -S warning -x on all .sh files
bash tests/test_syntax.sh        # bash -n on all .sh files
```

## Architecture

### Profile system

`profiles/NAME.conf` files are sourced by `install.sh` before any module runs. They export bash variables that modules read with safe defaults. Available profiles: `vps`, `docker-host`, `homelab`, `desktop`, `paranoid`.

Profile variable pattern in modules:
```bash
SSH_PORT="${SSH_PORT:-22}"   # profile sets it; module reads with default
```

### Entry point → modules

`install.sh` loads a profile, builds the module list (`ENABLED_MODULES` from profile, overridable via `--module`/`--skip-module`), then for each module: sources the file, calls `run_<id>()`, writes result to state.

Module registry order (profile-defined, not hardcoded):
```
preflight → system → users → ssh → firewall → fail2ban → crowdsec → sysctl → audit → permissions → docker → monitoring
```

### Shared library: `lib/`

`lib/common.sh` is a thin loader — it sources the four actual libraries:

| File | Owns |
|---|---|
| `lib/logging.sh` | ANSI colors, `log_info/success/warning/error/section/step`, `print_banner`, `show_progress`, `print_summary_table` |
| `lib/helpers.sh` | Port constants, OS detection (`detect_os` → `OS_ID/VERSION/CODENAME`), system checks (`command_exists`, `service_running`, `package_installed`, `port_in_use`), state I/O (`save_state`, `get_state`, `mark_module_complete`, `module_completed`), prompts (`confirm`, `ask`, `ask_password`) |
| `lib/backups.sh` | `backup_file`, `restore_file`, `list_backups`, `run_with_log` |
| `lib/validation.sh` | `validate_sshd_config`, `validate_sysctl_value`, `validate_ufw_active`, `validate_service_active`, `check_dependencies`, `post_module_verify` |

Port constants (from `lib/helpers.sh`):
- `PORT_CROWDSEC_LAPI=6767` (moved from default 8080 — cAdvisor conflict)
- `PORT_PROMETHEUS=9090`, `PORT_GRAFANA=3000`, `PORT_LOKI=3100`
- `PORT_NODE_EXPORTER=9100`, `PORT_CADVISOR=8081`, `PORT_PROMTAIL=9080`

### DRY_RUN mode

`install.sh --dry-run` exports `DRY_RUN=1`. Every module checks this before any destructive operation:
```bash
[[ "${DRY_RUN:-0}" == "1" ]] && { log_info "[DRY-RUN] Would do X."; return 0; }
```

### Idempotency pattern

Modules check `module_completed "<id>"` at start and return early if done (unless `--force` passed). Packages checked with `package_installed` before `apt-get`. Config files backed up with `backup_file` before modification. Backups in `./backups/` (gitignored, may contain secrets).

### Monitoring stack

Deployed by `modules/monitoring.sh` to `${MONITORING_DIR:-/opt/monitoring}/` via Docker Compose. All services bind to `127.0.0.1`. Access via SSH tunnel:

```bash
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 user@VPS_IP
```

**Node Exporter**: `network_mode: host` — required for accurate NIC stats.  
**cAdvisor**: `privileged: true` — required for cgroup access. Host port `8081` (not 8080) to avoid CrowdSec LAPI conflict.  
**Loki**: `kvstore: inmemory` + `replication_factor: 1` — mandatory for single-node. Do not change to consul/memberlist.  
**DOCKER-USER chain**: Docker bypasses UFW by default. `modules/firewall.sh` inserts rules into DOCKER-USER to restore UFW authority.

### CrowdSec LAPI port

Always `127.0.0.1:6767`. If changed via `CROWDSEC_LAPI_PORT` profile variable, the module updates both `/etc/crowdsec/config.yaml` and `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`.

## Adding a New Module

1. Create `modules/name.sh` with `set -euo pipefail`, double-source guard, lib/common.sh source guard.
2. Declare profile variables at top with safe defaults: `VAR="${VAR:-default}"`.
3. Expose one public function `run_name()`.
4. Call `mark_module_complete "name"` at the end on success.
5. Wrap all destructive commands in `[[ "${DRY_RUN:-0}" != "1" ]]`.
6. Add to relevant profile `.conf` files under `ENABLED_MODULES`.
7. Add a `post_module_verify "name"` hook in `lib/validation.sh` if applicable.
8. Document threat model at top of file (what threat, what breaks, what trade-off).

## Key Design Constraints

- **No `experimental: true` in Docker daemon.json** — security risk on production outweighs metrics endpoint benefit.
- **CrowdSec LAPI never on 8080** — cAdvisor uses that port internally.
- **Loki kvstore always `inmemory` for single-node** — memberlist/consul only for multi-replica clusters.
- **sshd never restarted without confirmation gate** — SSH misconfiguration can lock out permanently.
- **All modules must tolerate being re-run** — no action if state is already correct.
