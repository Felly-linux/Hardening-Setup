# VPS Hardening Suite

```
 ██╗   ██╗██████╗ ███████╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗███╗   ██╗ ██████╗
 ██║   ██║██╔══██╗██╔════╝    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║████╗  ██║██╔════╝
 ██║   ██║██████╔╝███████╗    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 ╚██╗ ██╔╝██╔═══╝ ╚════██║    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╗██║██║   ██║
  ╚████╔╝ ██║     ███████║    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██║██║ ╚████║╚██████╔╝
   ╚═══╝  ╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝

        VPS Hardening Suite  •  Urpe Integral Services  •  2025
        Automated security hardening for production Linux servers
```

---

## Overview

**VPS Hardening Suite** is an idempotent, modular Bash automation framework that transforms a bare Ubuntu/Debian VPS into a hardened, fully observable production server in a single command. It installs and configures a multi-layer security stack (UFW, Fail2Ban, CrowdSec) and a complete observability stack (Prometheus, Grafana, Loki, Node Exporter, cAdvisor, Promtail) — all wired together and secured by default.

Every module is designed to be run multiple times without side effects. State is tracked in `/var/lib/vps-hardening/state.json` so the installer can safely resume after interruption or skip already-completed steps. All critical config files are backed up before modification. The suite targets solo VPS operators, small DevOps teams, and AI agents maintaining infrastructure on behalf of clients.

---

## Features

- **Layered security hardening** — UFW firewall, Fail2Ban brute-force protection, and CrowdSec community threat intelligence working in concert
- **SSH fortress** — ed25519 + RSA keys, modern cipher suites only, MaxAuthTries limited, agent and TCP forwarding disabled
- **Full observability** — Prometheus metrics + Grafana dashboards + Loki log aggregation, all provisioned automatically
- **Container metrics** — cAdvisor tracks every Docker container's CPU, memory, and I/O in real time
- **Host metrics** — Node Exporter runs on the host network for accurate NIC statistics
- **Centralized logging** — Promtail ships auth, syslog, kernel, UFW, Fail2Ban, CrowdSec, and Docker container logs to Loki
- **Idempotent execution** — safe to re-run; completed modules are skipped automatically
- **Pre-flight backups** — all modified system files are backed up with timestamps before any change
- **Conflict-aware port assignment** — CrowdSec LAPI on 6767 and cAdvisor on host port 8081 to avoid the common 8080 collision
- **Docker log management** — json-file driver capped at 10 MB / 3 rotations; live-restore enabled so containers survive daemon restarts
- **Non-interactive mode** — set `NONINTERACTIVE=1` for fully automated CI/CD or agent-driven deployment

---

## Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| **OS** | Ubuntu 20.04 LTS / Debian 11 | Ubuntu 22.04 LTS / Debian 12 |
| **RAM** | 1 GB | 2 GB+ |
| **CPU** | 1 vCPU | 2 vCPU+ |
| **Disk** | 10 GB free | 20 GB+ free |
| **Privileges** | root (sudo) | root (sudo) |
| **Network** | Outbound HTTPS | Outbound HTTPS |
| **Shell** | Bash 4.4+ | Bash 5.x |
| **Dependencies** | `curl`, `jq`, `git` | same |

**Ports that must be available at install time:**

| Port | Required by |
|---|---|
| 22 (or custom SSH port) | SSH daemon |
| 9090 | Prometheus |
| 3000 | Grafana |
| 9100 | Node Exporter |
| 8081 (host) | cAdvisor |
| 3100 | Loki |
| 9080 | Promtail |
| 6767 | CrowdSec LAPI |

> All monitoring ports bind to `127.0.0.1` only. They are not accessible from the internet without an SSH tunnel or reverse proxy.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/urpe/vps-hardening-suite.git /opt/vps-hardening-suite
cd /opt/vps-hardening-suite

# 2. Copy and edit the environment file
cp .env.example .env
nano .env   # Set GRAFANA_PASSWORD, SERVER_DOMAIN, SSH_PORT, etc.

# 3. Run the installer as root
sudo bash install.sh

# 4. Access Grafana (via SSH tunnel if on a remote VPS)
ssh -L 3000:127.0.0.1:3000 user@your-vps
# Then open: http://localhost:3000  (admin / your GRAFANA_PASSWORD)
```

---

## Installation Modes

| Mode | What It Installs | Best For |
|---|---|---|
| **basic** | UFW + SSH hardening | Minimal attack surface, no extra stack |
| **intermediate** | basic + Fail2Ban + CrowdSec | Active threat response without containers |
| **hardcore** | intermediate + full Docker monitoring stack | Production VPS with full observability |
| **custom** | Interactive menu — pick individual modules | Advanced users, partial upgrades |

Select the mode at the prompt or pass it as an argument:

```bash
sudo bash install.sh --mode hardcore
sudo bash install.sh --mode custom
```

---

## Module Overview

| Module | What It Does | Idempotent |
|---|---|---|
| `ufw` | Configures UFW rules: deny all in, allow SSH + specified ports, enable IPv6 | Yes |
| `ssh` | Hardens sshd_config: ed25519/RSA keys, modern ciphers, MaxAuthTries 3, no agent/TCP forwarding | Yes |
| `fail2ban` | Installs Fail2Ban, writes jail.local for SSH + recurring jails, starts service | Yes |
| `crowdsec` | Installs CrowdSec, registers machine, installs bouncers, sets LAPI port to 6767 | Yes |
| `docker` | Installs Docker Engine, configures daemon (json-file logs, live-restore, metrics on 9323) | Yes |
| `monitoring` | Creates Docker network, writes all config files, pulls images, runs `docker compose up -d` | Yes |
| `prometheus` | Prometheus config + scrape targets for node-exporter, cadvisor, docker, self | Yes |
| `grafana` | Grafana datasource provisioning (Prometheus + Loki), installs dashboard plugins | Yes |
| `loki` | Standalone Loki with inmemory ring kvstore + filesystem TSDB storage | Yes |
| `promtail` | Ships auth, syslog, kernel, ufw, fail2ban, crowdsec, dpkg, docker logs to Loki | Yes |
| `backup` | Backs up all modified system config files to `./backups/` with timestamps | Yes |

---

## Port Reference

| Service | Internal Port | Host Binding | Notes |
|---|---|---|---|
| **Prometheus** | 9090 | `127.0.0.1:9090` | Metrics TSDB; never expose publicly |
| **Grafana** | 3000 | `127.0.0.1:3000` | Web UI; access via SSH tunnel or reverse proxy |
| **Node Exporter** | 9100 | host network | Uses `network_mode: host` for accurate NIC metrics |
| **cAdvisor** | 8080 (internal) | `127.0.0.1:8081` | Host port shifted to 8081 to avoid conflict with CrowdSec |
| **Loki** | 3100 | `127.0.0.1:3100` | Log ingestion + query API |
| **Promtail** | 9080 | `127.0.0.1:9080` | Internal only; no host binding needed |
| **CrowdSec LAPI** | 6767 | `127.0.0.1:6767` | Moved from default 8080 to avoid port conflict |
| **Docker metrics** | 9323 | `127.0.0.1:9323` | Docker daemon Prometheus endpoint; requires `experimental: true` |

> **Security note:** No monitoring port is exposed on `0.0.0.0`. Access is strictly via localhost. Use `ssh -L LOCAL_PORT:127.0.0.1:REMOTE_PORT user@host` to forward any port to your workstation.

---

## Directory Structure

```
vps-hardening-suite/
├── install.sh                      # Main installer entrypoint
├── .env.example                    # Environment variable template
├── .env                            # Your local configuration (gitignored)
│
├── lib/
│   └── common.sh                   # Shared library: logging, state, helpers
│
├── modules/                        # One .sh file per installer module
│   ├── ufw.sh
│   ├── ssh.sh
│   ├── fail2ban.sh
│   ├── crowdsec.sh
│   ├── docker.sh
│   └── monitoring.sh
│
├── configs/                        # Static config files deployed by modules
│   ├── sshd/
│   │   └── sshd_config             # Hardened SSH daemon config
│   ├── fail2ban/
│   │   └── jail.local              # Fail2Ban jail definitions
│   ├── crowdsec/                   # CrowdSec config overrides
│   ├── prometheus/
│   ├── grafana/
│   ├── loki/
│   └── promtail/
│
├── docker/                         # Docker Compose stack for monitoring
│   ├── docker-compose.yml          # All monitoring services
│   ├── prometheus/
│   │   └── prometheus.yml          # Scrape targets and rules
│   ├── grafana/
│   │   └── provisioning/
│   │       └── datasources/
│   │           └── datasources.yml # Auto-provisioned Prometheus + Loki
│   ├── loki/
│   │   └── loki-config.yml         # Standalone Loki, inmemory ring, TSDB v13
│   └── promtail/
│       └── promtail-config.yml     # Log scrape jobs for all system sources
│
├── backups/                        # Auto-created; timestamped config backups
├── logs/                           # Installer log output
│   └── install.log
│
├── templates/                      # Jinja-style templates for generated files
│
└── docs/                           # This documentation
    ├── README.md                   # You are here
    ├── ARCHITECTURE.md             # Deep technical architecture
    ├── TROUBLESHOOTING.md          # Diagnostic runbooks
    └── index.html                  # Self-contained HTML docs page
```

---

## Post-Install: Accessing Services

All services bind to `127.0.0.1`. On a remote VPS you must forward ports with SSH.

### Grafana (dashboards)

```bash
# Forward Grafana to your local machine
ssh -L 3000:127.0.0.1:3000 user@YOUR_VPS_IP

# Open in browser
http://localhost:3000
# Username: admin
# Password: value of GRAFANA_PASSWORD in your .env
```

### Prometheus (raw metrics / query)

```bash
ssh -L 9090:127.0.0.1:9090 user@YOUR_VPS_IP
# Open: http://localhost:9090
```

### Loki (log exploration via Grafana)

Loki is accessed through Grafana's Explore view — no direct browser access needed.
Navigate to: `Grafana > Explore > select "Loki" datasource > run LogQL queries`.

### Verify all containers are running

```bash
docker compose -f /opt/monitoring/docker-compose.yml ps
```

### CrowdSec management

```bash
cscli decisions list          # Active IP bans
cscli alerts list             # Recent threat alerts
cscli machines list           # Registered agents
cscli bouncers list           # Active bouncers
```

---

## Environment Variables

Copy `.env.example` to `.env` and set values before running the installer.

| Variable | Default | Description |
|---|---|---|
| `GRAFANA_PASSWORD` | `admin` | Grafana admin password — **change this** |
| `SERVER_DOMAIN` | `localhost` | Public hostname or IP for Grafana server config |
| `SSH_PORT` | `22` | SSH listen port (module will update UFW + sshd_config) |
| `SSH_USER` | *(current user)* | Non-root user to authorize for key-based SSH |
| `NONINTERACTIVE` | `0` | Set to `1` to skip all prompts (CI/agent mode) |
| `INSTALL_MODE` | `hardcore` | One of: `basic`, `intermediate`, `hardcore`, `custom` |
| `CROWDSEC_LAPI_PORT` | `6767` | CrowdSec LAPI listen port (default avoids 8080 conflict) |
| `MONITORING_DIR` | `/opt/monitoring` | Where monitoring stack files are deployed |
| `BACKUP_CONFIGS` | `1` | Set to `0` to skip pre-modification backups (not recommended) |

---

## Security Notes

> Read carefully before deploying.

- **Never expose monitoring ports publicly.** Prometheus, Grafana, Loki, and cAdvisor all listen on `127.0.0.1` only. If you put Grafana behind a reverse proxy (nginx/Caddy), require authentication and enforce HTTPS.

- **Change the Grafana admin password.** The default is `admin`. Set `GRAFANA_PASSWORD` in `.env` before running the installer.

- **The CrowdSec bouncer blocks IPs at the OS level (iptables/nftables).** If you accidentally trigger a ban on your own IP, you will be locked out. Always keep an out-of-band console access (VPS provider panel) available.

- **SSH hardening disables password authentication.** Ensure your public key is in `~/.ssh/authorized_keys` on the server before running the SSH module. The installer will verify this before making changes.

- **Backup files in `./backups/` are unencrypted.** They may contain sensitive configuration. Do not commit this directory to version control (`.gitignore` excludes it).

- **Docker daemon metrics endpoint (port 9323) requires `experimental: true`** in `/etc/docker/daemon.json`. This is set automatically by the docker module. If you disable experimental features later, the Prometheus scrape target `docker` will go down — this is non-critical.

- **Fail2Ban and CrowdSec can both ban IPs.** They operate independently. This is intentional (defense in depth) but means an IP can appear in both `fail2ban-client status sshd` and `cscli decisions list`.

- **UFW and Docker interact.** Docker manipulates iptables directly and can bypass UFW rules. The installer applies the `DOCKER-USER` iptables chain approach to restore UFW authority over Docker traffic. Review `ufw.sh` before customizing firewall rules.

---

## License

MIT License — Copyright (c) 2025 Urpe Integral Services

## Author

**Maximiliano Arango** — Ingeniero de Ciberseguridad, Urpe Integral Services
Contact: ma@urpeailab.com
