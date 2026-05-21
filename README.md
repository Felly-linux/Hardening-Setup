<div align="center">

```
 ██╗   ██╗██████╗ ███████╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗███╗   ██╗ ██████╗
 ██║   ██║██╔══██╗██╔════╝    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║████╗  ██║██╔════╝
 ██║   ██║██████╔╝███████╗    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 ╚██╗ ██╔╝██╔═══╝ ╚════██║    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╗██║██║   ██║
  ╚████╔╝ ██║     ███████║    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██║██║ ╚████║╚██████╔╝
   ╚═══╝  ╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
```

**Automated, modular security hardening for production Linux servers**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2020.04%2B%20%7C%20Debian%2011%2B-blue)](#requirements)
[![Shell](https://img.shields.io/badge/shell-Bash%204.4%2B-green)](#requirements)
[![Idempotent](https://img.shields.io/badge/idempotent-yes-brightgreen)](#idempotency)

*Built by [Urpe Integral Services](https://urpe.com) · Author: Maximiliano Arango*

</div>

---

## What It Does

VPS Hardening Suite transforms a bare Ubuntu or Debian VPS into a production-ready, fully observable server in a **single command**. It installs and wires together:

| Layer | Tools | What it protects |
|---|---|---|
| **Network perimeter** | UFW + CrowdSec | Blocks known-bad IPs before they reach any service |
| **Authentication** | SSH hardening + Fail2Ban | Eliminates weak auth vectors; bans brute-force attempts |
| **Runtime isolation** | Docker with hardened daemon | Monitoring stack runs containerized with least privilege |
| **Observability** | Prometheus + Grafana + Loki | Every security event is captured, correlated, and queryable |

Every module is **idempotent** — safe to re-run. State is tracked in `/var/lib/vps-hardening/state.json`. All config files are backed up before modification.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/urpe-integral-services/vps-hardening-suite.git
cd vps-hardening-suite

# 2. Configure
cp .env.example .env
nano .env          # Set GRAFANA_PASSWORD, SSH_PORT, SSH_USER at minimum

# 3. Run
sudo bash install.sh
```

That's it. The interactive menu guides you through the rest.

---

## Installation Modes

Pass `--mode` to skip the menu entirely:

```bash
sudo bash install.sh --mode=basic          # SSH + UFW + Fail2Ban
sudo bash install.sh --mode=intermediate   # + CrowdSec + Docker + full monitoring stack
sudo bash install.sh --mode=hardcore       # everything, strictest settings
sudo bash install.sh --mode=custom         # pick modules individually

# CI / agent-driven (no prompts)
NONINTERACTIVE=1 sudo bash install.sh --mode=intermediate
```

Additional flags:

```bash
--skip-module=NAME   # Skip a specific module (repeatable)
--force              # Re-run modules already marked complete
```

---

## Modules

| # | ID | What it installs / configures |
|---|---|---|
| 00 | `preflight` | OS check, disk/RAM, internet, port conflict scan |
| 01 | `system` | Kernel hardening via sysctl, unattended-upgrades, login policies |
| 02 | `users` | Admin user, sudo hardening, SSH key provisioning |
| 03 | `ssh` | ed25519/RSA-only keys, modern ciphers, `MaxAuthTries 3`, no password auth |
| 04 | `firewall` | UFW — deny-all default, DOCKER-USER chain, IPv6 enforcement |
| 05 | `fail2ban` | sshd, sshd-ddos, and recidive jails; systemd backend |
| 06 | `crowdsec` | CrowdSec agent + firewall bouncer; LAPI on `127.0.0.1:6767` |
| 07 | `docker` | Docker Engine — json-file log capping, live-restore, metrics endpoint |
| 08 | `monitoring` | Prometheus · Grafana · Loki · Promtail · Node Exporter · cAdvisor |

---

## Security Architecture

```
                         INTERNET
                            │
                     ┌──────▼──────┐
                     │  UFW        │  deny all inbound by default
                     │  iptables   │  DOCKER-USER chain enforced
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │  CrowdSec   │  community blocklists → iptables DROP
                     │  Bouncer    │  LAPI: 127.0.0.1:6767
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │  Fail2Ban   │  watches auth.log → bans brute-force IPs
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │  sshd       │  ed25519, no password auth, MaxAuthTries 3
                     └─────────────┘

   All security events → Promtail → Loki → Grafana (queryable + alertable)
```

All monitoring ports bind to `127.0.0.1`. Access via SSH tunnel:

```bash
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 user@YOUR_VPS
# Grafana:    http://localhost:3000   (admin / your GRAFANA_PASSWORD)
# Prometheus: http://localhost:9090
```

---

## Port Reference

| Service | Host binding | Notes |
|---|---|---|
| SSH | `0.0.0.0:22` (configurable) | Only public port |
| Prometheus | `127.0.0.1:9090` | SSH tunnel to access |
| Grafana | `127.0.0.1:3000` | SSH tunnel to access |
| Node Exporter | host network `:9100` | `network_mode: host` for accurate NIC stats |
| cAdvisor | `127.0.0.1:8081` | Host port 8081, internal 8080 |
| Loki | `127.0.0.1:3100` | Access via Grafana Explore |
| CrowdSec LAPI | `127.0.0.1:6767` | Moved from default 8080 to avoid conflicts |
| Docker metrics | `127.0.0.1:9323` | Requires `experimental: true` in daemon.json |

---

## Requirements

| | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04 / Debian 11 | Ubuntu 22.04 / Debian 12 |
| RAM | 1 GB | 2 GB+ |
| Disk | 10 GB free | 20 GB+ free |
| Shell | Bash 4.4 | Bash 5.x |
| Privileges | root | root |
| Dependencies | `curl`, `jq`, `git` | same |

---

## After Installation

### Check module status

```bash
sudo bash install.sh   # reopens the menu → option 9: Show status
# or directly:
cat /var/lib/vps-hardening/state.json | jq .
```

### Manage CrowdSec

```bash
cscli decisions list        # active IP bans
cscli alerts list           # recent threat events
cscli hub update            # update threat intelligence
```

### Manage Fail2Ban

```bash
fail2ban-client status sshd                    # banned IPs + counters
fail2ban-client set sshd unbanip IP_ADDRESS    # unban yourself if locked out
```

### Restart the monitoring stack

```bash
docker compose -f /opt/monitoring/docker-compose.yml restart
docker compose -f /opt/monitoring/docker-compose.yml ps
```

### Force re-run a module

```bash
sudo jq 'del(.module_crowdsec, .module_crowdsec_time)' \
    /var/lib/vps-hardening/state.json > /tmp/s.tmp \
    && sudo mv /tmp/s.tmp /var/lib/vps-hardening/state.json
sudo bash install.sh --mode=custom   # pick crowdsec
```

---

## Important Security Notes

> Read before deploying.

**SSH keys required.** The SSH module disables password authentication. Ensure your public key is in `~/.ssh/authorized_keys` on the server *before* running the SSH module. The installer verifies this before making changes.

**Keep console access.** The CrowdSec bouncer blocks at the iptables level. If your own IP gets banned, you will be locked out of SSH. Always keep the VPS provider's web console (KVM/VNC) available as a fallback.

**Change the Grafana password.** Set `GRAFANA_PASSWORD` in `.env` before running the installer. Do not leave it as `changeme`.

**Backups contain config secrets.** The `backups/` directory holds original copies of `/etc/ssh/sshd_config`, `/etc/crowdsec/config.yaml`, and others. This directory is git-ignored — never commit it.

**UFW and Docker.** Docker manipulates iptables directly and can bypass UFW rules. This suite installs DOCKER-USER chain rules to restore UFW authority. If you add UFW rules manually after installation, test that Docker container traffic is not inadvertently blocked.

---

## Directory Structure

```
vps-hardening-suite/
├── install.sh                  # Main entry point
├── .env.example                # Environment variable template — copy to .env
├── lib/
│   └── common.sh               # Shared library: logging, state, helpers, port constants
├── modules/
│   ├── 00_preflight.sh .. 08_monitoring.sh
├── configs/
│   ├── sshd/sshd_config.template
│   ├── fail2ban/jail.local
│   └── crowdsec/config.yaml.template
├── docker/
│   ├── docker-compose.yml
│   ├── prometheus/prometheus.yml
│   ├── grafana/provisioning/
│   ├── loki/loki-config.yml
│   └── promtail/promtail-config.yml
├── templates/
│   ├── motd.sh                 # Dynamic login MOTD
│   └── banner.txt              # SSH pre-auth legal banner
├── docs/
│   ├── ARCHITECTURE.md         # Deep technical architecture + data flow diagrams
│   └── TROUBLESHOOTING.md      # Diagnostic runbooks for every component
└── backups/                    # Auto-created at runtime; git-ignored
```

---

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, security layers, service descriptions, state management, network architecture |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Symptom → cause → fix runbooks for SSH, Docker, Prometheus, Grafana, Loki, CrowdSec, Fail2Ban, UFW |
| [CHANGELOG.md](CHANGELOG.md) | Release history and security decisions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute, code style, security disclosure |

---

## License

MIT — see [LICENSE](LICENSE).

© 2025 [Urpe Integral Services](https://urpe.com) · Maximiliano Arango
