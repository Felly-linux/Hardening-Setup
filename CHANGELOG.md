# Changelog

All notable changes to VPS Hardening Suite are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Planned
- Nginx module with hardened TLS config and rate limiting
- Automatic Let's Encrypt / Caddy reverse proxy for Grafana
- Alertmanager integration with Prometheus
- Wazuh HIDS module

---

## [1.0.0] — 2025-05-18

### Added
- `modules/00_preflight.sh` — OS check, internet, disk, RAM, port conflict scan
- `modules/01_system.sh` — Base system hardening (sysctl, kernel params, auto-updates)
- `modules/02_users.sh` — Admin user creation, sudo lockdown, SSH key provisioning
- `modules/03_ssh.sh` — Full SSH hardening: ed25519/RSA keys, modern ciphers only, no password auth
- `modules/04_firewall.sh` — UFW with DOCKER-USER chain, IPv6 enforcement
- `modules/05_fail2ban.sh` — Fail2Ban with sshd, sshd-ddos, and recidive jails
- `modules/06_crowdsec.sh` — CrowdSec agent + firewall bouncer, LAPI on port 6767
- `modules/07_docker.sh` — Docker Engine with json-file log capping and live-restore
- `modules/08_monitoring.sh` — Full Prometheus + Grafana + Loki + Promtail + Node Exporter + cAdvisor stack
- `lib/common.sh` — Shared library: logging, state, prompts, OS detection, network helpers
- `configs/` — Hardened templates for sshd_config, jail.local, crowdsec config.yaml
- `docker/` — Docker Compose stack with health checks, named volumes, `monitoring` bridge network
- `templates/motd.sh` — Dynamic login MOTD showing system and security service status
- `templates/banner.txt` — Legal notice SSH pre-auth banner
- Idempotent state tracking via `/var/lib/vps-hardening/state.json`
- Non-interactive mode (`NONINTERACTIVE=1`) for CI/agent use
- Automatic backup of all modified system config files to `./backups/`
- Port conflict detection and auto-remapping in preflight module
- `docs/ARCHITECTURE.md` — Detailed system architecture with data flow diagrams
- `docs/TROUBLESHOOTING.md` — Runbooks for SSH, Docker, Prometheus, Grafana, Loki, CrowdSec, Fail2Ban, UFW

### Security decisions
- CrowdSec LAPI moved from default `0.0.0.0:8080` to `127.0.0.1:6767` to avoid conflict with cAdvisor
- cAdvisor host port mapped to `8081` instead of `8080`
- All monitoring ports bound to `127.0.0.1` — never `0.0.0.0`
- Grafana Explore is the access path for Loki (no direct browser access to `:3100`)
- Loki configured with `kvstore: inmemory` for stable single-node operation
