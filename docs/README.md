# VPS Hardening Suite

```
 ██╗   ██╗██████╗ ███████╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗███╗   ██╗ ██████╗
 ██║   ██║██╔══██╗██╔════╝    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║████╗  ██║██╔════╝
 ██║   ██║██████╔╝███████╗    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 ╚██╗ ██╔╝██╔═══╝ ╚════██║    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╗██║██║   ██║
  ╚████╔╝ ██║     ███████║    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██║██║ ╚████║╚██████╔╝
   ╚═══╝  ╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝

        VPS Hardening Suite  •  Maximiliano Arango  •  2025
        Profile-driven security hardening for production Linux servers
```

---

## Overview

**VPS Hardening Suite** is an idempotent, profile-driven Bash automation framework that transforms a bare Ubuntu/Debian server into a hardened, fully observable production system. Every hardening action documents the specific threat it mitigates, what can break, and the trade-off involved — no generic CIS benchmark copy-paste.

---

## Features

- **Profile-driven** — choose `vps`, `docker-host`, `homelab`, `desktop`, or `paranoid`; customize with plain bash variables
- **Kernel hardening** — sysctl: SYN cookies, RP filter, ICMP hardening, dmesg_restrict, ASLR, symlink/hardlink protection
- **Audit trail** — auditd rules covering sudo, SSH key changes, privilege escalation, module loads, cron
- **Filesystem hardening** — /tmp noexec via systemd override, umask 027, SUID/SGID audit with diff tracking
- **SSH fortress** — ed25519/RSA-only, modern cipher suites, MaxAuthTries 3, no forwarding, moduli hardening
- **Layered threat response** — UFW + Fail2Ban (reactive) + CrowdSec (proactive threat intelligence)
- **Full observability** — Prometheus + Grafana + Loki + Promtail, all provisioned automatically
- **Idempotent execution** — safe to re-run; state tracked in `/var/lib/vps-hardening/state.json`
- **Dry-run mode** — `--dry-run` shows every action without making any changes
- **Audit-only mode** — `--audit-only` scores your current security posture (0–100), no changes

---

## Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| **OS** | Ubuntu 20.04 LTS / Debian 11 | Ubuntu 22.04 LTS / Debian 12 |
| **RAM** | 512 MB (vps profile) | 2 GB+ (docker-host profile) |
| **Disk** | 5 GB free | 20 GB+ free |
| **Privileges** | root | root |
| **Network** | Outbound HTTPS | Outbound HTTPS |
| **Shell** | Bash 4.4+ | Bash 5.x |
| **Dependencies** | `curl`, `jq`, `git` | same |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/fellcrack/vps-hardening-suite.git
cd vps-hardening-suite

# 2. Preview what will happen (no changes)
sudo bash install.sh --profile vps --dry-run

# 3. Run
sudo bash install.sh --profile vps
```

---

## Profiles

| Profile | Modules | Use case |
|---|---|---|
| `vps` | preflight system users ssh firewall fail2ban crowdsec sysctl audit permissions | Standard VPS |
| `docker-host` | All vps + docker monitoring | VPS running Docker |
| `homelab` | preflight system users ssh firewall sysctl | Relaxed: forwarding on |
| `desktop` | preflight sysctl firewall permissions | Workstation |
| `paranoid` | All modules, strictest settings | SSH port 2222, 2-try lockout |

Customize by copying and editing a profile:

```bash
cp profiles/vps.conf profiles/my-server.conf
# Edit SSH_PORT, FAIL2BAN_WHITELIST_IPS, CROWDSEC_LAPI_PORT, etc.
sudo bash install.sh --profile my-server
```

---

## CLI Reference

```
sudo bash install.sh [OPTIONS]

  --profile NAME          Load profiles/NAME.conf
  --dry-run               Show all actions; make no changes
  --audit-only            Security score check, no changes
  --module NAME           Run only this module (repeatable)
  --skip-module NAME      Skip this module (repeatable)
  --force                 Re-run completed modules
  --rollback MODULE       Restore backed-up configs for a module
  --report json|text      Write execution report
  --non-interactive       Skip prompts, use profile defaults
  --list-profiles         List available profiles and exit
```

---

## Module Overview

| Module | What it hardens | Key threats mitigated |
|---|---|---|
| `preflight` | Pre-run checks | Incompatible OS, port conflicts, insufficient resources |
| `system` | Base system | Missing updates, weak login policies |
| `users` | Accounts and sudo | Password brute force, sudo misconfiguration |
| `ssh` | SSH daemon | Weak ciphers, password auth, agent forwarding abuse |
| `firewall` | UFW + iptables | Unrestricted inbound, Docker iptables bypass |
| `fail2ban` | Brute-force detection | SSH credential stuffing, persistent attackers |
| `crowdsec` | Threat intelligence | Known-malicious IPs (crowd-sourced blocklists) |
| `sysctl` | Kernel parameters | SYN flood, IP spoofing, ASLR bypass, kernel pointer leaks |
| `audit` | System call auditing | Insider threats, privilege escalation, compliance |
| `permissions` | Filesystem | /tmp malware, SUID escalation, world-writable dirs |
| `docker` | Docker daemon | Container escape, disk exhaustion, ICC attack paths |
| `monitoring` | Observability stack | Security blind spots, undetected intrusions |

---

## Port Reference

| Service | Host Binding | Notes |
|---|---|---|
| **SSH** | `0.0.0.0:<SSH_PORT>` | Only public-facing port |
| **CrowdSec LAPI** | `127.0.0.1:6767` | Moved from 8080 to avoid cAdvisor conflict |
| **Prometheus** | `127.0.0.1:9090` | SSH tunnel required |
| **Grafana** | `127.0.0.1:3000` | SSH tunnel required |
| **Node Exporter** | host network `:9100` | `network_mode: host` for accurate NIC stats |
| **cAdvisor** | `127.0.0.1:8081` | Host 8081 → container 8080 |
| **Loki** | `127.0.0.1:3100` | Access via Grafana Explore |
| **Promtail** | `127.0.0.1:9080` | Internal only |

All monitoring ports bind to `127.0.0.1`. Forward to your workstation:

```bash
ssh -L 3000:127.0.0.1:3000 \
    -L 9090:127.0.0.1:9090 \
    user@YOUR_VPS
# Grafana:    http://localhost:3000  (admin / GRAFANA_PASSWORD)
# Prometheus: http://localhost:9090
```

---

## Post-Install

### Check security score

```bash
sudo bash install.sh --audit-only
```

### CrowdSec management

```bash
cscli decisions list          # active IP bans
cscli alerts list             # recent threat events
cscli hub update              # refresh threat intelligence
```

### Fail2Ban management

```bash
fail2ban-client status sshd                      # banned IPs
fail2ban-client set sshd unbanip 1.2.3.4         # unban yourself if locked out
```

### Monitoring stack

```bash
cd /opt/monitoring
docker compose ps
docker compose logs -f grafana
docker compose pull && docker compose up -d   # update images
```

### Rollback a module

```bash
sudo bash install.sh --rollback ssh    # restore sshd_config from backup
sudo bash install.sh --rollback ufw    # restore UFW rules
```

---

## Security Notes

**SSH keys required.** The `vps` and `paranoid` profiles disable password authentication. Add your public key to `~/.ssh/authorized_keys` before running the SSH module.

**Keep console access.** CrowdSec blocks at the iptables level. Keep the VPS provider's web console (KVM/VNC) available if you get locked out.

**Fail2Ban + CrowdSec run in parallel.** This is intentional — defense in depth. They ban independently.

**Backups contain config secrets.** The `backups/` directory holds original copies of sshd_config, crowdsec config, etc. Never commit it (gitignored by default).

**UFW + Docker.** Docker manipulates iptables directly and can bypass UFW. The firewall module adds DOCKER-USER chain rules to restore UFW authority.

---

## Directory Structure

```
vps-hardening-suite/
├── install.sh                      # Profile loader + module runner
├── profiles/                       # vps · docker-host · homelab · desktop · paranoid
├── lib/
│   ├── common.sh                   # Thin loader
│   ├── logging.sh                  # Colors, log_* functions
│   ├── helpers.sh                  # OS detection, state I/O, port utils
│   ├── backups.sh                  # backup_file, restore_file
│   └── validation.sh               # Post-module validators
├── modules/                        # One file per hardening domain (named, not numbered)
├── configs/
│   ├── sshd/                       # sshd_config template + banner
│   ├── fail2ban/jail.local
│   ├── sysctl/                     # 99-hardening-{network,kernel,fs}.conf
│   └── audit/hardening.rules
├── tests/
└── docs/
    ├── ARCHITECTURE.md
    ├── TROUBLESHOOTING.md
    └── THREAT_MODEL.md
```

---

## License

MIT License — Copyright (c) 2025 Maximiliano Arango

## Author

**Maximiliano Arango** — [@fellcrack](https://github.com/fellcrack)
