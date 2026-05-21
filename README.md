<div align="center">

```
 ██╗   ██╗██████╗ ███████╗    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██╗███╗   ██╗ ██████╗
 ██║   ██║██╔══██╗██╔════╝    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██║████╗  ██║██╔════╝
 ██║   ██║██████╔╝███████╗    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
 ╚██╗ ██╔╝██╔═══╝ ╚════██║    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║██║╚██╗██║██║   ██║
  ╚████╔╝ ██║     ███████║    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██║██║ ╚████║╚██████╔╝
   ╚═══╝  ╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
```

**Profile-driven, idempotent Linux hardening framework**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2020.04%2B%20%7C%20Debian%2011%2B-blue)](#requirements)
[![Shell](https://img.shields.io/badge/shell-Bash%204.4%2B-green)](#requirements)
[![ShellCheck](https://img.shields.io/badge/shellcheck-passing-brightgreen)](#testing)
[![Idempotent](https://img.shields.io/badge/idempotent-yes-brightgreen)](#how-idempotency-works)

*By [Maximiliano Arango (fellcrack)](https://github.com/fellcrack)*

</div>

---

## What This Is

VPS Hardening Suite is a **profile-driven**, idempotent Bash framework that turns a bare Ubuntu/Debian server into a hardened, observable production system. Unlike generic CIS benchmark scripts, every hardening action is documented with the specific threat it mitigates, what can break, and the trade-off involved.

It is designed for:
- VPS operators running self-managed infrastructure
- Homelabs and development servers
- AI agents maintaining infrastructure autonomously
- Docker hosts requiring container-aware firewall rules

### What it installs and configures

| Layer | Components | Threat mitigated |
|---|---|---|
| **Network perimeter** | UFW + DOCKER-USER chain | Unrestricted inbound, Docker iptables bypass |
| **Threat intelligence** | CrowdSec agent + bouncer | Known-malicious IPs blocked before connection |
| **Brute-force prevention** | Fail2Ban (sshd + recidive) | Credential stuffing, SSH brute force |
| **Kernel hardening** | sysctl (network + kernel + fs) | IP spoofing, SYN flood, kernel pointer leaks, ASLR bypass |
| **SSH fortress** | sshd_config + host key hardening | Weak ciphers, password auth, agent forwarding abuse |
| **Audit trail** | auditd rules | Insider threats, privilege escalation, compliance |
| **Filesystem** | /tmp noexec, umask, SUID audit | /tmp malware, setuid privilege escalation |
| **Observability** | Prometheus + Grafana + Loki + Promtail | Security blind spots, undetected intrusions |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/fellcrack/vps-hardening-suite.git
cd vps-hardening-suite

# 2. Run with a profile (no .env needed)
sudo bash install.sh --profile vps

# 3. Preview what it would do without making any changes
sudo bash install.sh --profile vps --dry-run

# 4. Check your current security posture (no changes)
sudo bash install.sh --audit-only
```

---

## Profiles

Profiles are `.conf` files in `profiles/` that define which modules run and what settings they use. Pick the one closest to your use case.

| Profile | Modules | Use case |
|---|---|---|
| `vps` | preflight system users ssh firewall fail2ban crowdsec sysctl audit permissions | Typical VPS — SSH key only, no containers |
| `docker-host` | All vps modules + docker monitoring | VPS running containerized workloads |
| `homelab` | preflight system users ssh firewall sysctl | Relaxed: TCP forwarding on, no brute-force protection |
| `desktop` | preflight sysctl firewall permissions | Minimal: workstation hardening only |
| `paranoid` | All modules | Strictest settings — SSH port 2222, 2-attempt lockout, 7-day bans |

### Customizing a profile

Copy an existing profile and modify it:

```bash
cp profiles/vps.conf profiles/my-server.conf
nano profiles/my-server.conf

sudo bash install.sh --profile my-server
```

Key variables you'll want to change:

```bash
SSH_PORT=2222                    # non-standard port reduces scan noise
SSH_PASSWORD_AUTH=no             # requires key in authorized_keys first
FAIL2BAN_SSH_BANTIME=86400       # 24-hour ban on brute force
FAIL2BAN_WHITELIST_IPS="1.2.3.4" # your management IP — never ban this
CROWDSEC_LAPI_PORT=6767          # keep away from 8080 (cAdvisor conflict)
SYSCTL_IP_FORWARD=no             # set yes only for Docker hosts / routers
```

---

## Installer Flags

```bash
sudo bash install.sh [OPTIONS]

  --profile NAME          Load profiles/NAME.conf (required unless --audit-only)
  --dry-run               Print all actions; make zero changes to the system
  --audit-only            Run security checks, output score (0-100), no changes
  --module NAME           Override profile module list (repeatable)
  --skip-module NAME      Remove a module from the run (repeatable)
  --force                 Re-run modules already marked complete
  --rollback MODULE       Restore backed-up configs for a specific module
  --report json|text      Write execution report to logs/
  --non-interactive       Skip all prompts; use profile defaults
  --list-profiles         Show available profiles and exit
```

### Examples

```bash
# Dry-run the paranoid profile to see what it would do
sudo bash install.sh --profile paranoid --dry-run

# Run only SSH and firewall hardening
sudo bash install.sh --profile vps --module ssh --module firewall

# Run full vps profile except monitoring
sudo bash install.sh --profile docker-host --skip-module monitoring

# Check security score after manual changes
sudo bash install.sh --audit-only

# Restore SSH config if something went wrong
sudo bash install.sh --rollback ssh

# Fully automated (CI/CD, agent-driven)
sudo bash install.sh --profile vps --non-interactive --report json
```

---

## Modules

Each module documents the threat it mitigates, what can break, and its operational impact. This is by design — no "security placebo" tweaks without justification.

| Module | What it does | Key profile vars |
|---|---|---|
| `preflight` | OS compatibility, disk space, RAM, port conflicts, internet connectivity | — |
| `system` | Unattended-upgrades, base packages, login policies | — |
| `users` | Admin user, SSH key provisioning, sudo hardening, PAM faillock | — |
| `ssh` | ed25519/RSA-only host keys, modern cipher suites, MaxAuthTries, no forwarding | `SSH_PORT` `SSH_PASSWORD_AUTH` `SSH_MAX_AUTH_TRIES` `SSH_ALLOW_TCP_FORWARDING` |
| `firewall` | UFW default-deny, SSH rate limiting, DOCKER-USER chain, profile port list | `UFW_ALLOW_PORTS` |
| `fail2ban` | sshd jail, recidive jail (persistent attackers), optional nginx jails | `FAIL2BAN_SSH_MAXRETRY` `FAIL2BAN_SSH_BANTIME` `FAIL2BAN_WHITELIST_IPS` |
| `crowdsec` | Agent + bouncer; crowd-sourced IP blocklists; LAPI on `127.0.0.1:6767` | `CROWDSEC_LAPI_PORT` |
| `sysctl` | Network (SYN cookies, RP filter, ICMP hardening), kernel (dmesg_restrict, ASLR), filesystem (symlink/hardlink protection) | `SYSCTL_NETWORK_HARDENING` `SYSCTL_IP_FORWARD` `SYSCTL_DISABLE_IPV6` |
| `audit` | auditd rules: sudo, SSH key changes, cron, user/group mods, setuid exec, module load/unload | `AUDITD_RULES_LEVEL` (standard\|paranoid) |
| `permissions` | /tmp noexec via systemd override, umask 027, SUID/SGID binary audit | `PERMISSIONS_TMP_NOEXEC` `PERMISSIONS_UMASK` `PERMISSIONS_AUDIT_SUID` |
| `docker` | Docker CE from official repo, hardened daemon.json (icc=false, no-new-privileges, log limits, live-restore) | `DOCKER_ENABLED` |
| `monitoring` | Prometheus + Grafana + Loki + Promtail + Node Exporter + cAdvisor via Docker Compose | `MONITORING_DIR` `GRAFANA_PASSWORD` |

---

## Security Architecture

```
                         INTERNET
                            │
                     ┌──────▼──────┐
                     │    UFW      │  default deny inbound
                     │  iptables   │  DOCKER-USER chain controls Docker traffic
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │  CrowdSec   │  blocks known-bad IPs via community blocklists
                     │  Bouncer    │  LAPI: 127.0.0.1:6767
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │  Fail2Ban   │  bans IPs after repeated auth failures
                     │  + recidive │  re-bans persistent offenders for 7 days
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │    sshd     │  ed25519 only, MaxAuthTries 3, no password auth
                     └─────────────┘

              ┌──────────────────────────────────────────────────┐
              │  Kernel: sysctl (network + kernel + fs hardening) │
              │  Audit:  auditd tracks all privileged operations  │
              │  Perms:  /tmp noexec · umask 027 · SUID audit     │
              └──────────────────────────────────────────────────┘

   All security events → Promtail → Loki → Grafana (queryable, alertable)
```

### Why no `experimental: true` in daemon.json

The Docker metrics endpoint (`127.0.0.1:9323`) was moved behind `experimental: true` in some Docker versions. This suite does not enable `experimental` by default — the security risk of running experimental daemon features on production outweighs the metrics benefit. Prometheus simply shows that scrape target as down. All other monitoring remains functional.

---

## Port Reference

All monitoring ports bind to `127.0.0.1`. Use SSH tunnels to access them from your workstation.

| Service | Host binding | Notes |
|---|---|---|
| SSH | `0.0.0.0:<SSH_PORT>` | Only public-facing port |
| CrowdSec LAPI | `127.0.0.1:6767` | Moved from default 8080 to avoid cAdvisor conflict |
| Prometheus | `127.0.0.1:9090` | Requires SSH tunnel |
| Grafana | `127.0.0.1:3000` | Requires SSH tunnel |
| Node Exporter | host network `:9100` | `network_mode: host` for accurate NIC stats |
| cAdvisor | `127.0.0.1:8081→8080` | Host 8081, container 8080 |
| Loki | `127.0.0.1:3100` | Access via Grafana Explore |
| Promtail | `127.0.0.1:9080` | Internal only |

```bash
# Forward all monitoring ports in one SSH command
ssh -L 3000:127.0.0.1:3000 \
    -L 9090:127.0.0.1:9090 \
    -L 3100:127.0.0.1:3100 \
    user@YOUR_VPS
# Grafana:    http://localhost:3000  (admin / GRAFANA_PASSWORD)
# Prometheus: http://localhost:9090
```

---

## Requirements

| | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04 LTS / Debian 11 | Ubuntu 22.04 LTS / Debian 12 |
| RAM | 512 MB (vps profile) | 2 GB+ (docker-host profile) |
| Disk | 5 GB free | 20 GB+ free |
| Shell | Bash 4.4 | Bash 5.x |
| Privileges | root | root |
| Runtime deps | `curl`, `jq`, `git` | same |

---

## How Idempotency Works

State is tracked in `/var/lib/vps-hardening/state.json` as a JSON object. Before running any module, the installer checks if `module_<name>` is `"completed"` in state. If it is, the module is skipped unless `--force` is passed.

All config files are backed up with timestamps before modification:

```
backups/
├── sshd_config.2025-01-15T14:23:01.bak
├── jail.local.2025-01-15T14:25:44.bak
└── ufw_after.rules.2025-01-15T14:26:12.bak
```

---

## Rollback

If a module leaves the system in a bad state, restore the backed-up configs:

```bash
# Via installer (recommended)
sudo bash install.sh --rollback ssh

# Manual restoration
ls backups/                               # list available backups
cp backups/sshd_config.*.bak /etc/ssh/sshd_config
systemctl reload ssh
```

---

## After Installation

### Check security score

```bash
sudo bash install.sh --audit-only
```

Output includes pass/fail for ~14 checks (SSH config, UFW state, sysctl values, service status) and a score from 0–100.

### Manage CrowdSec

```bash
cscli decisions list          # active IP bans
cscli alerts list             # recent threat events
cscli hub update              # refresh threat intelligence
cscli bouncers list           # verify bouncer is registered
```

### Manage Fail2Ban

```bash
fail2ban-client status sshd                          # banned IPs
fail2ban-client set sshd unbanip 1.2.3.4             # unban an IP
fail2ban-client status                               # all active jails
```

### Manage the monitoring stack

```bash
cd /opt/monitoring
docker compose ps                  # container status
docker compose logs -f grafana     # live Grafana logs
docker compose restart             # restart all services
docker compose pull && docker compose up -d   # update images
```

---

## Security Notes

**SSH keys required.** The `vps` and `paranoid` profiles disable password authentication. Add your public key to `~/.ssh/authorized_keys` before running the SSH module. The installer checks for a key before disabling password auth.

**Keep console access.** CrowdSec blocks at the iptables level. If you accidentally ban your own IP, you need the VPS provider's web console (KVM/VNC) to recover.

**Fail2Ban and CrowdSec both ban IPs.** This is intentional — defense in depth. They operate independently. An IP can appear in both `fail2ban-client status sshd` and `cscli decisions list`.

**Backups may contain secrets.** `backups/` holds original copies of sshd_config, CrowdSec config, etc. This directory is git-ignored. Never commit it.

**UFW + Docker.** Docker manipulates iptables directly and bypasses UFW by default. The firewall module adds DOCKER-USER chain rules to restore UFW authority. Do not remove these rules if you need to control which ports Docker containers can receive traffic on.

---

## Testing

```bash
# Run all tests
bash tests/run_tests.sh

# ShellCheck only
bash tests/test_shellcheck.sh

# Syntax check only
bash tests/test_syntax.sh
```

CI runs both on every push via `.github/workflows/`.

---

## Directory Structure

```
vps-hardening-suite/
├── install.sh                      # Profile loader, module runner, CLI flags
├── .env.example                    # Environment template (optional — profiles preferred)
│
├── profiles/
│   ├── vps.conf                    # Standard VPS hardening
│   ├── docker-host.conf            # VPS + Docker + monitoring
│   ├── homelab.conf                # Relaxed: forwarding on, monitoring optional
│   ├── desktop.conf                # Minimal: UFW + sysctl only
│   └── paranoid.conf               # All modules, strictest settings
│
├── lib/
│   ├── common.sh                   # Thin loader — sources the 4 files below
│   ├── logging.sh                  # Colors, log_* functions, banner, progress
│   ├── helpers.sh                  # OS detection, state I/O, prompts, port utils
│   ├── backups.sh                  # backup_file, restore_file, run_with_log
│   └── validation.sh               # post-module validators (sshd -t, sysctl, UFW)
│
├── modules/                        # One file per hardening domain
│   ├── preflight.sh  system.sh  users.sh
│   ├── ssh.sh  firewall.sh  fail2ban.sh  crowdsec.sh
│   ├── sysctl.sh  audit.sh  permissions.sh
│   └── docker.sh  monitoring.sh
│
├── configs/
│   ├── sshd/                       # sshd_config template + banner
│   ├── fail2ban/jail.local
│   ├── sysctl/                     # 99-hardening-{network,kernel,fs}.conf
│   └── audit/hardening.rules
│
├── tests/
│   ├── run_tests.sh
│   ├── test_shellcheck.sh
│   └── test_syntax.sh
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── TROUBLESHOOTING.md
│   └── THREAT_MODEL.md
│
└── backups/                        # Auto-created at runtime; gitignored
```

---

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, data flows, service descriptions, state management |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Symptom → cause → fix runbooks |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Per-module threat analysis, attack surfaces, mitigations |
| [CHANGELOG.md](CHANGELOG.md) | Release history and security decisions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code style, module conventions, security disclosure |

---

## Roadmap

- [ ] `--report html` — self-contained HTML audit report
- [ ] AppArmor profiles for high-risk services
- [ ] WireGuard VPN module
- [ ] Automated CrowdSec allowlist for Cloudflare IP ranges
- [ ] Integration tests via Docker-in-Docker

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version:

1. All scripts must pass `shellcheck -S warning -x`
2. Every module must be idempotent
3. Every hardening action must document its threat in a comment
4. Add a test case to `tests/` for new modules

Security issues: report privately via [@fellcrack on GitHub](https://github.com/fellcrack).

---

## License

MIT — see [LICENSE](LICENSE).

© 2025 [Maximiliano Arango](https://github.com/fellcrack)
