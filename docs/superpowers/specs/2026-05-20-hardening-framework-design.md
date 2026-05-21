# Design Spec: Production-Grade Linux Hardening Framework

**Date:** 2026-05-20  
**Author:** Maximiliano Arango (fellcrack)  
**Status:** Approved — implementing

---

## Objective

Re-architect `vps-hardening-suite` from a numbered-module bash script into a profile-driven, idempotent, validated hardening framework suitable for VPS, Docker hosts, homelabs, and desktops.

---

## Directory Structure

```
vps-hardening-suite/
├── install.sh                    # Profile loader, module runner, CLI flags
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── .env.example
├── .gitignore
│
├── lib/
│   ├── logging.sh                # Colors, log_* functions, banner, progress
│   ├── helpers.sh                # OS detection, checks, state management, prompts
│   ├── backups.sh                # backup_file, restore_file, list_backups
│   ├── validation.sh             # validate_sshd, validate_sysctl, post-module checks
│   └── common.sh                 # Thin loader: sources the 4 lib files above
│
├── profiles/
│   ├── vps.conf                  # SSH + UFW + Fail2Ban + CrowdSec + Sysctl
│   ├── docker-host.conf          # VPS + Docker + Monitoring
│   ├── homelab.conf              # Relaxed: TCP forwarding on, monitoring optional
│   ├── desktop.conf              # Minimal: UFW + sysctl only
│   └── paranoid.conf             # All modules, strictest settings
│
├── modules/
│   ├── preflight.sh              # OS, deps, ports, root check
│   ├── system.sh                 # Base packages, unattended-upgrades
│   ├── users.sh                  # Admin user, sudo hardening
│   ├── ssh.sh                    # Full SSH hardening (profile-tuned)
│   ├── firewall.sh               # UFW + DOCKER-USER chain
│   ├── fail2ban.sh               # Jails from profile vars
│   ├── crowdsec.sh               # LAPI port from profile
│   ├── docker.sh                 # Daemon hardening
│   ├── monitoring.sh             # Prometheus/Grafana/Loki stack
│   ├── sysctl.sh                 # Kernel parameter hardening
│   ├── audit.sh                  # auditd rules
│   └── permissions.sh            # /tmp noexec, umask, SUID audit
│
├── configs/
│   ├── sshd/sshd_config.template
│   ├── fail2ban/jail.local
│   ├── crowdsec/config.yaml.template
│   ├── sysctl/
│   │   ├── 99-hardening-network.conf
│   │   ├── 99-hardening-kernel.conf
│   │   └── 99-hardening-fs.conf
│   └── audit/
│       └── hardening.rules
│
├── tests/
│   ├── run_tests.sh
│   ├── test_shellcheck.sh
│   └── test_syntax.sh
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── TROUBLESHOOTING.md
│   └── THREAT_MODEL.md           # NEW: per-module threat analysis
│
└── .github/
    ├── workflows/
    │   ├── shellcheck.yml
    │   └── tests.yml
    └── ISSUE_TEMPLATE/
```

---

## Profile Variable Schema

Each profile sets these variables; modules read them with safe defaults.

```bash
# Core
PROFILE_NAME="vps"
PROFILE_DESC="..."
ENABLED_MODULES="preflight system users ssh firewall fail2ban crowdsec sysctl"

# SSH
SSH_PORT=22
SSH_PERMIT_ROOT_LOGIN=no
SSH_PASSWORD_AUTH=no
SSH_MAX_AUTH_TRIES=3
SSH_MAX_SESSIONS=3
SSH_ALLOW_TCP_FORWARDING=no
SSH_ALLOW_AGENT_FORWARDING=no

# Firewall
UFW_ALLOW_PORTS="22"

# Fail2Ban
FAIL2BAN_SSH_MAXRETRY=3
FAIL2BAN_SSH_BANTIME=7200
FAIL2BAN_SSH_FINDTIME=300
FAIL2BAN_WHITELIST_IPS=""

# CrowdSec
CROWDSEC_LAPI_PORT=6767

# Sysctl
SYSCTL_NETWORK_HARDENING=yes
SYSCTL_KERNEL_HARDENING=yes
SYSCTL_FS_HARDENING=yes
SYSCTL_DISABLE_IPV6=no
SYSCTL_IP_FORWARD=no

# Audit
AUDITD_RULES_LEVEL=standard   # standard|paranoid

# Docker / Monitoring
DOCKER_ENABLED=no
MONITORING_ENABLED=no
MONITORING_DIR=/opt/monitoring
GRAFANA_PASSWORD=changeme

# Permissions
PERMISSIONS_TMP_NOEXEC=yes
PERMISSIONS_UMASK=027
PERMISSIONS_AUDIT_SUID=yes
```

---

## install.sh Flags

```
--profile NAME          Load profiles/NAME.conf
--dry-run               Print actions, make no changes
--audit-only            Run validation checks, output score, no changes
--module NAME           Override profile module list (repeatable)
--skip-module NAME      Skip a module (repeatable)
--force                 Re-run completed modules
--rollback MODULE       Restore backed-up configs for a module
--report json|text      Output execution report
--non-interactive       No prompts, use profile defaults
```

---

## lib/ Responsibilities

| File | Owns |
|---|---|
| `logging.sh` | Colors, log_* funcs, banner, progress bar, summary table |
| `helpers.sh` | OS detection, system checks, state management, prompts, network utils |
| `backups.sh` | backup_file, restore_file, list_backups, run_with_log |
| `validation.sh` | validate_sshd_config, validate_sysctl, validate_ufw, check_dependencies, post_module_verify |

---

## New Modules

### sysctl.sh
- **Threat:** IP spoofing, SYN floods, ICMP redirect attacks, kernel pointer leaks, ASLR bypass
- Deploys 3 sysctl configs to `/etc/sysctl.d/`
- Idempotent: backs up, applies with `sysctl --system`
- Profile vars: SYSCTL_NETWORK_HARDENING, SYSCTL_KERNEL_HARDENING, SYSCTL_FS_HARDENING

### audit.sh
- **Threat:** Insider threats, privilege escalation, rootkit persistence, compliance gaps
- Installs auditd, deploys rules based on AUDITD_RULES_LEVEL
- Tracks: sudo, SSH key changes, cron, user/group mods, setuid exec
- Paranoid level adds: /etc writes, execve, module load/unload

### permissions.sh
- **Threat:** /tmp-based malware, privilege escalation via SUID, world-writable dir abuse
- Mounts /tmp noexec,nosuid,nodev via systemd override
- Sets umask 027 via /etc/profile.d/
- Audits unexpected SUID/SGID binaries (report only, no silent removal)

---

## CI/CD

- `shellcheck.yml`: ShellCheck `-S warning -x` on all .sh files, blocks PRs
- `tests.yml`: `bash -n` syntax check on all scripts
