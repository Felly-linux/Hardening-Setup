# Architecture Reference — VPS Hardening Suite

> **Audience:** Sysadmins, DevOps engineers, and AI agents (Claude Code, GPT-4+) that need to understand, modify, or extend this system.
>
> This document is the authoritative technical reference. Read `README.md` first for operational context.

---

## 1. System Architecture Overview

```
                          ┌─────────────────────────────────────────────────────┐
                          │                    INTERNET                         │
                          └──────────────────────┬──────────────────────────────┘
                                                 │ inbound traffic
                          ┌──────────────────────▼──────────────────────────────┐
                          │              KERNEL / NETFILTER                     │
                          │  ┌─────────────────────────────────────────────┐   │
                          │  │  UFW (iptables front-end)                   │   │
                          │  │  • Default: deny all inbound                │   │
                          │  │  • Allow: SSH port, HTTP/HTTPS if needed    │   │
                          │  │  • DOCKER-USER chain for container traffic  │   │
                          │  └───────────────┬─────────────────────────────┘   │
                          │                  │ allowed traffic                  │
                          │  ┌───────────────▼─────────────────────────────┐   │
                          │  │  CrowdSec Bouncer (crowdsec-firewall-bouncer)│   │
                          │  │  • Blocks IPs from community threat feeds   │   │
                          │  │  • Listens to LAPI on 127.0.0.1:6767        │   │
                          │  └───────────────┬─────────────────────────────┘   │
                          │                  │                                  │
                          │  ┌───────────────▼─────────────────────────────┐   │
                          │  │  Fail2Ban                                    │   │
                          │  │  • Watches /var/log/auth.log                 │   │
                          │  │  • Bans brute-force IPs via iptables        │   │
                          │  └───────────────┬─────────────────────────────┘   │
                          │                  │ authenticated SSH                │
                          │  ┌───────────────▼─────────────────────────────┐   │
                          │  │  SSHD (hardened)                            │   │
                          │  │  • ed25519 + RSA host keys                  │   │
                          │  │  • PasswordAuthentication no                │   │
                          │  │  • MaxAuthTries 3                           │   │
                          │  │  • Modern ciphers only                      │   │
                          │  └─────────────────────────────────────────────┘   │
                          │                   HOST SYSTEM                       │
                          └──────────────────────┬──────────────────────────────┘
                                                 │
                   ┌─────────────────────────────┼──────────────────────────────────┐
                   │                             │                                  │
        ┌──────────▼─────────┐       ┌───────────▼──────────┐         ┌────────────▼──────────┐
        │   Node Exporter    │       │  Docker Engine        │         │  CrowdSec Agent       │
        │   (host network)   │       │  (monitoring network) │         │  (systemd service)    │
        │   port 9100        │       │                       │         │  LAPI: 127.0.0.1:6767 │
        └──────────┬─────────┘       │  ┌──────────────┐    │         └────────────┬──────────┘
                   │ metrics         │  │  Prometheus  │    │                      │
                   │                 │  │  :9090       │◄───┼── scrapes node       │ decisions
                   │                 │  └──────┬───────┘    │    exporter:9100     │
                   │                 │         │             │                      │
                   │                 │  ┌──────▼───────┐    │  ┌────────────────┐  │
                   │                 │  │  Grafana     │    │  │  cAdvisor      │  │
                   │                 │  │  :3000       │    │  │  :8081(host)   │  │
                   │                 │  └──────┬───────┘    │  │  :8080(intern) │  │
                   │                 │         │ queries     │  └────────┬───────┘  │
                   │                 │  ┌──────▼───────┐    │           │ metrics  │
                   │                 │  │  Loki        │    │           │          │
                   │                 │  │  :3100       │◄───┼── Promtail pushes    │
                   │                 │  └──────────────┘    │                      │
                   │                 │  ┌──────────────┐    │                      │
                   │                 │  │  Promtail    │    │                      │
                   │                 │  │  :9080       │    │                      │
                   │                 │  └──────────────┘    │                      │
                   │                 └──────────────────────┘                      │
                   │                          ▲                                     │
                   │                          │ /var/log (ro mount)                 │
                   └──────────────────────────┘                                    │
                              host filesystem                                       │
                                                                                    │
                   /var/log/auth.log → Fail2Ban ──────────────────────────────────►│
                   /var/log/crowdsec*.log → Promtail → Loki                        │
                   /var/log/ufw.log → Promtail → Loki                              │
                   /var/lib/docker/containers/*/*-json.log → Promtail → Loki       │
```

---

## 2. Security Layers

The suite implements four concentric security layers. Each layer is independent; failure of one does not disable the others.

### Layer 1: Network (UFW + CrowdSec)

**What it protects:** The perimeter. Traffic is evaluated before it reaches any service.

- **UFW** sets the default policy to `deny` for all inbound traffic. Only explicitly allowed ports pass (SSH, HTTP/HTTPS if configured). IPv6 is enforced alongside IPv4.
- **CrowdSec** operates as a collaborative firewall. The agent (`crowdsec`) continuously parses logs and applies crowd-sourced threat intelligence. The bouncer (`crowdsec-firewall-bouncer`) translates CrowdSec decisions into iptables DROP rules in real time.
- **DOCKER-USER chain**: Docker bypasses UFW by default. The installer inserts rules into the `DOCKER-USER` iptables chain to restore UFW authority over container-bound traffic without interfering with Docker's internal routing.

### Layer 2: Authentication (SSH + Fail2Ban)

**What it protects:** The control plane. Prevents unauthorized shell access.

- **SSH hardening** removes weak authentication vectors. Password authentication is disabled entirely. Only `ed25519` and `RSA` host key algorithms are offered. `AllowAgentForwarding` and `AllowTcpForwarding` are set to `no` to prevent pivoting.
- **Fail2Ban** monitors `/var/log/auth.log` for repeated authentication failures and bans offending IPs via iptables after a configurable threshold (`maxretry = 3` by default for SSH). Bans are permanent until manually lifted or expired (default `bantime = 1h`).

### Layer 3: Runtime (Docker isolation)

**What it protects:** The monitoring stack. Containers run with least privilege.

- Each monitoring container runs as a non-root user where the image supports it.
- Containers communicate over the isolated `monitoring` Docker bridge network. No container port is bound to `0.0.0.0`.
- Docker daemon is configured with `live-restore: true` — containers keep running if the daemon restarts (e.g., during Docker upgrades).
- Log driver is `json-file` with `max-size: 10m` and `max-file: 3`, preventing log-based disk exhaustion.
- The exception is **Node Exporter**, which requires `network_mode: host` and `pid: host` to accurately observe host-level network interfaces and process statistics. This is a known, intentional trade-off.
- **cAdvisor** requires `privileged: true` to access cgroup and device statistics. It has no write access to the host filesystem.

### Layer 4: Observability (Loki + Promtail)

**What it protects:** Audit trail integrity. Ensures all security events are captured and queryable.

- **Promtail** ships log lines from every critical source to Loki within seconds of generation.
- **Loki** stores logs in an append-only TSDB-backed structure. Logs are retained for 7 days (configurable via `reject_old_samples_max_age`).
- **Grafana** provides a unified view over both metrics (Prometheus) and logs (Loki) in a single interface, enabling correlation: e.g., spike in `node_cpu_seconds_total` + Fail2Ban banning events visible simultaneously.

---

## 3. Service Descriptions

### UFW (Uncomplicated Firewall)

| Attribute | Detail |
|---|---|
| **What it is** | iptables/nftables front-end for Linux kernel netfilter |
| **Why we use it** | Human-readable rule management; integrates with `ufw-docker` for container traffic |
| **What it controls** | Inbound/outbound packet filtering at the kernel level |
| **Key config** | `/etc/ufw/` — rules, before.rules, after.rules |
| **Integration** | CrowdSec bouncer writes iptables rules in parallel; DOCKER-USER chain bridges them |
| **Log output** | `/var/log/ufw.log` — shipped to Loki via Promtail |

### Fail2Ban

| Attribute | Detail |
|---|---|
| **What it is** | Log-parsing intrusion prevention daemon |
| **Why we use it** | Lightweight, highly configurable, no external dependencies |
| **What it watches** | `/var/log/auth.log` (SSH), extensible to other jails |
| **Ban mechanism** | iptables DROP rules injected per-jail (chain: `f2b-sshd`) |
| **Key config** | `/etc/fail2ban/jail.local` — jails, maxretry, bantime, findtime |
| **Log output** | `/var/log/fail2ban.log` — shipped to Loki |
| **State** | `/var/lib/fail2ban/fail2ban.sqlite3` — persistent ban database |

### CrowdSec

| Attribute | Detail |
|---|---|
| **What it is** | Collaborative security engine with community threat intelligence |
| **Why we use it** | Blocks known bad IPs proactively before they attempt attacks |
| **Components** | Agent (log parser + scenario engine) + LAPI (local API) + Bouncer (iptables enforcement) |
| **LAPI port** | `127.0.0.1:6767` — **moved from default 8080** to avoid conflict with cAdvisor |
| **Key config** | `/etc/crowdsec/config.yaml` — `listen_uri: 127.0.0.1:6767` |
| **Log output** | `/var/log/crowdsec.log`, `/var/log/crowdsec-agent.log` — shipped to Loki |
| **Threat feeds** | Community blocklists pulled periodically via `cscli hub update` |

### Docker Engine

| Attribute | Detail |
|---|---|
| **What it is** | Container runtime for the monitoring stack |
| **Why we use it** | Isolates monitoring services; simplifies deployment and upgrades |
| **Key config** | `/etc/docker/daemon.json` |
| **Log driver** | `json-file`, `max-size: 10m`, `max-file: 3` |
| **Metrics** | Prometheus endpoint on `127.0.0.1:9323` (requires `experimental: true`) |
| **Network** | `monitoring` external bridge network created by installer |
| **live-restore** | Enabled — containers survive daemon restarts |

### Prometheus

| Attribute | Detail |
|---|---|
| **What it is** | Pull-based time-series metrics database |
| **Why we use it** | Industry standard; native integrations with all monitoring stack components |
| **Port** | `127.0.0.1:9090` |
| **Retention** | 15 days (configurable via `--storage.tsdb.retention.time`) |
| **Scrape interval** | 15 seconds global; 30 seconds for cAdvisor |
| **Scrape targets** | `prometheus` (self), `node-exporter` (host), `cadvisor` (containers), `docker` (daemon) |
| **Image** | `prom/prometheus:v2.50.1` |
| **Data volume** | `prometheus_data` (Docker named volume) |
| **Rules** | `/etc/prometheus/rules/*.yml` — add alerting rules here |

### Grafana

| Attribute | Detail |
|---|---|
| **What it is** | Metrics and log visualization platform |
| **Why we use it** | Unified view over Prometheus (metrics) and Loki (logs) |
| **Port** | `127.0.0.1:3000` |
| **Auth** | Admin password via `GRAFANA_PASSWORD` env var; sign-up disabled |
| **Datasources** | Auto-provisioned via `grafana/provisioning/datasources/datasources.yml` |
| **Plugins** | `grafana-piechart-panel`, `grafana-worldmap-panel` (installed at startup) |
| **Image** | `grafana/grafana:10.3.3` |
| **Data volume** | `grafana_data` (Docker named volume) |

### Node Exporter

| Attribute | Detail |
|---|---|
| **What it is** | Prometheus exporter for host-level hardware and OS metrics |
| **Why we use it** | CPU, memory, disk I/O, network interface, filesystem statistics |
| **Port** | `9100` (host network — no Docker bridge) |
| **Network mode** | `host` — required for accurate NIC and socket statistics |
| **PID namespace** | `host` — required for process-level metrics |
| **Image** | `prom/node-exporter:v1.7.0` |
| **Mounts** | `/proc`, `/sys`, `/` (all read-only) |
| **Key collectors** | cpu, meminfo, diskstats, netdev, filesystem, loadavg, uname |

### cAdvisor

| Attribute | Detail |
|---|---|
| **What it is** | Container Advisor — per-container resource usage exporter |
| **Why we use it** | Node Exporter does not break down metrics per container |
| **Port (host)** | `127.0.0.1:8081` — **mapped to 8081** to avoid CrowdSec LAPI conflict on 8080 |
| **Port (internal)** | `8080` — Prometheus scrapes via Docker network as `cadvisor:8080` |
| **Privileged** | Yes — required to read cgroup hierarchies |
| **Image** | `gcr.io/cadvisor/cadvisor:v0.49.1` |
| **Metrics** | CPU, memory, network, disk per container label |

### Loki

| Attribute | Detail |
|---|---|
| **What it is** | Horizontally scalable log aggregation system (used in single-binary mode) |
| **Why we use it** | Native Grafana integration; low resource footprint vs. ELK stack |
| **Port** | `127.0.0.1:3100` |
| **Mode** | Standalone / single-binary — `kvstore: inmemory`, no Consul, no memberlist |
| **Storage** | Filesystem TSDB v13 in Docker named volume `loki_data` |
| **Retention** | `reject_old_samples_max_age: 168h` (7 days) |
| **Image** | `grafana/loki:2.9.4` |
| **Critical note** | Default Loki config expects consul/memberlist. This project uses `kvstore: inmemory` to avoid ring formation errors in single-node deployments. See TROUBLESHOOTING.md for details. |

### Promtail

| Attribute | Detail |
|---|---|
| **What it is** | Log shipping agent for Loki |
| **Why we use it** | Efficient, label-aware log shipping; parses Docker JSON log format |
| **Port** | `9080` (internal only — push target is Loki, not reverse) |
| **Push target** | `http://loki:3100/loki/api/v1/push` (Docker DNS resolves `loki`) |
| **Log sources** | auth, syslog, kern, fail2ban, crowdsec, ufw, dpkg, docker containers |
| **Docker log parsing** | Pipeline extracts `log`, `stream`, `container_id` from JSON envelope |
| **Image** | `grafana/promtail:2.9.4` |
| **Mounts** | `/var/log` (ro), `/var/lib/docker/containers` (ro) |

---

## 4. Data Flow

### Metrics Flow

```
/proc, /sys, /                     Docker cgroups
      │                                  │
      ▼                                  ▼
Node Exporter :9100            cAdvisor :8080 (internal)
      │                                  │
      └──────────────┬───────────────────┘
                     │ HTTP scrape every 15s (node) / 30s (cadvisor)
                     ▼
              Prometheus :9090
              (TSDB, 15d retention)
                     │
                     │ PromQL queries
                     ▼
               Grafana :3000
               (dashboards, alerts)
```

Additional scrape sources pulled by Prometheus:
- `localhost:9090` — Prometheus self-monitoring
- `localhost:9323` — Docker daemon metrics

### Logs Flow

```
/var/log/auth.log          /var/log/ufw.log
/var/log/syslog            /var/log/fail2ban.log
/var/log/kern.log          /var/log/crowdsec*.log
/var/log/dpkg.log          /var/lib/docker/containers/*/*-json.log
        │                              │
        └──────────────┬───────────────┘
                       │ tail + ship (Promtail)
                       ▼
                  Loki :3100
                  (TSDB v13, 7d retention)
                       │
                       │ LogQL queries
                       ▼
                  Grafana :3000
                  (Explore view, log panels)
```

### Security Events Flow

```
SSH brute force attempt
        │
        ▼
/var/log/auth.log written
        │
        ├──► Fail2Ban (watches auth.log)
        │         │ maxretry exceeded
        │         ▼
        │    iptables DROP rule injected
        │    (chain: f2b-sshd)
        │
        ├──► CrowdSec Agent (parses auth.log)
        │         │ scenario matched
        │         ▼
        │    Decision sent to LAPI :6767
        │         │
        │         ▼
        │    Bouncer polls LAPI
        │         │
        │         ▼
        │    iptables DROP rule injected
        │    (chain: CROWDSEC_CHAIN)
        │
        └──► Promtail (tails auth.log)
                  │
                  ▼
             Loki (stores log line)
                  │
                  ▼
             Grafana (queryable, alertable)
```

Note: Fail2Ban and CrowdSec operate independently. An IP may be banned by both. This provides defense in depth — if one system fails, the other continues protecting the server.

---

## 5. File Reference

### `/etc/ssh/sshd_config`

Managed by the `ssh` module. Key settings applied:

```
PermitRootLogin             prohibit-password
PasswordAuthentication      no
PubkeyAuthentication        yes
AuthorizedKeysFile          .ssh/authorized_keys
MaxAuthTries                3
MaxSessions                 5
AllowAgentForwarding        no
AllowTcpForwarding          no
X11Forwarding               no
HostKey                     /etc/ssh/ssh_host_ed25519_key
HostKey                     /etc/ssh/ssh_host_rsa_key
Ciphers                     chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs                        hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms               curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
```

### `/etc/ufw/` (directory)

Managed by the `ufw` module.
- `ufw.conf` — enables UFW, sets logging level to `low`
- `before.rules` — DOCKER-USER chain rules appended here
- `after.rules` — post-processing rules (not modified by installer)

### `/etc/fail2ban/jail.local`

Managed by the `fail2ban` module. Overrides `/etc/fail2ban/jail.conf`.

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
```

### `/etc/crowdsec/config.yaml`

Managed by the `crowdsec` module. Critical change from default:

```yaml
api:
  server:
    listen_uri: 127.0.0.1:6767   # DEFAULT WAS 0.0.0.0:8080 — changed to avoid conflict
```

### `/opt/monitoring/docker-compose.yml`

Deployed by the `monitoring` module from `docker/docker-compose.yml`. This is the runtime file used by `docker compose`. Services: prometheus, grafana, node-exporter, cadvisor, loki, promtail.

### `/opt/monitoring/prometheus/prometheus.yml`

Prometheus scrape configuration. Deployed from `docker/prometheus/prometheus.yml`.
- Global scrape interval: 15s
- Jobs: `prometheus`, `node-exporter`, `cadvisor`, `docker`
- Rule files loaded from `/etc/prometheus/rules/*.yml`

### `/opt/monitoring/loki/loki-config.yml`

Loki standalone configuration. Deployed from `docker/loki/loki-config.yml`.
- `kvstore.store: inmemory` — **critical** for single-node deployment
- `replication_factor: 1` — no cluster replication
- `schema: v13`, `store: tsdb`, `object_store: filesystem`
- Storage path: `/loki` (inside named volume `loki_data`)

### `/opt/monitoring/promtail/promtail-config.yml`

Promtail scrape jobs. Deployed from `docker/promtail/promtail-config.yml`.
- Push URL: `http://loki:3100/loki/api/v1/push`
- Jobs: `auth`, `syslog`, `kernel`, `fail2ban`, `crowdsec`, `ufw`, `dpkg`, `docker`
- Docker job uses pipeline stages to parse JSON log envelope and extract `container_id`

### `/etc/docker/daemon.json`

Managed by the `docker` module.

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "metrics-addr": "127.0.0.1:9323",
  "experimental": true
}
```

---

## 6. Port Inventory

| Port | Protocol | Service | Process | Bind Address | Accessible From |
|---|---|---|---|---|---|
| 22 | TCP | SSH | sshd | `0.0.0.0` | Internet (protected by UFW + F2B + CS) |
| 6767 | TCP | CrowdSec LAPI | crowdsec | `127.0.0.1` | localhost only |
| 9090 | TCP | Prometheus | prometheus (Docker) | `127.0.0.1` | localhost / SSH tunnel |
| 3000 | TCP | Grafana | grafana (Docker) | `127.0.0.1` | localhost / SSH tunnel |
| 9100 | TCP | Node Exporter | node-exporter (Docker, host net) | host network | localhost / SSH tunnel |
| 8081 | TCP | cAdvisor (host) | cadvisor (Docker) | `127.0.0.1` | localhost / SSH tunnel |
| 8080 | TCP | cAdvisor (internal) | cadvisor (Docker) | Docker bridge | `cadvisor:8080` within monitoring network |
| 3100 | TCP | Loki | loki (Docker) | `127.0.0.1` | localhost / SSH tunnel |
| 9080 | TCP | Promtail | promtail (Docker) | Docker bridge | internal only |
| 9323 | TCP | Docker metrics | dockerd | `127.0.0.1` | localhost only |
| 9096 | TCP | Loki gRPC | loki (Docker) | Docker bridge | internal only |

---

## 7. Network Architecture

### Host Network Interfaces

The host has one or more network interfaces (typically `eth0` or `ens3`). UFW governs all traffic on these interfaces. Node Exporter uses `network_mode: host` to observe all interfaces directly — if it ran in a Docker bridge network, it would only see the virtual `eth0` inside the container.

### Docker Bridge Networks

The installer creates one external Docker network:

```bash
docker network create monitoring
```

This is a standard Linux bridge (`docker network inspect monitoring`). All monitoring containers except Node Exporter attach to this network. Containers resolve each other by name (Docker embedded DNS): `prometheus`, `grafana`, `loki`, `promtail`, `cadvisor`.

Node Exporter uses `network_mode: host` — it shares the host network stack entirely and does not participate in the `monitoring` bridge.

### Port Exposure Strategy

| Exposure level | How it works | Services |
|---|---|---|
| **Public** | UFW `allow` rule, bound to `0.0.0.0` | SSH (port 22 or custom) |
| **Localhost only** | Bound to `127.0.0.1` | Prometheus, Grafana, Loki, cAdvisor, CrowdSec LAPI, Docker metrics |
| **Docker network only** | No host port mapping | Promtail (:9080), Loki gRPC (:9096), cAdvisor internal (:8080) |
| **Host network** | `network_mode: host` | Node Exporter (:9100) |

To access localhost-bound services from your workstation:

```bash
ssh -L 3000:127.0.0.1:3000 \
    -L 9090:127.0.0.1:9090 \
    -L 3100:127.0.0.1:3100 \
    user@VPS_IP
```

---

## 8. State Management

The installer tracks progress in a flat JSON file at `/var/lib/vps-hardening/state.json`.

### File Format

```json
{
  "module_ufw": "completed",
  "module_ufw_time": "2025-05-18T15:30:00+00:00",
  "module_ssh": "completed",
  "module_ssh_time": "2025-05-18T15:30:45+00:00",
  "module_fail2ban": "completed",
  "module_fail2ban_time": "2025-05-18T15:31:10+00:00",
  "module_crowdsec": "completed",
  "module_crowdsec_time": "2025-05-18T15:32:00+00:00",
  "module_docker": "completed",
  "module_docker_time": "2025-05-18T15:35:00+00:00",
  "module_monitoring": "completed",
  "module_monitoring_time": "2025-05-18T15:36:30+00:00",
  "ssh_port": "22",
  "crowdsec_lapi_port": "6767",
  "grafana_password_set": "true",
  "server_ip": "203.0.113.42"
}
```

### State Keys Reference

| Key pattern | Type | Description |
|---|---|---|
| `module_<name>` | `"completed"` or absent | Whether a module has run successfully |
| `module_<name>_time` | ISO-8601 timestamp | When the module last completed |
| `ssh_port` | integer string | SSH port configured by the `ssh` module |
| `crowdsec_lapi_port` | integer string | CrowdSec LAPI port (default: `6767`) |
| `grafana_password_set` | `"true"` / `"false"` | Whether a non-default Grafana password was set |
| `server_ip` | IPv4 string | Detected public IP at install time |

### How Modules Use State

```bash
# Check if a module was already completed — skip if so
if module_completed "fail2ban"; then
    log_info "fail2ban already installed, skipping"
    return 0
fi

# Read a value set by another module
ssh_port=$(get_state "ssh_port")

# After successful completion, mark the module done
mark_module_complete "fail2ban"
```

`module_completed()`, `get_state()`, `save_state()`, and `mark_module_complete()` are all defined in `lib/common.sh`.

### Forcing Re-execution

To force a module to re-run even if already marked complete:

```bash
# Remove the module's completed flag
sudo jq 'del(.module_fail2ban, .module_fail2ban_time)' \
    /var/lib/vps-hardening/state.json > /tmp/state.tmp \
    && sudo mv /tmp/state.tmp /var/lib/vps-hardening/state.json

# Re-run the installer or specific module
sudo bash install.sh --module fail2ban
```

---

## 9. Backup Strategy

### What Gets Backed Up

Before modifying any system file, the `backup_file()` function in `lib/common.sh` copies the original to `./backups/` with a timestamp suffix.

Files backed up by default:

| Original Path | Module |
|---|---|
| `/etc/ssh/sshd_config` | `ssh` |
| `/etc/ufw/ufw.conf` | `ufw` |
| `/etc/ufw/before.rules` | `ufw` |
| `/etc/fail2ban/jail.conf` | `fail2ban` |
| `/etc/crowdsec/config.yaml` | `crowdsec` |
| `/etc/docker/daemon.json` | `docker` |

### Backup Location and Naming

```
backups/
├── sshd_config.20250518_153000.bak
├── ufw.conf.20250518_153010.bak
├── before.rules.20250518_153010.bak
├── jail.conf.20250518_153045.bak
├── config.yaml.20250518_153120.bak
└── daemon.json.20250518_153500.bak
```

Format: `<original_filename>.<YYYYMMDD_HHMMSS>.bak`

The `backups/` directory is in `.gitignore`. Do not commit it — it may contain sensitive configuration values.

### How to Restore a Backup

```bash
# Find the backup
ls -lt /opt/vps-hardening-suite/backups/

# Restore a specific file
sudo cp backups/sshd_config.20250518_153000.bak /etc/ssh/sshd_config

# Test the restored config before restarting
sudo sshd -t

# Restart the service
sudo systemctl restart ssh
```

### Monitoring Data Persistence

Prometheus, Grafana, and Loki data live in Docker named volumes:
- `prometheus_data` — metrics TSDB
- `grafana_data` — dashboards, user data, plugin state
- `loki_data` — log chunks and TSDB index

To back up these volumes:

```bash
# Stop the stack first for a consistent snapshot
docker compose -f /opt/monitoring/docker-compose.yml stop

# Export each volume
docker run --rm -v prometheus_data:/data -v /backup:/backup \
    alpine tar czf /backup/prometheus_data.tar.gz /data

docker run --rm -v grafana_data:/data -v /backup:/backup \
    alpine tar czf /backup/grafana_data.tar.gz /data

docker run --rm -v loki_data:/data -v /backup:/backup \
    alpine tar czf /backup/loki_data.tar.gz /data

# Restart
docker compose -f /opt/monitoring/docker-compose.yml start
```

To restore a volume from backup:

```bash
docker run --rm -v prometheus_data:/data -v /backup:/backup \
    alpine sh -c "cd /data && tar xzf /backup/prometheus_data.tar.gz --strip-components=1"
```
