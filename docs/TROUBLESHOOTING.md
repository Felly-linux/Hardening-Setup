# Troubleshooting Guide — VPS Hardening Suite

> **Format:** Each issue follows: **Symptoms → Diagnostic Commands → Root Cause → Fix**
>
> All commands assume you are logged in as root or using `sudo`. Replace `YOUR_VPS_IP` with your server's IP address.

---

## Table of Contents

1. [SSH Troubleshooting](#1-ssh-troubleshooting)
2. [Docker Troubleshooting](#2-docker-troubleshooting)
3. [Prometheus Troubleshooting](#3-prometheus-troubleshooting)
4. [Grafana Troubleshooting](#4-grafana-troubleshooting)
5. [Loki Troubleshooting](#5-loki-troubleshooting)
6. [CrowdSec Troubleshooting](#6-crowdsec-troubleshooting)
7. [Fail2Ban Troubleshooting](#7-fail2ban-troubleshooting)
8. [UFW Troubleshooting](#8-ufw-troubleshooting)
9. [General Useful Commands](#9-general-useful-commands)

---

## 1. SSH Troubleshooting

### 1.1 — Can't Connect After Port Change

**Symptoms:**
- `Connection refused` or `Connection timed out` after changing the SSH port
- Previously working SSH sessions still work, new sessions fail

**Diagnostic:**
```bash
# On the server (via console/VPS panel):
# Check what port sshd is actually listening on
ss -tlnp | grep sshd

# Check if UFW allows the new port
ufw status verbose | grep ssh

# Check sshd_config for the Port directive
grep -i "^Port" /etc/ssh/sshd_config

# Check if sshd is running
systemctl status ssh
```

**Root Cause:** The SSH port was changed in `sshd_config` but the UFW rule was not updated, or the daemon was not restarted.

**Fix:**
```bash
# Allow the new port in UFW (e.g., port 2222)
ufw allow 2222/tcp comment 'SSH custom port'

# Remove the old rule if no longer needed
ufw delete allow 22/tcp

# Restart sshd
systemctl restart ssh

# Verify
ss -tlnp | grep sshd
# Expected: LISTEN 0.0.0.0:2222
```

> **Warning:** Always keep an active session open when changing the SSH port. If you get locked out, use the VPS provider's web console (KVM/VNC access) to recover.

---

### 1.2 — Permission Denied (publickey)

**Symptoms:**
- `Permission denied (publickey)` on every connection attempt
- Worked before; stopped working after a key rotation or module run

**Diagnostic:**
```bash
# On the server:
# Check authorized_keys exists and has correct permissions
ls -la ~/.ssh/
cat ~/.ssh/authorized_keys

# Check sshd_config points to the right authorized keys file
grep AuthorizedKeysFile /etc/ssh/sshd_config

# Check home directory and .ssh permissions
stat ~ | grep Access
stat ~/.ssh | grep Access
stat ~/.ssh/authorized_keys | grep Access

# Check SELinux/AppArmor labels (if applicable)
ls -laZ ~/.ssh/ 2>/dev/null

# Check auth log for specifics
journalctl -u ssh -n 50
grep "publickey" /var/log/auth.log | tail -20
```

**Root Cause options:**
1. `authorized_keys` has wrong permissions (must be `600`, not `644` or `777`)
2. `.ssh/` directory has wrong permissions (must be `700`)
3. Home directory is world-writable (sshd rejects this as insecure)
4. Wrong public key in `authorized_keys`
5. `sshd_config` has `AuthorizedKeysFile` pointing to a non-existent path

**Fix:**
```bash
# Fix permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 755 ~    # home must NOT be world-writable (755 max)

# Verify the correct key is present
# On your local machine, get your public key:
cat ~/.ssh/id_ed25519.pub
# Copy and paste into ~/.ssh/authorized_keys on the server

# Test sshd config before restarting
sshd -t && systemctl restart ssh
```

---

### 1.3 — Connection Timeout

**Symptoms:**
- `ssh: connect to host YOUR_VPS_IP port 22: Connection timed out`
- Connection hangs indefinitely, no response

**Diagnostic:**
```bash
# From your local machine:
# Test basic connectivity
ping -c 4 YOUR_VPS_IP
traceroute YOUR_VPS_IP

# Test if the port is filtered (from outside)
nc -zv YOUR_VPS_IP 22 -w 5

# On the server (via console):
# Check UFW
ufw status verbose

# Check iptables directly
iptables -L INPUT -n -v | grep -E "22|DROP|REJECT"

# Check if CrowdSec banned your IP
cscli decisions list | grep YOUR_CLIENT_IP

# Check if Fail2Ban banned your IP
fail2ban-client status sshd
```

**Root Cause:** Your IP is blocked by UFW, CrowdSec, or Fail2Ban. Or UFW is not allowing the SSH port.

**Fix:**
```bash
# If CrowdSec banned your IP:
cscli decisions delete --ip YOUR_CLIENT_IP

# If Fail2Ban banned your IP:
fail2ban-client set sshd unbanip YOUR_CLIENT_IP

# If UFW is blocking it:
ufw allow from YOUR_CLIENT_IP to any port 22
# Or re-allow SSH globally:
ufw allow ssh
```

---

### 1.4 — Too Many Authentication Failures

**Symptoms:**
- `Received disconnect from ... Too many authentication failures`
- Happens immediately on connection attempt

**Diagnostic:**
```bash
# On your local machine:
# Check how many keys your SSH agent is offering
ssh-add -l

# Check verbose SSH output
ssh -v user@YOUR_VPS_IP

# On the server:
grep MaxAuthTries /etc/ssh/sshd_config
```

**Root Cause:** `MaxAuthTries` is set to `3` (hardened default) but your SSH agent is offering many keys before the correct one, exhausting the limit.

**Fix — Option A:** Specify the exact key on the client:
```bash
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes user@YOUR_VPS_IP
```

**Fix — Option B:** Add to `~/.ssh/config` on your local machine:
```
Host YOUR_VPS_IP
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
```

**Fix — Option C (server side):** Increase MaxAuthTries temporarily for debugging:
```bash
# Edit sshd_config
sed -i 's/MaxAuthTries 3/MaxAuthTries 6/' /etc/ssh/sshd_config
systemctl reload ssh
```

---

## 2. Docker Troubleshooting

### 2.1 — docker: command not found

**Symptoms:**
- `bash: docker: command not found`
- `which docker` returns nothing

**Diagnostic:**
```bash
# Check if docker is installed
dpkg -l | grep docker
ls /usr/bin/docker* 2>/dev/null
ls /usr/local/bin/docker* 2>/dev/null

# Check if the docker module completed
jq '.module_docker' /var/lib/vps-hardening/state.json 2>/dev/null
```

**Root Cause:** The `docker` module did not complete, or Docker was installed in a non-standard path.

**Fix:**
```bash
# Re-run the docker module
sudo bash install.sh --module docker

# Or install Docker manually (official method)
curl -fsSL https://get.docker.com | sh

# Verify
docker --version
systemctl status docker
```

---

### 2.2 — Permission Denied Running Docker

**Symptoms:**
- `permission denied while trying to connect to the Docker daemon socket`
- Works with `sudo` but not as regular user

**Diagnostic:**
```bash
# Check if your user is in the docker group
groups $USER
id $USER | grep docker

# Check docker socket permissions
ls -la /var/run/docker.sock
```

**Root Cause:** Your user is not in the `docker` group, or the group membership hasn't been applied to the current session.

**Fix:**
```bash
# Add user to docker group
usermod -aG docker $USER

# Apply without logging out (current session only)
newgrp docker

# Or log out and back in for persistent effect
```

> **Security note:** Adding a user to the `docker` group is effectively granting root-equivalent privileges. Only add trusted users.

---

### 2.3 — Container Fails to Start

**Symptoms:**
- `docker compose up -d` shows containers as `Exited (1)` or `Restarting`
- Container starts and immediately dies

**Diagnostic:**
```bash
# Check container status
docker compose -f /opt/monitoring/docker-compose.yml ps

# View logs for a specific container (replace 'loki' with your container)
docker logs loki --tail 50

# Check events for context
docker events --since 10m &
docker compose -f /opt/monitoring/docker-compose.yml restart loki

# Inspect the container
docker inspect loki | jq '.[0].State'
```

**Root Cause:** Config file error, volume permission issue, port already in use, or image pull failure.

**Fix:**
```bash
# Check if config files exist and are readable
ls -la /opt/monitoring/loki/
cat /opt/monitoring/loki/loki-config.yml

# Check for port conflicts
ss -tlnp | grep -E "3100|9090|3000|8081"

# Pull images manually if network was flaky
docker compose -f /opt/monitoring/docker-compose.yml pull

# Remove and recreate the container
docker compose -f /opt/monitoring/docker-compose.yml up -d --force-recreate loki
```

---

### 2.4 — Network Conflicts

**Symptoms:**
- `Error response from daemon: network monitoring not found`
- `failed to create network monitoring: ... address already in use`

**Diagnostic:**
```bash
# List all Docker networks
docker network ls

# Inspect the monitoring network
docker network inspect monitoring

# Check for subnet conflicts
docker network ls --format "{{.Name}}" | xargs -I{} docker network inspect {} | jq -r '.[0] | "\(.Name): \(.IPAM.Config[0].Subnet // "no subnet")"'

# Check host routes
ip route
```

**Root Cause:** The `monitoring` network doesn't exist (not created by installer), or its subnet conflicts with an existing network.

**Fix:**
```bash
# Create the missing network
docker network create monitoring

# If subnet conflicts, remove the conflicting network or specify a different subnet
docker network create --subnet=172.20.0.0/16 monitoring
```

---

### 2.5 — Port Already in Use

**Symptoms:**
- `Bind for 0.0.0.0:3000 failed: port is already allocated`
- Container cannot start because the host port is taken

**Diagnostic:**
```bash
# Find what is using the port
ss -tlnp | grep :3000
lsof -i :3000 2>/dev/null

# Check if another container is already using it
docker ps | grep "3000"
```

**Root Cause:** Another process or container already bound the port.

**Fix:**
```bash
# Stop the conflicting process
kill $(lsof -t -i:3000)

# Or stop the conflicting container
docker stop $(docker ps -q --filter publish=3000)

# Then start the monitoring stack
docker compose -f /opt/monitoring/docker-compose.yml up -d
```

---

## 3. Prometheus Troubleshooting

### 3.1 — No Data in Grafana from Prometheus

**Symptoms:**
- Grafana dashboards show "No data" for metrics panels
- Time series are empty

**Diagnostic:**
```bash
# Check Prometheus is healthy
curl -s http://localhost:9090/-/healthy
# Expected: Prometheus Server is Healthy.

# Check all scrape targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health, lastError: .lastError}'

# Check Prometheus logs
docker logs prometheus --tail 50
```

**Root Cause:** Prometheus datasource URL is wrong in Grafana, or Prometheus is unhealthy.

**Fix:**
```bash
# In Grafana UI:
# Configuration → Data Sources → Prometheus
# URL must be: http://prometheus:9090
# (Docker DNS name, NOT localhost)
# Click "Save & Test"

# If the datasource was provisioned automatically via YAML, verify:
cat /opt/monitoring/grafana/provisioning/datasources/datasources.yml
# url should be: http://prometheus:9090
```

---

### 3.2 — Scrape Target Down

**Symptoms:**
- Prometheus UI shows a target as `DOWN` at `http://localhost:9090/targets`
- Missing metrics from a specific service

**Diagnostic:**
```bash
# See all target statuses and last error
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.health != "up") | {job: .labels.job, health: .health, lastError: .lastError, lastScrape: .lastScrape}'

# Manually scrape the endpoint to reproduce the error
curl -s http://localhost:9100/metrics | head -5        # node-exporter
curl -s http://localhost:8081/metrics | head -5        # cadvisor (host port)
curl -s http://localhost:9323/metrics | head -5        # docker daemon
```

**Root Cause options:**
- Service is not running (node-exporter stopped, cAdvisor crashed)
- Wrong scrape target address in `prometheus.yml` (e.g., using host port vs Docker network port)
- Network connectivity between Prometheus container and the target

**Fix for node-exporter (host network):**
```bash
# node-exporter must use 'localhost:9100' in prometheus.yml
# because it runs on the HOST network, not the Docker network
grep "node-exporter" /opt/monitoring/prometheus/prometheus.yml
# Should show: targets: ['localhost:9100']
```

**Fix for cAdvisor (Docker network):**
```bash
# Prometheus scrapes cAdvisor via Docker DNS on internal port 8080:
# targets: ['cadvisor:8080']   ← correct (Docker network)
# NOT: localhost:8081           ← that is the host-mapped port for external access
grep "cadvisor" /opt/monitoring/prometheus/prometheus.yml
```

---

### 3.3 — High Cardinality Warnings

**Symptoms:**
- Prometheus logs: `Error on ingesting samples that are too old or are too far into the future`
- Prometheus logs: `TSDB head series: ...` value growing unboundedly
- Grafana becomes slow

**Diagnostic:**
```bash
# Check head series count
curl -s http://localhost:9090/api/v1/status/tsdb | jq '.data.headStats'

# Find high-cardinality metrics
curl -s http://localhost:9090/api/v1/status/tsdb | jq '.data.seriesCountByMetricName | sort_by(.seriesCount) | reverse | .[0:10]'
```

**Root Cause:** Docker container labels or dynamic labels creating too many unique time series.

**Fix:**
```bash
# In prometheus.yml, add metric_relabel_configs to drop high-cardinality labels
# For cAdvisor, drop unused label dimensions:
# metric_relabel_configs:
#   - source_labels: [__name__]
#     regex: 'container_tasks_state|container_memory_failures_total'
#     action: drop
```

---

## 4. Grafana Troubleshooting

### 4.1 — Can't Login to Grafana

**Symptoms:**
- `Invalid username or password` with admin credentials
- Grafana login page loads but credentials are rejected

**Diagnostic:**
```bash
# Check Grafana logs
docker logs grafana --tail 50

# Check what password is configured
docker inspect grafana | jq '.[0].Config.Env | map(select(startswith("GF_SECURITY")))' 

# Check if .env is loaded
cat /opt/monitoring/.env | grep GRAFANA_PASSWORD
```

**Root Cause:** The `.env` file is missing, or the password was changed in the UI but the `GF_SECURITY_ADMIN_PASSWORD` env var no longer matches.

**Fix — Reset password via CLI:**
```bash
# Enter the Grafana container and reset the password
docker exec -it grafana grafana-cli admin reset-admin-password NEW_PASSWORD_HERE

# Or use the Grafana API (if you know the current password)
curl -X PUT -H "Content-Type: application/json" \
  -d '{"oldPassword":"old","newPassword":"new","confirmNew":"new"}' \
  http://admin:old@localhost:3000/api/user/password
```

---

### 4.2 — Datasource Connection Failed

**Symptoms:**
- Grafana shows "datasource connection failed" in the data source configuration
- "Post http://prometheus:9090/api/v1/query: dial tcp..."

**Diagnostic:**
```bash
# From inside the Grafana container, test connectivity
docker exec grafana wget -qO- http://prometheus:9090/-/healthy
docker exec grafana wget -qO- http://loki:3100/ready

# Check if containers are on the same network
docker network inspect monitoring | jq '.[0].Containers | keys'
```

**Root Cause:** The Grafana container cannot reach Prometheus or Loki because they are not on the same Docker network.

**Fix:**
```bash
# Verify all containers are on the monitoring network
docker network inspect monitoring

# If a container is missing, reconnect it
docker network connect monitoring prometheus
docker network connect monitoring loki

# Or recreate the stack
docker compose -f /opt/monitoring/docker-compose.yml down
docker compose -f /opt/monitoring/docker-compose.yml up -d
```

---

### 4.3 — Dashboard Shows "No Data"

**Symptoms:**
- Dashboard panels show "No data" in the time range
- Other datasource queries work fine

**Diagnostic:**
```bash
# In Grafana: open the panel in edit mode and check the query
# Look at the "Query Inspector" tab for the raw response

# Test the PromQL query directly
curl -s "http://localhost:9090/api/v1/query?query=up" | jq '.data.result'

# Check if the metric name exists
curl -s "http://localhost:9090/api/v1/label/__name__/values" | jq '.data | map(select(test("node_")))' | head -20
```

**Root Cause:** Dashboard uses metric names or label filters that don't match the actual data. This can happen after a Node Exporter version update that renamed metrics.

**Fix:**
```bash
# In Grafana, check the time range — may be set to a period before data collection started
# Also check if the variable ${job} or ${instance} matches actual label values:
curl -s "http://localhost:9090/api/v1/label/job/values"
```

---

### 4.4 — Dashboards Not Loading from Provisioning

**Symptoms:**
- Dashboard folder exists in `/opt/monitoring/grafana/dashboards/` but doesn't appear in Grafana
- New dashboard JSON files are ignored

**Diagnostic:**
```bash
# Check Grafana logs for provisioning errors
docker logs grafana 2>&1 | grep -i "provision"

# Check provisioning config
cat /opt/monitoring/grafana/provisioning/datasources/datasources.yml

# Check dashboard provisioning config exists
ls /opt/monitoring/grafana/provisioning/dashboards/
```

**Root Cause:** Dashboard provider config is missing or points to the wrong path.

**Fix — Create the dashboard provider config:**
```bash
mkdir -p /opt/monitoring/grafana/provisioning/dashboards/

cat > /opt/monitoring/grafana/provisioning/dashboards/dashboards.yml << 'EOF'
apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
EOF

# Restart Grafana
docker compose -f /opt/monitoring/docker-compose.yml restart grafana
docker logs grafana --follow
```

---

## 5. Loki Troubleshooting

### 5.1 — Loki Container Crashes on Startup (Ring / Consul Error)

> **This is the most common Loki issue.** Document it thoroughly.

**Symptoms:**
- Loki container exits immediately after starting
- `docker logs loki` shows errors like:
  ```
  failed to initialize ring: context deadline exceeded
  memberlist: Failed to resolve host...
  error initialising module: ingester
  consul: connect: connection refused 127.0.0.1:8500
  ```
- Loki keeps restarting in a loop (`docker ps` shows `Restarting`)

**Diagnostic:**
```bash
# Check exit code and logs
docker logs loki --tail 100
docker inspect loki | jq '.[0].State | {Status, ExitCode, Error}'

# Check if consul is expected
grep -r "consul\|memberlist\|kvstore" /opt/monitoring/loki/loki-config.yml
```

**Root Cause:**

Loki's default configuration assumes a distributed cluster with a ring-based coordination layer. The ring uses a distributed key-value store — by default, it tries to connect to **Consul** at `localhost:8500` or form a **memberlist** gossip cluster. On a single-node VPS, neither exists, so Loki hangs waiting for ring members, then exits with a timeout.

**Fix:**

The `loki-config.yml` used by this suite already contains the correct configuration. If you modified it or are using an external config, ensure these settings are present:

```yaml
common:
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory   # <-- THIS IS THE CRITICAL LINE
```

The `store: inmemory` setting tells Loki to use an in-process key-value store instead of reaching out to Consul or forming a gossip ring. This is correct and appropriate for single-node deployments.

**Verify the fix:**
```bash
# Confirm the config is correct
grep -A3 "kvstore" /opt/monitoring/loki/loki-config.yml
# Expected output:
#   kvstore:
#     store: inmemory

# Restart Loki
docker compose -f /opt/monitoring/docker-compose.yml restart loki

# Watch logs for successful startup
docker logs loki --follow
# Expected: "Loki started" or similar — no ring/consul errors

# Test the ready endpoint
curl -s http://localhost:3100/ready
# Expected: "ready"
```

**If the config file looks correct but Loki still crashes:**
```bash
# Wipe the Loki data volume (CAUTION: deletes all stored logs)
docker compose -f /opt/monitoring/docker-compose.yml stop loki
docker volume rm vps-hardening-suite_loki_data
docker compose -f /opt/monitoring/docker-compose.yml up -d loki
```

---

### 5.2 — Promtail Can't Connect to Loki

**Symptoms:**
- Promtail logs show: `Error sending batch: Post http://loki:3100/loki/api/v1/push: dial tcp: lookup loki`
- Logs are not appearing in Grafana even though Loki is running

**Diagnostic:**
```bash
# Check Promtail logs
docker logs promtail --tail 50

# Test DNS resolution from inside Promtail container
docker exec promtail wget -qO- http://loki:3100/ready

# Verify both containers are on monitoring network
docker network inspect monitoring | jq '.[0].Containers | keys'
```

**Root Cause:** Promtail container is not on the `monitoring` network, so `loki` hostname doesn't resolve.

**Fix:**
```bash
docker network connect monitoring promtail
docker compose -f /opt/monitoring/docker-compose.yml restart promtail
```

---

### 5.3 — Logs Not Appearing in Grafana

**Symptoms:**
- Loki is healthy (`/ready` returns `ready`)
- Promtail is running with no errors
- Grafana Explore → Loki returns no results

**Diagnostic:**
```bash
# Query Loki directly for any logs
curl -s -G \
  --data-urlencode 'query={job="syslog"}' \
  --data-urlencode 'limit=5' \
  http://localhost:3100/loki/api/v1/query_range

# Check Promtail positions (tracks which files were read)
docker exec promtail cat /tmp/positions.yaml

# Check Promtail metrics
curl -s http://localhost:9080/metrics | grep "promtail_"
```

**Root Cause:** Promtail cannot read `/var/log` files (permission denied), or the file glob pattern doesn't match any files.

**Fix:**
```bash
# Check file permissions
ls -la /var/log/auth.log /var/log/syslog

# Promtail runs as root inside the container (the image default)
# If /var/log files are unreadable, check the volume mount:
docker inspect promtail | jq '.[0].Mounts'
# Should show /var/log mounted read-only

# If /var/log/auth.log doesn't exist (Ubuntu 22.04 uses journald by default):
# Enable traditional syslog
apt install -y rsyslog
systemctl enable --now rsyslog
```

---

### 5.4 — "Entry Out of Order" Errors

**Symptoms:**
- Promtail logs show: `level=warn msg="entry out of order" ...`
- Some logs appear, but others are silently dropped

**Diagnostic:**
```bash
docker logs promtail 2>&1 | grep "out of order"
```

**Root Cause:** Log entries are being pushed to Loki with timestamps older than `reject_old_samples_max_age` (default: 168h / 7 days). This typically happens if a log file has very old entries, or if the system clock is wrong.

**Fix:**
```bash
# Check system clock
timedatectl

# Sync if needed
timedatectl set-ntp true

# Increase or disable the rejection window in loki-config.yml:
# limits_config:
#   reject_old_samples_max_age: 720h  # 30 days

# Restart Loki after config change
docker compose -f /opt/monitoring/docker-compose.yml restart loki
```

---

## 6. CrowdSec Troubleshooting

### 6.1 — Port 8080 Conflict (Real Deployment Issue)

> **This issue occurred during the initial production deployment of this suite.** It is documented in detail.

**Symptoms:**
- CrowdSec fails to start or restarts in a loop
- `systemctl status crowdsec` shows: `bind: address already in use` or `listen tcp 0.0.0.0:8080: bind: address already in use`
- `journalctl -u crowdsec -n 50` shows port binding errors

**Diagnostic:**
```bash
# Find what is using port 8080
ss -tlnp | grep :8080

# Check CrowdSec logs for the bind error
journalctl -u crowdsec -n 100 | grep -E "8080|bind|listen"

# Check the current listen_uri in config
grep "listen_uri" /etc/crowdsec/config.yaml
```

**Root Cause:**

CrowdSec's default LAPI `listen_uri` is `0.0.0.0:8080`. In this suite, cAdvisor also wants to use port 8080 internally (its default internal port). When CrowdSec and cAdvisor both try to bind 8080 on the host, one of them fails. In practice, cAdvisor is the monitoring container that holds port 8080 internally, and CrowdSec tries to bind it on the host.

The solution adopted by this suite is to move CrowdSec LAPI to `127.0.0.1:6767` (a port with no known conflicts in this stack), and map cAdvisor to host port `8081` instead of `8080`.

**Fix:**
```bash
# Edit CrowdSec main config
nano /etc/crowdsec/config.yaml

# Find and change:
#   listen_uri: 127.0.0.1:8080
# to:
#   listen_uri: 127.0.0.1:6767

# Also update the bouncer's LAPI URL if configured:
nano /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
# api_url: http://127.0.0.1:6767

# Restart both services
systemctl restart crowdsec
systemctl restart crowdsec-firewall-bouncer

# Verify
systemctl status crowdsec
ss -tlnp | grep 6767
cscli machines list
```

**Why 6767?** It is not in the IANA well-known or registered port ranges that conflict with any service in this stack. The value is defined as `PORT_CROWDSEC_LAPI=6767` in `lib/common.sh` — the single source of truth.

---

### 6.2 — Can't Connect to LAPI

**Symptoms:**
- `cscli` commands fail: `unable to run command: Post http://127.0.0.1:8080/v1/watchers/login`
- Bouncer shows: `connection refused 127.0.0.1:8080`

**Diagnostic:**
```bash
# Check what port LAPI is actually listening on
ss -tlnp | grep crowdsec
grep "listen_uri" /etc/crowdsec/config.yaml

# Check the cscli config
cat /etc/crowdsec/config.yaml | grep -A5 "api:"
```

**Root Cause:** The LAPI port was changed to `6767` but the `cscli` or bouncer config still references `8080`.

**Fix:**
```bash
# The cscli local API config is at:
cat ~/.config/crowdsec/config.yaml 2>/dev/null || cat /root/.config/crowdsec/config.yaml

# Or check the main config:
grep -A10 "client:" /etc/crowdsec/config.yaml

# If it shows 8080, update all references to 6767
sed -i 's|127.0.0.1:8080|127.0.0.1:6767|g' /etc/crowdsec/config.yaml
systemctl restart crowdsec

# Re-register the machine if needed
cscli machines add --auto
```

---

### 6.3 — Bouncer Not Working

**Symptoms:**
- `cscli bouncers list` shows the bouncer as registered
- But banned IPs can still connect
- `cscli decisions list` shows active bans but iptables doesn't reflect them

**Diagnostic:**
```bash
# Check bouncer service status
systemctl status crowdsec-firewall-bouncer

# Check bouncer logs
journalctl -u crowdsec-firewall-bouncer -n 50

# Check if iptables rules were applied
iptables -L -n | grep -i crowdsec
```

**Root Cause:** Bouncer is not running, or the `api_url` in the bouncer config points to the wrong LAPI port.

**Fix:**
```bash
# Check bouncer config
cat /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml | grep "api_url"
# Should be: api_url: http://127.0.0.1:6767

# Fix and restart
sed -i 's|http://127.0.0.1:8080|http://127.0.0.1:6767|g' \
    /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
systemctl restart crowdsec-firewall-bouncer
systemctl status crowdsec-firewall-bouncer
```

---

### 6.4 — cscli Commands Fail

**Symptoms:**
- `cscli hub list` or `cscli decisions list` returns errors
- `FATA[...] unable to load configuration: ...`

**Diagnostic:**
```bash
# Check CrowdSec config file syntax
crowdsec -t -c /etc/crowdsec/config.yaml

# Check if crowdsec service is running
systemctl status crowdsec

# Run cscli with explicit config
cscli -c /etc/crowdsec/config.yaml machines list
```

**Root Cause:** Configuration file syntax error, or CrowdSec daemon is not running.

**Fix:**
```bash
systemctl start crowdsec
systemctl enable crowdsec
cscli hub update
cscli hub upgrade
```

---

## 7. Fail2Ban Troubleshooting

### 7.1 — Fail2Ban Not Banning Attackers

**Symptoms:**
- Repeated failed SSH attempts visible in auth.log
- `fail2ban-client status sshd` shows no banned IPs despite visible attacks
- `/var/log/fail2ban.log` shows no `Ban` actions

**Diagnostic:**
```bash
# Check Fail2Ban service status
systemctl status fail2ban

# Check which jails are active
fail2ban-client status

# Check sshd jail specifically
fail2ban-client status sshd

# Check if auth.log matches the filter
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf | tail -20

# Check jail.local configuration
cat /etc/fail2ban/jail.local

# Check Fail2Ban logs
tail -100 /var/log/fail2ban.log
```

**Root Cause options:**
1. `jail.local` has `enabled = false` for the sshd jail
2. Wrong `logpath` — auth.log is in a different location
3. `maxretry` is set very high
4. The attacker's IP is in `ignoreip`

**Fix:**
```bash
# Verify jail is enabled
grep -A10 "\[sshd\]" /etc/fail2ban/jail.local
# Should show: enabled = true

# Correct log path for Ubuntu 22.04+ (uses journald, not auth.log):
# In jail.local:
# [sshd]
# backend = systemd
# (no logpath needed when using systemd backend)

# Restart Fail2Ban after changes
systemctl restart fail2ban
```

---

### 7.2 — Wrong Log Path

**Symptoms:**
- Fail2Ban starts but never bans anyone
- `fail2ban-client status sshd` shows `File list:` pointing to a non-existent file

**Diagnostic:**
```bash
# Ubuntu 22.04 uses systemd journal, not /var/log/auth.log
ls /var/log/auth.log 2>/dev/null || echo "file not found"

# Check jail backend
grep "backend" /etc/fail2ban/jail.local
```

**Root Cause:** Ubuntu 22.04 moved SSH logs to journald. The default `logpath = /var/log/auth.log` doesn't exist.

**Fix:**
```bash
# Option A: Use systemd backend (recommended for Ubuntu 22.04+)
cat >> /etc/fail2ban/jail.local << 'EOF'

[sshd]
backend = systemd
enabled = true
maxretry = 3
bantime  = 1h
EOF

systemctl restart fail2ban

# Option B: Install rsyslog to restore auth.log
apt install -y rsyslog
systemctl enable --now rsyslog
```

---

### 7.3 — Accidentally Banned Own IP

**Symptoms:**
- You are suddenly locked out of SSH
- Connection refused or timed out to the server

**Resolution (via VPS console):**
```bash
# Access the server via your VPS provider's web console (KVM/VNC)

# Check if your IP is banned
fail2ban-client status sshd

# Unban your IP
fail2ban-client set sshd unbanip YOUR_IP_ADDRESS

# Verify
fail2ban-client status sshd

# To prevent it happening again, add your IP to ignoreip in jail.local:
echo "ignoreip = 127.0.0.1/8 ::1 YOUR_IP_ADDRESS" >> /etc/fail2ban/jail.local
systemctl reload fail2ban
```

---

## 8. UFW Troubleshooting

### 8.1 — UFW Blocking Docker Container Traffic

**Symptoms:**
- Containers can't reach the internet (e.g., Grafana can't install plugins)
- `docker exec grafana curl https://example.com` fails
- Works after disabling UFW

**Diagnostic:**
```bash
# Check UFW's default forward policy
grep "DEFAULT_FORWARD_POLICY" /etc/default/ufw

# Check if DOCKER-USER chain has restrictive rules
iptables -L DOCKER-USER -n -v
```

**Root Cause:** UFW's default `DEFAULT_FORWARD_POLICY` is `DROP`, which blocks Docker container traffic routed through the host.

**Fix:**
```bash
# Allow Docker container forwarding
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

# Reload UFW
ufw reload

# Alternatively, add a rule to accept forwarded traffic from Docker networks
ufw route allow in on docker0
ufw route allow in on br-$(docker network inspect monitoring --format '{{.Id}}' | cut -c1-12)
```

---

### 8.2 — UFW Blocking Monitoring Stack

**Symptoms:**
- Prometheus can't scrape Node Exporter at `localhost:9100`
- Services on `127.0.0.1` unexpectedly unreachable

**Diagnostic:**
```bash
# Check UFW rules for localhost
ufw status verbose

# Test connectivity directly
curl -sv http://127.0.0.1:9100/metrics 2>&1 | head -20

# Check if UFW has a rule blocking loopback
iptables -L INPUT -n | grep "127.0.0.1\|lo"
```

**Root Cause:** UFW should never block loopback traffic — `before.rules` contains `ACCEPT` rules for `lo`. If those were removed accidentally, loopback is blocked.

**Fix:**
```bash
# Check UFW's before.rules
grep -A5 "loopback" /etc/ufw/before.rules
# Should contain:
# -A ufw-before-input -i lo -j ACCEPT
# -A ufw-before-output -o lo -j ACCEPT

# If missing, restore from backup
cp /opt/vps-hardening-suite/backups/before.rules.XXXXXXXX.bak /etc/ufw/before.rules
ufw reload
```

---

### 8.3 — SSH Locked Out via UFW

**Symptoms:**
- UFW was enabled or rules changed and SSH no longer works
- `Connection refused` on the SSH port

**Resolution (via VPS console):**
```bash
# Via VPS provider console:
# Disable UFW temporarily
ufw disable

# Add SSH rule and re-enable
ufw allow ssh
ufw enable

# Or specify the exact port
ufw allow 22/tcp
ufw enable
```

> **Prevention:** Always run `ufw allow ssh` (or the specific port) BEFORE running `ufw enable`. The installer does this automatically.

---

### 8.4 — Rules Not Applying to IPv6

**Symptoms:**
- IPv4 connections blocked correctly, but IPv6 attacks or connections pass through
- `ufw status` shows rules without `(v6)` variants

**Diagnostic:**
```bash
# Check if IPv6 is enabled in UFW
grep "IPV6" /etc/default/ufw

# Check if IPv6 rules are present
ufw status verbose | grep v6
```

**Root Cause:** UFW's IPv6 support is disabled in `/etc/default/ufw`.

**Fix:**
```bash
sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw
ufw reload

# Verify
ufw status verbose | grep v6
```

---

## 9. General Useful Commands

### Service Health Checks

```bash
# Check all core security services
systemctl status docker fail2ban crowdsec ufw

# Check all monitoring containers
docker compose -f /opt/monitoring/docker-compose.yml ps

# Quick health summary
for svc in docker fail2ban crowdsec; do
    echo -n "$svc: "
    systemctl is-active $svc
done
```

### Port and Network Inspection

```bash
# Show all listening TCP ports with process names
ss -tlnp

# Show all open ports (TCP + UDP)
ss -tunlp

# Check which process owns a specific port
ss -tlnp | grep :9090
lsof -i :9090 2>/dev/null

# Trace the firewall chain for an IP
iptables -L -n -v | grep -E "DROP|REJECT"
```

### Log Monitoring

```bash
# Follow all system logs
journalctl -f

# Follow SSH logs
journalctl -u ssh -f

# Follow Docker logs for all monitoring containers
docker compose -f /opt/monitoring/docker-compose.yml logs -f

# Follow a specific container
docker logs prometheus -f --tail 50

# Check auth log for brute force activity
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20
```

### Prometheus

```bash
# Test Prometheus health
curl -s http://localhost:9090/-/healthy

# Get all scrape target statuses
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'

# Query a specific metric
curl -s 'http://localhost:9090/api/v1/query?query=up' | jq '.data.result'

# Reload Prometheus config (no restart needed)
curl -X POST http://localhost:9090/-/reload
```

### Loki

```bash
# Test Loki readiness
curl -s http://localhost:3100/ready

# Test Loki health
curl -s http://localhost:3100/loki/api/v1/status/buildinfo | jq '.version'

# Query recent logs from Loki
curl -s -G \
  --data-urlencode 'query={job="auth"}' \
  --data-urlencode 'limit=10' \
  http://localhost:3100/loki/api/v1/query_range | jq '.data.result[].values'
```

### Fail2Ban

```bash
# List all jails and their status
fail2ban-client status

# Check SSH jail in detail
fail2ban-client status sshd

# Unban an IP
fail2ban-client set sshd unbanip IP_ADDRESS

# Check all banned IPs
fail2ban-client status sshd | grep "Banned IP list"

# Test a log file against a filter
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf
```

### CrowdSec

```bash
# List active decisions (bans)
cscli decisions list

# List recent alerts
cscli alerts list

# List installed parsers and scenarios
cscli hub list

# Update threat intelligence
cscli hub update && cscli hub upgrade

# List registered machines
cscli machines list

# List active bouncers
cscli bouncers list

# Delete a specific ban
cscli decisions delete --ip IP_ADDRESS

# Check LAPI status (note: this suite uses port 6767)
curl -s http://127.0.0.1:6767/health
```

### Installer State

```bash
# View all installer state
cat /var/lib/vps-hardening/state.json | jq .

# Check which modules completed
cat /var/lib/vps-hardening/state.json | jq 'to_entries | map(select(.key | startswith("module_"))) | from_entries'

# View installer log
tail -100 /var/log/vps-hardening/install.log

# Force re-run of a specific module
sudo jq 'del(.module_fail2ban, .module_fail2ban_time)' \
    /var/lib/vps-hardening/state.json > /tmp/state.tmp \
    && sudo mv /tmp/state.tmp /var/lib/vps-hardening/state.json
```

### Docker Volume Management

```bash
# List all monitoring volumes
docker volume ls | grep -E "prometheus|grafana|loki"

# Inspect a volume's mount point
docker volume inspect prometheus_data | jq '.[0].Mountpoint'

# Check disk usage by volume
du -sh $(docker volume inspect prometheus_data | jq -r '.[0].Mountpoint')

# Prune unused Docker resources (CAUTION: only run if sure)
docker system prune -f
```
