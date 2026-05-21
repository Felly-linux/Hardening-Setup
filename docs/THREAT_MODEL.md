# Threat Model — Linux Hardening Framework

## Methodology

Every control in this framework is evaluated against four questions:

1. **What threat does it mitigate?** Specific attack classes, not vague categories. "Brute-force credential attack against sshd from a botnet" is a threat. "Unauthorized access" is not useful.
2. **What attack surface does it reduce?** What listener, file, syscall, or capability is removed or restricted?
3. **What are the tradeoffs?** What legitimate use is broken or degraded? Who is affected and how severely?
4. **Who should use it?** Which profiles apply this control and why; who should omit it.

We explicitly reject "security theater" — controls that appear on compliance checklists but provide negligible real-world protection. Every control in this document was included because it stops a real attack class or reduces the blast radius of a compromise. Controls that were considered and excluded are noted where relevant.

The framework uses three deployment profiles:

- **vps**: Minimal attack surface, key-only SSH, no Docker, no monitoring. Hardest baseline.
- **docker-host**: Full stack — Docker, Prometheus/Grafana/Loki, IP forwarding required.
- **homelab**: Trusted LAN, relaxed bans, TCP/agent forwarding permitted, no CrowdSec.

---

## Module Threat Analysis

---

### Module 01 — System Base Hardening

#### Threat: Exploitation of unpatched software vulnerabilities

**Attack surface:** Any service running a vulnerable version of a library or binary. The overwhelming majority of real-world server compromises begin with exploitation of a known CVE in an unpatched package — not zero-days.

**Controls applied:**
- `apt-get upgrade` is run first, before any other module touches the system.
- `unattended-upgrades` is configured to automatically apply security-origin packages daily. Kernel and `openssh-server` are blacklisted from auto-upgrade to prevent regressions (these require manual review).
- `APT::Periodic::AutocleanInterval 7` prevents the package cache from growing unbounded.

**Tradeoffs:** Automatic upgrades can break application compatibility when a library ABI changes. The kernel blacklist means kernel CVEs require a manual `apt-get upgrade && reboot` cycle. Acceptable for a server administrator; unacceptable for an unattended kiosk.

**Profile recommendations:** All profiles. There is no scenario where running known-vulnerable packages is the correct choice.

---

#### Threat: Unnecessary service attack surface (Avahi mDNS poisoning, Bluetooth stack exploits, CUPS remote code execution)

**Attack surface:** Services that are running and listening on the network or D-Bus are reachable attack surfaces. `avahi-daemon` responds to mDNS queries on all interfaces and has had multiple remote DoS and information disclosure CVEs. `cups-browsed` has had remote code execution vulnerabilities (CVE-2024-47176 and related 2024 chain). `bluetooth` stack vulnerabilities (BlueBorne, BIAS) affect systems even when no device is paired.

**Controls applied:**
- The following services are stopped, disabled, and masked: `bluetooth`, `cups`, `cups-browsed`, `avahi-daemon`, `ModemManager`, `apport`, `whoopsie`, `snapd`.
- Masking (via `systemctl mask`) prevents re-enable by package postinst scripts after future upgrades.

**Tradeoffs:** `snapd` removal breaks any Snap-packaged software. If the operator relies on a Snap (e.g., certain Canonical tools), they must re-enable it. `avahi-daemon` is required for certain mDNS-dependent applications (e.g., some service discovery tools) — these must use unicast DNS instead.

**Profile recommendations:** All profiles. On homelab, the operator may choose to re-enable specific services after the fact.

---

#### Threat: Exploitation of writable /tmp for privilege escalation (/tmp symlink TOCTOU, dropper staging)

**Attack surface:** `/tmp` on the root filesystem is executable by default. Attackers who achieve code execution as a low-privileged user frequently write shellcode, compiled exploits, or malicious scripts to `/tmp` and execute them. TOCTOU (time-of-check/time-of-use) symlink attacks — where a process creates a predictable temp file and an attacker replaces it with a symlink to a privileged file — are also blocked by `nosuid` and `nodev`.

**Controls applied:**
- `/tmp` is mounted as a `tmpfs` with `noexec,nosuid,nodev,mode=1777` via `/etc/fstab`. This means:
  - `noexec`: binaries and scripts in `/tmp` cannot be executed directly. An attacker who writes `exploit.sh` to `/tmp` cannot run it as `/tmp/exploit.sh`.
  - `nosuid`: setuid bits on files in `/tmp` are ignored. A setuid binary copied to `/tmp` by an attacker gains no privilege.
  - `nodev`: device nodes in `/tmp` have no effect.
- Size is capped at 512 MB to prevent `/tmp`-based disk exhaustion attacks.

**Tradeoffs:** Some software (build systems, compilers, certain Java applications) writes compiled artifacts to `/tmp` and attempts to execute them. These will fail silently or with a "Permission denied" error. `cc1`, some `javac` configurations, and certain install scripts are affected. This is an acceptable breakage — such tools should use a dedicated build directory, not `/tmp`.

**Profile recommendations:** All profiles (`PERMISSIONS_TMP_NOEXEC=yes` in all three). Homelab keeps it enabled.

---

#### Threat: Core dump leaking sensitive memory (cryptographic keys, passwords, tokens)

**Attack surface:** When a process crashes, the kernel writes its full address space to a core file. If that process was running as root, handling SSL private keys, or processing credentials, the core dump contains that data in plaintext. On many default systems, core dumps are written to the current working directory — potentially world-readable.

**Controls applied:**
- `fs.suid_dumpable = 0` via sysctl prevents setuid processes from dumping core at all.
- `/etc/security/limits.d/99-disable-coredumps.conf` sets `* hard core 0` and `* soft core 0` via PAM limits, applying to all processes spawned through PAM sessions.

**Tradeoffs:** Developers debugging application crashes lose the ability to capture core dumps in production. The operator must use `ulimit -c unlimited` manually in a debugging session, or configure a separate development environment. This is an acceptable restriction for a production server.

**Profile recommendations:** `vps` and `docker-host` enable this (`SYSCTL_DISABLE_CORE_DUMPS=yes`). `homelab` disables it (`SYSCTL_DISABLE_CORE_DUMPS=no`) to allow local debugging with GDB or LLDB.

---

### Module 02 — User Management

#### Threat: Password-based brute force against local login and sudo

**Attack surface:** Default Linux installations allow weak passwords and have no account lockout policy. An attacker with console access (or access to the tty via a misconfigured container) can attempt unlimited password guesses.

**Controls applied:**
- `libpam-pwquality` enforces: minimum 14 characters, at least one digit, one uppercase, one lowercase, one special character, minimum three character classes, maximum three consecutive identical characters, dictionary check enabled, username rejection.
- `libpam-faillock` configured via `pam_faillock.so`: 5 failures in the observation window trigger a 15-minute (`unlock_time=900`) account lockout. Applied as `preauth` (silent, before password check) and `authfail` (after failure) to catch both guessing and enumeration.
- `/etc/login.defs`: `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 14`, `ENCRYPT_METHOD SHA512`, `SHA_CRYPT_MIN_ROUNDS 5000`. SHA-512 with 5000 rounds increases the cost of offline dictionary attacks on `/etc/shadow` by roughly 5x over the default 1000 rounds.
- `LOGIN_RETRIES 5`, `LOGIN_TIMEOUT 60`.

**Tradeoffs:** The 14-character minimum will force password resets for any existing accounts with shorter passwords when the policy is applied. The 90-day expiry is a compliance requirement that has mixed security research support — forced rotation can lead to weaker passwords (incrementing a number). Operators who find this disruptive may increase `PASS_MAX_DAYS` or set it to `99999` to disable expiry while keeping strength requirements.

**Profile recommendations:** `vps` and `docker-host` (via the `users` module). `homelab` omits the users module — password policy is managed manually.

---

#### Threat: Privilege escalation via direct root login

**Attack surface:** A root account with an active password is a high-value target: compromising it gives the attacker immediate, unconditional system control with no audit trail linking actions to a named user.

**Controls applied:**
- `passwd -l root` locks the root password entry, preventing password-based root login from any interface.
- Root shell is changed to `/usr/sbin/nologin`, blocking interactive root sessions even with a valid key.
- `/etc/securetty` is emptied, disabling all direct TTY root logins.
- `PermitRootLogin no` in sshd_config ensures the SSH daemon refuses root logins at the protocol level, before PAM is consulted.
- The admin user gains `sudo` access — all privileged operations go through the audit trail of `sudo`.

**Tradeoffs:** If the admin account is locked or its SSH key is lost, the operator must use the VPS provider's emergency console (KVM/VNC) to recover access. This is the intended recovery path. The `nologin` shell means `sudo su -` also fails — `sudo -i` or `sudo bash` must be used instead.

**Profile recommendations:** All profiles that include the `users` module (`vps`, `docker-host`).

---

#### Threat: New files created with world-readable permissions exposing sensitive data

**Attack surface:** The default Linux umask is `022`, meaning new files are created as `644` (world-readable) and directories as `755` (world-executable). Scripts, configuration files, and log files containing credentials or private data written by root or the admin user are readable by any local user.

**Controls applied:**
- Umask set to `027` via `/etc/profile.d/99-secure-umask.sh` and `/etc/login.defs`. New files are created as `640` (owner read/write, group read, others nothing); directories as `750`.

**Tradeoffs:** Applications that expect to share files with other users via world-readable permissions will be broken. `vps.conf` and `docker-host.conf` use `027`; `homelab.conf` uses `022` because home services often need to share files across multiple local user accounts.

**Profile recommendations:** `vps` and `docker-host` use `027`. `homelab` uses `022`.

---

### Module 03 — SSH Hardening

#### Threat: Brute-force credential attacks against sshd

**Attack surface:** SSH port 22 is scanned continuously by automated botnets. Shodan data consistently shows that any host with port 22 open receives authentication attempts within minutes of provisioning. Default sshd allows unlimited authentication attempts per connection and does not enforce key-only auth.

**Controls applied:**
- `MaxAuthTries 3`: after 3 failed authentication attempts in a single connection, the connection is dropped. Combined with fail2ban's SSH jail (which bans after 3 failures across connections), this creates two independent throttling layers.
- `PasswordAuthentication no` (when an SSH key has been configured): password-based login is disabled entirely. Brute-force attacks against a key-only sshd have no effective attack surface — the private key is never sent to the server and cannot be guessed by network access alone.
- `MaxStartups 10:30:60`: limits concurrent unauthenticated connections. After 10 unauthenticated connections exist simultaneously, 30% of new connections are dropped; after 60, all new connections are rejected. This limits the parallelism of automated scanners.
- `LoginGraceTime 30`: unauthenticated connections are dropped after 30 seconds, freeing sshd slots held by slow or malicious clients.
- Custom SSH port (default 2222): reduces the volume of automated scanner noise. This is not a security control — a port scan will find it — but it reduces log volume significantly, making genuine attacks easier to detect.

**Tradeoffs:** `PasswordAuthentication no` is only applied when the users module has confirmed an SSH key is present. The module performs a safety check (`get_state "admin_ssh_key_set"`) before applying this setting, precisely to avoid lockout. Users without keys keep password auth enabled with a warning logged. The non-standard port breaks SSH clients that assume port 22; operators must use `ssh -p <port>` or configure `~/.ssh/config`.

**Profile recommendations:** All three profiles. `vps` and `docker-host` enforce `SSH_PASSWORD_AUTH=no` and `SSH_MAX_AUTH_TRIES=3`. `homelab` uses `SSH_MAX_AUTH_TRIES=5` to reduce self-lockout during configuration.

---

#### Threat: Weak cipher exploitation (BEAST, SWEET32, Lucky13, RC4 bias)

**Attack surface:** Older OpenSSH defaults permit CBC-mode ciphers (vulnerable to Lucky13 padding oracle attacks), 3DES (vulnerable to SWEET32 birthday attacks over long sessions), and HMAC-MD5/SHA1 MACs. An on-path attacker who can observe enough ciphertext can recover session plaintext in some configurations.

**Controls applied:**
- `KexAlgorithms`: restricted to `curve25519-sha256` variants and `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`. DH groups 14 and 15 (2048-bit) are excluded; minimum is 4096-bit for classical DH, or Curve25519 (equivalent to ~3000-bit security).
- `HostKeyAlgorithms`: `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`. DSA and ECDSA host keys are removed from disk. Legacy `ssh-rsa` (SHA-1 signed) is excluded.
- `Ciphers`: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, then CTR-mode AES. All CBC-mode ciphers are excluded.
- `MACs`: only ETM (encrypt-then-MAC) variants: `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `umac-128-etm`. ETM MACs are not vulnerable to Lucky13 because the MAC is computed over the ciphertext, not the plaintext.
- `/etc/ssh/moduli` is filtered to remove Diffie-Hellman moduli smaller than 3072 bits. Logjam-style precomputation attacks on small DH groups (1024-bit) are practical with nation-state resources.
- Weak DSA and ECDSA P-256/P-384 host keys are deleted and replaced with ed25519 (when absent) and RSA-4096.

**Tradeoffs:** Clients running OpenSSH older than 6.5 (2014) cannot connect. This includes some embedded systems, old macOS versions, and legacy CI/CD infrastructure. PuTTY users need version 0.68 or later. Any network appliance using ssh with default settings from a 2012-era firmware may also be incompatible. For a modern server this is entirely acceptable.

**Profile recommendations:** All profiles. Cipher hardening does not affect functionality for any supported client.

---

#### Threat: Lateral movement and pivoting via SSH forwarding

**Attack surface:** `AllowTcpForwarding yes` allows an authenticated SSH user to open arbitrary TCP tunnels through the server to any host reachable from it. An attacker who compromises one machine and gains SSH access to a hardened server can use it as a pivot to reach internal services that are not directly internet-accessible. `AllowAgentForwarding yes` allows the client's SSH agent to be forwarded to the server — if the server is compromised, the attacker can use in-memory private keys from the forwarded agent to authenticate to other systems without ever possessing the key material.

**Controls applied:**
- `AllowAgentForwarding no` on all profiles except `homelab`.
- `AllowTcpForwarding no` on `vps` and `docker-host` (default in `_ssh_write_config`). The module explicitly offers to enable it in non-HARDCORE_MODE with a confirmation prompt — the operator must affirmatively choose to enable it.
- `X11Forwarding no`: X11 forwarding opens a bidirectional channel that can be used to inject keystrokes or read screen contents of other X11 clients on the server.
- `PermitTunnel no`: disables layer-3 VPN tunneling via SSH `tun` devices.
- `GatewayPorts no`: prevents forwarded ports from being bound on `0.0.0.0` (which would expose them to the internet); they are bound on `127.0.0.1` only.

**Tradeoffs:** `AllowTcpForwarding no` breaks legitimate use cases: developers who use SSH port forwarding to reach internal databases, monitoring stacks, or development services. The `homelab` profile explicitly re-enables both TCP and agent forwarding (`SSH_ALLOW_TCP_FORWARDING=yes`, `SSH_ALLOW_AGENT_FORWARDING=yes`) for this reason — on a trusted LAN, the risk model is different.

**Profile recommendations:** `vps` and `docker-host` disable forwarding entirely. `homelab` enables TCP and agent forwarding.

---

#### Threat: Environment variable injection via authorized_keys options

**Attack surface:** The `environment="VAR=value"` option in `authorized_keys` allows a connecting client to set arbitrary environment variables for their session. Combined with certain shell startup files or programs that respect `LD_PRELOAD`, `PYTHONPATH`, etc., this can be used for privilege escalation.

**Controls applied:**
- `PermitUserEnvironment no`: disables all environment variable injection via `authorized_keys`.
- `PermitUserRC no`: prevents execution of `~/.ssh/rc` at login, which could be used to run attacker-controlled code after authentication.
- `StrictModes yes`: sshd checks that `~/.ssh` and `authorized_keys` have correct ownership and permissions; world-writable files cause authentication to be rejected.

**Tradeoffs:** Minimal. Environment injection via `authorized_keys` is a rarely-used feature; most operators are unaware of it. `PermitUserRC no` may break some legacy deployment automation that relied on `.ssh/rc`.

**Profile recommendations:** All profiles.

---

### Module 04 — UFW Firewall

#### Threat: Unrestricted inbound connections to all listening services

**Attack surface:** A newly provisioned server with no firewall has every listening service (sshd, potentially nginx, docker-proxy ports, node-exporter, etc.) reachable from the internet. Docker's default behavior is particularly dangerous: it bypasses iptables INPUT rules and inserts rules into the DOCKER chain in the FORWARD chain, meaning `ufw deny` rules do not affect ports bound by containers.

**Controls applied:**
- Default policy: `deny incoming`, `allow outgoing`, `deny forward`. All inbound traffic is dropped unless explicitly allowed.
- SSH on the configured port is added as a `ufw limit` rule: this applies kernel-level rate limiting (`hashlimit` iptables module, 6 connections per 30 seconds per source IP) in addition to fail2ban. Two independent throttling layers.
- Monitoring ports (Grafana, Prometheus, Node Exporter, cAdvisor, Loki, Promtail) are restricted to `127.0.0.1` and Docker bridge networks (`172.16.0.0/12`). These services have no authentication by default (or weak default credentials) and must not be internet-facing.
- Docker-UFW compatibility: rules are written to `/etc/ufw/after.rules` targeting the `DOCKER-USER` chain. The `DOCKER-USER` chain is evaluated before Docker's own `DOCKER` chain in the FORWARD hook, allowing UFW to enforce rules on traffic destined for containers. Without this, Docker's iptables rules allow any source to reach published container ports, bypassing the UFW INPUT chain entirely.

**Tradeoffs:** UFW's Docker compatibility block adds complexity to `/etc/ufw/after.rules`. If Docker's internal network range changes (e.g., a custom bridge CIDR), the rules may need updating. The `deny forward` default breaks container networking until the Docker-UFW block is applied — the module applies them in the correct order (reset, defaults, SSH, services, Docker compat, enable) to avoid a window where networking is broken.

A temporary rule for port 22 is added during configuration (in case the operator configured a non-22 SSH port) and flagged with a comment for manual removal. This is an acceptable tradeoff against the risk of self-lockout.

**Profile recommendations:** All profiles. `vps` opens only the SSH port. `docker-host` adds 80/443 for the reverse proxy. `homelab` adds 8080 and 3000 for common development services.

---

### Module 05 — Fail2Ban

#### Threat: SSH credential brute force from distributed sources

**Attack surface:** Automated credential stuffing and brute-force campaigns distribute their attempts across many source IPs and connections to stay under per-connection limits. `MaxAuthTries 3` in sshd stops per-connection attacks, but a botnet using 10,000 IPs each making one attempt is not caught by sshd alone.

**Controls applied:**
- `[sshd]` jail: monitors the systemd journal (via `backend = systemd`) for authentication failures. After 3 failures (`maxretry = 3`) within 300 seconds (`findtime = 300`), the source IP is banned for 7200 seconds (2 hours) via an iptables DROP rule (`banaction = iptables-multiport`).
- Custom `sshd-enhanced` filter at `/etc/fail2ban/filter.d/sshd-enhanced.conf`: catches 20+ distinct sshd failure patterns including PAM authentication failures, invalid user attempts, maximum authentication attempts exceeded, `preauth` disconnects (typical of scanner probes), and `pam_unix` failures. The default sshd filter misses several of these.
- `[recidive]` jail: reads fail2ban's own log. An IP that triggers 3 bans within any 12-hour window is banned for 1 week (604800 seconds). This catches persistent attackers who wait for the 2-hour ban to expire and immediately resume.
- `[nginx-http-auth]`, `[nginx-limit-req]`, `[nginx-botsearch]` jails: conditionally enabled when nginx is detected. `nginx-botsearch` bans after 2 hits and holds the ban for 24 hours — web scanners (DirBuster, Nikto, gobuster) are extremely noisy and their IPs should be banned aggressively.

**Tradeoffs:** The `recidive` jail reads `/var/log/fail2ban.log`. If fail2ban is restarted (e.g., during an upgrade), previously recorded bans are not automatically reloaded into the recidive counters. Persistent ban state requires the `dbpurgeage` database feature, which is not enabled by default to keep the configuration simple.

Fail2ban uses iptables `INPUT` chain rules. Docker-exposed ports are in the FORWARD chain and are not covered by fail2ban's SSH jail. CrowdSec's firewall bouncer (module 06) covers this gap for container-exposed services.

**Profile recommendations:** All profiles that include the `fail2ban` module (`vps`, `docker-host`, `homelab`). `homelab` relaxes ban thresholds to `maxretry = 5` and `bantime = 3600` to reduce self-lockout during home network configuration.

---

### Module 06 — CrowdSec

#### Threat: Attacks from IPs with known malicious history (botnets, Tor exit nodes, scanning infrastructure)

**Attack surface:** Fail2ban is reactive: it bans IPs after they have already attacked the local system. A significant proportion of inbound attacks originate from infrastructure that is already known to the security community — IPs that have attacked thousands of other systems before reaching this one. Fail2ban provides no protection against a first-attempt attack from such IPs.

**Controls applied:**
- CrowdSec agent continuously reads logs and applies detection scenarios from the threat intelligence hub. When an IP triggers a scenario (e.g., SSH brute force pattern detected), CrowdSec checks the community blocklist for that IP. If it has a known reputation score, it is banned before it can trigger fail2ban.
- `crowdsecurity/linux` collection: baseline detection for Linux systems (SSH, syslog, audit events).
- `crowdsecurity/sshd` collection: dedicated SSH attack detection scenarios, including distributed brute force (multiple IPs targeting the same account) and protocol anomalies.
- `crowdsecurity/linux-lpe` collection: local privilege escalation detection (sudo misuse, unusual setuid execution patterns observed in logs).
- `crowdsec-firewall-bouncer-iptables`: the bouncer receives ban decisions from the CrowdSec LAPI and writes iptables DROP rules. Unlike fail2ban which can only ban based on local log events, CrowdSec bans can be pushed from the community threat feed before the IP has ever touched this server.
- LAPI runs on a non-default port (6767 instead of 8080) to avoid conflicts with common web services and to reduce fingerprinting — a scanner looking for the default CrowdSec port will not find it.

**Tradeoffs:** CrowdSec requires network access to the CrowdSec Hub for collection updates and community blocklist synchronization. Environments without outbound internet (air-gapped systems) cannot use the community threat feed, though local-only detection still functions. The community blocklist also introduces a false-positive risk: a legitimate IP that was previously used for attacks may still be on the blocklist when it is now in use by an innocent party. CrowdSec's reputation scoring mitigates this but does not eliminate it.

The firewall bouncer manipulates iptables directly, independent of UFW. This creates two sources of firewall truth. In practice they do not conflict, but troubleshooting firewall rules requires checking both `ufw status` and `iptables -L` (or `ipset list` for CrowdSec's ipset-based bans).

**Profile recommendations:** `vps` and `docker-host`. `homelab` omits CrowdSec — the community blocklist is less relevant on a trusted LAN, and the false-positive risk of blocking a legitimate NAT gateway is higher in a home network context.

---

### Module 07 — Docker Hardening

#### Threat: Container escape via daemon misconfiguration

**Attack surface:** The Docker socket (`/var/run/docker.sock`) grants the ability to create containers with any Linux capabilities, mount the host filesystem, and load kernel modules. Access to the socket is equivalent to root on the host. By default, Docker CE enables several daemon features that increase the attack surface.

**Controls applied:**

**`no-new-privileges: true`** (daemon default): maps to the `PR_SET_NO_NEW_PRIVS` prctl flag on all container processes. Prevents processes inside containers from gaining additional capabilities via setuid binaries or file capabilities. A container running a web server that has a vulnerability allowing it to invoke a setuid binary cannot use that binary to escalate to root inside the container.

**`icc: false`** (inter-container communication disabled): by default, all Docker containers on the same bridge network can communicate freely with each other. Disabling ICC means containers on `docker0` must explicitly publish ports to reach each other. This enforces network segmentation: a compromised container cannot reach other containers on the default network. Containers on user-defined networks (like the monitoring network) still communicate freely with each other, but are isolated from containers on different networks.

**`userland-proxy: false`**: Docker's default behavior uses a `docker-proxy` process running as root to handle port forwarding for published ports. Setting this to false uses iptables `DNAT` rules directly (hairpin NAT), eliminating the userland proxy process. This removes a root-owned process from the attack surface and improves performance.

**`live-restore: true`**: containers continue running when the Docker daemon is restarted (for upgrades or configuration changes). This prevents service interruption during daemon updates but also means a compromised container continues running even after the daemon is stopped for maintenance — operators should be aware of this.

**`log-driver: json-file` with `max-size: 10m`, `max-file: 3`**: without log rotation, long-running container logs fill the disk. A disk-full condition causes container failures, kernel OOM events, and can silence security tools that write to disk. The 30 MB ceiling (3 × 10 MB) is conservative; adjust for high-traffic services.

**`metrics-addr: 127.0.0.1:9323`**: Docker daemon metrics are exposed for Prometheus scraping, bound to localhost only.

**`storage-driver: overlay2`**: the default and recommended driver. Avoids the deprecated `aufs` and `devicemapper` drivers which have known security issues with privileged container operations.

**Threat: docker group membership as privilege escalation**

Any user in the `docker` group can run `docker run --rm -v /:/host ubuntu chroot /host bash` and obtain a root shell on the host. The docker module adds only the configured admin user to the docker group and logs a warning that group membership is equivalent to root access.

**Threat: Docker's iptables bypass of UFW**

Docker inserts rules directly into the `FORWARD` chain's `DOCKER` subchain, bypassing UFW's `INPUT`-chain rules. A container publishing port 8080 with `0.0.0.0:8080:8080` is reachable from the internet regardless of `ufw deny 8080`. The firewall module addresses this with `DOCKER-USER` chain rules in `/etc/ufw/after.rules` (see module 04).

**Tradeoffs:** `icc: false` breaks applications that rely on containers communicating on the default `docker0` bridge. The correct fix is to place communicating containers on a named user-defined network (where they can reach each other by service name). `no-new-privileges` can break containers that legitimately need to run setuid binaries (e.g., certain ping implementations, some authentication helpers). These containers must be run with `--security-opt no-new-privileges=false` explicitly.

**Profile recommendations:** `docker-host` only. `vps` and `homelab` do not install Docker (`DOCKER_ENABLED=no`).

---

### Module 08 — Monitoring Stack

#### Threat: Undetected compromise due to lack of visibility

**Attack surface:** Without centralized metrics and log aggregation, an attacker who achieves initial access can operate undetected for extended periods. The average dwell time before detection on compromised servers without monitoring is measured in months.

**Controls applied:**
- **Node Exporter** exposes host system metrics (CPU, memory, disk, network, filesystem). Prometheus alert `UnusualNetworkConnections` fires when TCP established connections exceed 500 — a possible indicator of a botnet C2 beaconing or a mass scanning tool running on the host.
- **cAdvisor** exposes per-container resource metrics. `ContainerKilled` alert fires when a container disappears unexpectedly. `ContainerHighCPU` fires at 80% for 5 minutes — cryptominer infections exhibit exactly this pattern.
- **Loki + Promtail**: `/var/log/auth.log` is scraped and shipped to Loki with extracted labels for `process` (sshd, sudo, pam), `jail` (fail2ban), and `action` (Ban/Unban). Grafana logs panel provides real-time SSH failure and sudo escalation visibility.
- **Prometheus security alerts**: `DiskSpaceLow` (below 10%) catches disk-exhaustion attacks or log injection flooding. `InstanceDown` (2-minute window) catches processes killed by an attacker or OOM killer.
- Custom security dashboard: "Active Fail2Ban Bans" and "SSH Login Failures (last hour)" panels provide at-a-glance attack activity without log parsing.

**Threat: Monitoring infrastructure itself as attack surface**

Grafana, Prometheus, Loki, and Node Exporter have all had authenticated and unauthenticated CVEs (Grafana SSRF CVE-2020-13379, Prometheus unauthenticated metrics scrape leading to infrastructure enumeration, Loki log injection, Node Exporter path traversal on older versions).

**Controls applied:**
- All monitoring ports except Grafana are bound to `127.0.0.1` only. Prometheus, Node Exporter, cAdvisor, Loki, and Promtail are not directly reachable from the internet.
- Grafana is bound to `0.0.0.0` on its port (so the operator can access the dashboard) but is protected by authentication. `GF_AUTH_ANONYMOUS_ENABLED: false` and `GF_USERS_ALLOW_SIGN_UP: false`. A random 32-character `GF_SECURITY_SECRET_KEY` is generated per deployment.
- UFW restricts monitoring ports to `127.0.0.1` and Docker bridge network ranges (`172.16.0.0/12`).
- `GF_ANALYTICS_REPORTING_ENABLED: false` and `GF_ANALYTICS_CHECK_FOR_UPDATES: false` prevent Grafana from phoning home and leaking instance metadata to Grafana Labs.

**Tradeoffs:** Grafana exposed on `0.0.0.0` means it is reachable from the internet on its port unless UFW rules are correctly configured. The operator is responsible for either placing Grafana behind a reverse proxy with TLS and additional authentication, or restricting access via UFW to known management CIDRs. The monitoring stack requires Docker, creating a dependency between modules 07 and 08.

**Profile recommendations:** `docker-host` only (`MONITORING_ENABLED=yes`). `vps` and `homelab` do not deploy the monitoring stack by default.

---

### Sysctl — Network Hardening

#### Threat: SYN flood (TCP amplification denial of service)

**Attack surface:** A SYN flood fills the kernel's half-open connection queue (`tcp_max_syn_backlog`) by sending TCP SYN packets and never completing the three-way handshake. The queue fills, and legitimate connection attempts are dropped.

**Controls applied:**
- `net.ipv4.tcp_syncookies = 1`: when the SYN backlog is full, the kernel responds with a SYN-ACK containing a cryptographic cookie in the sequence number. No state is allocated until the client completes the handshake with the correct ACK. This defends against SYN floods that originate from spoofed IPs.
- `net.ipv4.tcp_max_syn_backlog = 2048`: increases the half-open queue, buying time before syncookies must activate.
- `net.ipv4.tcp_synack_retries = 2`: limits SYN-ACK retransmission to 2 attempts (default is 5), reducing the window during which half-open connections consume memory.

**Tradeoffs:** SYN cookies cause minor issues with some TCP options (window scaling, selective acknowledgement) in very specific network configurations. In practice, these issues are negligible on a server handling normal workloads.

---

#### Threat: ICMP redirect attack (routing table manipulation)

**Attack surface:** ICMP redirect messages instruct a host to update its routing table to use a different gateway for a specific destination. An on-path attacker can send spoofed ICMP redirects to cause the server to route traffic through an attacker-controlled host, enabling MITM attacks on unencrypted protocols.

**Controls applied:**
- `net.ipv4.conf.all.accept_redirects = 0`
- `net.ipv4.conf.default.accept_redirects = 0`
- `net.ipv6.conf.all.accept_redirects = 0`
- `net.ipv6.conf.default.accept_redirects = 0`
- `net.ipv4.conf.all.send_redirects = 0`: also disables the server from sending ICMP redirects, which would assist an attacker in mapping the network topology.

**Tradeoffs:** In a multi-homed environment with multiple gateways, ICMP redirects are a legitimate network optimization mechanism. On a single-NIC VPS, disabling them has no operational impact.

---

#### Threat: IP source routing attacks (strict source routing for traffic steering)

**Attack surface:** IPv4 source routing options allow the sender to specify the exact path a packet should take through the network. An attacker can use this to bypass firewall rules by routing packets through hosts that have trusted relationships with the target, or to probe internal network topology.

**Controls applied:**
- `net.ipv4.conf.all.accept_source_route = 0`
- `net.ipv4.conf.default.accept_source_route = 0`
- `net.ipv6.conf.all.accept_source_route = 0`

**Tradeoffs:** Source routing is not used on any modern production network. Disabling it has no operational impact.

---

#### Threat: IP spoofing via asymmetric routing (Reverse Path Filtering)

**Attack surface:** Without RPF, the kernel accepts packets whose source address does not match a route back through the receiving interface. An attacker can send packets with a spoofed source address (e.g., an internal management IP) to bypass IP-based access controls or to inject traffic into stateful sessions.

**Controls applied:**
- `net.ipv4.conf.all.rp_filter = 1` (strict mode): packets whose source address would not be routed back through the interface they arrived on are dropped. This catches most spoofing scenarios.

**Tradeoffs:** Strict RPF (`rp_filter = 1`) can drop legitimate traffic on asymmetrically routed networks (where packets take different paths in each direction). This is common in ECMP (equal-cost multipath) setups or with multiple ISP uplinks. On a single-NIC VPS, asymmetric routing does not occur. The `docker-host` profile enables `SYSCTL_IP_FORWARD=yes` and the sysctl already sets `net.ipv4.ip_forward = 1` — Docker containers use NAT (MASQUERADE), which is compatible with `rp_filter = 1`.

---

#### Threat: Smurf attack (ICMP broadcast amplification)

**Attack surface:** A Smurf attack sends ICMP echo requests to the broadcast address of a network with the victim's IP as the source address. All hosts on the network reply to the victim, amplifying the DoS.

**Controls applied:**
- `net.ipv4.icmp_echo_ignore_broadcasts = 1`: the kernel ignores ICMP echo requests sent to broadcast addresses.

**Tradeoffs:** None. No legitimate application requires a host to respond to broadcast pings.

---

#### Threat: IPv6 router advertisement hijacking

**Attack surface:** IPv6 SLAAC relies on router advertisement (RA) messages sent by routers. An attacker on the local network can send spoofed RA messages to redirect all IPv6 traffic through an attacker-controlled gateway (rogue RA attack, effectively IPv6 MITM).

**Controls applied:**
- `net.ipv6.conf.all.accept_ra = 0`
- `net.ipv6.conf.default.accept_ra = 0`

IPv6 is kept enabled (`net.ipv6.conf.all.disable_ipv6 = 0`) — disabling IPv6 does not remove the attack surface on modern kernels (the IPv6 stack is still active); it just prevents legitimate use while potentially causing unexpected behavior.

**Tradeoffs:** Disabling RA acceptance requires that IPv6 addresses be configured statically (via `/etc/network/interfaces` or `netplan`) rather than via SLAAC. On a VPS, the provider typically configures IPv6 addresses statically or via DHCPv6 — RA acceptance is not required. On a homelab behind an IPv6-capable router using SLAAC, this must be left enabled.

---

### Sysctl — Kernel Hardening

#### Threat: ptrace-based memory inspection (credential harvesting, process injection)

**Attack surface:** The `ptrace` syscall allows one process to inspect and modify the memory and registers of another process. Unprivileged users can use `ptrace` to attach to any process they own. An attacker who achieves code execution as any user (e.g., via a web application vulnerability) can use `ptrace` to inspect a running `sshd`, `sudo`, or authentication daemon process, extract plaintext credentials from memory, or inject shellcode.

**Controls applied:**
- `kernel.yama.ptrace_scope = 1`: restricts `ptrace` to processes with `CAP_SYS_PTRACE` or to parent processes of the target. A child process can be ptraced by its parent; an unrelated process cannot ptrace another unrelated process even if they share the same UID.

**Tradeoffs:** This breaks debuggers (`gdb`, `strace`, `ltrace`) when attaching to a running process that the user owns but did not start as a child of the debugger. Developers must use `sudo gdb -p <pid>`, `sudo strace -p <pid>`, or start the program under the debugger from the beginning. The `homelab` profile disables kernel hardening (`SYSCTL_KERNEL_HARDENING=no`) precisely because `ptrace_scope = 1` breaks VirtualBox (which needs to ptrace vbox kernel modules) and interactive debugger workflows.

---

#### Threat: Kernel pointer leaks enabling KASLR bypass

**Attack surface:** KASLR (Kernel Address Space Layout Randomization) randomizes the base address of kernel code and data structures at boot, making it harder for an attacker to target specific kernel structures in an exploit. However, if the kernel exposes its own virtual addresses through `/proc/kallsyms`, `/proc/kcore`, or `dmesg`, KASLR is bypassed trivially.

**Controls applied:**
- `kernel.kptr_restrict = 2`: kernel pointers printed via `%pK` in `/proc/kallsyms` and similar interfaces are replaced with zeros for all users, including root. Only processes with `CAP_SYSLOG` can see real pointers.
- `kernel.dmesg_restrict = 1`: `/proc/kmsg` and `dmesg` output are restricted to processes with `CAP_SYSLOG`. Unprivileged processes cannot read kernel messages that may include pointer values.
- `kernel.printk = 3 4 1 3`: limits kernel console message verbosity.

**Tradeoffs:** With `kptr_restrict = 2`, even root cannot read kernel symbol addresses from `/proc/kallsyms` without `CAP_SYSLOG`. Kernel debugging tools that rely on symbol addresses (`perf`, `SystemTap`, some eBPF programs) may require additional capabilities. On a production server, this is an acceptable restriction. `homelab` disables kernel hardening, relaxing these controls for development use.

---

#### Threat: Exploitation of predictable memory layout (ASLR bypass)

**Attack surface:** Without ASLR, executable and library base addresses are deterministic. Return-oriented programming (ROP) and heap spray attacks that depend on knowing fixed addresses become trivially constructable.

**Controls applied:**
- `kernel.randomize_va_space = 2`: full ASLR — randomizes stack, heap, mmap regions, and executable base addresses (requires PIE binaries). This is the maximum ASLR level available in the Linux kernel.

**Tradeoffs:** ASLR with `randomize_va_space = 2` reduces the address space available for per-process allocations on 32-bit systems, potentially causing mmap failures in memory-heavy applications. On 64-bit systems (all modern VPS environments), this is not a practical concern.

---

#### Threat: Magic SysRq key providing privileged console access

**Attack surface:** The SysRq key combination (`Alt+SysRq+<key>`) on a console provides direct kernel-level actions: killing all processes (`k`), unmounting filesystems (`u`), rebooting (`b`), and dumping memory (`m`). An attacker with physical or virtual console access (e.g., via a VPS provider's KVM console) can use this to bypass normal authentication.

**Controls applied:**
- `kernel.sysrq = 0`: disables all SysRq functions.

**Tradeoffs:** Disabling SysRq removes the ability to perform emergency recovery operations from the console (e.g., `SysRq+e` to kill all processes during a hang). VPS providers typically provide a separate emergency reboot mechanism in their control panel. On physical hardware without such a mechanism, disabling SysRq creates a higher risk of being unable to recover a hung system.

---

### Sysctl — Filesystem Hardening

#### Threat: Hard link TOCTOU attacks (privilege escalation via link following)

**Attack surface:** If a privileged process opens a file using a path that passes through a directory writable by an unprivileged user, an attacker can replace the file with a hard link to a privileged file between the path resolution and the open. The privileged process then operates on the attacker's target. This class of vulnerability affects many old setuid programs and some system daemons.

**Controls applied:**
- `fs.protected_hardlinks = 1`: the kernel refuses to create a hard link to a file that the calling process does not own, unless the process has `CAP_FOWNER`. Hard links can no longer be used to create references to files the attacker does not own.

**Tradeoffs:** None in practice. Hard linking to files the caller does not own is an unusual operation with no legitimate use case on a modern system.

---

#### Threat: /tmp symlink TOCTOU attacks

**Attack surface:** Programs that create temporary files with predictable names in world-writable directories (`/tmp`, `/var/tmp`) are vulnerable to symlink attacks: the attacker creates a symlink from the predictable filename to a sensitive target file before the program creates the file. When the program creates (and writes to) the file, it follows the symlink and overwrites the attacker's target.

**Controls applied:**
- `fs.protected_symlinks = 1`: the kernel refuses to follow a symlink in a world-writable sticky directory (like `/tmp`) if the symlink owner differs from the follower's UID and the directory owner's UID. This blocks the standard `/tmp` symlink race: even if the attacker creates the symlink first, the kernel will not follow it when a different UID attempts to create the file.

**Tradeoffs:** Some legacy software that relies on specific symlink behavior in `/tmp` may break. This is rare in modern software and the affected software typically has its own security vulnerabilities anyway.

---

#### Threat: setuid program core dump leaking sensitive data

**Controls applied:**
- `fs.suid_dumpable = 0`: setuid and setgid programs do not create core dumps. Prevents a crash in a privileged program (e.g., `sudo`, `su`) from writing a file containing sensitive memory to a world-readable location.

See also: Module 01 core dump controls (belt-and-suspenders with `limits.d`).

---

## Control Interaction Map

The following modules interact and must be applied in order:

```
users (02) ──────► ssh (03): admin_ssh_key_set state determines PasswordAuthentication
ssh (03) ────────► firewall (04): ssh_port state used for UFW rule
ssh (03) ────────► fail2ban (05): ssh_port state used for jail port
docker (07) ─────► firewall (04): DOCKER-USER chain rules depend on Docker being installed
docker (07) ─────► monitoring (08): monitoring stack requires Docker
sysctl (in 01) ──► docker (07): ip_forward = 1 required for Docker bridge networking
```

The `install.sh` orchestrator enforces module execution order and propagates state between modules via the state file (`/var/lib/vps-hardening/state.json` or equivalent). Running modules out of order or in isolation may produce a misconfigured system.

---

## Out of Scope

The following threats are explicitly not addressed by this framework:

- **Physical access attacks**: an attacker with physical access to the hardware can bypass all software controls via cold boot attack, JTAG debugging, or boot media substitution. Physical security is an operational concern.
- **Supply chain compromise of base system packages**: this framework trusts the Ubuntu/Debian APT infrastructure. Compromised upstream packages are not mitigated.
- **Zero-day vulnerabilities in kernel or OpenSSH**: no software-based hardening fully mitigates an unpatched zero-day. The combination of automatic updates, ASLR, and the principle of least privilege reduces exploitability but does not eliminate it.
- **Application-layer attacks against deployed services**: if the operator deploys a web application with SQL injection vulnerabilities, this framework does not protect the application itself. It limits the blast radius by restricting what a compromised web application process can do on the host.
- **Insider threats from users with sudo access**: the admin user created by this framework has full sudo access. An insider with this credential can bypass all controls. Privileged access management (PAM solutions, just-in-time access, session recording) is beyond the scope of this framework.
