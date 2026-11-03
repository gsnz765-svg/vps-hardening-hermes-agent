# Hardening a Cloud-Hosted AI Agent: VPS Security Report

**Author:** Gabriela Sanchez Ramirez
**Date:** November 3, 2026
**Environment:** Ubuntu 24.04 LTS VPS (Hostinger) running Hermes Agent (Nous Research) in Docker behind Traefik

> All IP addresses belonging to the author are shown as `x.x.x.x`. No credentials, API keys or tokens appear in this report.

---

## Summary

I hardened a public-facing VPS that hosts a self-improving AI agent with access to API credits and personal data. During the work I found that the agent's admin dashboard was **exposed to the internet over unencrypted HTTP**, even though the host firewall did not allow its port. The cause was **Docker publishing the container port and bypassing ufw**.

I bound the dashboard to localhost, moved access to an **SSH tunnel**, rotated the dashboard credential, and verified the fix with a full external **Nmap** scan. I also locked down SSH, enabled fail2ban and automatic updates, and reviewed the agent's own security settings.

| Area | Before | After |
|---|---|---|
| SSH authentication | Root login with password | Key-only, root disabled, named sudo user |
| Host firewall | None | ufw default-deny; only 22, 80, 443 |
| Brute-force protection | None | fail2ban on SSH (5 tries, 1h ban) |
| Patching | Manual | `unattended-upgrades` enabled |
| Agent dashboard | Public on `0.0.0.0:32768` over HTTP | `127.0.0.1` only, reached via SSH tunnel |
| Dashboard credential | Original, possibly exposed | Rotated (24-byte random) |
| API spending | Uncapped | Credit limit on the agent's API key |

---

## Objective

1. Reduce the server's attack surface to only the services it needs.
2. Remove password-based and root access paths.
3. Make sure the AI agent cannot be reached or abused from the internet.
4. Verify every control from an attacker's point of view, not just from configuration files.

## Environment

| Component | Details |
|---|---|
| Host | Hostinger VPS, Ubuntu 24.04.5 LTS, kernel 6.8 |
| Admin workstation | Windows 11, OpenSSH client, PowerShell |
| Containers | `hermes-agent` (agent + web dashboard), `traefik` (reverse proxy) |
| Agent data | Single bind mount: `/docker/hermes-agent-hraf/data` → `/opt/data` |
| Model provider | OpenRouter (API key with credit limit) |

---

## Finding: Agent dashboard exposed over HTTP, bypassing the firewall

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Asset** | Hermes Agent admin dashboard |
| **Status** | Remediated and verified |
| **Related ATT&CK techniques** | T1595 Active Scanning, T1110 Brute Force, T1190 Exploit Public-Facing Application |

### What I found

After enabling ufw with only ports 22, 80 and 443 allowed, I listed the running containers:

```bash
sudo docker ps --format "table {{.Names}}\t{{.Ports}}"
```

```
NAMES                              PORTS
hermes-agent-hraf-hermes-agent-1   0.0.0.0:32768->4860/tcp, [::]:32768->4860/tcp
traefik-traefik-1
```

The agent's dashboard was published on **all interfaces** (`0.0.0.0` and `[::]`) on port 32768. Browsing to `http://x.x.x.x:32768` from my laptop loaded a login page marked **"Public bind · Auth required"** with a **"Not Secure"** warning.

### Why it happened

Docker writes its own iptables rules for published ports. Traffic to a container is redirected (NAT) and then **forwarded** to it, so it never passes through the INPUT rules that ufw manages. A container port can therefore be reachable even when `ufw status` doesn't list it. The firewall status looked correct while the port was still open.

### Why it mattered

- **Cleartext credentials:** the login form used plain HTTP, so the username and password crossed the internet unencrypted.
- **No brute-force protection:** fail2ban watched SSH, not this web login, so password guessing was unlimited.
- **High-value target:** the dashboard controls an agent with terminal access, stored API keys and personal data. A compromise would mean running commands in the container and spending the API balance.

Authentication on the page kept this from being critical, but the combination of public exposure, cleartext login and unlimited guessing made it a real risk.

### Remediation

1. **Bound the port to localhost** in `docker-compose.yml`:

   ```yaml
   ports:
     - "127.0.0.1:32768:4860"
   ```

   ```bash
   sudo docker compose up -d
   ```

2. **Moved access to an SSH tunnel** from the admin workstation. The dashboard is now only reachable by someone who already holds the SSH key:

   ```powershell
   ssh -L 4860:127.0.0.1:32768 gabi@x.x.x.x
   ```

   Then browse to `http://localhost:4860`. The HTTP traffic travels inside the encrypted SSH session.

3. **Rotated the dashboard credential**, since the old one had been sent over HTTP. The new value was generated on the server and set in the container's `.env` file:

   ```bash
   openssl rand -base64 24
   ```

### Verification

```bash
sudo docker ps --format "table {{.Names}}\t{{.Ports}}"
# hermes-agent-hraf-hermes-agent-1   127.0.0.1:32768->4860/tcp
```

A full external TCP scan from the admin workstation showed port 32768 is gone:

```
nmap -Pn -p- x.x.x.x

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
Not shown: 65532 filtered tcp ports (no-response)
```

---

## Additional hardening

### SSH

- Generated an **Ed25519 key pair** with a passphrase on the workstation.
- Created a named admin user (`gabi`) with sudo rights and installed the public key.
- Confirmed key-only login worked **before** disabling passwords, with a second session kept open as a fallback.
- Added a drop-in config. It is named `00-` so it loads **before** the provider's `50-cloud-init.conf`; in sshd, the first value read wins.

```bash
# /etc/ssh/sshd_config.d/00-hardening.conf
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
```

```bash
sudo sshd -t && sudo systemctl restart ssh
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication'
# permitrootlogin no
# passwordauthentication no
```

Test: `ssh root@x.x.x.x` → `Permission denied (publickey)`. No password prompt is offered.

### Firewall (ufw)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Rules apply to IPv4 and IPv6. Ports 80/443 stay open for Traefik.

### Fail2ban

```ini
# /etc/fail2ban/jail.local
[sshd]
enabled = true
backend = systemd
maxretry = 5
bantime = 1h
ignoreip = 127.0.0.1/8 ::1 169.254.0.1
```

### Automatic security updates

`unattended-upgrades` confirmed enabled (`/etc/apt/apt.conf.d/20auto-upgrades` set to `"1"`).

### Container review

| Check | Result |
|---|---|
| Privileged mode | `false` |
| Docker socket mounted | No (`/var/run/docker.sock` absent) |
| Host paths mounted | One data folder only; no `/` or `/root` |
| Published ports | `127.0.0.1` only after remediation |

### Agent configuration

| Setting | Value | Reason |
|---|---|---|
| Redact secrets | On | Keeps keys out of logs and chats |
| Redact PII | On | Limits personal data sent to the model provider |
| Allow private URLs | Off | Blocks SSRF toward internal addresses |
| Allow lazy installs | Off | Agent cannot install packages on its own |
| Adopt external logins | Off | Agent uses only its own credentials |
| Cron / unattended approvals | Most restrictive | Scheduled jobs cannot auto-approve risky commands |
| Terminal backend | Local (inside the container) | The Docker backend would require mounting the Docker socket |
| Env passthrough | Empty | Commands do not inherit secrets |
| Working directory | `/opt/data/workspace` | Keeps agent files apart from its config |
| API key | Credit limit set | Caps damage from a looping or hijacked agent |

---

## Threat evidence from the first day

Within hours of setup, the logs showed automated attacks. All were blocked.

**Failed SSH logins (7 days):** 6 attempts from 2 IPs in the same cloud provider range.

```bash
sudo journalctl -u ssh --since "7 days ago" | grep -oP 'Invalid user \K\S+' | sort | uniq -c | sort -rn
```

| Username tried | Attempts | Likely target |
|---|---|---|
| `solana` | 2 | Crypto validator nodes |
| `validator` | 1 | Crypto validator nodes |
| `sol` | 1 | Crypto validator nodes |
| `nvidia` | 1 | GPU servers |
| `erpnext` | 1 | ERP business software |

**Firewall drops:** ufw logged SYN probes to random high ports (for example 7148, 13244, 25140, 30005, 35664) over both IPv4 and IPv6, a pattern consistent with internet-wide port scanning.

**Result:** password login is disabled, so these attempts could not succeed regardless of the password guessed.

---

## Lessons learned

1. **"The firewall says it's closed" is not proof.** Docker bypassed ufw. Only an external scan showed the truth. Verify controls from the attacker's side.
2. **Security controls can block your own tools.** Fail2ban banned `169.254.0.1`, a link-local address used by the hosting provider's browser console, after root SSH was disabled. I unbanned it and added it to `ignoreip`. Controls need tuning after they are deployed.
3. **Hardening has tradeoffs.** Disabling root SSH also disabled the provider's root web console. The serial console still works as a break-glass path with the admin user's password.
4. **Test before you lock the door.** I confirmed key login in a second session before turning off passwords, which avoided a lockout.
5. **Config file order matters.** In sshd, the first value read wins, so the hardening file is named `00-` to load before the provider's defaults.
6. **Redact before you share.** During setup a credential was visible in a screenshot. Treating it as exposed, I rotated it. Screenshots and logs need the same care as config files.
7. **Least privilege applies to AI agents too.** The agent runs unprivileged, with one mount, no Docker socket, no package installs and a spending cap.

## Ongoing maintenance

| Cadence | Tasks |
|---|---|
| Weekly | Review fail2ban bans and failed logins; confirm the dashboard port is still bound to localhost; check API usage |
| Monthly | Patch manually as a backup to auto updates; re-run Nmap; re-check the compose port binding after any provider redeploy; review the API credit limit |

## Future work

- Enable the agent's **egress proxy** so the agent never holds real API keys in its own environment.
- Forward SSH, ufw and fail2ban logs into **Splunk** and build alerts for brute-force bursts and new listening ports.
- Map observed activity to **MITRE ATT&CK** in a short detection writeup.
