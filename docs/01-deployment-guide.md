# 01 — Deployment Guide: Step-by-Step

Takes about 1.5–2 hours. Every command is copy-paste. Lines starting with `#` are comments.

```
 Internet attackers
        │ TCP 22 (SSH), 23 (Telnet)
        ▼
┌──────────────────── DigitalOcean Cloud Firewall ────────────────────┐
│ allow 22, 23 from anywhere · allow 22222 from YOUR IP only          │
└──────────────────────────────┬──────────────────────────────────────┘
┌──────────────── Droplet: Ubuntu 24.04, 1 GB, $6/mo ─────────────────┐
│  Docker: cowrie  (22→2222, 23→2223, read-only, no capabilities)     │
│  Real SSH: port 22222, key-only, user hpadmin                       │
│  honeypot-alerter (systemd) ──────────────► Telegram                │
│  cron: healthcheck / daily digest ────────► Telegram                │
│  Filebeat ──── HTTPS + API key ───────────► Elastic Cloud (Kibana)  │
│  Python: enrich_iocs / attack_mapper / export_iocs ──► VT, AbuseIPDB│
└─────────────────────────────────────────────────────────────────────┘
```

> **Ethics and safety rules for the whole project**
> - Only watch and record. Never attack back ("hack back") or scan the attackers' IPs.
> - **Never run** captured malware. Only hash it, look it up, and inspect it statically (`file`, `strings`, `yara`).
> - Don't download malware samples to your own laptop: your antivirus will flag them and it's risky.
> - Delete the droplet when you're done.

---

## Step 0 — Before you start (on your own computer)

**0.1 Create an SSH key** if you don't have one. On Windows use PowerShell; on Mac/Linux use Terminal:
```bash
ssh-keygen -t ed25519 -C "honeypot-admin"
```
Press Enter to accept the default path and **set a passphrase**. Your public key is in `~/.ssh/id_ed25519.pub`.

**0.2 Find your home public IP**: open https://ifconfig.me. You'll need it for the firewall.
> If your home IP changes often (dynamic IP), that's OK. If you ever get locked out, use the **DigitalOcean web console** (Droplet → Access → Launch Droplet Console), which bypasses the firewall.

**0.3 Accounts you'll need:**

| Account | Why | Cost |
|---|---|---|
| DigitalOcean | Droplet | $6/mo. New accounts often get free credit, as does the GitHub Student Pack. |
| GitHub | Your portfolio repo | Free |
| Telegram | Alerts | Free |
| Elastic Cloud | Kibana dashboards (do this on day ~3, see doc 03) | 14-day free trial |
| VirusTotal | Malware hash lookups | Free API key |
| AbuseIPDB | IP reputation | Free API key |
| GreyNoise | "Is this a mass scanner?" | Free community key (optional) |

**0.4 Push this repo to your GitHub** (public is fine, since `.env` and `data/` are git-ignored).

---

## Step 1 — Create the droplet

DigitalOcean → **Create → Droplets**:

| Setting | Value |
|---|---|
| Region | Any. Frankfurt/Amsterdam/Singapore/NYC all get attacked within minutes. Write down which one you chose: it's part of your methodology. |
| Image | **Ubuntu 24.04 (LTS) x64** |
| Size | Basic → Regular → **$6/mo (1 GB / 1 CPU / 25 GB SSD)** |
| Authentication | **SSH Key** → New SSH Key → paste the contents of `id_ed25519.pub` |
| Hostname | Something boring that looks real, e.g. `web-prod-02` (don't call it "honeypot") |
| Monitoring | ✅ enable (free graphs plus CPU/disk alerts) |
| Backups | ❌ off |

Write down the droplet's **public IPv4**. Below it's written as `DROPLET_IP`.

**Billing alert**: Settings → Billing → **Billing alerts** → set **$10**.

---

## Step 2 — Create the Cloud Firewall

Networking → **Firewalls** → Create Firewall → name `honeypot-fw`

**Inbound rules:**

| Type | Protocol | Port | Sources |
|---|---|---|---|
| SSH | TCP | 22 | All IPv4, All IPv6 |
| Custom | TCP | 23 | All IPv4, All IPv6 |
| Custom | TCP | 22222 | **Your home IP only** (from step 0.2) |

**Outbound:** keep the defaults (all allowed). Cowrie needs outbound HTTP to capture the malware attackers download.

**Apply to Droplets:** select your droplet → Create.

> Why do it at the network level? Docker-published ports **bypass UFW** on the host, so a host firewall alone would give you a false sense of security. The DO Cloud Firewall filters before traffic ever reaches the VM.

---

## Step 3 — First login and an admin user

From your computer:
```bash
ssh root@DROPLET_IP
```

Then on the droplet, update and create a non-root admin user:

```bash
apt update && apt -y full-upgrade
```

```bash
adduser hpadmin
```

```bash
usermod -aG sudo hpadmin
```

```bash
rsync --archive --chown=hpadmin:hpadmin ~/.ssh /home/hpadmin
```

If the upgrade installed a new kernel, reboot (`reboot`) and SSH back in.

---

## Step 4 — Move the real SSH to port 22222 ⚠️ the important part

**Keep this SSH window open** until you've tested the new port in a **second** window. That's your safety net.

**4.1 Create the config file.** It must be named `00-...`: sshd uses the **first** value it reads, and DigitalOcean's `50-cloud-init.conf` would otherwise override your settings.
```bash
cat > /etc/ssh/sshd_config.d/00-honeypot.conf <<'EOF'
Port 22222
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers hpadmin
MaxAuthTries 3
EOF
```

**4.2 Check the config.** The first command must print nothing; the second must show your new settings:
```bash
sshd -t
```

```bash
sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication) '
```
Expected output:
```
port 22222
permitrootlogin no
passwordauthentication no
```

**4.3 Turn off socket activation.** On Ubuntu 24.04, `ssh.socket` would keep listening on port 22 and ignore your `Port` setting:
```bash
systemctl disable --now ssh.socket
```

```bash
systemctl enable ssh.service
```

```bash
systemctl restart ssh.service
```

```bash
ss -ltnp | grep sshd
```
You should see `0.0.0.0:22222`, and **not** `:22`.

**4.4 In a NEW terminal on your computer, test it:**
```bash
ssh -p 22222 hpadmin@DROPLET_IP
```

```bash
sudo whoami
```
That should print `root`. Only now close the old root session. From here on, always connect with:
```bash
ssh -p 22222 hpadmin@DROPLET_IP
```

> Tip: add this to `~/.ssh/config` on your computer, then just type `ssh honeypot-admin`:
> ```
> Host honeypot-admin
>     HostName DROPLET_IP
>     Port 22222
>     User hpadmin
> ```

---

## Step 5 — Get the project onto the droplet

```bash
sudo git clone https://github.com/<your-github-username>/honeypot-threat-intel.git /opt/honeypot
```

```bash
cd /opt/honeypot
```

```bash
sudo cp .env.example .env
```

```bash
sudo chmod 600 .env
```

Now set up the **Telegram bot**: follow **[02-telegram-bot-setup.md](02-telegram-bot-setup.md)**, steps 1–5.

Then fill in the rest of `.env`:

```bash
sudo nano .env
```

- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`: from the Telegram guide.
- `VT_API_KEY`: virustotal.com → sign up → profile icon → **API key**.
- `ABUSEIPDB_API_KEY`: abuseipdb.com → sign up → Account → **API** → Create Key.
- `GREYNOISE_API_KEY`: optional. viz.greynoise.io → sign up → Account → API key.
- `OWN_IPS`: **your home IP**, so your own test logins don't end up in the statistics.

---

## Step 6 — Install and start everything

```bash
sudo bash infra/install.sh
```

This script:
- installs Docker, YARA and jq
- adds 1 GB of swap
- creates the data folders (owned by UID 999, Cowrie's user)
- starts Cowrie
- applies the egress firewall (`infra/egress-firewall.sh`), which blocks the container from SMTP, private networks and the DO metadata service
- starts the Telegram alerter service
- installs the cron jobs

---

## Step 7 — Check that it works

**On the droplet:**

```bash
sudo docker ps
```
The `cowrie` container should show `Up ...`.

```bash
sudo ss -ltnp | grep -E ':(22|23|22222)\s'
```
`docker-proxy` should be on 22 and 23, and `sshd` on 22222.

```bash
sudo systemctl status honeypot-alerter --no-pager
```

```bash
sudo python3 scripts/healthcheck.py --print
```
That should print `all OK`. Log freshness may complain for the first few minutes.

```bash
sudo python3 scripts/healthcheck.py --test
```
That sends a Telegram test message.

**Be an attacker yourself (from your computer):**
```bash
ssh root@DROPLET_IP
```
- Type any password except `root` or `123456` (Cowrie's default users file accepts the rest).
- You're now in the **fake** shell. Try `uname -a`, `whoami`, `cat /etc/passwd`.
- Then type `echo test >> ~/.ssh/authorized_keys`.
- Then `exit`.

> Your own IP is in `OWN_IPS`, so you won't get a Telegram alert for this. To see an alert, temporarily remove your IP from `OWN_IPS` and run `sudo systemctl restart honeypot-alerter`. Remember to put it back afterwards.
>
> Your computer will warn that the host key for `DROPLET_IP` changed between port 22 and 22222. That's expected: they are two different SSH servers.

**Watch real attackers arrive** (usually within minutes):
```bash
sudo tail -f data/cowrie/log/cowrie.json | jq -c '{t:.timestamp, ip:.src_ip, e:.eventid, u:.username, p:.password, cmd:.input}'
```
Press Ctrl+C to stop.

---

## Step 8 — The 14-day plan

| Day | Action |
|---|---|
| 0 | Steps 1–7. Take screenshots of each step for your README. |
| 1 | Check the first Telegram digest. Look at `data/cowrie/log/` and get to know the event types. |
| **3** | **Start the Elastic Cloud trial and set up Filebeat ([03-elastic-cloud-setup.md](03-elastic-cloud-setup.md)).** Filebeat sends days 0–3 automatically, so nothing is lost, and the trial lasts until day ~17, which leaves time for analysis after capture ends. |
| 3–4 | Build the Kibana dashboard |
| 7 | Mid-point: run `enrich_iocs.py` and `attack_mapper.py` ([04-analysis-and-detections.md](04-analysis-and-detections.md)). Write down any interesting sessions. |
| 7–14 | Write and test the Sigma/YARA rules, run YARA on the downloads, and start the report |
| 14 | Stop capture. Run the final enrichment and exports, export the Kibana dashboard, and take screenshots. |
| 15–17 | Finish the report and README. Tear down ([05-teardown.md](05-teardown.md)). |

**Daily 2-minute check** (or just trust the Telegram health alerts):

```bash
df -h /
```

```bash
sudo docker ps
```

```bash
ls -lh /opt/honeypot/data/cowrie/log/
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Connection refused` on 22222 | Check `ss -ltnp \| grep sshd`. If sshd is still on 22, `ssh.socket` is active: redo step 4.3. Locked out? Use the DO web console. |
| `docker compose up` fails: `port 22 already in use` | The real sshd is still on 22: do step 4. |
| Cowrie restarts in a loop | Run `sudo docker logs cowrie`. A permission error means you need `sudo chown -R 999:999 /opt/honeypot/data/cowrie`. |
| No events in `cowrie.json` | Check that the cloud firewall allows TCP 22 from all and is applied to the droplet. Test with `ssh root@DROPLET_IP` from your phone's hotspot. |
| Disk filling up | Run `sudo du -sh /opt/honeypot/data/cowrie/*`. The cron job gzips old logs, and you can also run `sudo docker system prune`. |
| Alerter not sending | Run `sudo journalctl -u honeypot-alerter -n 50`, and check `.env` with `healthcheck.py --test`. |
