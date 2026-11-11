# 🍯 Honeypot Deployment & Threat Intelligence

> An internet-facing **Cowrie SSH/Telnet honeypot** on DigitalOcean that captures real attacker behaviour, ships the logs to **Elastic Cloud (ELK)**, enriches IOCs with **VirusTotal / AbuseIPDB / GreyNoise**, maps activity to **MITRE ATT&CK**, produces **Sigma/YARA detections** and a **STIX 2.1 IOC feed**, and sends real-time **Telegram alerts**.

**Skills shown:** cloud deployment and hardening · log pipelines / SIEM · threat intelligence and OSINT enrichment · malware triage · detection engineering · Python automation

---

## Results (14-day capture: `<start>` → `<end>`)

> Fill this in from `out/full_period_summary.txt`, `out/ip_report.csv` and Kibana.

| Metric | Value |
|---|---|
| Connections | `X` |
| Unique attacker IPs | `X` |
| Countries | `X` |
| Failed / successful logins | `X` / `X` |
| Commands executed in the fake shell | `X` |
| Unique malware samples | `X` (`X` unknown to VirusTotal) |
| ATT&CK techniques observed | `X` |
| IOCs exported (STIX 2.1) | `X` |
| Time to first attack | `X` minutes |

**Top 3 findings:** `<1>` · `<2>` · `<3>`

📄 **[Full threat intelligence report (PDF)](report/Threat_Intel_Report.pdf)**

<!-- screenshots: docs/images/dashboard.png, docs/images/attack-map.png, docs/images/navigator.png, docs/images/telegram.png -->

---

## Architecture

```
            Internet attackers (botnets, scanners)
                         │ TCP 22 / 23
                         ▼
   DigitalOcean Cloud Firewall  (22, 23 open · 22222 = admin IP only)
                         │
   ┌─────────── Droplet: Ubuntu 24.04 · 1 vCPU · 1 GB · $6/mo ───────────┐
   │ Docker ▸ Cowrie (read-only, no capabilities, egress-filtered)       │
   │          22→2222 SSH · 23→2223 Telnet · JSON logs + TTY + malware   │
   │ Real SSH ▸ port 22222, key-only, non-root                           │
   │ honeypot-alerter ▸ new malware / suspicious commands ──► Telegram   │
   │ cron ▸ health check (10 min) · daily digest ──────────► Telegram   │
   │ Filebeat ──────── TLS + API key ───────────► Elastic Cloud          │
   │ Python ▸ enrich_iocs · attack_mapper · export_iocs ─► VT/AbuseIPDB  │
   └─────────────────────────────────────────────────────────────────────┘
                                                    │
                       Elasticsearch ingest pipeline (GeoIP + ASN) → Kibana dashboards
```

## Repository layout

| Path | Contents |
|---|---|
| `docs/01-deployment-guide.md` | Step-by-step: droplet, firewall, SSH hardening, install, verification |
| `docs/02-telegram-bot-setup.md` | Creating the Telegram bot and testing alerts |
| `docs/03-elastic-cloud-setup.md` | Elastic Cloud trial, Filebeat, ingest pipeline, Kibana dashboard |
| `docs/04-analysis-and-detections.md` | Enrichment, ATT&CK mapping, IOC export, malware triage, detections |
| `docs/05-teardown.md` | Final run, exporting results, destroying resources |
| `infra/` | `docker-compose.yml`, `install.sh`, egress firewall, systemd units, cron |
| `elastic/` | `filebeat.yml`, ingest pipeline, (exported Kibana dashboard) |
| `scripts/` | Python (standard library only): alerter, digest, health check, enrichment, ATT&CK mapper, IOC export |
| `detections/` | 4 Sigma rules, 3 YARA rules |
| `iocs/` | `blocklist.txt`, `iocs.csv`, `iocs.stix.json` |
| `report/` | Report template, final PDF and result tables |
| `data/sample/` | Synthetic sample log for testing the scripts (no real data) |

## Quick start

On a fresh Ubuntu 24.04 droplet, **after** moving the real SSH to port 22222 (see the guide):

```bash
sudo git clone https://github.com/<you>/honeypot-threat-intel.git /opt/honeypot
```

```bash
cd /opt/honeypot
```

```bash
sudo cp .env.example .env
```

Fill in the Telegram token/chat ID, API keys and your own IP:

```bash
sudo nano .env
```

```bash
sudo bash infra/install.sh
```

```bash
sudo python3 scripts/healthcheck.py --test
```

Try the scripts on the sample data without a honeypot. Each one runs on its own:

```bash
python3 scripts/telegram_alerter.py --file data/sample/cowrie-sample.json --once --dry-run
```

```bash
python3 scripts/daily_digest.py --file data/sample/cowrie-sample.json --hours 0 --print
```

```bash
python3 scripts/enrich_iocs.py --file data/sample/cowrie-sample.json --offline
```

```bash
python3 scripts/attack_mapper.py --file data/sample/cowrie-sample.json
```

## Security design

| Risk | Control |
|---|---|
| Admin access hijacked | Real SSH on 22222, key-only, no root, allowed from the admin IP only (cloud firewall) |
| Docker bypasses UFW | Filtering happens at the DigitalOcean Cloud Firewall, in front of the VM |
| Honeypot abused to attack others | Cowrie only emulates a shell (never runs attacker code). Container is read-only with `cap_drop: ALL` and `no-new-privileges`. Egress rules block SMTP, private networks/VPC and the metadata service. |
| Disk fills up and data is lost | Download size limit, Docker log limits, gzip of old logs, disk/freshness health alerts on Telegram |
| Secrets leak | `.env` (mode 600, git-ignored), Filebeat keystore, systemd `DynamicUser` for the alerter |
| Malware handling | Static analysis only. Samples never leave the VPS and are destroyed with it. Only hashes are published. |
| Accidental clicks | All IOCs in alerts and reports are defanged (`hxxp://1[.]2[.]3[.]4`) |

## Lessons learned
`<fill in during the project: what broke, what surprised you, what you'd change>`

---
*Ethics: this project only records traffic that attackers send to a system they have no permission to access. No hack-back, scanning of attacker infrastructure, or malware execution was performed.*
