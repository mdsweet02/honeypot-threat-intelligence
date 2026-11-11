# 04 — Threat Intel Analysis, ATT&CK Mapping and Detections

Everything runs on the droplet with **plain Python 3**, with no `pip install` needed. Output goes to `out/` (reports) and `iocs/` (shareable feed).

Each step below starts from the project folder:

```bash
cd /opt/honeypot
```

---

## 1. IOC extraction + OSINT enrichment

```bash
sudo python3 scripts/enrich_iocs.py --top 100
```

What it does:
1. Reads **all** Cowrie logs, including the rotated and gzipped ones.
2. Extracts per-IP stats (connections, failed/successful logins, commands, downloads, SSH client, HASSH), file hashes, and download URLs.
3. Enriches:
   - the **top 100 most active IPs**: **AbuseIPDB** (abuse score, ISP, usage type) and **GreyNoise** (mass scanner? benign service?)
   - **every captured file hash**: **VirusTotal** (detections, malware family label)
4. Gives each IP a simple verdict: `known malicious` / `known mass scanner` / `previously reported` / `unknown / new` / `benign service`.
5. Caches every API answer in `out/enrichment_cache.sqlite`, so re-running it is free and fast.

Output:

| File | Use in report |
|---|---|
| `out/ip_report.csv` | Top attackers table, % of IPs already known as malicious, ISP/hosting breakdown |
| `out/malware_report.csv` | Malware table: hash, VT detections, family label |
| `out/url_report.csv` | Malware distribution servers (defanged) |

**Rate limits:** VirusTotal free allows 4 lookups/min, so the script waits 15 s between hashes. 100 hashes takes about 25 minutes, so run it in `tmux` or `screen`. Use `--offline` for a quick extract-only run.

> 💡 Interesting finding to look for: what **% of attacker IPs were NOT in AbuseIPDB/GreyNoise**? Those are IOCs *your* sensor found first, which is the whole value of running a honeypot.

**Optional:** upload `ip_report.csv` to Kibana (☰ → **Upload a file**) to make an "enriched attackers" table on your dashboard.

---

## 2. MITRE ATT&CK mapping

```bash
sudo python3 scripts/attack_mapper.py
```

It maps every login event and every command typed in the fake shell to ATT&CK techniques. The rules are in `scripts/common.py` → `COMMAND_RULES`, and you can add your own.

| Behaviour seen | Technique |
|---|---|
| Brute-force login attempts | T1110.001 Password Guessing |
| Login with default creds | T1078 Valid Accounts |
| `wget`/`curl`/`tftp` downloads | T1105 Ingress Tool Transfer |
| `sh -c`, piping into `sh`, `./file` | T1059.004 Unix Shell |
| Writing to `authorized_keys` | T1098.004 SSH Authorized Keys |
| `crontab` | T1053.003 Cron |
| `chattr`, `chmod +x/777` | T1222.002 File Permissions Modification |
| `history -c`, `unset HISTFILE` | T1070.003 Clear Command History |
| `xmrig`, `stratum+tcp` | T1496 Resource Hijacking |
| `uname`, `/proc/cpuinfo`, `free -m` | T1082 System Information Discovery |
| `whoami`, `id` | T1033 System Owner/User Discovery |
| `ps`, `top` | T1057 Process Discovery |
| `ifconfig`, `ip a` | T1016 Network Configuration Discovery |
| `chpasswd`, `passwd` | T1098 Account Manipulation |
| `useradd` | T1136.001 Create Local Account |
| `iptables -F`, `ufw disable` | T1562.001 Impair Defenses |

Output:
- `out/attack_mapping.md`: a ready-made Markdown table for your report/README.
- `out/attack_mapping.csv`
- `out/navigator_layer.json`: open https://mitre-attack.github.io/attack-navigator/ → **Open Existing Layer → Upload from local**. You'll get a colored heat map of the techniques you observed. **Take a screenshot**: it's one of the best images for your README.

---

## 3. Export IOCs as a threat-intel feed

```bash
sudo python3 scripts/export_iocs.py --min-failed 10
```

| File | Format | Who would use it |
|---|---|---|
| `iocs/blocklist.txt` | One IP per line | Firewalls, fail2ban, EDR blocklists |
| `iocs/iocs.csv` | type, value, first/last seen, verdict, context | Analysts, spreadsheets |
| `iocs/iocs.stix.json` | **STIX 2.1** bundle | MISP, OpenCTI, Microsoft Sentinel, any TIP |

Included:
- every IP that logged in, ran commands, or dropped a file, plus IPs with ≥ `--min-failed` failed logins
- all hashes and URLs
- GreyNoise "RIOT" (known-benign) IPs are excluded

It's fine to commit these files: sharing attacker IOCs is normal practice. Make sure **your own IP isn't in them** (`OWN_IPS` in `.env` takes care of that).

---

## 4. Malware triage (static only, never run it)

Captured files are in `data/cowrie/downloads/`, named by their SHA256 hash.

Go to the downloads folder:
```bash
sudo -i
```

```bash
cd /opt/honeypot/data/cowrie/downloads
```

What type is each file (ELF binary? shell script?):
```bash
file *
```

Scan everything with your YARA rules (`-s` shows which strings matched):
```bash
yara -s -r /opt/honeypot/detections/yara/ .
```

Readable strings: look for C2 IPs/domains, mining pools and wallet addresses:
```bash
strings -n 8 <sha256> | less
```

Shell scripts are safe to read as text:
```bash
head -50 <sha256>
```

For each interesting sample, look up the hash at `https://www.virustotal.com/gui/file/<sha256>` and check the detections, family label, "Relations" (C2 servers), and "Behavior".
Also check **MalwareBazaar** (bazaar.abuse.ch) for the family and tags.

**Never** `chmod +x` or run a sample. Never copy samples to your laptop. If you must keep samples, zip them with the password `infected` (the industry convention). Leave them out of GitHub entirely.

---

## 5. Detection rules (`detections/`)

| Rule | Type | Detects | ATT&CK |
|---|---|---|---|
| `sigma/cowrie_ssh_key_persistence.yml` | Sigma | Writing to `authorized_keys` | T1098.004 |
| `sigma/cowrie_cryptominer_activity.yml` | Sigma | Miner names / mining-pool URLs | T1496 |
| `sigma/cowrie_download_and_execute.yml` | Sigma | `wget/curl` + `chmod/sh` in one command | T1105, T1059.004 |
| `sigma/cowrie_history_clearing.yml` | Sigma | `history -c`, `unset HISTFILE` | T1070.003 |
| `yara/linux_cryptominer_xmrig.yar` | YARA | XMRig miners and configs | T1496 |
| `yara/linux_mirai_like_bot.yar` | YARA | Mirai-family IoT bot ELF files | — |
| `yara/linux_shell_dropper.yar` | YARA | Multi-architecture dropper scripts (`bins.sh`) | T1105 |

**How to test them, and write down the results for your report:**

- **Sigma → Kibana:** each rule's description contains the KQL equivalent. Paste it into Discover and record how many events and sessions it matched.
  - Optional, to convert properly with the official tool (on any machine with Python):
    ```bash
    pipx install sigma-cli
    ```
    ```bash
    sigma plugin install elasticsearch
    ```
    ```bash
    sigma convert -t lucene --without-pipeline detections/sigma/
    ```
- **YARA:** `yara -r detections/yara/ data/cowrie/downloads/` gives you the hit count per rule.
- **Improve them using your data.** This is what interviewers love: "I wrote rule X, it missed sample Y, I added string Z." Record the before/after in the report.

**Write at least one rule from scratch** based on something specific you observed, e.g. the exact SSH key comment of a botnet (`mdrfckr` is a famous one), a specific dropper URL path, or a miner wallet address.

---

## 6. Ideas for the "interesting findings" section

```bash
cd /opt/honeypot/data/cowrie/log
```

Most common credential pairs:
```bash
zcat -f cowrie.json* | jq -r 'select(.eventid=="cowrie.login.failed" or .eventid=="cowrie.login.success") | "\(.username)/\(.password)"' | sort | uniq -c | sort -rn | head -20
```

Botnet "campaigns": the same command line sent from many IPs:
```bash
zcat -f cowrie.json* | jq -r 'select(.eventid=="cowrie.command.input") | .input' | sort | uniq -c | sort -rn | head -20
```

Watch a full attacker session like a video (TTY replay). First find the session ID from the alert or Kibana, then:
```bash
sudo docker exec -it cowrie playlog var/lib/cowrie/tty/<tty-file>
```

How fast was the first attack after going live?
```bash
zcat -f cowrie.json* | jq -r 'select(.eventid=="cowrie.session.connect") | .timestamp' | sort | head -1
```

Other questions to answer in the report:
- Telnet vs SSH: which usernames are IoT-style (`admin/admin`, `default`, `support`)?
- Same **HASSH** across different IPs = same tool, so probably the same botnet.
- Which hosting providers (ASNs) host most attackers? (Elastic `source.as.organization.name`, or `isp` in `ip_report.csv`)
- What % of IPs ran commands after logging in, vs. only brute-forced?
