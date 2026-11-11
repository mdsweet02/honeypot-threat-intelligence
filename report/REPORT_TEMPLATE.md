# Threat Intelligence Report: SSH/Telnet Honeypot

**Author:** Madina Zhakina · **Period:** <YYYY-MM-DD> → <YYYY-MM-DD> (14 days) · **Sensor:** Cowrie on DigitalOcean <region>
**TLP:CLEAR** (the IOCs in this report can be shared freely)

---

## 1. Executive Summary
3–5 sentences for a non-technical manager. What was observed, how much, and what it means for defenders.
> Example: "Over 14 days, an internet-facing SSH honeypot received **X** connection attempts from **Y** unique IPs in **Z** countries. **N%** of attackers that gained (fake) access attempted to install persistence or cryptominers within seconds, showing that any exposed SSH service with weak credentials will be compromised automatically. Key recommendations: disable password authentication, block the IOCs in Appendix A, and alert on the behaviours in Section 7."

## 2. Key Findings (bullet list, 5–8 items with numbers)
- First attack arrived **N minutes** after the sensor went live
- Top credential: `root / 123456` (N attempts)
- **N** unique malware samples captured; **N** were unknown to VirusTotal
- One campaign (same command line / SSH key) came from **N** IPs = botnet
- **N%** of attacker IPs were already listed on AbuseIPDB; **N%** were new

## 3. Methodology
- Architecture diagram (from README)
- Sensor: Cowrie <version>, SSH (22) + Telnet (23), hostname changed, default fingerprints reduced
- Pipeline: Filebeat → Elastic Cloud (GeoIP/ASN ingest pipeline) → Kibana
- Enrichment: VirusTotal, AbuseIPDB, GreyNoise (scripts/enrich_iocs.py)
- Safety controls: isolated VPS, egress filtering, no malware execution, management SSH key-only on a non-standard port
- Limitations: one sensor/one region, a honeypot only sees opportunistic (not targeted) attacks, Cowrie can be fingerprinted by advanced actors, any data gaps

## 4. Attack Volume & Sources
- Chart: attacks per day (Kibana)
- Map + table: top 10 countries
- Table: top 10 ASNs / hosting providers. Note how much comes from cloud/VPS providers rather than home users.
- Table: top 10 IPs with AbuseIPDB score and GreyNoise classification (from ip_report.csv)
- SSH vs Telnet split

## 5. Credential Analysis
- Top 15 usernames, top 15 passwords, top 10 pairs
- IoT-default credentials (Telnet) vs Linux-server credentials (SSH)
- Observation: e.g. passwords from well-known wordlists, the vendor defaults being tried

## 6. Post-Compromise Behaviour
- % of successful logins that ran commands
- Top 10 commands and what they do
- 2–3 **session walkthroughs** (TTY replay screenshots): step-by-step what the bot did and why

## 7. MITRE ATT&CK Mapping
- Paste `out/attack_mapping.md`
- ATT&CK Navigator heat map screenshot
- Short explanation of the most frequent technique per tactic

## 8. Malware Analysis (static only)
| SHA256 (short) | Type | VT detections | Family | Delivered via | Notes |
|---|---|---|---|---|---|
- For 1–2 samples: `file` / `strings` findings (C2 address, mining pool, wallet), YARA hits

## 9. Tooling Fingerprints
- Top SSH client versions and HASSH values. Do different IPs share a tool? (campaign clustering)

## 10. Detections Developed
| Rule | Type | ATT&CK | Hits on our data | Notes / tuning |
|---|---|---|---|---|
- What you changed after testing it against real data

## 11. Defensive Recommendations
1. Disable SSH password authentication; use keys + MFA
2. Block the IOCs in Appendix A at the perimeter
3. Alert on: authorized_keys changes, new cron entries, outbound connections to mining pools, `chattr` on `.ssh`
4. Don't expose management services to the internet (VPN/bastion)
5. Rate-limit and ban (fail2ban/CrowdSec)
6. Change default credentials on IoT and network devices (the Telnet findings)

## 12. Lessons Learned
What went wrong and what you would do differently (honest = credible).

## Appendix A: IOCs
Top 50 IPs, all hashes, all URLs (defanged). Full feed: `iocs/iocs.csv`, `iocs/iocs.stix.json`, `iocs/blocklist.txt`.

## Appendix B: Tools
Cowrie, Docker, Filebeat, Elasticsearch/Kibana (Elastic Cloud), Python, VirusTotal, AbuseIPDB, GreyNoise, YARA, Sigma, MITRE ATT&CK Navigator, Telegram Bot API.
