# 05 — Finish & Teardown (day 14–17)

## 1. Final analysis run (on the droplet)

```bash
cd /opt/honeypot
```

Stop capturing so the numbers are final:

```bash
sudo docker compose -f infra/docker-compose.yml stop
```

```bash
sudo python3 scripts/enrich_iocs.py --top 300
```

```bash
sudo python3 scripts/attack_mapper.py
```

```bash
sudo python3 scripts/export_iocs.py
```

```bash
sudo python3 scripts/daily_digest.py --hours 0 --print > out/full_period_summary.txt
```

```bash
sudo yara -r detections/yara/ data/cowrie/downloads/ > out/yara_hits.txt
```

## 2. Copy the results to GitHub (logs and malware stay behind)

```bash
sudo mkdir -p report/results
```

```bash
sudo cp out/*.csv out/*.md out/navigator_layer.json out/full_period_summary.txt out/yara_hits.txt report/results/
```

```bash
sudo chown -R hpadmin: /opt/honeypot
```

```bash
cd /opt/honeypot
```

Before committing, open the CSVs and check that your own IP is not in them:

```bash
git status
```

```bash
git add report/results iocs
```

```bash
git commit -m "Final 14-day results"
```

```bash
git push
```

You'll need a GitHub personal access token, or use `scp` to copy the files off instead.

Optional: keep a compressed copy of the **logs only, no malware** for later. On your computer:
```bash
ssh -p 22222 hpadmin@DROPLET_IP "sudo tar czf - -C /opt/honeypot/data/cowrie log" > cowrie-logs.tgz
```

## 3. Elastic Cloud (before the trial expires)
Export the dashboard (`elastic/kibana-dashboard.ndjson`), take screenshots, and delete the API key (see doc 03, step 9).

## 4. Destroy everything that costs money or holds secrets

| What | How |
|---|---|
| Droplet | DigitalOcean → Droplet → **Destroy**. This deletes the malware samples too. |
| Snapshots/volumes | Check that there are none left (Images → Snapshots) |
| Cloud Firewall | Networking → Firewalls → delete `honeypot-fw` |
| Elastic deployment | Delete it, or let the trial expire |
| API keys | Rotate or delete the VirusTotal/AbuseIPDB keys if they were ever exposed |
| Telegram bot | Keep it for future projects, or `/deletebot` in BotFather |
| Billing | Check the next invoice: it should be about $3–6 |

## 5. Write-up checklist
- [ ] `report/Threat_Intel_Report.pdf`, from `report/REPORT_TEMPLATE.md` (export via Google Docs/Word, or `pandoc`)
- [ ] README results table filled in with real numbers
- [ ] Screenshots: Kibana dashboard, attack map, ATT&CK Navigator heat map, Telegram alerts (blur the bot token/chat ID), VirusTotal result of a captured sample
- [ ] Your own IP masked everywhere
- [ ] Resume bullet updated with real numbers
