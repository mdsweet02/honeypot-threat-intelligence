#!/usr/bin/env python3
"""
IOC extraction + OSINT enrichment.

1. Reads all Cowrie logs and extracts IOCs:
     attacker IPs (with attempt/login/command counts), file hashes, URLs.
2. Enriches the top N IPs with AbuseIPDB + GreyNoise, and every hash with
   VirusTotal. Results are cached in out/enrichment_cache.sqlite so you
   never pay the API rate limit twice for the same IOC.
3. Writes CSV reports to out/ (open in Excel / Google Sheets, or upload to
   Kibana with "Upload a file").

Free-tier limits (as of 2026 - check the sites):
  VirusTotal   4 requests/min, 500/day   -> script waits 15s between calls
  AbuseIPDB    1,000 checks/day
  GreyNoise    Community API, small daily quota (key optional)

Usage:
  python3 enrich_iocs.py                 # top 100 IPs + all hashes
  python3 enrich_iocs.py --top 300
  python3 enrich_iocs.py --offline       # extract only, no API calls
  python3 enrich_iocs.py --file data/sample/cowrie-sample.json --offline
"""
import argparse
import csv
import json
import os
import sqlite3
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

CACHE_TTL = 7 * 24 * 3600
VT_DELAY = 15.5  # seconds between VirusTotal requests (free tier = 4/min)


# ---------------------------------------------------------------------------
# 1. Extraction
# ---------------------------------------------------------------------------
def extract(events):
    ips = defaultdict(lambda: {"connections": 0, "failed_logins": 0, "successful_logins": 0,
                               "commands": 0, "downloads": 0, "first_seen": None,
                               "last_seen": None, "clients": set(), "hassh": set()})
    hashes = defaultdict(lambda: {"count": 0, "sources": set(), "ips": set(),
                                  "first_seen": None, "event": ""})
    urls = defaultdict(lambda: {"count": 0, "ips": set(), "shasum": ""})

    for ev in events:
        ip = ev.get("src_ip")
        if not ip:
            continue
        ts = ev.get("timestamp", "")
        rec = ips[ip]
        if ts:
            rec["first_seen"] = min(rec["first_seen"] or ts, ts)
            rec["last_seen"] = max(rec["last_seen"] or ts, ts)
        eid = ev.get("eventid", "")
        if eid == "cowrie.session.connect":
            rec["connections"] += 1
        elif eid == "cowrie.login.failed":
            rec["failed_logins"] += 1
        elif eid == "cowrie.login.success":
            rec["successful_logins"] += 1
        elif eid == "cowrie.command.input":
            rec["commands"] += 1
        elif eid == "cowrie.client.version":
            rec["clients"].add(ev.get("version", ""))
        elif eid == "cowrie.client.kex" and ev.get("hassh"):
            rec["hassh"].add(ev["hassh"])
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            rec["downloads"] += 1
            sha = ev.get("shasum")
            src = ev.get("url") or ev.get("filename") or ""
            if sha:
                h = hashes[sha]
                h["count"] += 1
                h["sources"].add(src)
                h["ips"].add(ip)
                if ts:
                    h["first_seen"] = min(h["first_seen"] or ts, ts)
                h["event"] = eid.rsplit(".", 1)[-1]
            if ev.get("url"):
                u = urls[ev["url"]]
                u["count"] += 1
                u["ips"].add(ip)
                u["shasum"] = sha or u["shasum"]
        elif eid == "cowrie.session.file_download.failed" and ev.get("url"):
            u = urls[ev["url"]]
            u["count"] += 1
            u["ips"].add(ip)
    return ips, hashes, urls


# ---------------------------------------------------------------------------
# 2. Enrichment with a tiny SQLite cache
# ---------------------------------------------------------------------------
class Cache:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS cache (source TEXT, key TEXT, "
                        "fetched REAL, data TEXT, PRIMARY KEY (source, key))")

    def get(self, source, key):
        row = self.db.execute("SELECT fetched, data FROM cache WHERE source=? AND key=?",
                              (source, key)).fetchone()
        if row and time.time() - row[0] < CACHE_TTL:
            return json.loads(row[1])
        return None

    def put(self, source, key, data):
        self.db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)",
                        (source, key, time.time(), json.dumps(data)))
        self.db.commit()


def abuseipdb(ip):
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return None
    status, resp = common.http_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": key, "Accept": "application/json"})
    if status != 200 or not resp:
        return None
    d = resp.get("data", {})
    return {"abuse_score": d.get("abuseConfidenceScore"), "country": d.get("countryCode"),
            "isp": d.get("isp"), "usage_type": d.get("usageType"),
            "domain": d.get("domain"), "abuse_reports": d.get("totalReports")}


def greynoise(ip):
    headers = {"Accept": "application/json"}
    if os.environ.get("GREYNOISE_API_KEY"):
        headers["key"] = os.environ["GREYNOISE_API_KEY"]
    status, resp = common.http_json(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
    if status == 404:
        return {"gn_noise": False, "gn_riot": False, "gn_classification": "not seen", "gn_name": ""}
    if status != 200 or not resp:
        return None
    return {"gn_noise": resp.get("noise"), "gn_riot": resp.get("riot"),
            "gn_classification": resp.get("classification"), "gn_name": resp.get("name")}


def cached(cache, source, key, func):
    data = cache.get(source, key)
    if data is None:
        data = func(key)
        if data is not None:
            cache.put(source, key, data)
    return data or {}


def classify(row):
    """Simple, explainable verdict for the report."""
    if row.get("gn_riot"):
        return "benign service (GreyNoise RIOT)"
    if row.get("gn_classification") == "malicious" or (row.get("abuse_score") or 0) >= 75:
        return "known malicious"
    if row.get("gn_noise"):
        return "known mass scanner"
    if (row.get("abuse_reports") or 0) > 0:
        return "previously reported"
    if "abuse_score" in row or "gn_classification" in row:
        return "unknown / new"
    return "not enriched"


# ---------------------------------------------------------------------------
# 3. Output
# ---------------------------------------------------------------------------
def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"  wrote {path} ({len(rows)} rows)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top", type=int, default=100, help="how many IPs to enrich (by activity)")
    ap.add_argument("--offline", action="store_true", help="no API calls")
    ap.add_argument("--file", help="read one file instead of the whole log folder")
    args = ap.parse_args()

    os.makedirs(common.OUT_DIR, exist_ok=True)
    paths = [args.file] if args.file else common.log_files()
    print(f"Reading {len(paths)} log file(s)...")
    ips, hashes, urls = extract(common.read_events(paths))
    print(f"Found {len(ips):,} IPs, {len(hashes):,} file hashes, {len(urls):,} URLs")

    # Rank IPs: logins + commands matter more than plain failed attempts
    def score(item):
        r = item[1]
        return (r["downloads"] * 100 + r["successful_logins"] * 10 + r["commands"] * 5
                + r["failed_logins"] + r["connections"])
    ranked = sorted(ips.items(), key=score, reverse=True)

    cache = Cache(os.path.join(common.OUT_DIR, "enrichment_cache.sqlite"))
    ip_rows = []
    for i, (ip, r) in enumerate(ranked):
        row = {"ip": ip, **{k: v for k, v in r.items() if k not in ("clients", "hassh")},
               "ssh_clients": " | ".join(sorted(r["clients"]))[:200],
               "hassh": " | ".join(sorted(r["hassh"]))}
        if not args.offline and i < args.top and common.is_public_ip(ip):
            row.update(cached(cache, "abuseipdb", ip, abuseipdb))
            row.update(cached(cache, "greynoise", ip, greynoise))
            if (i + 1) % 25 == 0:
                print(f"  enriched {i + 1}/{min(args.top, len(ranked))} IPs")
        row["verdict"] = classify(row)
        ip_rows.append(row)

    hash_rows = []
    for n, (sha, h) in enumerate(sorted(hashes.items(), key=lambda x: -x[1]["count"])):
        row = {"sha256": sha, "times_seen": h["count"], "type": h["event"],
               "first_seen": h["first_seen"], "attacker_ips": len(h["ips"]),
               "sources": " | ".join(sorted(h["sources"]))[:300]}
        if not args.offline and os.environ.get("VT_API_KEY"):
            vt = cache.get("virustotal", sha)
            if vt is None:
                vt = common.virustotal_file(sha)
                if vt is not None:
                    cache.put("virustotal", sha, vt)
                print(f"  VT {n + 1}/{len(hashes)}: {sha[:16]}… -> "
                      f"{vt.get('malicious', 'not found') if vt else 'error'}")
                time.sleep(VT_DELAY)
            if vt:
                row.update({"vt_found": vt.get("found"), "vt_malicious": vt.get("malicious"),
                            "vt_total": vt.get("total"), "vt_label": vt.get("label"),
                            "vt_type": vt.get("type")})
        hash_rows.append(row)

    url_rows = [{"url": u, "defanged": common.defang(u), "times_seen": d["count"],
                 "attacker_ips": len(d["ips"]), "sha256": d["shasum"]}
                for u, d in sorted(urls.items(), key=lambda x: -x[1]["count"])]

    print("Writing reports:")
    write_csv(os.path.join(common.OUT_DIR, "ip_report.csv"), ip_rows,
              ["ip", "verdict", "connections", "failed_logins", "successful_logins", "commands",
               "downloads", "first_seen", "last_seen", "country", "isp", "usage_type", "domain",
               "abuse_score", "abuse_reports", "gn_noise", "gn_riot", "gn_classification",
               "gn_name", "ssh_clients", "hassh"])
    write_csv(os.path.join(common.OUT_DIR, "malware_report.csv"), hash_rows,
              ["sha256", "times_seen", "type", "first_seen", "attacker_ips", "vt_found",
               "vt_malicious", "vt_total", "vt_label", "vt_type", "sources"])
    write_csv(os.path.join(common.OUT_DIR, "url_report.csv"), url_rows,
              ["defanged", "times_seen", "attacker_ips", "sha256", "url"])

    verdicts = defaultdict(int)
    for r in ip_rows:
        verdicts[r["verdict"]] += 1
    print("\nIP verdicts:", dict(verdicts))


if __name__ == "__main__":
    main()
