#!/usr/bin/env python3
"""
Export IOCs as a shareable threat-intel feed (iocs/ folder):

  blocklist.txt     one IP per line - ready for a firewall / fail2ban / EDR
  iocs.csv          type, value, first/last seen, counts, context
  iocs.stix.json    STIX 2.1 bundle (the standard format for sharing CTI,
                    importable into MISP, OpenCTI, Microsoft Sentinel ...)

Which IPs are included (to keep the feed meaningful):
  any IP that logged in, ran commands or downloaded a file, OR
  made at least --min-failed failed login attempts (default 10).
GreyNoise "RIOT" (benign services) IPs are excluded if out/ip_report.csv exists.

Usage:
  python3 export_iocs.py
  python3 export_iocs.py --min-failed 50
"""
import argparse
import csv
import json
import os
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
from enrich_iocs import extract  # noqa: E402

IOC_DIR = os.path.join(common.ROOT, "iocs")
NS = uuid.UUID("4b1c5b7e-8d55-4c35-9b1a-6a1f8b3f0c11")  # fixed namespace -> stable STIX ids


def stix_indicator(kind, value, pattern, first, last, desc, labels):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    valid_from = (first or now)[:19] + ".000Z" if first else now
    return {
        "type": "indicator", "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(NS, kind + ':' + value)}",
        "created": now, "modified": now,
        "name": f"{kind}: {common.defang(value)}",
        "description": desc,
        "indicator_types": labels,
        "pattern": pattern, "pattern_type": "stix", "pattern_version": "2.1",
        "valid_from": valid_from,
        "labels": ["honeypot", "cowrie"],
    }


def stix_escape(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-failed", type=int, default=10)
    ap.add_argument("--file")
    ap.add_argument("--include-private", action="store_true",
                    help="keep private/documentation IPs (only for testing with sample data)")
    args = ap.parse_args()

    paths = [args.file] if args.file else common.log_files()
    ips, hashes, urls = extract(common.read_events(paths))

    verdicts = {}
    report = os.path.join(common.OUT_DIR, "ip_report.csv")
    if os.path.exists(report):
        with open(report, encoding="utf-8") as fh:
            verdicts = {r["ip"]: r for r in csv.DictReader(fh)}

    os.makedirs(IOC_DIR, exist_ok=True)
    rows, objects = [], []

    for ip, r in sorted(ips.items()):
        interactive = r["successful_logins"] or r["commands"] or r["downloads"]
        if not args.include_private and not common.is_public_ip(ip):
            continue
        if not interactive and r["failed_logins"] < args.min_failed:
            continue
        v = verdicts.get(ip, {})
        if v.get("gn_riot") == "True":
            continue
        ctx = (f"failed={r['failed_logins']} success={r['successful_logins']} "
               f"commands={r['commands']} downloads={r['downloads']}")
        if v.get("abuse_score"):
            ctx += f" abuseipdb={v['abuse_score']}"
        rows.append({"type": "ipv4" if ":" not in ip else "ipv6", "value": ip,
                     "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                     "verdict": v.get("verdict", ""), "context": ctx})
        stype = "ipv6-addr" if ":" in ip else "ipv4-addr"
        objects.append(stix_indicator("IP", ip, f"[{stype}:value = '{ip}']", r["first_seen"],
                                      r["last_seen"], "SSH/Telnet attacker seen by Cowrie. " + ctx,
                                      ["malicious-activity"]))

    for sha, h in sorted(hashes.items()):
        ctx = f"seen={h['count']} ips={len(h['ips'])} via={h['event']}"
        rows.append({"type": "sha256", "value": sha, "first_seen": h["first_seen"],
                     "last_seen": "", "verdict": "", "context": ctx})
        objects.append(stix_indicator("SHA256", sha, f"[file:hashes.'SHA-256' = '{sha}']",
                                      h["first_seen"], None,
                                      "File dropped by attacker on Cowrie honeypot. " + ctx,
                                      ["malicious-activity"]))

    for url, u in sorted(urls.items()):
        ctx = f"seen={u['count']} ips={len(u['ips'])}"
        rows.append({"type": "url", "value": common.defang(url), "first_seen": "",
                     "last_seen": "", "verdict": "", "context": ctx})
        objects.append(stix_indicator("URL", url, f"[url:value = '{stix_escape(url)}']", None, None,
                                      "Malware download URL used by attacker. " + ctx,
                                      ["malicious-activity"]))

    with open(os.path.join(IOC_DIR, "blocklist.txt"), "w") as fh:
        fh.write("# Attacker IPs observed by Cowrie honeypot - generated by export_iocs.py\n")
        fh.writelines(r["value"] + "\n" for r in rows if r["type"].startswith("ipv"))
    with open(os.path.join(IOC_DIR, "iocs.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["type", "value", "first_seen", "last_seen", "verdict", "context"])
        w.writeheader()
        w.writerows(rows)
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    with open(os.path.join(IOC_DIR, "iocs.stix.json"), "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)

    counts = {t: sum(1 for r in rows if r["type"] == t) for t in ("ipv4", "ipv6", "sha256", "url")}
    print(f"Exported {len(rows)} IOCs to {IOC_DIR}/  {counts}")


if __name__ == "__main__":
    main()
