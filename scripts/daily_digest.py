#!/usr/bin/env python3
"""
Daily Telegram digest: what happened on the honeypot in the last N hours.

Run from cron once a day (see infra/honeypot.cron).

Usage:
  python3 daily_digest.py                 # last 24h, send to Telegram
  python3 daily_digest.py --hours 6 --print
  python3 daily_digest.py --file data/sample/cowrie-sample.json --hours 0 --print
                                          # --hours 0 = no time filter
"""
import argparse
import os
import sys
import time
from collections import Counter
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
from common import defang, esc  # noqa: E402


def build_digest(events, hours):
    since = common.utcnow() - timedelta(hours=hours) if hours else None
    sessions, ips, success_ips = set(), Counter(), set()
    failed = success = commands = 0
    users, passwords, combos, cmds, clients = Counter(), Counter(), Counter(), Counter(), Counter()
    hashes = {}

    for ev in events:
        ts = common.parse_ts(ev.get("timestamp"))
        if since and (ts is None or ts < since):
            continue
        eid = ev.get("eventid", "")
        ip = ev.get("src_ip")
        if eid == "cowrie.session.connect":
            sessions.add(ev.get("session"))
            ips[ip] += 1
        elif eid == "cowrie.login.failed":
            failed += 1
            users[ev.get("username")] += 1
            passwords[ev.get("password")] += 1
            combos[f"{ev.get('username')} / {ev.get('password')}"] += 1
        elif eid == "cowrie.login.success":
            success += 1
            success_ips.add(ip)
            combos[f"{ev.get('username')} / {ev.get('password')}"] += 1
        elif eid == "cowrie.command.input":
            commands += 1
            cmds[ev.get("input", "")[:80]] += 1
        elif eid == "cowrie.client.version":
            clients[ev.get("version", "")] += 1
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload") and ev.get("shasum"):
            hashes.setdefault(ev["shasum"], ev.get("url") or ev.get("filename") or "?")

    def top(counter, n=5):
        if not counter:
            return "  (none)"
        return "\n".join(f"  {c:>6}  <code>{esc(defang(k), 70)}</code>" for k, c in counter.most_common(n))

    period = f"last {hours}h" if hours else "whole file"
    lines = [
        f"📊 <b>Honeypot daily digest</b> ({period})",
        "",
        f"Connections: <b>{len(sessions):,}</b>",
        f"Unique attacker IPs: <b>{len(ips):,}</b>",
        f"Failed logins: <b>{failed:,}</b>",
        f"Successful (fake) logins: <b>{success:,}</b> from {len(success_ips):,} IPs",
        f"Commands typed: <b>{commands:,}</b>",
        f"New/unique files captured: <b>{len(hashes):,}</b>",
        "",
        "<b>Top attacker IPs</b>", top(ips),
        "", "<b>Top usernames</b>", top(users),
        "", "<b>Top passwords</b>", top(passwords),
        "", "<b>Top commands</b>", top(cmds),
        "", "<b>Top SSH clients</b>", top(clients, 3),
    ]
    if hashes:
        lines += ["", "<b>Files</b>"] + [
            f"  <code>{sha[:16]}…</code> {esc(defang(src), 60)}" for sha, src in list(hashes.items())[:5]]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--file", help="read one file instead of the Cowrie log folder")
    ap.add_argument("--print", action="store_true", help="print instead of sending")
    args = ap.parse_args()

    if args.file:
        paths = [args.file]
    else:
        # only open files touched in the window (+1 day margin) - keeps it fast
        since = time.time() - (args.hours + 24) * 3600 if args.hours else None
        paths = common.log_files(since_ts=since)
    text = build_digest(common.read_events(paths), args.hours)
    if args.print:
        print(text)
    else:
        common.send_telegram(text)


if __name__ == "__main__":
    main()
