#!/usr/bin/env python3
"""
Real-time Telegram alerter for Cowrie.

Follows cowrie.json (like `tail -F`) and sends a Telegram message when:
  1. A NEW malware file is downloaded/uploaded (once per unique SHA256),
     with the VirusTotal verdict if VT_API_KEY is set.
  2. A suspicious command is typed (SSH-key persistence, cron, miners,
     history clearing, ...) - at most once per attacker IP per rule per hour.

Runs forever as a systemd service (see infra/systemd/honeypot-alerter.service).

Usage:
  python3 telegram_alerter.py               # follow the live log
  python3 telegram_alerter.py --file data/sample/cowrie-sample.json --once
                                            # replay a file and exit (testing)
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
from common import defang, esc, match_command, send_telegram, virustotal_file  # noqa: E402

STATE_DIR = os.environ.get("ALERT_STATE_DIR", os.path.join(common.ROOT, "out", "alerter-state"))
SEEN_HASHES_FILE = os.path.join(STATE_DIR, "seen_hashes.txt")
PER_IP_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "3600"))
MAX_ALERTS_PER_HOUR = int(os.environ.get("ALERT_MAX_PER_HOUR", "30"))


class Alerter:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        os.makedirs(STATE_DIR, exist_ok=True)
        self.seen_hashes = set()
        if os.path.exists(SEEN_HASHES_FILE):
            with open(SEEN_HASHES_FILE) as fh:
                self.seen_hashes = {line.strip() for line in fh if line.strip()}
        self.last_alert = {}       # (ip, rule_id) -> unix time
        self.sent_times = []       # timestamps of sent alerts (global flood cap)
        self.suppressed = 0
        self.own_ips = common.ignored_ips()

    # -- sending with a global flood limit ---------------------------------
    def send(self, text):
        now = time.time()
        self.sent_times = [t for t in self.sent_times if now - t < 3600]
        if len(self.sent_times) >= MAX_ALERTS_PER_HOUR:
            self.suppressed += 1
            return
        if self.suppressed:
            text += f"\n\n<i>({self.suppressed} alerts suppressed by the hourly limit)</i>"
            self.suppressed = 0
        self.sent_times.append(now)
        if self.dry_run:
            print("----- ALERT -----\n" + text)
        else:
            send_telegram(text)

    # -- event handlers -----------------------------------------------------
    def handle(self, ev):
        if ev.get("src_ip") in self.own_ips:
            return
        eid = ev.get("eventid", "")
        if eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            self.on_file(ev)
        elif eid == "cowrie.command.input":
            self.on_command(ev)

    def on_file(self, ev):
        sha = ev.get("shasum")
        if not sha or sha in self.seen_hashes:
            return
        self.seen_hashes.add(sha)
        with open(SEEN_HASHES_FILE, "a") as fh:
            fh.write(sha + "\n")

        vt = None if self.dry_run else virustotal_file(sha)
        if vt is None:
            vt_line = "VirusTotal: not checked (no VT_API_KEY or API error)"
        elif not vt["found"]:
            vt_line = "VirusTotal: ❗ <b>not found</b> - possibly a new sample"
        else:
            vt_line = (f"VirusTotal: <b>{vt['malicious']}/{vt['total']}</b> engines malicious"
                       + (f" - {esc(vt['label'])}" if vt["label"] else ""))

        source = ev.get("url") or ev.get("filename") or "?"
        kind = "download" if ev["eventid"].endswith("download") else "upload (SCP/SFTP)"
        self.send(
            "🦠 <b>New malware file captured</b>\n"
            f"Type: {kind}\n"
            f"From IP: <code>{esc(defang(ev.get('src_ip')))}</code>\n"
            f"Source: <code>{esc(defang(source))}</code>\n"
            f"SHA256: <code>{esc(sha)}</code>\n"
            f"{vt_line}\n"
            f"Session: <code>{esc(ev.get('session'))}</code>"
        )

    def on_command(self, ev):
        cmd = ev.get("input", "")
        ip = ev.get("src_ip")
        for rule_id, technique, name, alert in match_command(cmd):
            if not alert:
                continue
            key = (ip, rule_id)
            now = time.time()
            if now - self.last_alert.get(key, 0) < PER_IP_COOLDOWN:
                continue
            self.last_alert[key] = now
            self.send(
                "⚠️ <b>Suspicious command</b>\n"
                f"Rule: {esc(name)} (<code>{technique}</code>)\n"
                f"From IP: <code>{esc(defang(ip))}</code>\n"
                f"Command: <code>{esc(defang(cmd))}</code>\n"
                f"Session: <code>{esc(ev.get('session'))}</code>"
            )


def follow(path, alerter, poll=1.0):
    """tail -F: keep reading, reopen when Cowrie rotates the file at midnight."""
    fh, inode, buf, first_open = None, None, "", True
    while True:
        if fh is None:
            try:
                fh = open(path, encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
                if first_open:  # at startup skip old events; after rotation read from start
                    fh.seek(0, os.SEEK_END)
                    first_open = False
                print(f"[alerter] following {path}", flush=True)
            except FileNotFoundError:
                time.sleep(5)
                continue
        line = fh.readline()
        if line:
            buf += line
            if not buf.endswith("\n"):
                continue  # Cowrie is still writing this line
            try:
                alerter.handle(common.json.loads(buf))
            except ValueError:
                pass
            buf = ""
            continue
        # No new data: check for rotation (new inode) or truncation
        try:
            st = os.stat(path)
            if st.st_ino != inode or st.st_size < fh.tell():
                fh.close()
                fh = None
                continue
        except FileNotFoundError:
            pass
        time.sleep(poll)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default=os.path.join(common.LOG_DIR, "cowrie.json"))
    ap.add_argument("--once", action="store_true", help="read the whole file once and exit")
    ap.add_argument("--dry-run", action="store_true", help="print alerts instead of sending")
    args = ap.parse_args()

    alerter = Alerter(dry_run=args.dry_run)
    if args.once:
        for ev in common.read_events([args.file]):
            alerter.handle(ev)
        return
    follow(args.file, alerter)


if __name__ == "__main__":
    main()
