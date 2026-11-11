#!/usr/bin/env python3
"""
Health check - runs every 10 minutes from cron and alerts on Telegram when
something breaks, and again when it is fixed (no repeated spam).

Checks:
  - the Cowrie container is running
  - disk usage is below DISK_ALERT_PERCENT (default 80%)
  - cowrie.json was written recently (a honeypot is never quiet for 30 min)
  - the alerter and Filebeat services are active (if installed)

Why: the sample project lost a whole day of data because the disk filled up
and nobody noticed. This script exists so that does not happen to you.

Usage:
  sudo python3 healthcheck.py           # normal run
  sudo python3 healthcheck.py --test    # send a test Telegram message
  sudo python3 healthcheck.py --print   # show status, send nothing
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

STATE_FILE = os.environ.get("HEALTH_STATE_FILE", "/var/lib/honeypot-health.json")
DISK_LIMIT = int(os.environ.get("DISK_ALERT_PERCENT", "80"))
STALE_MINUTES = int(os.environ.get("LOG_STALE_MINUTES", "30"))


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def service_state(name):
    """'active', 'inactive', 'failed' ... or 'missing' if not installed."""
    if not run(["systemctl", "list-unit-files", f"{name}.service", "--no-legend"]):
        return "missing"
    return run(["systemctl", "is-active", name]) or "unknown"


def check():
    problems = {}

    if run(["docker", "inspect", "-f", "{{.State.Running}}", "cowrie"]) != "true":
        problems["cowrie"] = "Cowrie container is NOT running"

    usage = shutil.disk_usage("/")
    pct = usage.used * 100 // usage.total
    if pct >= DISK_LIMIT:
        problems["disk"] = f"Disk is {pct}% full ({usage.free // 2**30} GB free)"

    log = os.path.join(common.LOG_DIR, "cowrie.json")
    if not os.path.exists(log):
        problems["log"] = f"{log} does not exist"
    else:
        age = (time.time() - os.path.getmtime(log)) / 60
        if age > STALE_MINUTES:
            problems["log"] = f"No new Cowrie events for {int(age)} minutes"

    for svc in ("honeypot-alerter", "filebeat"):
        state = service_state(svc)
        if state not in ("active", "missing"):
            problems[svc] = f"Service {svc} is {state}"

    return problems, pct


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--print", action="store_true")
    args = ap.parse_args()

    if args.test:
        ok = common.send_telegram("✅ <b>Honeypot test message</b>\nTelegram alerts are working.")
        print("sent" if ok else "FAILED - check TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env")
        return

    problems, pct = check()
    if args.print:
        print(f"disk: {pct}%")
        print(json.dumps(problems, indent=2) if problems else "all OK")
        return

    try:
        with open(STATE_FILE) as fh:
            previous = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        previous = {}

    new = {k: v for k, v in problems.items() if k not in previous}
    fixed = [k for k in previous if k not in problems]

    if new:
        common.send_telegram("🚨 <b>Honeypot health problem</b>\n" +
                             "\n".join(f"• {common.esc(v)}" for v in new.values()))
    if fixed:
        common.send_telegram("✅ <b>Resolved</b>: " + ", ".join(fixed))

    with open(STATE_FILE, "w") as fh:
        json.dump(problems, fh)
    print(time.strftime("%F %T"), "problems:", problems or "none")


if __name__ == "__main__":
    main()
