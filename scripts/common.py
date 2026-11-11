"""
Shared helpers used by every script in this folder.

Everything here uses only the Python standard library, so nothing needs to be
installed with pip. That keeps the droplet simple (Ubuntu 24.04 ships Python 3.12).
"""
import glob
import gzip
import html
import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Folder that contains this repo (one level above scripts/)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Configuration (.env file)
# ---------------------------------------------------------------------------
def load_env(path=None):
    """Read KEY=VALUE lines from .env into os.environ (without overwriting).

    systemd already passes .env to the alerter, so a permission error here is
    harmless and simply ignored.
    """
    path = path or os.environ.get("HONEYPOT_ENV", os.path.join(ROOT, ".env"))
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except (FileNotFoundError, PermissionError):
        pass


load_env()

LOG_DIR = os.environ.get("COWRIE_LOG_DIR", os.path.join(ROOT, "data", "cowrie", "log"))
OUT_DIR = os.environ.get("OUT_DIR", os.path.join(ROOT, "out"))


def ignored_ips():
    """Your own IPs (OWN_IPS in .env) so your test logins don't pollute results."""
    raw = os.environ.get("OWN_IPS", "")
    return {ip.strip() for ip in raw.split(",") if ip.strip()}


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Reading Cowrie logs
# ---------------------------------------------------------------------------
def log_files(log_dir=None, since_ts=None):
    """Return cowrie.json* files, oldest first, current cowrie.json last.

    Cowrie rotates daily: cowrie.json -> cowrie.json.2026-11-08 (and we gzip
    old ones). If since_ts is given, skip files last modified before it.
    """
    log_dir = log_dir or LOG_DIR
    files = glob.glob(os.path.join(log_dir, "cowrie.json*"))
    if since_ts is not None:
        files = [f for f in files if os.path.getmtime(f) >= since_ts]
    return sorted(files, key=lambda f: (os.path.basename(f) == "cowrie.json", f))


def read_events(paths=None, skip_own=True):
    """Yield one dict per Cowrie JSON event from plain or .gz files."""
    paths = paths if paths is not None else log_files()
    own = ignored_ips() if skip_own else set()
    for path in paths:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue  # half-written or corrupt line
                if event.get("src_ip") in own:
                    continue
                yield event


def parse_ts(value):
    """Cowrie timestamps look like 2026-11-08T10:00:00.123456Z."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def utcnow():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# MITRE ATT&CK rules for commands typed in the fake shell.
# Used by attack_mapper.py (reporting) and telegram_alerter.py (alerts).
# alert=True means "send a Telegram message when this is seen".
# ---------------------------------------------------------------------------
COMMAND_RULES = [
    # id,                  technique,    name,                                   regex,                                                                 alert
    ("ssh_key_persistence", "T1098.004", "Account Manipulation: SSH Authorized Keys", r"authorized_keys",                                              True),
    ("cron_persistence",    "T1053.003", "Scheduled Task/Job: Cron",             r"crontab|/etc/cron|/var/spool/cron",                                  True),
    ("history_clearing",    "T1070.003", "Indicator Removal: Clear Command History", r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|rm\s+[^;|&]*\.bash_history", True),
    ("crypto_miner",        "T1496",     "Resource Hijacking (cryptomining)",    r"xmrig|minerd|cpuminer|stratum\+tcp|cryptonight|nicehash|c3pool|moneroocean", True),
    ("impair_defenses",     "T1562.001", "Impair Defenses: Disable or Modify Tools", r"iptables\s+-F|ufw\s+disable|setenforce\s+0|systemctl\s+(stop|disable)\s+\S*(firewall|apparmor|auditd)|pkill\s+-9\s+\S*(sshd|auditd)", True),
    ("create_account",      "T1136.001", "Create Account: Local Account",        r"\buseradd\b|\badduser\b",                                            True),
    ("password_change",     "T1098",     "Account Manipulation (password change)", r"\bchpasswd\b|\bpasswd\b|usermod\s",                                True),
    ("file_attr_change",    "T1222.002", "File Permissions Modification: Linux", r"\bchattr\b|chmod\s+(\+x|[0-7]*7[0-7]*)\b",                           False),
    ("ingress_transfer",    "T1105",     "Ingress Tool Transfer",                r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b|\bscp\b",                      False),
    ("unix_shell",          "T1059.004", "Command and Scripting Interpreter: Unix Shell", r"\b(sh|bash)\s+-c\b|\|\s*(sh|bash)\b|\./\S+",                 False),
    ("system_info",         "T1082",     "System Information Discovery",         r"\buname\b|/proc/cpuinfo|\blscpu\b|\bnproc\b|\bfree\s+-|hostnamectl|/etc/os-release|\bdmidecode\b", False),
    ("user_discovery",      "T1033",     "System Owner/User Discovery",          r"\bwhoami\b|^\s*id\s*$|\bid\s*;|\bw\s*$|/etc/passwd",                 False),
    ("process_discovery",   "T1057",     "Process Discovery",                    r"\bps\s+(-|aux)|\btop\b",                                             False),
    ("network_discovery",   "T1016",     "System Network Configuration Discovery", r"\bifconfig\b|\bip\s+(a|addr|route)\b|\bnetstat\b|\broute\s+-n",   False),
    ("file_discovery",      "T1083",     "File and Directory Discovery",         r"\bls\s|\bfind\s+/|\blocate\b",                                       False),
]
COMPILED_RULES = [(rid, tech, name, re.compile(rx, re.IGNORECASE), alert)
                  for rid, tech, name, rx, alert in COMMAND_RULES]


def match_command(command):
    """Return list of (rule_id, technique, name, alert) that match a command."""
    return [(rid, tech, name, alert) for rid, tech, name, rx, alert in COMPILED_RULES
            if rx.search(command or "")]


# ---------------------------------------------------------------------------
# HTTP + Telegram
# ---------------------------------------------------------------------------
def http_json(url, headers=None, data=None, timeout=20):
    """Small wrapper around urllib. Returns (status_code, parsed_json_or_None)."""
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {})
    req.add_header("User-Agent", "honeypot-threat-intel/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as err:
        try:
            return err.code, json.loads(err.read().decode() or "null")
        except json.JSONDecodeError:
            return err.code, None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
        print(f"[http] {url.split('?')[0]} failed: {err}")
        return 0, None


def defang(text):
    """Make IPs/URLs non-clickable (http -> hxxp, . -> [.]) - standard CTI practice."""
    text = re.sub(r"(?i)\bhttp", "hxxp", str(text))
    return re.sub(r"(?<=\w)\.(?=\w)", "[.]", text)


def esc(text, limit=300):
    """HTML-escape for Telegram and cut very long attacker commands."""
    text = str(text)
    if len(text) > limit:
        text = text[:limit] + "…"
    return html.escape(text)


def send_telegram(text):
    """Send an HTML-formatted message. Returns True on success."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("[telegram] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set; message was:\n" + text)
        return False
    status, resp = http_json(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data={"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML",
              "disable_web_page_preview": "true"},
    )
    if status != 200:
        print(f"[telegram] send failed ({status}): {resp}")
    return status == 200


def virustotal_file(sha256):
    """Look up a file hash on VirusTotal. Returns a small dict or None."""
    key = os.environ.get("VT_API_KEY")
    if not key:
        return None
    status, resp = http_json(f"https://www.virustotal.com/api/v3/files/{sha256}",
                             headers={"x-apikey": key})
    if status == 404:
        return {"found": False}
    if status != 200 or not resp:
        return None
    attr = resp.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    label = (attr.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "total": sum(stats.values()) if stats else 0,
        "label": label,
        "type": attr.get("type_description", ""),
        "first_seen": attr.get("first_submission_date"),
    }
