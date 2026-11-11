#!/usr/bin/env python3
"""
Map observed attacker behaviour to MITRE ATT&CK techniques.

Rules live in common.py (COMMAND_RULES) plus a few event-based ones below.
Outputs (in out/):
  attack_mapping.csv       technique, events, sessions, IPs, example commands
  attack_mapping.md        same as a Markdown table - paste into your report
  navigator_layer.json     open at https://mitre-attack.github.io/attack-navigator/
                           -> "Open Existing Layer" -> "Upload from local"

Usage:
  python3 attack_mapper.py
  python3 attack_mapper.py --file data/sample/cowrie-sample.json
"""
import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

# Behaviour we can map from the event type alone (not from a command)
EVENT_RULES = {
    "cowrie.login.failed": ("T1110.001", "Brute Force: Password Guessing"),
    "cowrie.login.success": ("T1078", "Valid Accounts (default/weak credentials)"),
    "cowrie.session.file_download": ("T1105", "Ingress Tool Transfer"),
    "cowrie.session.file_upload": ("T1105", "Ingress Tool Transfer"),
    "cowrie.direct-tcpip.request": ("T1090", "Proxy (SSH tunnelling attempt)"),
}

TACTICS = {  # for the report table
    "T1110.001": "Credential Access", "T1078": "Initial Access", "T1105": "Command and Control",
    "T1090": "Command and Control", "T1098.004": "Persistence", "T1053.003": "Persistence",
    "T1070.003": "Defense Evasion", "T1496": "Impact", "T1562.001": "Defense Evasion",
    "T1136.001": "Persistence", "T1098": "Persistence", "T1222.002": "Defense Evasion",
    "T1059.004": "Execution", "T1082": "Discovery", "T1033": "Discovery",
    "T1057": "Discovery", "T1016": "Discovery", "T1083": "Discovery",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file")
    args = ap.parse_args()
    paths = [args.file] if args.file else common.log_files()

    names = {}
    events = Counter()
    sessions = defaultdict(set)
    ips = defaultdict(set)
    examples = defaultdict(Counter)

    for ev in common.read_events(paths):
        eid = ev.get("eventid", "")
        hits = []
        if eid in EVENT_RULES:
            hits.append(EVENT_RULES[eid])
        if eid == "cowrie.command.input":
            hits += [(tech, name) for _, tech, name, _ in common.match_command(ev.get("input"))]
        for tech, name in set(hits):
            names[tech] = name
            events[tech] += 1
            sessions[tech].add(ev.get("session"))
            ips[tech].add(ev.get("src_ip"))
            if eid == "cowrie.command.input":
                examples[tech][ev.get("input", "")[:120]] += 1
            elif eid.startswith("cowrie.session.file"):
                examples[tech][common.defang(ev.get("url") or ev.get("filename") or "")[:120]] += 1

    if not events:
        print("No events found - check COWRIE_LOG_DIR or --file")
        return

    os.makedirs(common.OUT_DIR, exist_ok=True)
    rows = []
    for tech, count in events.most_common():
        rows.append({
            "technique": tech, "name": names[tech], "tactic": TACTICS.get(tech, ""),
            "events": count, "sessions": len(sessions[tech]), "unique_ips": len(ips[tech]),
            "examples": " || ".join(c for c, _ in examples[tech].most_common(3)),
        })

    csv_path = os.path.join(common.OUT_DIR, "attack_mapping.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    md_path = os.path.join(common.OUT_DIR, "attack_mapping.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("| Technique | Name | Tactic | Events | Sessions | IPs | Example |\n")
        fh.write("|---|---|---|---:|---:|---:|---|\n")
        for r in rows:
            ex = r["examples"].split(" || ")[0].replace("|", "\\|")
            fh.write(f"| [{r['technique']}](https://attack.mitre.org/techniques/"
                     f"{r['technique'].replace('.', '/')}/) | {r['name']} | {r['tactic']} | "
                     f"{r['events']:,} | {r['sessions']:,} | {r['unique_ips']:,} | `{ex}` |\n")

    # Score = number of sessions, so the heat map shows how common each technique is
    max_s = max(r["sessions"] for r in rows)
    layer = {
        "name": "Cowrie honeypot - observed techniques",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": "Techniques observed on an internet-facing Cowrie SSH/Telnet honeypot. "
                       "Score = number of attacker sessions.",
        "filters": {"platforms": ["Linux"]},
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": max_s},
        "techniques": [{"techniqueID": r["technique"], "score": r["sessions"],
                        "comment": f"{r['events']} events, {r['unique_ips']} IPs. "
                                   f"e.g. {r['examples'].split(' || ')[0]}",
                        "enabled": True} for r in rows],
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }
    layer_path = os.path.join(common.OUT_DIR, "navigator_layer.json")
    with open(layer_path, "w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2)

    print(f"{len(rows)} techniques mapped:")
    for r in rows:
        print(f"  {r['technique']:<10} {r['name']:<50} sessions={r['sessions']:<6} ips={r['unique_ips']}")
    print(f"\nWrote {csv_path}\n      {md_path}\n      {layer_path}")


if __name__ == "__main__":
    main()
