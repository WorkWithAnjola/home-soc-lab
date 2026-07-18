#!/usr/bin/env python3
"""
parse_wazuh_alerts.py

Parses a Wazuh alerts.json file (one JSON object per line) and extracts a
clean summary of Indicators of Compromise (IOCs) — source IPs, target
usernames, rule descriptions, and severity levels — for faster triage
during incident investigation.

Usage:
    python3 parse_wazuh_alerts.py alerts.json
    python3 parse_wazuh_alerts.py alerts.json --min-level 7
    python3 parse_wazuh_alerts.py alerts.json --output summary.csv

Author: Anjola
Project: home-soc-lab
"""

import json
import argparse
import csv
import sys
from collections import Counter


def parse_alerts(filepath, min_level=0):
    """Read a Wazuh alerts.json file and return a list of parsed alert dicts."""
    alerts = []
    skipped = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            rule = record.get("rule", {})
            level = rule.get("level", 0)

            if level < min_level:
                continue

            alerts.append({
                "timestamp": record.get("timestamp", "unknown"),
                "src_ip": record.get("data", {}).get("srcip", "unknown"),
                "dst_user": record.get("data", {}).get("dstuser", "unknown"),
                "rule_id": rule.get("id", "unknown"),
                "rule_level": level,
                "rule_description": rule.get("description", "unknown"),
                "agent_name": record.get("agent", {}).get("name", "unknown"),
            })

    if skipped:
        print(f"[!] Skipped {skipped} malformed line(s) while parsing.", file=sys.stderr)

    return alerts


def summarize(alerts):
    """Print a quick triage summary to the console."""
    if not alerts:
        print("No alerts matched the given criteria.")
        return

    print(f"\n=== Wazuh Alert Summary ({len(alerts)} alerts) ===\n")

    src_ip_counts = Counter(a["src_ip"] for a in alerts)
    user_counts = Counter(a["dst_user"] for a in alerts)
    rule_counts = Counter(a["rule_description"] for a in alerts)

    print("Top Source IPs:")
    for ip, count in src_ip_counts.most_common(5):
        print(f"  {ip:<20} {count} alert(s)")

    print("\nTop Targeted Users:")
    for user, count in user_counts.most_common(5):
        print(f"  {user:<20} {count} alert(s)")

    print("\nTop Alert Types:")
    for desc, count in rule_counts.most_common(5):
        print(f"  {desc:<50} {count} alert(s)")

    high_severity = [a for a in alerts if a["rule_level"] >= 10]
    if high_severity:
        print(f"\n⚠️  {len(high_severity)} high-severity alert(s) (level >= 10) — review first.")

    print()


def write_csv(alerts, output_path):
    """Write parsed alerts to a CSV file for further analysis or reporting."""
    if not alerts:
        print("No alerts to write.")
        return

    fieldnames = ["timestamp", "src_ip", "dst_user", "rule_id", "rule_level",
                  "rule_description", "agent_name"]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"[+] Wrote {len(alerts)} alert(s) to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Parse Wazuh alerts.json and extract an IOC summary."
    )
    parser.add_argument("filepath", help="Path to the Wazuh alerts.json file")
    parser.add_argument("--min-level", type=int, default=0,
                         help="Only include alerts at or above this rule level (default: 0)")
    parser.add_argument("--output", type=str, default=None,
                         help="Optional path to write results as a CSV file")

    args = parser.parse_args()

    alerts = parse_alerts(args.filepath, min_level=args.min_level)
    summarize(alerts)

    if args.output:
        write_csv(alerts, args.output)


if __name__ == "__main__":
    main()
