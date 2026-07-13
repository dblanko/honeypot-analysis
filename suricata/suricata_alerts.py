#!/usr/bin/env python3
"""
suricata_alerts.py — Suricata alert analysis module.
Features:
    • Top signatures (SID and signature name)
    • Top source IPs
    • Top destination IPs
    • Alert frequency by hour (UTC)
    • Correlation with flow sessions (via flow_id)
    • Grouping alerts by SID
"""

import argparse
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

from load_suricata import load_suricata_events


def top_n(counter, n=10):
    return counter.most_common(n)


def analyze_alerts(events):
    alerts = events.get("alert", [])
    flows = events.get("flow", [])

    # SID → signature name
    sid_counter = Counter()
    sig_name_counter = Counter()

    # IP statistics
    src_ip_counter = Counter()
    dest_ip_counter = Counter()

    # Hourly frequency (UTC)
    hourly_freq = Counter()

    # Correlation: SID → flow_ids
    sid_flow_map = defaultdict(set)

    # Build flow lookup by flow_id
    flow_lookup = {f.get("flow_id"): f for f in flows if "flow_id" in f}

    for alert in alerts:
        alert_info = alert.get("alert", {})
        sid = alert_info.get("signature_id")
        sig_name = alert_info.get("signature")

        src_ip = alert.get("src_ip")
        dest_ip = alert.get("dest_ip")

        # Count SID and signature names
        if sid:
            sid_counter[sid] += 1
        if sig_name:
            sig_name_counter[sig_name] += 1

        # Count IPs
        if src_ip:
            src_ip_counter[src_ip] += 1
        if dest_ip:
            dest_ip_counter[dest_ip] += 1

        # Hourly frequency
        ts = alert.get("timestamp_utc")
        if ts:
            hour = ts.replace(minute=0, second=0, microsecond=0)
            hourly_freq[hour] += 1

        # Correlate with flows
        flow_id = alert.get("flow_id")
        if sid and flow_id in flow_lookup:
            sid_flow_map[sid].add(flow_id)

    return {
        "sid_counter": sid_counter,
        "sig_name_counter": sig_name_counter,
        "src_ip_counter": src_ip_counter,
        "dest_ip_counter": dest_ip_counter,
        "hourly_freq": hourly_freq,
        "sid_flow_map": sid_flow_map,
    }


def print_results(results):
    print("\n=== Top Signatures (SID) ===")
    for sid, count in top_n(results["sid_counter"]):
        print(f"SID {sid}: {count} alerts")

    print("\n=== Top Signature Names ===")
    for name, count in top_n(results["sig_name_counter"]):
        print(f"{name}: {count} alerts")

    print("\n=== Top Source IPs ===")
    for ip, count in top_n(results["src_ip_counter"]):
        print(f"{ip}: {count} alerts")

    print("\n=== Top Destination IPs ===")
    for ip, count in top_n(results["dest_ip_counter"]):
        print(f"{ip}: {count} alerts")

    print("\n=== Alert Frequency by Hour (UTC) ===")
    for hour, count in sorted(results["hourly_freq"].items()):
        print(f"{hour}: {count} alerts")

    print("\n=== SID → Flow Correlation ===")
    for sid, flow_ids in results["sid_flow_map"].items():
        print(f"SID {sid}: {len(flow_ids)} correlated flows")


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata alerts")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)
    results = analyze_alerts(events)
    print_results(results)


if __name__ == "__main__":
    main()
