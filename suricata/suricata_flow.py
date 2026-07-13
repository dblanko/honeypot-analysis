#!/usr/bin/env python3
"""
suricata_flows.py — Suricata flow analysis module.
Features:
    • Flow duration
    • Traffic volume (bytes-in / bytes-out)
    • Protocol statistics
    • Top IPs
    • Top ports
    • Detection of anomalous flows (long, large, frequent)
"""

import argparse
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from load_suricata import load_suricata_events


def analyze_flows(events):
    flows = events.get("flow", [])

    durations = []
    bytes_in = []
    bytes_out = []
    proto_counter = Counter()
    src_ip_counter = Counter()
    dest_ip_counter = Counter()
    src_port_counter = Counter()
    dest_port_counter = Counter()

    # For anomaly detection
    long_flows = []
    large_flows = []
    frequent_flows = Counter()

    for f in flows:
        # Duration
        start = f.get("timestamp_utc")
        end = f.get("flow", {}).get("end")
        if isinstance(end, str):
            try:
                end_dt = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone()
            except:
                end_dt = None
        else:
            end_dt = None

        if start and end_dt:
            duration = (end_dt - start).total_seconds()
            durations.append(duration)

            if duration > 3600:  # > 1 hour
                long_flows.append(f)

        # Traffic volume
        b_in = f.get("flow", {}).get("bytes_toserver", 0)
        b_out = f.get("flow", {}).get("bytes_toclient", 0)

        bytes_in.append(b_in)
        bytes_out.append(b_out)

        if b_in + b_out > 10_000_000:  # > 10 MB
            large_flows.append(f)

        # Protocol
        proto = f.get("proto")
        if proto:
            proto_counter[proto] += 1

        # IPs
        src_ip = f.get("src_ip")
        dest_ip = f.get("dest_ip")
        if src_ip:
            src_ip_counter[src_ip] += 1
            frequent_flows[src_ip] += 1
        if dest_ip:
            dest_ip_counter[dest_ip] += 1

        # Ports
        src_port = f.get("src_port")
        dest_port = f.get("dest_port")
        if src_port:
            src_port_counter[src_port] += 1
        if dest_port:
            dest_port_counter[dest_port] += 1

    return {
        "durations": durations,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "proto_counter": proto_counter,
        "src_ip_counter": src_ip_counter,
        "dest_ip_counter": dest_ip_counter,
        "src_port_counter": src_port_counter,
        "dest_port_counter": dest_port_counter,
        "long_flows": long_flows,
        "large_flows": large_flows,
        "frequent_flows": frequent_flows,
    }


def print_results(results):
    print("\n=== Protocol Statistics ===")
    for proto, count in results["proto_counter"].most_common(10):
        print(f"{proto}: {count} flows")

    print("\n=== Top Source IPs ===")
    for ip, count in results["src_ip_counter"].most_common(10):
        print(f"{ip}: {count} flows")

    print("\n=== Top Destination IPs ===")
    for ip, count in results["dest_ip_counter"].most_common(10):
        print(f"{ip}: {count} flows")

    print("\n=== Top Source Ports ===")
    for port, count in results["src_port_counter"].most_common(10):
        print(f"{port}: {count} flows")

    print("\n=== Top Destination Ports ===")
    for port, count in results["dest_port_counter"].most_common(10):
        print(f"{port}: {count} flows")

    print("\n=== Flow Duration Statistics ===")
    if results["durations"]:
        print(f"Min: {min(results['durations']):.2f} sec")
        print(f"Max: {max(results['durations']):.2f} sec")
        print(f"Avg: {sum(results['durations'])/len(results['durations']):.2f} sec")

    print("\n=== Traffic Volume ===")
    print(f"Total bytes to server: {sum(results['bytes_in'])}")
    print(f"Total bytes to client: {sum(results['bytes_out'])}")

    print("\n=== Anomalous Flows ===")
    print(f"Long flows (>1 hour): {len(results['long_flows'])}")
    print(f"Large flows (>10MB): {len(results['large_flows'])}")

    print("\n=== Frequent Flows (Top Talkers) ===")
    for ip, count in results["frequent_flows"].most_common(10):
        print(f"{ip}: {count} flows")


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata flows")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)
    results = analyze_flows(events)
    print_results(results)


if __name__ == "__main__":
    main()
