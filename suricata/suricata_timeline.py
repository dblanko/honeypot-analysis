#!/usr/bin/env python3
"""
suricata_timeline.py — Suricata timeline builder.
Features:
    • flow → alert → http → dns → tls → smb → fileinfo
    • sorting by timestamp
    • correlation by flow_id
    • attack chain reconstruction
"""

import argparse
from pathlib import Path
from collections import defaultdict

from load_suricata import load_suricata_events


def collect_by_flow(events):
    """Group all Suricata events by flow_id."""
    timeline = defaultdict(list)

    for etype, items in events.items():
        for ev in items:
            fid = ev.get("flow_id")
            if not fid:
                continue

            ts = ev.get("timestamp_utc")
            timeline[fid].append({
                "timestamp": ts,
                "event_type": etype,
                "data": ev
            })

    return timeline


def sort_timeline(timeline):
    """Sort events inside each flow_id by timestamp."""
    for fid in timeline:
        timeline[fid].sort(key=lambda x: x["timestamp"])
    return timeline


def print_chain(fid, chain):
    """Pretty-print a single attack chain."""
    print(f"\n=== Flow ID: {fid} ===")

    for ev in chain:
        ts = ev["timestamp"]
        etype = ev["event_type"]
        data = ev["data"]

        print(f"[{ts}] {etype}")

        if etype == "alert":
            print(f"    ALERT: {data.get('alert', {}).get('signature')}")
        elif etype == "http":
            http = data.get("http", {})
            print(f"    HTTP: {http.get('http_method')} {http.get('url')}")
        elif etype == "dns":
            dns = data.get("dns", {})
            print(f"    DNS: {dns.get('rrname')} ({dns.get('rcode')})")
        elif etype == "tls":
            tls = data.get("tls", {})
            print(f"    TLS: SNI={tls.get('sni')} JA3={tls.get('ja3')}")
        elif etype == "smb":
            smb = data.get("smb", {})
            print(f"    SMB: {smb.get('command')}")
        elif etype == "fileinfo":
            fi = data.get("fileinfo", {})
            print(f"    FILE: {fi.get('filename')} size={fi.get('size')}")

    print("=== End of chain ===")


def main():
    parser = argparse.ArgumentParser(description="Build Suricata attack timeline")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)

    # Build timeline
    timeline = collect_by_flow(events)
    timeline = sort_timeline(timeline)

    # Print chains
    print(f"Total flows with events: {len(timeline)}")

    for fid, chain in timeline.items():
        print_chain(fid, chain)


if __name__ == "__main__":
    main()
