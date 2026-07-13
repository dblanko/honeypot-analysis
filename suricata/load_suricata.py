#!/usr/bin/env python3
"""
load_suricata.py — Unified Suricata eve.json loader.
Reads events line-by-line, normalizes timestamps to UTC,
and groups events by type (alert, flow, http, dns, tls, fileinfo, smb, ftp, ssh, smtp).
"""

import json
import argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict


def normalize_timestamp(ts: str):
    """
    Convert Suricata timestamp to UTC datetime.
    Example: "2024-06-01T12:34:56.789012+0200"
    """
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        # fallback without microseconds
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")
    return dt.astimezone(timezone.utc)


def load_suricata_events(path: Path):
    """
    Load Suricata eve.json events and group them by event_type.
    Returns dict: { "alert": [...], "flow": [...], ... }
    """
    events = defaultdict(list)

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip broken lines

            # Normalize timestamp
            if "timestamp" in event:
                event["timestamp_utc"] = normalize_timestamp(event["timestamp"])

            # Group by event_type
            etype = event.get("event_type", "unknown")
            events[etype].append(event)

    return events


def main():
    parser = argparse.ArgumentParser(description="Load and normalize Suricata eve.json")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)

    # Print summary
    print("Loaded Suricata events:")
    for etype, items in events.items():
        print(f"  {etype}: {len(items)} events")

    print("\nExample event:")
    for etype, items in events.items():
        if items:
            example = items[0].copy()

            # Convert datetime to string for JSON output
            if "timestamp_utc" in example:
                example["timestamp_utc"] = example["timestamp_utc"].isoformat()

            print(json.dumps(example, indent=2, ensure_ascii=False))
            break


if __name__ == "__main__":
    main()
