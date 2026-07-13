#!/usr/bin/env python3
"""
suricata_fileinfo_behavior.py — Behavioral fileinfo analysis for Suricata.
Works even when Suricata does NOT provide MIME or hashes.
Features:
    • File extension analysis
    • Suspicious extensions
    • File size analysis
    • Top download sources (src_ip)
    • Top download destinations (dest_ip)
    • Per-flow download chains
    • Rare extensions
    • Large/small file anomalies
"""

import argparse
from pathlib import Path
from collections import Counter, defaultdict
import os

from load_suricata import load_suricata_events


SUSPICIOUS_EXT = [
    ".exe", ".dll", ".bin", ".sh", ".py", ".ps1",
    ".zip", ".rar", ".7z", ".gz", ".tar", ".tgz",
    ".apk", ".iso", ".msi"
]


def get_extension(filename):
    if not filename:
        return None
    return os.path.splitext(filename)[1].lower()


def analyze_fileinfo(events):
    fileinfo_events = events.get("fileinfo", [])

    ext_counter = Counter()
    src_ip_counter = Counter()
    dest_ip_counter = Counter()
    flow_downloads = defaultdict(list)

    suspicious_downloads = []
    rare_extensions = []
    large_files = []
    tiny_files = []

    for ev in fileinfo_events:
        fi = ev.get("fileinfo", {})
        filename = fi.get("filename")
        size = fi.get("size")
        src_ip = ev.get("src_ip")
        dest_ip = ev.get("dest_ip")
        fid = ev.get("flow_id")

        ext = get_extension(filename)

        # Count extensions
        if ext:
            ext_counter[ext] += 1

        # Suspicious extensions
        if ext in SUSPICIOUS_EXT:
            suspicious_downloads.append(ev)

        # Rare extensions (heuristic: appear < 5 times)
        if ext and ext_counter[ext] < 5:
            rare_extensions.append(ext)

        # Size anomalies
        if isinstance(size, int):
            if size > 5_000_000:  # > 5 MB
                large_files.append(ev)
            if size < 200:  # < 200 bytes
                tiny_files.append(ev)

        # Top IPs
        if src_ip:
            src_ip_counter[src_ip] += 1
        if dest_ip:
            dest_ip_counter[dest_ip] += 1

        # Per-flow download chains
        if fid:
            flow_downloads[fid].append(filename)

    return {
        "ext_counter": ext_counter,
        "src_ip_counter": src_ip_counter,
        "dest_ip_counter": dest_ip_counter,
        "suspicious_downloads": suspicious_downloads,
        "rare_extensions": rare_extensions,
        "large_files": large_files,
        "tiny_files": tiny_files,
        "flow_downloads": flow_downloads,
    }


def print_results(results):
    print("\n=== Top File Extensions ===")
    for ext, count in results["ext_counter"].most_common(10):
        print(f"{ext}: {count}")

    print("\n=== Suspicious Extensions ===")
    print(f"Total suspicious downloads: {len(results['suspicious_downloads'])}")

    print("\n=== Rare Extensions (appear < 5 times) ===")
    print(f"Total rare extensions: {len(results['rare_extensions'])}")
    print(f"Examples: {list(set(results['rare_extensions']))[:10]}")

    print("\n=== Large Files (>5MB) ===")
    print(f"Total large files: {len(results['large_files'])}")

    print("\n=== Tiny Files (<200 bytes) ===")
    print(f"Total tiny files: {len(results['tiny_files'])}")

    print("\n=== Top Download Sources (src_ip) ===")
    for ip, count in results["src_ip_counter"].most_common(10):
        print(f"{ip}: {count}")

    print("\n=== Top Download Destinations (dest_ip) ===")
    for ip, count in results["dest_ip_counter"].most_common(10):
        print(f"{ip}: {count}")

    print("\n=== Per-flow Download Chains ===")
    for fid, files in list(results["flow_downloads"].items())[:10]:
        print(f"Flow {fid}: {files[:10]} ...")


def main():
    parser = argparse.ArgumentParser(description="Behavioral fileinfo analysis for Suricata")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)
    results = analyze_fileinfo(events)
    print_results(results)


if __name__ == "__main__":
    main()
