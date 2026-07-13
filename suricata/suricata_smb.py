#!/usr/bin/env python3
"""
suricata_smb_behavior.py — Behavioral SMB analysis for Suricata.
Works even when Suricata does NOT decode exploits (MS17-010).
Features:
    • SMB scan detection
    • Aggressive clients (top talkers)
    • High-frequency command bursts
    • Suspicious behavioral patterns
    • Per-flow SMB activity analysis
"""

import argparse
from pathlib import Path
from collections import Counter, defaultdict

from load_suricata import load_suricata_events


# Commands that indicate scanning / probing
SCAN_COMMANDS = [
    "SMB1_COMMAND_NEGOTIATE_PROTOCOL",
    "SMB1_COMMAND_SESSION_SETUP_ANDX",
    "SMB1_COMMAND_TREE_CONNECT_ANDX",
]

# Commands that indicate possible brute-force or repeated login attempts
AUTH_COMMANDS = [
    "SMB1_COMMAND_SESSION_SETUP_ANDX",
    "SMB1_COMMAND_LOGOFF_ANDX",
]

# Commands that indicate possible enumeration (even if Suricata didn't decode NT_TRANSACT)
ENUM_HINTS = [
    "SMB1_COMMAND_TREE_CONNECT_ANDX",
]


def analyze_behavior(events):
    smb_events = events.get("smb", [])

    # Basic counters
    cmd_counter = Counter()
    src_ip_counter = Counter()
    flow_cmd_count = defaultdict(int)
    flow_cmd_list = defaultdict(list)

    # Behavioral indicators
    smb_scanners = Counter()
    smb_bruteforce = Counter()
    smb_enum = Counter()
    smb_aggressive_flows = []

    for ev in smb_events:
        smb = ev.get("smb", {})
        cmd = smb.get("command")
        src_ip = ev.get("src_ip")
        fid = ev.get("flow_id")

        if cmd:
            cmd_counter[cmd] += 1
        if src_ip:
            src_ip_counter[src_ip] += 1
        if fid:
            flow_cmd_count[fid] += 1
            flow_cmd_list[fid].append(cmd)

        # Scan detection
        if cmd in SCAN_COMMANDS and src_ip:
            smb_scanners[src_ip] += 1

        # Brute-force detection (repeated auth attempts)
        if cmd in AUTH_COMMANDS and src_ip:
            smb_bruteforce[src_ip] += 1

        # Enumeration detection (heuristic)
        if cmd in ENUM_HINTS and src_ip:
            smb_enum[src_ip] += 1

    # Aggressive flows: flows with unusually high number of SMB commands
    for fid, count in flow_cmd_count.items():
        if count > 50:  # threshold for aggressive SMB behavior
            smb_aggressive_flows.append((fid, count, flow_cmd_list[fid]))

    return {
        "cmd_counter": cmd_counter,
        "src_ip_counter": src_ip_counter,
        "smb_scanners": smb_scanners,
        "smb_bruteforce": smb_bruteforce,
        "smb_enum": smb_enum,
        "smb_aggressive_flows": smb_aggressive_flows,
    }


def print_results(results):
    print("\n=== Top SMB Commands ===")
    for cmd, count in results["cmd_counter"].most_common(10):
        print(f"{cmd}: {count}")

    print("\n=== Top SMB Source IPs ===")
    for ip, count in results["src_ip_counter"].most_common(10):
        print(f"{ip}: {count}")

    print("\n=== SMB Scanners (high-frequency NEGOTIATE/SESSION_SETUP) ===")
    for ip, count in results["smb_scanners"].most_common(10):
        print(f"{ip}: {count}")

    print("\n=== SMB Brute-force Candidates (repeated SESSION_SETUP/LOGOFF) ===")
    for ip, count in results["smb_bruteforce"].most_common(10):
        print(f"{ip}: {count}")

    print("\n=== SMB Enumeration Candidates (TREE_CONNECT bursts) ===")
    for ip, count in results["smb_enum"].most_common(10):
        print(f"{ip}: {count}")

    print("\n=== Aggressive SMB Flows (many commands in one session) ===")
    for fid, count, cmds in results["smb_aggressive_flows"][:10]:
        print(f"Flow {fid}: {count} commands")
        print(f"    Commands: {cmds[:10]} ...")


def main():
    parser = argparse.ArgumentParser(description="Behavioral SMB analysis for Suricata")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)
    results = analyze_behavior(events)
    print_results(results)


if __name__ == "__main__":
    main()
