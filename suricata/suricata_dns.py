#!/usr/bin/env python3
"""
suricata_dns.py — Suricata DNS analysis module.
Features:
    • Query frequency
    • NXDOMAIN detection
    • Suspicious domains
    • DGA-like domain heuristics
    • Rare TLD detection
"""

import argparse
from pathlib import Path
from collections import Counter
import re

from load_suricata import load_suricata_events


def is_dga(domain: str):
    """
    Simple heuristic for DGA-like domains:
    - long domain labels
    - high consonant ratio
    - random-looking patterns
    """
    if not domain:
        return False

    label = domain.split(".")[0]  # first part of domain

    if len(label) > 15:
        return True

    consonants = sum(c.lower() in "bcdfghjklmnpqrstvwxyz" for c in label)
    vowels = sum(c.lower() in "aeiou" for c in label)

    if vowels == 0:
        return True

    if consonants / max(vowels, 1) > 5:
        return True

    if re.search(r"[0-9]{4,}", label):
        return True

    return False


def is_suspicious(domain: str):
    """
    Simple heuristics for suspicious domains:
    - known malicious keywords
    - strange patterns
    """
    if not domain:
        return False

    domain_lower = domain.lower()

    patterns = [
        "update", "download", "malware", "bot", "shell", "cmd",
        "hack", "exploit", "backdoor", "stealer"
    ]

    return any(p in domain_lower for p in patterns)


def analyze_dns(events):
    dns_events = events.get("dns", [])

    query_counter = Counter()
    nxdomain_counter = Counter()
    suspicious_domains = []
    dga_domains = []
    rare_tlds = Counter()

    for d in dns_events:
        dns = d.get("dns", {})

        # Query name
        qname = dns.get("rrname")
        if qname:
            query_counter[qname] += 1

        # NXDOMAIN
        if dns.get("rcode") == "NXDOMAIN":
            nxdomain_counter[qname] += 1

        # Suspicious domains
        if is_suspicious(qname):
            suspicious_domains.append(qname)

        # DGA-like domains
        if is_dga(qname):
            dga_domains.append(qname)

        # Rare TLDs
        if qname and "." in qname:
            tld = qname.split(".")[-1]
            if len(tld) > 3:  # uncommon TLDs
                rare_tlds[tld] += 1

    return {
        "query_counter": query_counter,
        "nxdomain_counter": nxdomain_counter,
        "suspicious_domains": suspicious_domains,
        "dga_domains": dga_domains,
        "rare_tlds": rare_tlds,
    }


def print_results(results):
    print("\n=== Top DNS Queries ===")
    for q, count in results["query_counter"].most_common(10):
        print(f"{q}: {count}")

    print("\n=== NXDOMAIN ===")
    for q, count in results["nxdomain_counter"].most_common(10):
        print(f"{q}: {count}")

    print("\n=== Suspicious Domains ===")
    print(f"Total suspicious: {len(results['suspicious_domains'])}")
    for d in results["suspicious_domains"][:10]:
        print(f"- {d}")

    print("\n=== DGA-like Domains ===")
    print(f"Total DGA-like: {len(results['dga_domains'])}")
    for d in results["dga_domains"][:10]:
        print(f"- {d}")

    print("\n=== Rare TLDs ===")
    for tld, count in results["rare_tlds"].most_common(10):
        print(f".{tld}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata DNS events")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)
    results = analyze_dns(events)
    print_results(results)


if __name__ == "__main__":
    main()
