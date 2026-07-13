#!/usr/bin/env python3
"""
suricata_tls.py — Suricata TLS analysis module.
Features:
    • JA3 / JA3S fingerprints
    • Certificate analysis
    • Self-signed detection
    • Rare cipher suites
    • Suspicious SNI
"""

import argparse
from pathlib import Path
from collections import Counter

from load_suricata import load_suricata_events


SUSPICIOUS_SNI_KEYWORDS = [
    "update", "bot", "malware", "shell", "cmd", "hack",
    "exploit", "backdoor", "stealer", "crypto", "miner"
]

RARE_CIPHERS = [
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_NULL_SHA",
]


def is_self_signed(cert):
    if not cert:
        return False
    subject = cert.get("subject")
    issuer = cert.get("issuer")
    return subject and issuer and subject == issuer


def is_suspicious_sni(sni: str):
    if not sni:
        return False
    sni_lower = sni.lower()
    return any(k in sni_lower for k in SUSPICIOUS_SNI_KEYWORDS)


def analyze_tls(events):
    tls_events = events.get("tls", [])

    ja3_counter = Counter()
    ja3s_counter = Counter()
    cipher_counter = Counter()
    sni_counter = Counter()

    self_signed = []
    suspicious_sni = []
    rare_cipher_hits = []

    for t in tls_events:
        tls = t.get("tls", {})

        # Normalize JA3
        ja3_raw = tls.get("ja3")
        if isinstance(ja3_raw, dict):
            ja3 = ja3_raw.get("hash")
        elif isinstance(ja3_raw, str):
            ja3 = ja3_raw
        else:
            ja3 = None

        # Normalize JA3S
        ja3s_raw = tls.get("ja3s")
        if isinstance(ja3s_raw, dict):
            ja3s = ja3s_raw.get("hash")
        elif isinstance(ja3s_raw, str):
            ja3s = ja3s_raw
        else:
            ja3s = None

        if ja3:
            ja3_counter[ja3] += 1
        if ja3s:
            ja3s_counter[ja3s] += 1

        # Cipher suite
        cipher = tls.get("cipher")
        if cipher:
            cipher_counter[cipher] += 1
            if cipher in RARE_CIPHERS:
                rare_cipher_hits.append(t)

        # SNI
        sni = tls.get("sni")
        if sni:
            sni_counter[sni] += 1
            if is_suspicious_sni(sni):
                suspicious_sni.append(sni)

        # Certificate analysis
        cert = tls.get("certificate")
        if is_self_signed(cert):
            self_signed.append(cert)

    return {
        "ja3_counter": ja3_counter,
        "ja3s_counter": ja3s_counter,
        "cipher_counter": cipher_counter,
        "sni_counter": sni_counter,
        "self_signed": self_signed,
        "suspicious_sni": suspicious_sni,
        "rare_cipher_hits": rare_cipher_hits,
    }


def print_results(results):
    print("\n=== JA3 Fingerprints ===")
    for fp, count in results["ja3_counter"].most_common(10):
        print(f"{fp}: {count}")

    print("\n=== JA3S Fingerprints ===")
    for fp, count in results["ja3s_counter"].most_common(10):
        print(f"{fp}: {count}")

    print("\n=== Cipher Suites ===")
    for c, count in results["cipher_counter"].most_common(10):
        print(f"{c}: {count}")

    print("\n=== Suspicious SNI ===")
    print(f"Total suspicious SNI: {len(results['suspicious_sni'])}")
    for sni in results["suspicious_sni"][:10]:
        print(f"- {sni}")

    print("\n=== Self-Signed Certificates ===")
    print(f"Total self-signed: {len(results['self_signed'])}")

    print("\n=== Rare Cipher Suite Hits ===")
    print(f"Total rare cipher hits: {len(results['rare_cipher_hits'])}")


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata TLS events")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)
    results = analyze_tls(events)
    print_results(results)


if __name__ == "__main__":
    main()
