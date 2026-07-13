#!/usr/bin/env python3
"""
suricata_http.py — Suricata HTTP analysis module.
Features:
    • HTTP methods (GET/POST/PUT/HEAD/OPTIONS)
    • User-Agent statistics
    • Domains (host)
    • URI / URL
    • File downloads detection
    • Suspicious request heuristics
"""

import argparse
from pathlib import Path
from collections import Counter, defaultdict
from urllib.parse import urlparse

from load_suricata import load_suricata_events


def is_download(uri: str):
    """Detect file downloads by extension."""
    if not uri:
        return False

    suspicious_ext = [
        ".exe", ".dll", ".bin", ".sh", ".py", ".zip", ".tar", ".gz",
        ".rar", ".7z", ".msi", ".apk", ".iso"
    ]

    uri_lower = uri.lower()
    return any(uri_lower.endswith(ext) for ext in suspicious_ext)


def is_suspicious(uri: str, ua: str):
    """Simple heuristics for suspicious HTTP requests."""
    if not uri:
        return False

    uri_lower = uri.lower()

    # Suspicious patterns
    patterns = [
        "cmd=", "exec=", "shell=", "upload", "download",
        "wp-admin", "wp-login", "phpinfo", "config", "passwd",
        "id=", "select", "union", "sleep(", "benchmark("
    ]

    if any(p in uri_lower for p in patterns):
        return True

    # Suspicious User-Agent
    if ua:
        ua_lower = ua.lower()
        bad_agents = ["curl", "wget", "python-requests", "powershell", "bot"]
        if any(b in ua_lower for b in bad_agents):
            return True

    return False


def analyze_http(events):
    http_events = events.get("http", [])

    method_counter = Counter()
    user_agent_counter = Counter()
    domain_counter = Counter()
    uri_counter = Counter()

    downloads = []
    suspicious = []

    for h in http_events:
        http = h.get("http", {})

        method = http.get("http_method")
        ua = http.get("http_user_agent")
        host = http.get("hostname") or http.get("host")
        uri = http.get("url") or http.get("uri")

        # Methods
        if method:
            method_counter[method] += 1

        # User-Agent
        if ua:
            user_agent_counter[ua] += 1

        # Domains
        if host:
            domain_counter[host] += 1

        # URI
        if uri:
            uri_counter[uri] += 1

            # Downloads
            if is_download(uri):
                downloads.append(h)

            # Suspicious requests
            if is_suspicious(uri, ua):
                suspicious.append(h)

    return {
        "method_counter": method_counter,
        "user_agent_counter": user_agent_counter,
        "domain_counter": domain_counter,
        "uri_counter": uri_counter,
        "downloads": downloads,
        "suspicious": suspicious,
    }


def print_results(results):
    print("\n=== HTTP Methods ===")
    for m, count in results["method_counter"].most_common(10):
        print(f"{m}: {count}")

    print("\n=== Top User-Agents ===")
    for ua, count in results["user_agent_counter"].most_common(10):
        print(f"{ua}: {count}")

    print("\n=== Top Domains ===")
    for d, count in results["domain_counter"].most_common(10):
        print(f"{d}: {count}")

    print("\n=== Top URIs ===")
    for u, count in results["uri_counter"].most_common(10):
        print(f"{u}: {count}")

    print("\n=== File Downloads Detected ===")
    print(f"Total downloads: {len(results['downloads'])}")

    print("\n=== Suspicious HTTP Requests ===")
    print(f"Total suspicious requests: {len(results['suspicious'])}")


def main():
    parser = argparse.ArgumentParser(description="Analyze Suricata HTTP events")
    parser.add_argument("logfile", help="Path to Suricata eve.json")
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"File not found: {path}")
        return

    events = load_suricata_events(path)
    results = analyze_http(events)
    print_results(results)


if __name__ == "__main__":
    main()
