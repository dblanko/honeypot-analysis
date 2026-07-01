#!/usr/bin/env python3
import sqlite3
import argparse
import geoip2.database
import os
from collections import Counter
from datetime import datetime, timedelta, timezone

DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"

# Possible paths to GeoLite2-ASN
ASN_DB_CANDIDATES = [
    "/home/honeypotuser/geoipdb/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
]


def find_asn_db(custom_path=None):
    """Returns the path to an existing GeoLite2-ASN database."""
    if custom_path:
        if os.path.isfile(custom_path):
            return custom_path
        print(f"[ERROR] ASN DB not found at: {custom_path}")
        return None

    for path in ASN_DB_CANDIDATES:
        if os.path.isfile(path):
            return path

    return None


def to_unix(dt: datetime) -> int:
    return int(dt.timestamp())


def build_time_filter(args):
    """Returns the SQL condition and parameters for filtering by connection_timestamp."""
    if args.last_week:
        today = datetime.now(timezone.utc).date()
        date_from = datetime.combine(today - timedelta(days=6), datetime.min.time(), tzinfo=timezone.utc)
        date_to   = datetime.combine(today, datetime.max.time(), tzinfo=timezone.utc)

    elif args.last_month:
        today = datetime.now(timezone.utc).date()
        date_from = datetime.combine(today - timedelta(days=29), datetime.min.time(), tzinfo=timezone.utc)
        date_to   = datetime.combine(today, datetime.max.time(), tzinfo=timezone.utc)

    else:
        date_from = datetime.fromisoformat(args.date_from) if args.date_from else None
        date_to   = datetime.fromisoformat(args.date_to)   if args.date_to   else None

    if date_from and date_to:
        return "WHERE connection_timestamp >= ? AND connection_timestamp <= ?", [
            to_unix(date_from), to_unix(date_to)
        ]
    elif date_from:
        return "WHERE connection_timestamp >= ?", [to_unix(date_from)]
    elif date_to:
        return "WHERE connection_timestamp <= ?", [to_unix(date_to)]
    else:
        return "", []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--geo-asn", dest="asn_db", help="Path to GeoLite2-ASN.mmdb")
    parser.add_argument("--from", dest="date_from", help="Start date YYYY-MM-DD")
    parser.add_argument("--to", dest="date_to", help="End date YYYY-MM-DD")
    parser.add_argument("--last-week", action="store_true")
    parser.add_argument("--last-month", action="store_true")
    args = parser.parse_args()

    # Determine the path to the ASN database
    asn_db_path = find_asn_db(args.asn_db)
    if not asn_db_path:
        print("[FATAL] GeoLite2-ASN.mmdb not found.")
        print("Specify manually: --geo-asn /path/to/GeoLite2-ASN.mmdb")
        return

    time_filter, params = build_time_filter(args)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Forming a correct WHERE
    if time_filter:
        where_clause = f"{time_filter} AND remote_host IS NOT NULL"
    else:
        where_clause = "WHERE remote_host IS NOT NULL"

    # We take only IP addresses that are actually active during the selected period
    cur.execute(f"""
        SELECT DISTINCT remote_host
        FROM connections
        {where_clause};
    """, params)

    ips = [row[0] for row in cur.fetchall()]

    reader = geoip2.database.Reader(asn_db_path)

    asn_counter = Counter()
    asn_names = {}

    for ip in ips:
        try:
            response = reader.asn(ip)
            asn = response.autonomous_system_number
            name = response.autonomous_system_organization
            asn_counter[asn] += 1
            asn_names[asn] = name
        except:
            continue

    reader.close()
    conn.close()

    print("\n=== TOP ASN BY NUMBER OF ATTACKING IPs ===\n")
    for asn, count in asn_counter.most_common(20):
        print(f"AS{asn} ({asn_names.get(asn, 'Unknown')}): {count} IPs")


if __name__ == "__main__":
    main()
