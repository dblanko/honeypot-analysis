#!/usr/bin/env python3
import sqlite3
import argparse
import geoip2.database
import requests
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import os

DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"
ASN_CACHE_PATH = os.path.expanduser("~/.asn_cache.sqlite")

ASN_DB_CANDIDATES = [
    "/home/honeypotuser/geoipdb/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
]


# ============================
#  ASN DB autodetect
# ============================
def find_asn_db(custom_path=None):
    if custom_path:
        return custom_path if os.path.isfile(custom_path) else None
    for p in ASN_DB_CANDIDATES:
        if os.path.isfile(p):
            return p
    return None


# ============================
#  ASN Cache DB (writable)
# ============================
def get_asn_cache_conn():
    conn = sqlite3.connect(ASN_CACHE_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS asn_cache (
            ip TEXT PRIMARY KEY,
            asn TEXT,
            org TEXT
        )
    """)
    conn.commit()
    return conn


def lookup_asn(ip, reader, cache_conn):
    cur = cache_conn.cursor()

    # Check cache
    cur.execute("SELECT asn, org FROM asn_cache WHERE ip=?", (ip,))
    row = cur.fetchone()
    if row:
        return row[0], row[1]

    # Try GeoLite2-ASN
    try:
        resp = reader.asn(ip)
        asn = f"AS{resp.autonomous_system_number}"
        org = resp.autonomous_system_organization
    except:
        # Fallback to API
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=asn,org,status",
                timeout=3
            )
            data = r.json()
            if data.get("status") == "success":
                asn = data.get("asn", "UNKNOWN")
                org = data.get("org", "UNKNOWN")
            else:
                asn, org = "UNKNOWN", "UNKNOWN"
        except:
            asn, org = "UNKNOWN", "UNKNOWN"

    cur.execute(
        "INSERT OR REPLACE INTO asn_cache (ip, asn, org) VALUES (?, ?, ?)",
        (ip, asn, org)
    )
    cache_conn.commit()

    return asn, org


# ============================
#  Time helpers
# ============================
def to_unix(dt):
    return int(dt.timestamp())


def parse_ts(ts):
    """Universal timestamp parser."""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, timezone.utc)

    if isinstance(ts, str):
        # First, let's try it as a UNIX timestamp.
        try:
            return datetime.fromtimestamp(float(ts), timezone.utc)
        except:
            pass

        # then ISO8601
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except:
            pass

    raise ValueError(f"Unknown timestamp format: {ts}")


def build_time_filter(args):
    if args.last_week:
        today = datetime.now(timezone.utc).date()
        df = datetime.combine(today - timedelta(days=6), datetime.min.time(), tzinfo=timezone.utc)
        dt = datetime.combine(today, datetime.max.time(), tzinfo=timezone.utc)
    elif args.last_month:
        today = datetime.now(timezone.utc).date()
        df = datetime.combine(today - timedelta(days=29), datetime.min.time(), tzinfo=timezone.utc)
        dt = datetime.combine(today, datetime.max.time(), tzinfo=timezone.utc)
    else:
        df = datetime.fromisoformat(args.date_from) if args.date_from else None
        dt = datetime.fromisoformat(args.date_to) if args.date_to else None

    if df and dt:
        return "WHERE connection_timestamp >= ? AND connection_timestamp <= ?", [to_unix(df), to_unix(dt)]
    elif df:
        return "WHERE connection_timestamp >= ?", [to_unix(df)]
    elif dt:
        return "WHERE connection_timestamp <= ?", [to_unix(dt)]
    else:
        return "", []


# ============================
#  ASN → Protocol Matrix
# ============================
def asn_protocol_matrix(conn, cache_conn, reader, time_filter, params):
    print("\n=== ASN → Protocol Matrix ===")

    cur = conn.cursor()

    # Forming a correct WHERE
    if time_filter:
        where_clause = f"{time_filter} AND remote_host IS NOT NULL AND connection_type IS NOT NULL"
    else:
        where_clause = "WHERE remote_host IS NOT NULL AND connection_type IS NOT NULL"

    # 1. Loading all lines
    cur.execute(f"""
        SELECT remote_host, connection_type
        FROM connections
        {where_clause};
    """, params)

    rows = cur.fetchall()

    # 2. Unique IPs
    unique_ips = {ip for ip, _ in rows}

    # 3. We define ASN only once per IP
    ip_to_asn = {}
    for ip in unique_ips:
        ip_to_asn[ip] = "{} ({})".format(*lookup_asn(ip, reader, cache_conn))

    # 4. We construct a matrix
    matrix = defaultdict(lambda: defaultdict(int))
    for ip, proto in rows:
        matrix[ip_to_asn[ip]][proto] += 1

    # 5. Conclusion
    for asn, protos in sorted(matrix.items(), key=lambda x: sum(x[1].values()), reverse=True):
        print(f"\nASN: {asn}")
        for proto, count in sorted(protos.items(), key=lambda x: x[1], reverse=True):
            print(f"  {proto}: {count}")


# ============================
#  Portscan Patterns
# ============================
def portscan_patterns(conn, time_filter, params):
    print("\n=== Portscan Patterns ===")

    cur = conn.cursor()
    cur.execute(f"""
        SELECT local_port, COUNT(*), COUNT(DISTINCT remote_host)
        FROM connections
        {time_filter}
        GROUP BY local_port
        ORDER BY COUNT(*) DESC;
    """, params)

    print(f"{'Port':<8} {'Events':<10} {'Unique IPs'}")
    for port, events, uniq in cur.fetchall():
        print(f"{port:<8} {events:<10} {uniq}")


# ============================
#  IP First/Last Seen
# ============================
def ip_first_last_seen(conn, time_filter, params):
    print("\n=== IP First/Last Seen ===")

    cur = conn.cursor()

    if time_filter:
        where_clause = f"{time_filter} AND remote_host IS NOT NULL"
    else:
        where_clause = "WHERE remote_host IS NOT NULL"

    cur.execute(f"""
        SELECT remote_host,
               MIN(connection_timestamp),
               MAX(connection_timestamp),
               COUNT(*)
        FROM connections
        {where_clause}
        GROUP BY remote_host
        ORDER BY MIN(connection_timestamp);
    """, params)

    print(f"{'IP':<18} {'First Seen':<20} {'Last Seen':<20} {'Events'}")

    for ip, first, last, count in cur.fetchall():
        fd = parse_ts(first).strftime("%Y-%m-%d %H:%M")
        ld = parse_ts(last).strftime("%Y-%m-%d %H:%M")
        print(f"{ip:<18} {fd:<20} {ld:<20} {count}")


# ============================
#  Main
# ============================
def main():
    parser = argparse.ArgumentParser(description="Infrastructure analysis for Dionaea honeypot")
    parser.add_argument("--asn-matrix", action="store_true")
    parser.add_argument("--portscan", action="store_true")
    parser.add_argument("--first-last", action="store_true")
    parser.add_argument("--all", action="store_true")

    parser.add_argument("--geo-asn", dest="asn_db", help="Path to GeoLite2-ASN.mmdb")
    parser.add_argument("--from", dest="date_from")
    parser.add_argument("--to", dest="date_to")
    parser.add_argument("--last-week", action="store_true")
    parser.add_argument("--last-month", action="store_true")

    args = parser.parse_args()

    conn = sqlite3.connect(DB_PATH)
    cache_conn = get_asn_cache_conn()

    asn_db_path = find_asn_db(args.asn_db)
    reader = geoip2.database.Reader(asn_db_path) if asn_db_path else None

    time_filter, params = build_time_filter(args)

    if args.asn_matrix or args.all:
        asn_protocol_matrix(conn, cache_conn, reader, time_filter, params)

    if args.portscan or args.all:
        portscan_patterns(conn, time_filter, params)

    if args.first_last or args.all:
        ip_first_last_seen(conn, time_filter, params)

    if not (args.asn_matrix or args.portscan or args.first_last or args.all):
        print("No arguments provided. Use --help for options.")


if __name__ == "__main__":
    main()
