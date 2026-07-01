#!/usr/bin/env python3
import sqlite3
from collections import defaultdict
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''SELECT remote_host, connection_protocol FROM connections
                   WHERE remote_host IS NOT NULL
                     AND connection_protocol IS NOT NULL;''')
    ip_services = defaultdict(set)
    for ip, proto in cur.fetchall(): ip_services[ip].add(proto)
    print("\n=== MULTI-SERVICE ATTACKERS ===")
    for ip, services in ip_services.items():
        if len(services) > 1:
            print(f"{ip}: {", ".join(sorted(services))}")
if __name__ == '__main__': main()
