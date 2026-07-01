#!/usr/bin/env python3
import sqlite3
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"
TABLES = ["mysql_commands","mssql_commands","dcerpcrequests",
          "dcerpcbinds","downloads","offers","logins"]

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    ip_counts = {}
    for table in TABLES:
        try:
            cur.execute(f'''SELECT c.remote_host, COUNT(*)
                FROM {table} t JOIN connections c ON t.connection=c.connection
                GROUP BY c.remote_host;''')
        except sqlite3.OperationalError: continue
        for ip, count in cur.fetchall():
            ip_counts[ip] = ip_counts.get(ip, 0) + count
    print("\n=== TOP ATTACKER IPs ===")
    for ip, count in sorted(ip_counts.items(),
                            key=lambda x: x[1], reverse=True)[:20]:
        print(f"{ip}: {count}")
if __name__ == '__main__': main()
