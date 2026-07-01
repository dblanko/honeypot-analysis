#!/usr/bin/env python3
import sqlite3
DB_PATH = "/opt/dionaea-data/sqlite/dionaea.sqlite"
PROTOCOL_TABLES = {
    "mysql": "mysql_commands", "mssql": "mssql_commands",
    "dcerpc_requests": "dcerpcrequests", "dcerpc_binds": "dcerpcbinds",
    "downloads": "downloads", "offers": "offers", "logins": "logins"
}

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    print("\n=== STATISTICS BY EVENT TYPE ===")
    for proto, table in PROTOCOL_TABLES.items():
        try:
            cur.execute(f'SELECT COUNT(*) FROM {table};')
            count = cur.fetchone()[0]
        except sqlite3.OperationalError: continue
        print(f"\nEvent Type: {proto} ({count} events)")
        if count == 0: continue
        cur.execute(f'''SELECT c.remote_host, COUNT(*)
            FROM {table} t JOIN connections c ON t.connection = c.connection
            GROUP BY c.remote_host ORDER BY COUNT(*) DESC LIMIT 10;''')
        print("  Top attacker IPs:")
        for ip, n in cur.fetchall(): print(f"    {ip}: {n}")
    conn.close()
if __name__ == '__main__': main()
